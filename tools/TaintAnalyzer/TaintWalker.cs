using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class TaintWalker
{
    private readonly AssemblyContext _context;
    // Memo key: (callee FullName, tainted-arg bitmask, sorted+joined seeded `this`-field names).
    // Seeded-fields-as-string keeps the key value-typed-equality friendly without a custom comparer.
    private readonly Dictionary<(string fullName, int bitmask, string seedKey), MethodSummary> _memo = new();

    // Recursion depth guard. The (FullName, bitmask, seedKey) memo handles ordinary cycles, but
    // when a method's caller re-enters with progressively larger `seedKey`s — typical when a
    // chunk-loop accumulates this-field taint per iteration and propagates the growing set into
    // each callee — each iteration's memo key differs and the placeholder never fires. The depth
    // limit caps that growth; methods walked past the limit return an empty summary (matching
    // the "couldn't reach sink" semantics already used for unresolved callees).
    private int _depth;
    private const int MaxDepth = 256;

    // Set by Program.cs before each WalkWithSeed to specify which external methods
    // should have their return value treated as tainted regardless of input taint.
    // Entries are matched as "TypeName::MethodName" (class name without namespace).
    public IReadOnlyList<string> TaintFromExternalReturns { get; set; } = Array.Empty<string>();

    public TaintWalker(AssemblyContext context) => _context = context;

    public MethodSummary Walk(MethodDefinition method, int taintedParamBitmask)
        => WalkWithSeed(method, taintedParamBitmask, taintedThisFields: Array.Empty<string>());

    public MethodSummary WalkWithSeed(MethodDefinition method, int taintedParamBitmask, IReadOnlyCollection<string> taintedThisFields)
    {
        var seedKey = BuildSeedKey(taintedThisFields);
        var key = (method.FullName, taintedParamBitmask, seedKey);
        if (_memo.TryGetValue(key, out var cached))
        {
            return cached;
        }

        if (_depth >= MaxDepth)
        {
            return EmptySummary(method, taintedParamBitmask);
        }

        // Sentinel placeholder breaks recursion on cycles — the recursive call sees this empty
        // summary and returns immediately, completing the cycle without infinite descent.
        var placeholder = EmptySummary(method, taintedParamBitmask);
        _memo[key] = placeholder;

        _depth++;
        MethodSummary summary;
        try
        {
            summary = WalkMethodBody(method, taintedParamBitmask, taintedThisFields);
        }
        finally
        {
            _depth--;
        }
        _memo[key] = summary;
        return summary;
    }

    private static MethodSummary EmptySummary(MethodDefinition method, int taintedParamBitmask) => new()
    {
        MethodFullName = method.FullName,
        TaintedParamBitmask = taintedParamBitmask,
        ReturnsTainted = false,
        NewlyTaintedThisFields = Array.Empty<string>(),
        Hops = Array.Empty<HopRecord>(),
        Absences = Array.Empty<EmittedSanitizerAbsence>(),
        ReachedSink = false,
        AppliedValueClamp = false,
    };

    private static string BuildSeedKey(IReadOnlyCollection<string> taintedThisFields)
    {
        if (taintedThisFields.Count == 0) return "";
        var sorted = taintedThisFields.OrderBy(s => s, StringComparer.Ordinal);
        return string.Join(",", sorted);
    }

    private MethodSummary WalkMethodBody(
        MethodDefinition method,
        int taintedParamBitmask,
        IReadOnlyCollection<string> taintedThisFields)
    {
        var state = new TaintState();
        SeedArgumentTaint(method, taintedParamBitmask, state);
        SeedThisFieldTaint(method, taintedThisFields, state);

        var hops = new List<HopRecord>();
        bool reachedSink = false;
        bool appliedValueClamp = false;
        bool returnsTainted = false;
        // Hop counter resets per method; Task 11 refines to aggregate hops across the call chain.
        int hopCounter = 0;
        var newlyTaintedFields = new HashSet<string>(StringComparer.Ordinal);
        // U10 — tracks which (callee.FullName|bitmask|seedKey) triples have already had their
        // hops merged into this walk's flat list. Prevents duplicate appends when the same
        // callee is called more than once with the same taint context.
        var expandedCallees = new HashSet<string>(StringComparer.Ordinal);

        if (method.Body is null)
        {
            return new MethodSummary
            {
                MethodFullName = method.FullName,
                TaintedParamBitmask = taintedParamBitmask,
                ReturnsTainted = false,
                NewlyTaintedThisFields = Array.Empty<string>(),
                Hops = hops,
                Absences = Array.Empty<EmittedSanitizerAbsence>(),
                ReachedSink = false,
                AppliedValueClamp = false,
            };
        }

        // Pre-compute sanitizer matches keyed by comparison IL offset so we can emit them in
        // IL order during the body walk (rather than splicing at the end, which mis-positions
        // them relative to the in-method sink for multi-sink traces).
        var sanitizerByOffset = SanitizerShapes.MatchAll(method)
            .GroupBy(m => m.ComparisonIlOffset)
            .ToDictionary(g => g.Key, g => g.First());

        // Pre-compute ternary-clamp matches keyed by JOIN IL offset. When the IL walker reaches
        // the join, the symbolic stack contains the post-join value (already pushed by the loaded
        // arm). If the comparison's two operands at ComparisonIlOffset were tainted vs bounded,
        // replace the join slot with an untainted slot.
        var clampMatchByJoinOffset = SanitizerShapes.MatchValueClamps(method)
            .GroupBy(c => c.JoinIlOffset)
            .ToDictionary(g => g.Key, g => g.First());

        foreach (var ins in method.Body.Instructions)
        {
            PushImplicitExceptionIfHandlerStart(method, ins, state);

            if (HandleSinkMatch(method, ins, state, hops, ref hopCounter))
            {
                reachedSink = true;
                // Continue iterating — future hops won't add more for this path, but multi-sink
                // methods could in principle produce additional sink records.
            }

            if (sanitizerByOffset.TryGetValue(ins.Offset, out var sanitizerMatch))
            {
                var sp = _context.GetSequencePoint(method, ins);
                hops.Add(new HopRecord
                {
                    Hop = hopCounter++,
                    Method = $"{method.DeclaringType.FullName}.{method.Name}",
                    File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
                    Line = sp?.StartLine ?? 0,
                    Role = HopRole.Sanitizer,
                    TaintedValueIn = sanitizerMatch.EstablishesBound.Target,
                    Transformation = "identity",
                    TaintedValueOut = sanitizerMatch.EstablishesBound.Target,
                    EstablishesBound = sanitizerMatch.EstablishesBound,
                    OnFailure = sanitizerMatch.OnFailure,
                    Dispatch = new ResolvedDispatch
                    {
                        Kind = "direct",
                        StaticType = method.DeclaringType.FullName,
                        ResolvedTargets = Array.Empty<string>(),
                        ClosureBoundary = false,
                    },
                });
            }

            // Apply ternary-clamp untainting BEFORE StepInstruction so that store instructions
            // (stloc.*) at the join point propagate the untainted value into the local variable.
            // The join instruction is either a `stloc` (OTel shape: value stored then reloaded)
            // or a `ret` (simple fixture shape: value returned directly). Both cases work with
            // the pre-step check because:
            //   - For stloc: the stack top is untainted before the store, so the local is clean.
            //   - For ret: StepInstruction is a no-op for ret; the returnsTainted check below
            //     also runs after this block and sees the untainted top.
            if (clampMatchByJoinOffset.TryGetValue(ins.Offset, out var clamp))
            {
                if (state.Stack.Depth > 0)
                {
                    var top = state.Stack.Peek();
                    if (top.Tainted)
                    {
                        state.Stack.Pop();
                        var prov = $"clamped({clamp.TaintedOperandProvenance}; bound={clamp.BoundedOperandProvenance})";
                        state.Stack.Push(new StackSlot(false, prov));
                        appliedValueClamp = true;
                    }
                }
            }

            StepInstruction(method, ins, state, newlyTaintedFields, hops, ref hopCounter, ref reachedSink, expandedCallees);

            // Detect tainted-return AFTER clamp untainting (above) so ternary-clamp join slots that
            // happen to coincide with `ret` (i.e. JoinIlOffset == ret offset) are already
            // cleaned before we sample the stack. The step itself is a no-op for `ret`.
            if (ins.OpCode.Code == Code.Ret
                && method.ReturnType.FullName != "System.Void"
                && state.Stack.Depth > 0
                && state.Stack.Peek().Tainted)
            {
                returnsTainted = true;
            }
        }

        // Sanitizer-absence synthesis lives in TraceEmitter — it has the per-sink path context
        // needed to decide whether each individual sink in a multi-sink trace is unsanitized.
        return new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = returnsTainted,
            NewlyTaintedThisFields = newlyTaintedFields.ToArray(),
            Hops = hops,
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = reachedSink,
            AppliedValueClamp = appliedValueClamp,
        };
    }

    private static void SeedThisFieldTaint(MethodDefinition method, IReadOnlyCollection<string> fields, TaintState state)
    {
        if (!method.HasThis || fields.Count == 0) return;
        var declaringType = method.DeclaringType;
        foreach (var name in fields)
        {
            var fd = declaringType.Fields.FirstOrDefault(f => f.Name == name);
            if (fd is null) continue;
            state.ThisFields[fd.FullName] = StackSlot.TaintedWith(name);
        }
    }

    private static void SeedArgumentTaint(MethodDefinition method, int bitmask, TaintState state)
    {
        int argOffset = method.HasThis ? 1 : 0;
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (((bitmask >> i) & 1) != 0)
            {
                state.Args[i + argOffset] = StackSlot.TaintedWith(method.Parameters[i].Name);
            }
            else
            {
                state.Args[i + argOffset] = StackSlot.Untainted;
            }
        }
        // MVP: don't seed `this` as tainted from bitmask — Task 10 introduces WalkWithSeed for that.
        // Use the `ThisRef` sentinel so a later `ldarg.0` push carries the "this" identity through
        // the stack — receiver detection in stfld/call relies on this.
        if (method.HasThis)
        {
            state.Args[0] = StackSlot.ThisRef;
        }
    }

    // Returns true when this instruction is a sink and its critical argument is tainted.
    private bool HandleSinkMatch(MethodDefinition method, Instruction ins, TaintState state, List<HopRecord> hops, ref int hopCounter)
    {
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack)
            ?? SinkShapes.MatchHttpRead(ins, state.Stack);

        if (m is null) return false;

        var sp = _context.GetSequencePoint(method, ins);

        // If the size operand came directly from a `ldloc <local>` (the common shape for
        // `new T[localVar]` etc.), attach the local's first-tainted-assignment line to the
        // sink hop. The trace emitter prefers this for sanitizer_absence location, since it
        // points at where the value's taint *originated* in the method — even when the
        // linear walker re-assigned the local across branches and the LAST stloc's
        // provenance won the symbolic stack.
        string? firstTaintedFile = null;
        int? firstTaintedLine = null;
        string? firstTaintedProvenance = null;
        var prev = ins.Previous;
        // Skip over Roslyn-emitted debug nops between the local-load and the sink instruction.
        while (prev is not null && prev.OpCode.Code == Code.Nop) prev = prev.Previous;
        int? sourceLocalIdx = prev?.OpCode.Code switch
        {
            Code.Ldloc_0 => 0,
            Code.Ldloc_1 => 1,
            Code.Ldloc_2 => 2,
            Code.Ldloc_3 => 3,
            Code.Ldloc or Code.Ldloc_S => ((VariableDefinition)prev.Operand).Index,
            _ => (int?)null,
        };
        if (sourceLocalIdx is { } idx && state.FirstLocalTaintLine.TryGetValue(idx, out var firstAssign))
        {
            firstTaintedFile = Path.GetFileName(firstAssign.File);
            firstTaintedLine = firstAssign.Line;
            firstTaintedProvenance = firstAssign.Provenance;
        }

        // Prefer the local's PDB debug name as the sink's tainted_value when the size operand
        // came from a `ldloc <local>` and the local has a debug name. The propagated symbolic
        // provenance reflects the value's derivation chain (e.g., `MemoryExtensions.IndexOf(...)`)
        // — the local's source-level name (`translatedKeywordLength`) is what fixture authors and
        // bug reports use. Falls back to SizeProvenance when no debug name is available.
        string taintedValue = m.SizeProvenance;
        if (sourceLocalIdx is { } li && method.Body?.Variables is { } vars && li < vars.Count)
        {
            if (method.DebugInformation?.TryGetName(vars[li], out var dn) == true && !string.IsNullOrEmpty(dn))
            {
                taintedValue = dn;
            }
        }

        hops.Add(new HopRecord
        {
            Hop = hopCounter++,
            Method = $"{method.DeclaringType.FullName}.{method.Name}",
            File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
            Line = sp?.StartLine ?? 0,
            Role = HopRole.Sink,
            TaintedValueIn = taintedValue,
            Transformation = "identity",
            TaintedValueOut = taintedValue,
            SinkKind = m.Kind,
            SinkApi = m.Api,
            SizeExpression = m.Kind == SinkKind.Allocation ? taintedValue : null,
            AccessExpression = m.Kind == SinkKind.SpanAccess ? taintedValue : null,
            FirstTaintedFile = firstTaintedFile,
            FirstTaintedLine = firstTaintedLine,
            FirstTaintedProvenance = firstTaintedProvenance,
        });
        return true;
    }

    // N2 — strip the `get_` property-getter prefix when composing call-return provenance,
    // so synthetic strings render as "receiver.Property" instead of "receiver.get_Property".
    // Conservative: matches only the common-case getter prefix; other accessor patterns
    // (set_/add_/remove_/op_) don't compose into provenance the same way and are out of scope.
    private static string CleanCalleeName(MethodReference callee)
    {
        var name = callee.Name;
        if (name.StartsWith("get_", StringComparison.Ordinal) && name.Length > 4)
        {
            return name.Substring(4);
        }
        return name;
    }

    private bool MatchesTaintFromExternalReturn(MethodReference callee)
    {
        foreach (var entry in TaintFromExternalReturns)
        {
            var sep = entry.IndexOf("::", StringComparison.Ordinal);
            if (sep < 0)
            {
                if (callee.Name == entry) return true;
            }
            else
            {
                if (callee.DeclaringType.Name == entry[..sep] && callee.Name == entry[(sep + 2)..])
                    return true;
            }
        }
        return false;
    }

    // N1 — predicate for whether a PDB-resolved local name is suitable for use as a slot's
    // Provenance. Skip compiler-generated state-machine fields (`<…>` prefix), compiler-generated
    // temporaries (`CS$…` prefix), and the `loc_N` debug-info fallback that matches the
    // sanitizer-side noise we explicitly want out of trace fields.
    private static bool IsMeaningfulLocalName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (name.StartsWith("<", StringComparison.Ordinal)) return false;
        if (name.StartsWith("CS$", StringComparison.Ordinal)) return false;
        // loc_<digits> shape — debug-info fallback emitted by some toolchains.
        if (name.Length > 4 && name.StartsWith("loc_", StringComparison.Ordinal))
        {
            bool allDigits = true;
            for (int i = 4; i < name.Length; i++)
            {
                if (!char.IsDigit(name[i])) { allDigits = false; break; }
            }
            if (allDigits) return false;
        }
        return true;
    }

    // Stloc helper: store top-of-stack into local `idx`, and remember the first instruction
    // whose stloc to this local landed a tainted value. Per-local tracking is needed because
    // a single local can be assigned across multiple branches (linear walking visits all
    // branches in IL order), and the last stloc's provenance wins on the stack — losing the
    // "where did taint first enter this local" information that's actually relevant for
    // sanitizer-absence location.
    private void StoreLocal(MethodDefinition method, Instruction ins, int idx, TaintState state)
    {
        // Defensive: real-world IL with try/catch/filter regions or compiler-generated state
        // machines can leave the linear walker's symbolic stack out-of-sync with the actual IL
        // stack at certain instructions. Treat underflow as "store untainted" rather than
        // crashing — the value isn't observable through this code path anyway.
        if (state.Stack.Depth == 0)
        {
            state.Locals[idx] = StackSlot.Untainted;
            return;
        }
        var value = state.Stack.Pop();

        // N1 — when storing a tainted value to a local with a meaningful PDB name, replace
        // the slot's Provenance with the local name. Subsequent ldloc of this local pushes
        // a slot carrying the local name, so downstream hops' tainted_value_* fields reflect
        // what a triager reads in source instead of synthetic call-return / arithmetic strings.
        var slotToStore = value;
        if (value.Tainted
            && method.Body?.Variables is { } vars && idx < vars.Count
            && method.DebugInformation?.TryGetName(vars[idx], out var dn) == true
            && IsMeaningfulLocalName(dn))
        {
            slotToStore = StackSlot.TaintedWith(dn);
        }
        state.Locals[idx] = slotToStore;

        if (slotToStore.Tainted && !state.FirstLocalTaintLine.ContainsKey(idx))
        {
            var sp = _context.GetSequencePoint(method, ins);
            if (sp is not null)
            {
                state.FirstLocalTaintLine[idx] = (sp.Document.Url, sp.StartLine, slotToStore.Provenance);
            }
        }
    }

    private void EmitPropagatorHop(
        MethodDefinition method,
        Instruction ins,
        string transformation,
        string valueIn,
        string valueOut,
        ResolvedDispatch? dispatch,
        List<HopRecord> hops,
        ref int hopCounter)
    {
        var sp = _context.GetSequencePoint(method, ins);
        hops.Add(new HopRecord
        {
            Hop = hopCounter++,
            Method = $"{method.DeclaringType.FullName}.{method.Name}",
            File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
            Line = sp?.StartLine ?? 0,
            Role = HopRole.Propagator,
            TaintedValueIn = valueIn,
            Transformation = transformation,
            TaintedValueOut = valueOut,
            Dispatch = dispatch,
        });
    }

    // Handles a single IL instruction by updating taint state. Called AFTER HandleSinkMatch;
    // at sink instructions, the operand stack still contains the critical arguments when matchers run.
    // This ordering is invariant and relied upon by cross-method analysis (Task 11).
    private void StepInstruction(MethodDefinition method, Instruction ins, TaintState state,
                                 HashSet<string> newlyTaintedFields,
                                 List<HopRecord> hops, ref int hopCounter,
                                 ref bool reachedSink, HashSet<string> expandedCallees)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Nop:
            case Code.Ret:
                break;

            case Code.Ldarg_0: state.Stack.Push(state.Args.GetValueOrDefault(0, StackSlot.Untainted)); break;
            case Code.Ldarg_1: state.Stack.Push(state.Args.GetValueOrDefault(1, StackSlot.Untainted)); break;
            case Code.Ldarg_2: state.Stack.Push(state.Args.GetValueOrDefault(2, StackSlot.Untainted)); break;
            case Code.Ldarg_3: state.Stack.Push(state.Args.GetValueOrDefault(3, StackSlot.Untainted)); break;
            case Code.Ldarg:
            case Code.Ldarg_S:
                {
                    var pd = (ParameterDefinition)ins.Operand;
                    int idx = pd.Index + (method.HasThis ? 1 : 0);
                    state.Stack.Push(state.Args.GetValueOrDefault(idx, StackSlot.Untainted));
                    break;
                }

            case Code.Stloc_0: StoreLocal(method, ins, 0, state); break;
            case Code.Stloc_1: StoreLocal(method, ins, 1, state); break;
            case Code.Stloc_2: StoreLocal(method, ins, 2, state); break;
            case Code.Stloc_3: StoreLocal(method, ins, 3, state); break;
            case Code.Stloc:
            case Code.Stloc_S:
                StoreLocal(method, ins, ((VariableDefinition)ins.Operand).Index, state);
                break;

            case Code.Ldloc_0: state.Stack.Push(state.Locals.GetValueOrDefault(0, StackSlot.Untainted)); break;
            case Code.Ldloc_1: state.Stack.Push(state.Locals.GetValueOrDefault(1, StackSlot.Untainted)); break;
            case Code.Ldloc_2: state.Stack.Push(state.Locals.GetValueOrDefault(2, StackSlot.Untainted)); break;
            case Code.Ldloc_3: state.Stack.Push(state.Locals.GetValueOrDefault(3, StackSlot.Untainted)); break;
            case Code.Ldloc:
            case Code.Ldloc_S:
                state.Stack.Push(state.Locals.GetValueOrDefault(((VariableDefinition)ins.Operand).Index, StackSlot.Untainted));
                break;

            case Code.Ldloca:
            case Code.Ldloca_S:
                // Address-of-local: push the local's slot. Subsequent `ldobj`/`call` (byref method)
                // operates on the underlying value's taint state. Required so passing `&local` to
                // a method (e.g., Span<>::op_Implicit, Nullable<T>::get_Value) preserves the taint
                // chain when the local is tainted.
                state.Stack.Push(state.Locals.GetValueOrDefault(((VariableDefinition)ins.Operand).Index, StackSlot.Untainted));
                break;

            case Code.Ldarga:
            case Code.Ldarga_S:
                {
                    var pd = (ParameterDefinition)ins.Operand;
                    int idx = pd.Index + (method.HasThis ? 1 : 0);
                    state.Stack.Push(state.Args.GetValueOrDefault(idx, StackSlot.Untainted));
                    break;
                }

            // Dereference: pop managed pointer/byref, push the pointed-to value with the
            // same taint. Without this, `Span<T>::get_Item(...)` followed by `ldobj T`
            // (the standard pattern for `span[i]` returning a struct by value) drops taint
            // — the ref-to-tainted-element loses its taint when materialized as a value.
            case Code.Ldobj:
            case Code.Ldind_I:
            case Code.Ldind_I1:
            case Code.Ldind_I2:
            case Code.Ldind_I4:
            case Code.Ldind_I8:
            case Code.Ldind_U1:
            case Code.Ldind_U2:
            case Code.Ldind_U4:
            case Code.Ldind_R4:
            case Code.Ldind_R8:
            case Code.Ldind_Ref:
                {
                    var addr = state.Stack.Pop();
                    state.Stack.Push(addr);
                    break;
                }

            case Code.Ldc_I4_0:
            case Code.Ldc_I4_1:
            case Code.Ldc_I4_2:
            case Code.Ldc_I4_3:
            case Code.Ldc_I4_4:
            case Code.Ldc_I4_5:
            case Code.Ldc_I4_6:
            case Code.Ldc_I4_7:
            case Code.Ldc_I4_8:
            case Code.Ldc_I4_M1:
            case Code.Ldc_I4:
            case Code.Ldc_I4_S:
            case Code.Ldc_I8:
            case Code.Ldc_R4:
            case Code.Ldc_R8:
            case Code.Ldnull:
            case Code.Ldstr:
                state.Stack.Push(StackSlot.Untainted);
                break;

            case Code.Add:
            case Code.Sub:
            case Code.Mul:
            case Code.Div:
            case Code.Rem:
            case Code.And:
            case Code.Or:
            case Code.Xor:
            case Code.Shl:
            case Code.Shr:
            case Code.Shr_Un:
            case Code.Add_Ovf:
            case Code.Add_Ovf_Un:
            case Code.Sub_Ovf:
            case Code.Sub_Ovf_Un:
            case Code.Mul_Ovf:
            case Code.Mul_Ovf_Un:
                {
                    var rhs = state.Stack.Pop();
                    var lhs = state.Stack.Pop();
                    if (lhs.Tainted || rhs.Tainted)
                    {
                        var prov = CombineProvenance(lhs, rhs, ins.OpCode);
                        state.Stack.Push(StackSlot.TaintedWith(prov));
                        var valueIn = lhs.Tainted ? lhs.Provenance : rhs.Provenance;
                        EmitPropagatorHop(method, ins, "arithmetic", valueIn, prov, null, hops, ref hopCounter);
                    }
                    else
                    {
                        state.Stack.Push(StackSlot.Untainted);
                    }
                    break;
                }

            // Unary ops (Neg, Not, Conv_*): the existing body below is a no-op (pop and
            // push back as-is), conservatively preserving taint and provenance on the top slot.
            // If a future fixture diverges on conv-width semantics, refine here.
            case Code.Neg:
            case Code.Not:
            case Code.Conv_I:
            case Code.Conv_I1:
            case Code.Conv_I2:
            case Code.Conv_I4:
            case Code.Conv_I8:
            case Code.Conv_U:
            case Code.Conv_U1:
            case Code.Conv_U2:
            case Code.Conv_U4:
            case Code.Conv_U8:
            case Code.Conv_R4:
            case Code.Conv_R8:
                // Unary on top-of-stack: keep taint, preserve provenance.
                // (pop and push back as-is — no stack mutation needed)
                // Emit a cast propagator hop when the top slot is tainted.
                if (state.Stack.Depth > 0 && state.Stack.Peek().Tainted)
                {
                    var slot = state.Stack.Peek();
                    EmitPropagatorHop(method, ins, "cast", slot.Provenance, slot.Provenance, null, hops, ref hopCounter);
                }
                break;

            case Code.Newarr:
                {
                    // Size arg on top is the only operand; replace with untainted array reference.
                    state.Stack.Pop();
                    state.Stack.Push(StackSlot.Untainted);
                    break;
                }

            case Code.Pop:
                state.Stack.Pop();
                break;

            case Code.Dup:
                {
                    var top = state.Stack.Peek();
                    state.Stack.Push(top);
                    break;
                }

            // Branches in intra-method MVP: pop comparison operands, do NOT follow control flow.
            // Linear scan — branches don't re-merge with different taint on either side; taint
            // can leak past conditional checks. Task 12 adds structural sanitizer dispatch;
            // full CFG-sensitive taint would require a worklist algorithm (out of scope).
            case Code.Br:
            case Code.Br_S:
            case Code.Beq:
            case Code.Beq_S:
            case Code.Bge:
            case Code.Bge_S:
            case Code.Bge_Un:
            case Code.Bge_Un_S:
            case Code.Bgt:
            case Code.Bgt_S:
            case Code.Bgt_Un:
            case Code.Bgt_Un_S:
            case Code.Ble:
            case Code.Ble_S:
            case Code.Ble_Un:
            case Code.Ble_Un_S:
            case Code.Blt:
            case Code.Blt_S:
            case Code.Blt_Un:
            case Code.Blt_Un_S:
            case Code.Bne_Un:
            case Code.Bne_Un_S:
            case Code.Brfalse:
            case Code.Brfalse_S:
            case Code.Brtrue:
            case Code.Brtrue_S:
                // Pop comparison operands; don't model control flow in MVP.
                {
                    int pops = ins.OpCode.StackBehaviourPop switch
                    {
                        StackBehaviour.Pop1_pop1 => 2,
                        StackBehaviour.Popi_popi => 2,
                        StackBehaviour.Popi => 1,
                        _ => 0,
                    };
                    for (int i = 0; i < pops && state.Stack.Depth > 0; i++) state.Stack.Pop();
                    break;
                }

            case Code.Ldfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var receiver = state.Stack.Pop();
                    StackSlot result;
                    string? valueIn = null;

                    if (receiver.Tainted)
                    {
                        // Taint propagates on field-load from a tainted struct/object.
                        result = StackSlot.TaintedWith($"{receiver.Provenance}.{fr.Name}");
                        valueIn = receiver.Provenance;
                    }
                    else if (state.ThisFields.TryGetValue(fr.FullName, out var fieldSlot) && fieldSlot.Tainted)
                    {
                        // Receiver is `this` (Ldarg.0) whose per-field taint map we track.
                        result = fieldSlot;
                        valueIn = "this";  // implicit receiver — provenance is `this.<field>` already in the slot
                    }
                    else
                    {
                        result = StackSlot.Untainted;
                    }

                    state.Stack.Push(result);

                    if (result.Tainted)
                    {
                        EmitPropagatorHop(method, ins, "field_load", valueIn ?? result.Provenance, result.Provenance, null, hops, ref hopCounter);
                    }
                    break;
                }

            case Code.Ldsfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    if (state.StaticFields.TryGetValue(fr.FullName, out var sfld) && sfld.Tainted)
                    {
                        state.Stack.Push(sfld);
                        var fieldValueIn = $"{fr.DeclaringType.Name}.{fr.Name}";
                        EmitPropagatorHop(method, ins, "field_load", fieldValueIn, sfld.Provenance, null, hops, ref hopCounter);
                    }
                    else
                    {
                        state.Stack.Push(StackSlot.Untainted);
                    }
                    break;
                }

            case Code.Ldflda:
                {
                    // Load managed pointer to a field. Mirrors ldfld for taint purposes — the
                    // resulting `&field` is "tainted" iff the underlying field is. Required for
                    // Nullable<T>.Value access (Roslyn emits `ldflda <Nullable>; call get_Value()`)
                    // and other byref-call patterns on a struct field.
                    var fr = (FieldReference)ins.Operand;
                    var receiver = state.Stack.Pop();
                    StackSlot result;

                    if (receiver.Tainted)
                    {
                        result = StackSlot.TaintedWith($"{receiver.Provenance}.{fr.Name}");
                    }
                    else if (state.ThisFields.TryGetValue(fr.FullName, out var fieldSlot) && fieldSlot.Tainted)
                    {
                        result = fieldSlot;
                    }
                    else
                    {
                        result = StackSlot.Untainted;
                    }
                    state.Stack.Push(result);
                    break;
                }

            case Code.Ldsflda:
                {
                    var fr = (FieldReference)ins.Operand;
                    state.Stack.Push(state.StaticFields.TryGetValue(fr.FullName, out var sfld) && sfld.Tainted
                        ? sfld
                        : StackSlot.Untainted);
                    break;
                }

            case Code.Stfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var value = state.Stack.Pop();
                    var receiver = state.Stack.Pop();

                    // Mark the field tainted on `this` when:
                    //   - value is tainted AND
                    //   - receiver is `this` (either explicitly provenance=="this" OR the receiver
                    //     came from an ldarg.0 whose slot we haven't specifically tainted).
                    bool receiverIsThisRooted = receiver.Provenance == "this" ||
                        (!receiver.Tainted && InstructionIsLdarg0(FindStfldReceiverSource(ins)));

                    if (value.Tainted && receiverIsThisRooted)
                    {
                        state.ThisFields[fr.FullName] = StackSlot.TaintedWith(fr.Name);
                        newlyTaintedFields.Add(fr.Name);
                    }
                    break;
                }

            case Code.Stsfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var value = state.Stack.Pop();
                    if (value.Tainted)
                    {
                        state.StaticFields[fr.FullName] = StackSlot.TaintedWith($"{fr.DeclaringType.Name}.{fr.Name}");
                    }
                    break;
                }

            case Code.Call:
            case Code.Callvirt:
                if (HandleCall(method, ins, state, newlyTaintedFields, hops, ref hopCounter, expandedCallees))
                {
                    reachedSink = true;
                }
                break;

            case Code.Newobj:
                {
                    var mr = (MethodReference)ins.Operand;
                    int paramCount = mr.Parameters.Count;
                    bool anyTainted = false;
                    string? firstTaintedProvenance = null;
                    for (int i = 0; i < paramCount && state.Stack.Depth > 0; i++)
                    {
                        var popped = state.Stack.Pop();
                        if (popped.Tainted)
                        {
                            anyTainted = true;
                            firstTaintedProvenance ??= popped.Provenance;
                        }
                    }
                    state.Stack.Push(anyTainted
                        ? StackSlot.TaintedWith($"new {mr.DeclaringType.Name}({firstTaintedProvenance})")
                        : StackSlot.Untainted);
                    break;
                }

            default:
                // Conservative fallback: pop the operand stack to the opcode's declared pop count,
                // then push untainted to the declared push count.
                ApplyStackBehavior(ins, state);
                break;
        }
    }

    private bool HandleCall(MethodDefinition callerMethod, Instruction ins, TaintState state,
                           HashSet<string> newlyTaintedFields, List<HopRecord> hops, ref int hopCounter,
                           HashSet<string> expandedCallees)
    {
        var callee = (MethodReference)ins.Operand;
        var paramCount = callee.Parameters.Count;
        bool hasThisOnStack = callee.HasThis;

        // Snapshot the args off the stack in order: [receiver?], arg0, arg1, ...
        // Stack top = last arg.
        int totalPops = paramCount + (hasThisOnStack ? 1 : 0);
        if (state.Stack.Depth < totalPops)
        {
            // Malformed or unsupported shape — pop what's there and treat as untainted return.
            for (int i = 0; i < state.Stack.Depth; i++) state.Stack.Pop();
            if (!IsVoidReturn(callee)) state.Stack.Push(StackSlot.Untainted);
            return false;
        }

        var argSlots = new StackSlot[paramCount];
        for (int i = paramCount - 1; i >= 0; i--)
        {
            argSlots[i] = state.Stack.Pop();
        }
        var receiverSlot = hasThisOnStack ? state.Stack.Pop() : default;

        int bitmask = 0;
        for (int i = 0; i < paramCount; i++)
        {
            if (argSlots[i].Tainted) bitmask |= (1 << i);
        }
        // Receiver-this with a tainted `this`-field counts as a tainted input for the
        // buffer-fill heuristic — the callee can read from `this.<taintedField>` and write
        // tainted bytes back into byref / Span / array args. Required for shapes like
        // `this.TryReadChunk(buffer, out chunk)` where `this.currentStream` is tainted but
        // the call-site args themselves aren't. Without this, the chain
        // `Decode → TryReadChunk → ReadInternationalTextChunk` doesn't propagate stream
        // taint into `chunk.Data`.
        bool receiverHasTaintedThisField = hasThisOnStack
            && receiverSlot.Provenance == "this"
            && state.ThisFields.Values.Any(slot => slot.Tainted);
        bool anyTaintedInput = bitmask != 0
            || (hasThisOnStack && receiverSlot.Tainted)
            || receiverHasTaintedThisField;

        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolveMethod(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: same over-approximation as in-assembly — any tainted input surfaces as
            // tainted return. Required for `Nullable<T>::get_Value()` on a tainted struct,
            // `Span<>::Slice` / `op_Implicit`, `BinaryPrimitives::ReadInt16LE(rosBuffer)`, etc.
            // (Without this, the #3074 chain `this.fileHeader.Value.Offset` drops taint at .Value.)
            // taint_from_external_returns: unconditionally taint returns from annotated methods.
            bool matchesTaintSource = MatchesTaintFromExternalReturn(callee);

            // Math.Min/Max/Clamp clamp recognizer. When at least one argument is bounded (untainted
            // constant/parameter/field), the result is bounded too; the call is a value-clamping
            // sanitizer at the call-site, regardless of input taint count.
            if (IsMathClampCall(callee) && argSlots.Any(s => !s.Tainted))
            {
                var taintedArgs = argSlots.Where(s => s.Tainted).Select(s => s.Provenance);
                var boundArgs = argSlots.Where(s => !s.Tainted).Select(s => s.Provenance);
                var prov = $"clamped({string.Join(",", taintedArgs)}; bound={string.Join(",", boundArgs)})";
                state.Stack.Push(new StackSlot(false, prov));
                return false;
            }

            if (!IsVoidReturn(callee))
            {
                if (anyTaintedInput || matchesTaintSource)
                {
                    string prov;
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{CleanCalleeName(callee)}";
                    }
                    else if (argSlots.Any(s => s.Tainted))
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}({firstTainted.Provenance})";
                    }
                    else
                    {
                        // Network/external source: no tainted args, taint introduced by annotation.
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}";
                    }
                    state.Stack.Push(StackSlot.TaintedWith(prov));
                }
                else
                {
                    state.Stack.Push(StackSlot.Untainted);
                }
            }
            TaintBufferLikeArgsFromCall(callerMethod, ins, callee, anyTaintedInput, state);
            return false;
        }

        // Determine if the receiver is caller's own `this` BEFORE walking, so we can pass
        // the caller's currently-tainted field names into WalkWithSeed (I-1 fix).
        bool receiverIsCallerThis = hasThisOnStack && IsReceiverCallerThis(receiverSlot, ins);

        // Compute seeded `this`-field set: when the receiver is caller's `this` AND the callee's
        // declaring type matches the caller's (or is a base/derived in the same field-shape), pass
        // the caller's currently-tainted field names that exist on the callee's declaring type.
        var seedFields = ComputeCrossMethodSeed(callerMethod, resolved, state, hasThisOnStack: receiverIsCallerThis);

        // N3 — tainted-local-receiver seed: when a tainted local object (not the caller's own
        // `this`) calls an in-assembly instance method, the callee's `this`-fields are invisible
        // to the walk (bitmask=0, empty seedFields) even though those fields were populated from
        // tainted data via the constructor. Seed PRIMITIVE (numeric) instance fields as tainted
        // so that arithmetic ops like `_count * _stride` inside the callee emit a hop.
        // Restricted to primitive fields (IsPrimitive) to avoid seeding Stream/object references —
        // those would cause arithmetic hops inside I/O methods to appear, bloating the trace.
        if (!receiverIsCallerThis && hasThisOnStack && receiverSlot.Tainted
            && resolved.HasThis && resolved.DeclaringType.HasFields)
        {
            var primitiveFields = resolved.DeclaringType.Fields
                .Where(static f => !f.IsStatic && f.FieldType.IsPrimitive)
                .Select(static f => f.Name)
                .ToList();
            if (primitiveFields.Count > 0)
                seedFields = primitiveFields;
        }

        // Cross-method walk with seeded `this`-fields.
        var calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);

        // U10 — per-walk callee-expansion guard. The expansion key matches the memo key
        // so the first call (which populates the memo) is also the one whose hops are merged.
        // Subsequent calls with the same (callee, bitmask, seedKey) still emit the call-boundary
        // identity hop (dispatch signal) but skip appending callee hops a second time.
        var expansionKey = $"{resolved.FullName}|{bitmask}|{BuildSeedKey(seedFields)}";
        bool alreadyExpanded = !expandedCallees.Add(expansionKey);

        // Return-value taint propagation: over-approximate — return is tainted when any tainted arg
        // was passed OR the callee's summary says ReturnsTainted OR the receiver itself was tainted
        // (any read on a tainted stream/object surfaces tainted bytes).
        bool callReturnIsTainted = !IsVoidReturn(callee)
            && (bitmask != 0
                || calleeSummary.ReturnsTainted
                || (hasThisOnStack && receiverSlot.Tainted));
        if (receiverIsCallerThis && resolved.HasThis)
        {
            foreach (var fName in calleeSummary.NewlyTaintedThisFields)
            {
                var fd = resolved.DeclaringType.Fields.FirstOrDefault(f => f.Name == fName);
                if (fd is null) continue;
                state.ThisFields[fd.FullName] = StackSlot.TaintedWith(fName);
                newlyTaintedFields.Add(fName);
            }
        }

        if (!IsVoidReturn(callee))
        {
            var provenance = callReturnIsTainted
                ? CombineProvenanceArgs(argSlots, $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}")
                : "";
            state.Stack.Push(callReturnIsTainted ? StackSlot.TaintedWith(provenance) : StackSlot.Untainted);
        }

        // Buffer-fill semantics: any tainted-flowing call may write into byref / Span / array args.
        // Mirror the conservative model from the external branch — we don't track per-method
        // mutation summaries, so over-approximate.
        TaintBufferLikeArgsFromCall(callerMethod, ins, callee, anyTaintedInput, state);

        // Emit a propagator hop for the call boundary if any taint flowed through (return or this-field).
        if (callReturnIsTainted || calleeSummary.NewlyTaintedThisFields.Count > 0 || calleeSummary.ReachedSink)
        {
            var dispatch = CallGraph.ResolveCallSite(callerMethod, ins, receiverStaticType: null, _context);
            string valueIn;
            string valueOut;
            if (callReturnIsTainted && argSlots.Any(s => s.Tainted))
            {
                valueIn = argSlots.First(s => s.Tainted).Provenance;
                valueOut = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}";
            }
            else if (callReturnIsTainted && hasThisOnStack && receiverSlot.Tainted)
            {
                valueIn = receiverSlot.Provenance;
                valueOut = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}";
            }
            else if (calleeSummary.NewlyTaintedThisFields.Count > 0)
            {
                valueIn = "this";
                valueOut = "this";
            }
            else
            {
                valueIn = "stream";   // best-effort fallback for #3074-style stream forwarding
                valueOut = "stream";
            }
            // U2: skip emitting an identity propagator hop when the previous emitted hop is in
            // the SAME method. Cross-method identity hops (call-boundary signal where method
            // changes) are preserved. The previous-hop check uses Method-string equality rather
            // than IL-region containment because hop labels mirror the user-facing trace.
            string callerMethodLabel = $"{callerMethod.DeclaringType.FullName}.{callerMethod.Name}";
            bool sameMethodAsPrev = hops.Count > 0 && hops[^1].Method == callerMethodLabel;
            if (!sameMethodAsPrev)
            {
                EmitPropagatorHop(callerMethod, ins, "identity", valueIn, valueOut, dispatch, hops, ref hopCounter);
            }

            // Append the callee's hops (the recursive walk's findings) into the caller's hop list,
            // preserving each hop's Method label so the trace shows the cross-method chain.
            // Don't append calleeSummary.Absences — only the outermost walked method synthesizes
            // absences (the caller's WalkMethodBody end-block will emit at most one).
            // U10: skip append on repeated calls to the same callee (alreadyExpanded).
            if (!alreadyExpanded)
            {
                foreach (var calleeHop in calleeSummary.Hops)
                {
                    hops.Add(calleeHop);
                }
            }
        }

        return calleeSummary.ReachedSink;
    }

    private static string CombineProvenanceArgs(StackSlot[] args, string fallback)
    {
        foreach (var s in args)
        {
            if (s.Tainted) return s.Provenance;
        }
        return fallback;
    }

    private static bool IsVoidReturn(MethodReference mr)
        => mr.ReturnType.FullName == "System.Void";

    private static bool IsMathClampCall(MethodReference callee)
    {
        if (callee.DeclaringType.FullName != "System.Math") return false;
        return callee.Name is "Min" or "Max" or "Clamp";
    }

    private static MethodDefinition? SafeResolveMethod(MethodReference mr)
    {
        try { return mr.Resolve(); }
        catch { return null; }
    }

    // Whether the receiver passed to the callee is the caller's own `this`.
    // Heuristic: in Debug IL, `ldarg.0; <arg-push>*; call` is the common shape.
    private static bool IsReceiverCallerThis(StackSlot receiverSlot, Instruction call)
    {
        // If the receiver slot is tainted with "this" provenance, trust it.
        if (receiverSlot.Provenance == "this" && receiverSlot.Tainted) return true;

        // Otherwise walk backward from the call instruction to find the receiver's source
        // (skip intervening arg-push instructions that produce the `paramCount` arg values).
        // For MVP, accept a conservative match: if any `ldarg.0` appears close-behind and no
        // other receiver-producing instruction is closer, treat as this.
        // Simplest heuristic: the receiver push is the instruction at call.Previous backed up
        // by `paramCount + (any nops)` instruction positions. The test fixtures we care about
        // (CrossMethodStore) have a straightforward `ldarg.0; ldarg.1; call` pattern. For now:
        // if `call.Previous` is an arg-push like `ldarg.*`/`ldloc.*`/`ldc.*`, walk back past
        // those and check if we land on `ldarg.0`.
        var cur = call.Previous;
        int budget = 16;
        while (cur is not null && budget-- > 0)
        {
            if (cur.OpCode.Code is Code.Ldarg_0) return true;
            if (cur.OpCode.Code is Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3
                or Code.Ldarg or Code.Ldarg_S
                or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3
                or Code.Ldloc or Code.Ldloc_S
                or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3 or Code.Ldc_I4_4
                or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8
                or Code.Ldc_I4_M1 or Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8
                or Code.Ldnull or Code.Ldstr or Code.Nop)
            {
                cur = cur.Previous;
                continue;
            }
            return false;  // something more complex on the stack — can't prove `this` safely
        }
        return false;
    }

    private static IReadOnlyCollection<string> ComputeCrossMethodSeed(
        MethodDefinition callerMethod,
        MethodDefinition callee,
        TaintState state,
        bool hasThisOnStack)
    {
        // Only propagate when the call passes the caller's `this` and the callee is on a type
        // that shares the field namespace. Strict MVP: types must match exactly.
        if (!hasThisOnStack) return Array.Empty<string>();
        if (!callee.HasThis) return Array.Empty<string>();
        if (callerMethod.DeclaringType.FullName != callee.DeclaringType.FullName) return Array.Empty<string>();

        // Collect tainted field names from caller's `this`-field map. Filter to fields that exist
        // on the callee's declaring type (which is the same as caller's per the guard above, but
        // future relaxation might allow base-type inheritance; this filter remains correct then).
        var seed = new List<string>();
        foreach (var (fieldFullName, slot) in state.ThisFields)
        {
            if (!slot.Tainted) continue;
            // FieldFullName format from Cecil: "ReturnType DeclaringType::FieldName".
            // Extract just the field name for the seed (matches Stfld bookkeeping convention).
            var doubleColon = fieldFullName.IndexOf("::", StringComparison.Ordinal);
            if (doubleColon < 0) continue;
            var name = fieldFullName.Substring(doubleColon + 2);
            // Confirm the field actually exists on the callee's declaring type.
            if (callee.DeclaringType.Fields.Any(f => f.Name == name))
            {
                seed.Add(name);
            }
        }
        return seed;
    }

    // Recovers the instruction that pushed the `stfld`'s receiver. Stack pattern at the call site:
    //   ..., obj, value, <stfld>
    // In Debug-mode linear IL with Roslyn-generated `this.F = simpleExpr`, the receiver push is
    // stfld.Previous.Previous (with intervening nops skipped). Multi-instruction value expressions
    // (e.g., `this.F = expr1 + expr2`) are OUT OF SCOPE — the two-step walk would wrongly identify
    // the `add` (the expression's tail instruction) as the receiver source. MVP scope accepts this
    // limitation since #3074/#3079 use simple `this.F = methodCall()` shapes.
    private static Instruction? FindStfldReceiverSource(Instruction stfld)
    {
        var a = stfld.Previous;
        if (a is null) return null;
        var b = a.Previous;
        // Skip over nop instructions in case Roslyn emitted debug nops between ldarg.0 and ldarg.1.
        while (b != null && b.OpCode.Code == Code.Nop) b = b.Previous;
        return b;
    }

    private static bool InstructionIsLdarg0(Instruction? ins)
        => ins is not null && ins.OpCode.Code is Code.Ldarg_0;

    // Buffer-fill semantics: when a call has any tainted input AND a parameter is byref / Span<> /
    // ReadOnlySpan<> / array, treat the call as writing tainted bytes through that arg. We don't
    // track per-method mutation summaries, so we approximate: walk back from the call site through
    // the simple-arg-push window and, for buffer-like params, taint the source local / parameter.
    //
    // Conservative scope: only handles ldloc.* / ldloca.* / ldarg.* / ldarga.* arg-pushes.
    // Multi-instruction arg expressions (e.g., `obj.Field` as an arg) are skipped — the corresponding
    // arg slot stays as-is. Adequate for the #3074 chain where buffers come from `stackalloc` stored
    // to a local and then pushed via `ldloc <buffer>`.
    private static void TaintBufferLikeArgsFromCall(
        MethodDefinition callerMethod,
        Instruction call,
        MethodReference callee,
        bool anyTaintedInput,
        TaintState state)
    {
        if (!anyTaintedInput) return;
        if (callee.Parameters.Count == 0) return;

        // Identify buffer-like params upfront.
        var bufferLikeIdx = new List<int>();
        for (int i = 0; i < callee.Parameters.Count; i++)
        {
            if (IsBufferLike(callee.Parameters[i].ParameterType)) bufferLikeIdx.Add(i);
        }
        if (bufferLikeIdx.Count == 0) return;

        // Walk back to the arg-push instructions. Total pushes = paramCount + (hasThis ? 1 : 0).
        // Layout in source order: [receiver?], arg0, arg1, ..., argN-1.
        int totalPushes = callee.Parameters.Count + (callee.HasThis ? 1 : 0);
        var pushers = new Instruction?[totalPushes];
        var cur = call.Previous;
        for (int slot = totalPushes - 1; slot >= 0 && cur is not null; slot--)
        {
            // Skip Roslyn-emitted debug nops.
            while (cur is not null && cur.OpCode.Code == Code.Nop) cur = cur.Previous;
            if (cur is null) break;
            pushers[slot] = cur;
            cur = cur.Previous;
        }

        int argZeroSlot = callee.HasThis ? 1 : 0;
        foreach (var paramIdx in bufferLikeIdx)
        {
            var pusher = pushers[argZeroSlot + paramIdx];
            if (pusher is null) continue;
            string prov = $"{callee.DeclaringType.Name}.{callee.Name}";
            switch (pusher.OpCode.Code)
            {
                case Code.Ldloc_0: state.Locals[0] = StackSlot.TaintedWith(prov); break;
                case Code.Ldloc_1: state.Locals[1] = StackSlot.TaintedWith(prov); break;
                case Code.Ldloc_2: state.Locals[2] = StackSlot.TaintedWith(prov); break;
                case Code.Ldloc_3: state.Locals[3] = StackSlot.TaintedWith(prov); break;
                case Code.Ldloc:
                case Code.Ldloc_S:
                case Code.Ldloca:
                case Code.Ldloca_S:
                    state.Locals[((VariableDefinition)pusher.Operand).Index] = StackSlot.TaintedWith(prov);
                    break;
                case Code.Ldarg_0: state.Args[0] = StackSlot.TaintedWith(prov); break;
                case Code.Ldarg_1: state.Args[1] = StackSlot.TaintedWith(prov); break;
                case Code.Ldarg_2: state.Args[2] = StackSlot.TaintedWith(prov); break;
                case Code.Ldarg_3: state.Args[3] = StackSlot.TaintedWith(prov); break;
                case Code.Ldarg:
                case Code.Ldarg_S:
                case Code.Ldarga:
                case Code.Ldarga_S:
                    {
                        var pd = (ParameterDefinition)pusher.Operand;
                        int idx = pd.Index + (callerMethod.HasThis ? 1 : 0);
                        state.Args[idx] = StackSlot.TaintedWith(prov);
                        break;
                    }
            }
        }
    }

    private static bool IsBufferLike(TypeReference t)
    {
        if (t.IsByReference) return true;
        if (t.IsArray) return true;
        if (t is GenericInstanceType g)
        {
            var n = g.ElementType.FullName;
            if (n == "System.Span`1" || n == "System.ReadOnlySpan`1" || n == "System.Memory`1" || n == "System.ReadOnlyMemory`1") return true;
        }
        else
        {
            var n = t.FullName;
            // Non-generic Span<T>/etc would be unusual but handle anyway.
            if (n == "System.Span`1" || n == "System.ReadOnlySpan`1") return true;
        }
        return false;
    }

    private static void PushImplicitExceptionIfHandlerStart(MethodDefinition method, Instruction ins, TaintState state)
    {
        if (method.Body is null || !method.Body.HasExceptionHandlers) return;

        foreach (var handler in method.Body.ExceptionHandlers)
        {
            // Catch handler: exception is on the stack at HandlerStart.
            if (handler.HandlerType == ExceptionHandlerType.Catch && ins == handler.HandlerStart)
            {
                state.Stack.Push(StackSlot.Untainted);
                return;
            }
            // Filter handler: exception is on the stack at BOTH FilterStart (filter clause entry)
            // AND HandlerStart (the actual handler body, after the filter returned 1).
            if (handler.HandlerType == ExceptionHandlerType.Filter
                && (ins == handler.FilterStart || ins == handler.HandlerStart))
            {
                state.Stack.Push(StackSlot.Untainted);
                return;
            }
            // Finally / Fault: no implicit push — these handlers run with empty stack.
        }
    }

    private static void ApplyStackBehavior(Instruction ins, TaintState state)
    {
        int pops = ins.OpCode.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 => 1,
            StackBehaviour.Popi => 1,
            StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 => 2,
            StackBehaviour.Popi_popi => 2,
            StackBehaviour.Popi_pop1 => 2,
            StackBehaviour.Popi_popi8 => 2,
            StackBehaviour.Popref_pop1 => 2,
            StackBehaviour.Popref_popi => 2,
            StackBehaviour.Popi_popi_popi => 3,
            StackBehaviour.Popref_popi_popi => 3,
            StackBehaviour.Popref_popi_popi8 => 3,
            StackBehaviour.Popref_popi_popr4 => 3,
            StackBehaviour.Popref_popi_popr8 => 3,
            StackBehaviour.Popref_popi_popref => 3,
            StackBehaviour.PopAll => state.Stack.Depth,
            _ => 0,
        };
        for (int i = 0; i < pops && state.Stack.Depth > 0; i++) state.Stack.Pop();

        int pushes = ins.OpCode.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 => 1,
            StackBehaviour.Push1_push1 => 2,
            StackBehaviour.Pushi => 1,
            StackBehaviour.Pushi8 => 1,
            StackBehaviour.Pushr4 => 1,
            StackBehaviour.Pushr8 => 1,
            StackBehaviour.Pushref => 1,
            _ => 0,
        };
        for (int i = 0; i < pushes; i++) state.Stack.Push(StackSlot.Untainted);
    }

    private static string CombineProvenance(StackSlot a, StackSlot b, OpCode? op = null)
    {
        if (a.Tainted && b.Tainted)
        {
            var sep = op?.Code switch
            {
                Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un => "*",
                Code.Div or Code.Div_Un => "/",
                Code.Rem or Code.Rem_Un => "%",
                Code.Shl => "<<",
                Code.Shr or Code.Shr_Un => ">>",
                Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => "-",
                Code.And => "&",
                Code.Or => "|",
                Code.Xor => "^",
                _ => "+",
            };
            return $"{a.Provenance}{sep}{b.Provenance}";
        }
        return a.Tainted ? a.Provenance : b.Provenance;
    }
}
