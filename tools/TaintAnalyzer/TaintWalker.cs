using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class TaintWalker
{
    private readonly AssemblyContext _context;
    // Memo key: (callee FullName, tainted-arg bitmask, sorted+joined seeded `this`-field names).
    // Seeded-fields-as-string keeps the key value-typed-equality friendly without a custom comparer.
    private readonly Dictionary<(string fullName, int bitmask, string seedKey), MethodSummary> _memo = new();

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

        // Sentinel placeholder breaks recursion on cycles — the recursive call sees this empty
        // summary and returns immediately, completing the cycle without infinite descent.
        var placeholder = new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = false,
            NewlyTaintedThisFields = Array.Empty<string>(),
            Hops = Array.Empty<HopRecord>(),
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = false,
        };
        _memo[key] = placeholder;

        var summary = WalkMethodBody(method, taintedParamBitmask, taintedThisFields);
        _memo[key] = summary;
        return summary;
    }

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
        bool returnsTainted = false;
        // Hop counter resets per method; Task 11 refines to aggregate hops across the call chain.
        int hopCounter = 0;
        var newlyTaintedFields = new HashSet<string>(StringComparer.Ordinal);

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
            };
        }

        // Pre-compute sanitizer matches keyed by comparison IL offset so we can emit them in
        // IL order during the body walk (rather than splicing at the end, which mis-positions
        // them relative to the in-method sink for multi-sink traces).
        var sanitizerByOffset = SanitizerShapes.MatchAll(method)
            .GroupBy(m => m.ComparisonIlOffset)
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

            // Detect tainted-return BEFORE stepping `ret` (the step is a no-op anyway).
            if (ins.OpCode.Code == Code.Ret
                && method.ReturnType.FullName != "System.Void"
                && state.Stack.Depth > 0
                && state.Stack.Peek().Tainted)
            {
                returnsTainted = true;
            }

            StepInstruction(method, ins, state, newlyTaintedFields, hops, ref hopCounter, ref reachedSink);
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
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack);

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

        hops.Add(new HopRecord
        {
            Hop = hopCounter++,
            Method = $"{method.DeclaringType.FullName}.{method.Name}",
            File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
            Line = sp?.StartLine ?? 0,
            Role = HopRole.Sink,
            TaintedValueIn = m.SizeProvenance,
            Transformation = "identity",
            TaintedValueOut = m.SizeProvenance,
            SinkKind = m.Kind,
            SinkApi = m.Api,
            SizeExpression = m.Kind == SinkKind.Allocation ? m.SizeProvenance : null,
            AccessExpression = m.Kind == SinkKind.SpanAccess ? m.SizeProvenance : null,
            FirstTaintedFile = firstTaintedFile,
            FirstTaintedLine = firstTaintedLine,
            FirstTaintedProvenance = firstTaintedProvenance,
        });
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
        var value = state.Stack.Pop();
        state.Locals[idx] = value;
        if (value.Tainted && !state.FirstLocalTaintLine.ContainsKey(idx))
        {
            var sp = _context.GetSequencePoint(method, ins);
            if (sp is not null)
            {
                state.FirstLocalTaintLine[idx] = (sp.Document.Url, sp.StartLine, value.Provenance);
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
                                 ref bool reachedSink)
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
                        var prov = CombineProvenance(lhs, rhs);
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
                if (HandleCall(method, ins, state, newlyTaintedFields, hops, ref hopCounter))
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
                           HashSet<string> newlyTaintedFields, List<HopRecord> hops, ref int hopCounter)
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
        bool anyTaintedInput = bitmask != 0 || (hasThisOnStack && receiverSlot.Tainted);

        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolveMethod(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: same over-approximation as in-assembly — any tainted input surfaces as
            // tainted return. Required for `Nullable<T>::get_Value()` on a tainted struct,
            // `Span<>::Slice` / `op_Implicit`, `BinaryPrimitives::ReadInt16LE(rosBuffer)`, etc.
            // (Without this, the #3074 chain `this.fileHeader.Value.Offset` drops taint at .Value.)
            if (!IsVoidReturn(callee))
            {
                if (anyTaintedInput)
                {
                    string prov;
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{callee.Name}";
                    }
                    else
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{callee.Name}({firstTainted.Provenance})";
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

        // Cross-method walk with seeded `this`-fields.
        var calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);

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
                ? CombineProvenanceArgs(argSlots, $"{callee.DeclaringType.Name}.{callee.Name}")
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
                valueOut = $"{callee.DeclaringType.Name}.{callee.Name}";
            }
            else if (callReturnIsTainted && hasThisOnStack && receiverSlot.Tainted)
            {
                valueIn = receiverSlot.Provenance;
                valueOut = $"{callee.DeclaringType.Name}.{callee.Name}";
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
            EmitPropagatorHop(callerMethod, ins, "identity", valueIn, valueOut, dispatch, hops, ref hopCounter);

            // Append the callee's hops (the recursive walk's findings) into the caller's hop list,
            // preserving each hop's Method label so the trace shows the cross-method chain.
            // Don't append calleeSummary.Absences — only the outermost walked method synthesizes
            // absences (the caller's WalkMethodBody end-block will emit at most one).
            foreach (var calleeHop in calleeSummary.Hops)
            {
                hops.Add(calleeHop);
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

    private static string CombineProvenance(StackSlot a, StackSlot b)
    {
        if (a.Tainted && b.Tainted) return $"{a.Provenance}+{b.Provenance}";
        return a.Tainted ? a.Provenance : b.Provenance;
    }
}
