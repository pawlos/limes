using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class TaintWalker
{
    private readonly AssemblyContext _context;
    private readonly Dictionary<(string fullName, int bitmask), MethodSummary> _memo = new();

    public TaintWalker(AssemblyContext context) => _context = context;

    public MethodSummary Walk(MethodDefinition method, int taintedParamBitmask)
        => WalkWithSeed(method, taintedParamBitmask, taintedThisFields: Array.Empty<string>());

    public MethodSummary WalkWithSeed(MethodDefinition method, int taintedParamBitmask, IReadOnlyCollection<string> taintedThisFields)
    {
        var key = (method.FullName, taintedParamBitmask);
        // Memo keyed only by method+param bitmask for MVP. Seeded this-fields are a caller-specific
        // refinement; we accept the cache collision risk for now — Task 11 revisits.
        if (_memo.TryGetValue(key, out var cached) && taintedThisFields.Count == 0)
        {
            return cached;
        }

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
        if (taintedThisFields.Count == 0) _memo[key] = placeholder;

        var summary = WalkMethodBody(method, taintedParamBitmask, taintedThisFields);
        if (taintedThisFields.Count == 0) _memo[key] = summary;
        return summary;
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

        var sanitizerMatch = SanitizerShapes.MatchCompareAndThrow(method)
                          ?? SanitizerShapes.MatchCompareAndReturnEarly(method);
        HopRecord? pendingSanitizerHop = null;
        if (sanitizerMatch is not null)
        {
            // Emit at the IL offset of the comparison's conditional branch.
            var branchIns = method.Body.Instructions.FirstOrDefault(i => i.Offset == sanitizerMatch.ComparisonIlOffset);
            var sp = branchIns is null ? null : _context.GetSequencePoint(method, branchIns);
            pendingSanitizerHop = new HopRecord
            {
                Hop = 0,                         // patched after the walk below so hops are contiguous
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
            };
        }

        foreach (var ins in method.Body.Instructions)
        {
            if (HandleSinkMatch(method, ins, state, hops, ref hopCounter))
            {
                reachedSink = true;
                // Continue iterating — future hops won't add more for this path, but multi-sink
                // methods could in principle produce additional sink records.
            }

            StepInstruction(method, ins, state, newlyTaintedFields);
        }

        if (pendingSanitizerHop is not null)
        {
            // Insert the sanitizer hop at a position that comes before the sink but after the setup
            // propagators. For MVP, put it right before the last hop (the sink).
            int insertAt = hops.Count > 0 && hops[^1].Role == HopRole.Sink ? hops.Count - 1 : hops.Count;
            hops.Insert(insertAt, pendingSanitizerHop with { Hop = insertAt });
            // Renumber.
            for (int i = 0; i < hops.Count; i++) hops[i] = hops[i] with { Hop = i };
        }

        var absences = new List<EmittedSanitizerAbsence>();
        if (pendingSanitizerHop is null && reachedSink && hops.Count > 0)
        {
            // Point at the propagator hop immediately preceding the sink, per spec.
            var sinkHop = hops.Last(h => h.Role == HopRole.Sink);
            var sinkIdx = hops.IndexOf(sinkHop);
            var preSinkIdx = Math.Max(0, sinkIdx - 1);
            var preSink = hops[preSinkIdx];
            var sinkFile = sinkHop.File;
            var sinkLine = sinkHop.Line;
            var sinkApiDisplay = sinkHop.SinkApi switch
            {
                SinkApi.NewArray => "new_array",
                SinkApi.ArrayPoolRent => "array_pool_rent",
                SinkApi.SpanSlice => "span_slice",
                SinkApi.SpanIndex => "span_index",
                _ => "unknown",
            };
            absences.Add(new EmittedSanitizerAbsence
            {
                Location = $"{preSink.File}:{preSink.Line}",
                TaintedValue = preSink.TaintedValueOut,
                ExpectedCheck = $"{preSink.TaintedValueOut} must be bounded before reaching {sinkApiDisplay} at {sinkFile}:{sinkLine}",
            });
        }

        return new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = false,
            NewlyTaintedThisFields = newlyTaintedFields.ToArray(),
            Hops = hops,
            Absences = absences,
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
        if (method.HasThis)
        {
            state.Args[0] = StackSlot.Untainted;
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
        });
        return true;
    }

    // Handles a single IL instruction by updating taint state. Called AFTER HandleSinkMatch;
    // at sink instructions, the operand stack still contains the critical arguments when matchers run.
    // This ordering is invariant and relied upon by cross-method analysis (Task 11).
    private void StepInstruction(MethodDefinition method, Instruction ins, TaintState state, HashSet<string> newlyTaintedFields)
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

            case Code.Stloc_0: state.Locals[0] = state.Stack.Pop(); break;
            case Code.Stloc_1: state.Locals[1] = state.Stack.Pop(); break;
            case Code.Stloc_2: state.Locals[2] = state.Stack.Pop(); break;
            case Code.Stloc_3: state.Locals[3] = state.Stack.Pop(); break;
            case Code.Stloc:
            case Code.Stloc_S:
                state.Locals[((VariableDefinition)ins.Operand).Index] = state.Stack.Pop();
                break;

            case Code.Ldloc_0: state.Stack.Push(state.Locals.GetValueOrDefault(0, StackSlot.Untainted)); break;
            case Code.Ldloc_1: state.Stack.Push(state.Locals.GetValueOrDefault(1, StackSlot.Untainted)); break;
            case Code.Ldloc_2: state.Stack.Push(state.Locals.GetValueOrDefault(2, StackSlot.Untainted)); break;
            case Code.Ldloc_3: state.Stack.Push(state.Locals.GetValueOrDefault(3, StackSlot.Untainted)); break;
            case Code.Ldloc:
            case Code.Ldloc_S:
                state.Stack.Push(state.Locals.GetValueOrDefault(((VariableDefinition)ins.Operand).Index, StackSlot.Untainted));
                break;

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
                    state.Stack.Push(lhs.Tainted || rhs.Tainted
                        ? StackSlot.TaintedWith(CombineProvenance(lhs, rhs))
                        : StackSlot.Untainted);
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
                // (pop and push back as-is)
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
                    if (receiver.Tainted)
                    {
                        // Taint propagates on field-load from a tainted struct/object.
                        state.Stack.Push(StackSlot.TaintedWith($"{receiver.Provenance}.{fr.Name}"));
                        break;
                    }
                    // Receiver is `this` (Ldarg.0) whose per-field taint map we track:
                    if (state.ThisFields.TryGetValue(fr.FullName, out var fieldSlot) && fieldSlot.Tainted)
                    {
                        state.Stack.Push(fieldSlot);
                        break;
                    }
                    state.Stack.Push(StackSlot.Untainted);
                    break;
                }

            case Code.Ldsfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    if (state.StaticFields.TryGetValue(fr.FullName, out var sfld) && sfld.Tainted)
                    {
                        state.Stack.Push(sfld);
                    }
                    else
                    {
                        state.Stack.Push(StackSlot.Untainted);
                    }
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
                HandleCall(method, ins, state, newlyTaintedFields);
                break;

            default:
                // Conservative fallback: pop the operand stack to the opcode's declared pop count,
                // then push untainted to the declared push count.
                ApplyStackBehavior(ins, state);
                break;
        }
    }

    private void HandleCall(MethodDefinition callerMethod, Instruction ins, TaintState state, HashSet<string> newlyTaintedFields)
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
            return;
        }

        var argSlots = new StackSlot[paramCount];
        for (int i = paramCount - 1; i >= 0; i--)
        {
            argSlots[i] = state.Stack.Pop();
        }
        var receiverSlot = hasThisOnStack ? state.Stack.Pop() : default;

        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolveMethod(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: push untainted return (conservative). Any tainted return from an external call
            // would need source_methods modelling.
            if (!IsVoidReturn(callee)) state.Stack.Push(StackSlot.Untainted);
            return;
        }

        int bitmask = 0;
        for (int i = 0; i < paramCount; i++)
        {
            if (argSlots[i].Tainted) bitmask |= (1 << i);
        }

        // Cross-method walk.
        var calleeSummary = Walk(resolved, bitmask);

        // Return-value taint propagation: over-approximate — return is tainted when any tainted arg
        // was passed OR the callee's summary says ReturnsTainted.
        bool callReturnIsTainted = !IsVoidReturn(callee) && (bitmask != 0 || calleeSummary.ReturnsTainted);

        // `this`-field taint propagation: callee's NewlyTaintedThisFields apply to caller's
        // receiver ONLY when the caller's receiver was itself `this`.
        bool receiverIsCallerThis = hasThisOnStack && IsReceiverCallerThis(receiverSlot, ins);
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
