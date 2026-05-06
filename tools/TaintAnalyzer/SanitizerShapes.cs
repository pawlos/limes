using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class BranchSides
{
    public required bool FailureSideIsBranchTarget { get; init; }
    public required FailureKind FailureKind { get; init; }
    public required MethodReference? ThrowHelper { get; init; }   // null when FailureKind == ReturnEarly
}

public sealed class SanitizerMatch
{
    public required EstablishesBound EstablishesBound { get; init; }
    public required OnFailure OnFailure { get; init; }
    public required int ComparisonIlOffset { get; init; }        // IL offset of the conditional branch
}

public sealed class ClampMatch
{
    /// <summary>IL offset of the comparison/branch that opened the diamond.</summary>
    public required int ComparisonIlOffset { get; init; }
    /// <summary>IL offset of the join instruction (where both arms converge).</summary>
    public required int JoinIlOffset { get; init; }
    /// <summary>Provenance string identifying the originally-tainted operand (e.g. "arg0", "stream.Length").</summary>
    public required string TaintedOperandProvenance { get; init; }
    /// <summary>Provenance string identifying the bounded operand (e.g. "ldc.i4 4096", "limit").</summary>
    public required string BoundedOperandProvenance { get; init; }
}

public static class SanitizerShapes
{
    private const string DoesNotReturnFullName = "System.Diagnostics.CodeAnalysis.DoesNotReturnAttribute";

    public static bool IsThrowHelper(MethodDefinition m)
    {
        if (m.ReturnType.FullName != "System.Void") return false;
        if (!m.Name.StartsWith("Throw", StringComparison.Ordinal)) return false;

        foreach (var ca in m.CustomAttributes)
        {
            if (ca.AttributeType.FullName == DoesNotReturnFullName) return true;
        }

        // Fallback: every return path ends in throw. For MVP we accept the simpler heuristic —
        // the body contains at least one `throw` and no `ret` instruction at all.
        if (m.Body is null) return false;
        bool hasThrow = false, hasRet = false;
        foreach (var ins in m.Body.Instructions)
        {
            if (ins.OpCode == OpCodes.Throw || ins.OpCode == OpCodes.Rethrow) hasThrow = true;
            if (ins.OpCode == OpCodes.Ret) hasRet = true;
        }
        return hasThrow && !hasRet;
    }

    public static string? ResolveExceptionType(MethodDefinition throwHelper)
    {
        // Walk the body for the first `newobj <ExceptionCtor>` and return the declaring type's
        // SHORT name (no namespace) — fixtures use the C# unqualified form
        // (`InvalidImageContentException`), not the FQN.
        if (throwHelper.Body is not null)
        {
            foreach (var ins in throwHelper.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Newobj && ins.Operand is MethodReference ctor)
                {
                    return ctor.DeclaringType.Name;
                }
            }
        }
        return NameSuffixException(throwHelper.Name);
    }

    // Extract the type-suffix of a throw-helper name: "ThrowInvalidImageContentException" → "InvalidImageContentException".
    public static string? NameSuffixException(string helperName)
    {
        if (!helperName.StartsWith("Throw", StringComparison.Ordinal)) return null;
        var suffix = helperName.Substring(5);
        return string.IsNullOrEmpty(suffix) ? null : suffix;
    }

    // Identify failure/safe sides of a conditional branch. Returns null when no branch side
    // structurally maps to "failure" (throw-helper call then exit, or unconditional ret).
    public static BranchSides? DetectBranchSides(Instruction conditionalBranch, MethodDefinition containingMethod)
    {
        if (conditionalBranch.OpCode.FlowControl != FlowControl.Cond_Branch
            || conditionalBranch.OpCode.Code == Code.Switch)
        {
            return null;
        }

        var target = (Instruction)conditionalBranch.Operand;
        var fallThrough = conditionalBranch.Next;
        if (fallThrough is null) return null;

        bool isVoidMethod = containingMethod.ReturnType.FullName == "System.Void";
        var branchTargetOutcome = ClassifyArm(target, isVoidMethod);
        var fallThroughOutcome  = ClassifyArm(fallThrough, isVoidMethod);

        // "Failure" = the arm that reaches a throw-helper-exit or a ret without further propagation.
        bool targetIsFailure = branchTargetOutcome.IsFailure;
        bool fallIsFailure   = fallThroughOutcome.IsFailure;

        // Tie-breaker: when both arms look like failure, prefer Throw over ReturnEarly. The
        // ReturnEarly classification on a bare `ret` in a void method is ambiguous — every void
        // method ends with `ret`, so an arm that immediately reaches `ret` could be either a
        // genuine early-return guard OR the safe-side normal exit of an if-throw. A Throw arm,
        // by contrast, is structurally unambiguous (it reaches a throw-helper). When the two
        // appear together, the bare-ret arm is the safe path.
        if (targetIsFailure && fallIsFailure)
        {
            if (branchTargetOutcome.Kind == FailureKind.Throw && fallThroughOutcome.Kind == FailureKind.ReturnEarly)
                fallIsFailure = false;
            else if (branchTargetOutcome.Kind == FailureKind.ReturnEarly && fallThroughOutcome.Kind == FailureKind.Throw)
                targetIsFailure = false;
        }

        if (targetIsFailure == fallIsFailure)
        {
            // Neither arm (or both, with no tie-break) look like failure — not a sanitizer shape.
            return null;
        }

        var failureOutcome = targetIsFailure ? branchTargetOutcome : fallThroughOutcome;

        return new BranchSides
        {
            FailureSideIsBranchTarget = targetIsFailure,
            FailureKind = failureOutcome.Kind,
            ThrowHelper = failureOutcome.ThrowHelper,
        };
    }

    private readonly record struct ArmOutcome(bool IsFailure, FailureKind Kind, MethodReference? ThrowHelper);

    // Walk straight-line IL from `start`, bounded by a small budget, looking for:
    //  - a call to a throw-helper followed by exit (throw or ret) → failure with kind=Throw
    //  - an unconditional `ret` that is a true early-return guard → failure with kind=ReturnEarly
    // Branches in the arm body abort the classification (not a straight-line failure body).
    //
    // ReturnEarly detection heuristic: `ret` is treated as a failure (early return) only when
    // (a) at least one constant- or parameter-load instruction appeared before `ret` (the arm
    //     is clearly producing a sentinel return value), AND
    // (b) no arithmetic opcode appeared (arithmetic indicates the normal computation path,
    //     not a short-circuit guard).
    // This correctly handles:
    //   - void-method safe tail (`ret` alone, no preceding load) → NOT failure
    //   - `if (x<0) return -1;` guard path → ldc.i4.m1 then ret → ReturnEarly failure
    //   - `nop; br; ret` safe-branch exit → no value load → NOT failure
    private static ArmOutcome ClassifyArm(Instruction start, bool isVoidContainingMethod)
    {
        const int budget = 40;
        var cur = start;
        int steps = 0;
        bool sawValueLoad = false;   // ldarg.* or ldc.* — something that produces a concrete value
        bool sawArithmetic = false;  // any computation opcode that indicates a "normal" body

        while (cur is not null && steps++ < budget)
        {
            if (cur.OpCode.FlowControl == FlowControl.Cond_Branch
                || cur.OpCode.Code == Code.Switch)
            {
                return new ArmOutcome(false, default, null);
            }

            if ((cur.OpCode == OpCodes.Call || cur.OpCode == OpCodes.Callvirt)
                && cur.Operand is MethodReference mr)
            {
                var resolved = SafeResolve(mr);
                if (resolved is not null && IsThrowHelper(resolved))
                {
                    return new ArmOutcome(true, FailureKind.Throw, mr);
                }
                // Non-throw-helper call: walk past it. Real-world throw arms may build an
                // interpolated string before the throw helper — DefaultInterpolatedStringHandler
                // .ctor / AppendLiteral / AppendFormatted / ToStringAndClear all appear between
                // the conditional branch and the actual throw call. Treating the first such call
                // as "not failure" misses these shapes. Continue iterating; the budget bounds
                // arm walks so we won't follow a runaway non-failure body forever.
                cur = cur.Next;
                continue;
            }

            if (cur.OpCode == OpCodes.Throw || cur.OpCode == OpCodes.Rethrow)
            {
                return new ArmOutcome(true, FailureKind.Throw, null);
            }

            if (cur.OpCode == OpCodes.Ret)
            {
                // For void methods, a bare `ret` (no preceding value load, no arithmetic) IS an
                // early-return guard — `if (x<0) return;` compiles to just `ret`. For
                // non-void methods, an early-return arm must produce a sentinel value (`return
                // -1;` etc.) and not do real computation.
                bool isEarlyReturn = isVoidContainingMethod
                    ? !sawArithmetic
                    : (sawValueLoad && !sawArithmetic);
                return isEarlyReturn
                    ? new ArmOutcome(true, FailureKind.ReturnEarly, null)
                    : new ArmOutcome(false, default, null);
            }

            if (cur.OpCode.FlowControl == FlowControl.Branch)
            {
                // An unconditional branch mid-arm — follow it once.
                cur = (Instruction)cur.Operand;
                continue;
            }

            // Track value-load and arithmetic opcodes for the ReturnEarly heuristic.
            TrackOpcode(cur.OpCode, ref sawValueLoad, ref sawArithmetic);

            cur = cur.Next;
        }
        return new ArmOutcome(false, default, null);
    }

    private static void TrackOpcode(OpCode op, ref bool sawValueLoad, ref bool sawArithmetic)
    {
        var code = op.Code;
        // Parameter and constant loads — signals the arm is producing a return value.
        if (code is Code.Ldarg   or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3
                 or Code.Ldarg_S or Code.Ldarga  or Code.Ldarga_S
                 or Code.Ldc_I4  or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3
                 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8
                 or Code.Ldc_I4_M1 or Code.Ldc_I4_S or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8
                 or Code.Ldnull or Code.Ldstr)
        {
            sawValueLoad = true;
            return;
        }
        // Arithmetic / logic / non-trivial ops — signals the arm is doing real computation (normal
        // body, not a guard). Object/array allocation opcodes are included because an arm that
        // allocates (`newarr`, `newobj`) is clearly not a short-circuit early-return guard; without
        // this, the normal-return path `ldarg; newarr; stloc; br; ret` would be falsely classified
        // as ReturnEarly because `ldarg` sets sawValueLoad and `newarr` (not in the arithmetic list)
        // would leave sawArithmetic=false.
        if (code is Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un
                 or Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un
                 or Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un
                 or Code.Div or Code.Div_Un
                 or Code.Rem or Code.Rem_Un
                 or Code.And or Code.Or or Code.Xor or Code.Not or Code.Neg
                 or Code.Shl or Code.Shr or Code.Shr_Un
                 or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un
                 or Code.Conv_I or Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_I8
                 or Code.Conv_Ovf_I or Code.Conv_Ovf_U or Code.Conv_U or Code.Conv_U1 or Code.Conv_U2
                 or Code.Conv_U4 or Code.Conv_U8 or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un
                 or Code.Newarr or Code.Newobj)
        {
            sawArithmetic = true;
        }
    }

    private static MethodDefinition? SafeResolve(MethodReference mr)
    {
        try { return mr.Resolve(); }
        catch { return null; }
    }

    // --- Full matchers (Task 7, extended in Task 14.5.2 for multi-sanitizer support) ---

    public static SanitizerMatch? MatchCompareAndThrow(MethodDefinition method)
        => MatchAllOfKind(method, FailureKind.Throw).FirstOrDefault();

    public static SanitizerMatch? MatchCompareAndReturnEarly(MethodDefinition method)
        => MatchAllOfKind(method, FailureKind.ReturnEarly).FirstOrDefault();

    public static IEnumerable<SanitizerMatch> MatchAll(MethodDefinition method)
    {
        // Yield matches across both failure-kinds, ordered by IL offset (already true since
        // each kind iterates the same body in order; we merge by offset to interleave both kinds
        // if a method had a mix).
        var matches = new List<SanitizerMatch>();
        matches.AddRange(MatchAllOfKind(method, FailureKind.Throw));
        matches.AddRange(MatchAllOfKind(method, FailureKind.ReturnEarly));
        matches.Sort((a, b) => a.ComparisonIlOffset.CompareTo(b.ComparisonIlOffset));
        return matches;
    }

    private static IEnumerable<SanitizerMatch> MatchAllOfKind(MethodDefinition method, FailureKind requiredFailureKind)
    {
        if (method.Body is null) yield break;

        foreach (var ins in method.Body.Instructions)
        {
            if (ins.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
            if (ins.OpCode.Code == Code.Switch) continue;

            var sides = DetectBranchSides(ins, method);
            if (sides is null) continue;
            if (sides.FailureKind != requiredFailureKind) continue;

            // Resolve the effective comparison opcode and operands.
            // Roslyn debug-mode emits cgt/clt/ceq + stloc + ldloc + brfalse/brtrue instead of
            // direct bgt/blt/beq etc., so we need to walk back through that pattern.
            Code effectiveCode;
            ComparisonOperands operands;
            if (!TryResolveEffectiveComparison(ins, method, out effectiveCode, out operands))
                continue;

            var bound = ReadBoundFromSafeSide(effectiveCode, operands, sides.FailureSideIsBranchTarget);
            if (bound is null) continue;
            bound = NormalizeAdditiveOffset(bound);

            string? exception = null;
            if (sides.FailureKind == FailureKind.Throw && sides.ThrowHelper is { } helper)
            {
                var resolved = SafeResolve(helper);
                exception = resolved is not null ? ResolveExceptionType(resolved) : NameSuffixException(helper.Name);
            }

            yield return new SanitizerMatch
            {
                EstablishesBound = bound,
                OnFailure = new OnFailure
                {
                    Kind = sides.FailureKind,
                    Exception = exception,
                },
                ComparisonIlOffset = ins.Offset,
            };
        }
    }

    private readonly record struct ComparisonOperands(string Left, string Right);

    // Resolve the effective comparison Code and operand names from a conditional branch instruction.
    //
    // Two shapes are handled:
    //
    // Shape A — direct comparison branch (bgt, blt, bge, ble, beq, bne.un and their variants):
    //   <push left>; <push right>; bXX TARGET
    //   The effective code is the branch opcode itself.
    //
    // Shape B — Roslyn debug-mode lowering (brfalse/brtrue after cgt/clt/ceq):
    //   <push left>; <push right>; cgt/clt/ceq; [ldc.i4.0; ceq;] stloc; ldloc; brfalse.s / brtrue.s
    //   The effective code is synthesized by combining the comparison opcode, the optional NOT-negation,
    //   and whether the branch is brfalse (fires when result=0) or brtrue (fires when result=1).
    //
    // Returns false when neither shape is recognized.
    private static bool TryResolveEffectiveComparison(
        Instruction branch, MethodDefinition method,
        out Code effectiveCode, out ComparisonOperands operands)
    {
        effectiveCode = default;
        operands = default;

        var brCode = branch.OpCode.Code;

        // Shape A: direct comparison branch opcode.
        if (brCode is Code.Bgt or Code.Bgt_Un or Code.Bgt_S or Code.Bgt_Un_S
                   or Code.Blt or Code.Blt_Un or Code.Blt_S or Code.Blt_Un_S
                   or Code.Bge or Code.Bge_Un or Code.Bge_S or Code.Bge_Un_S
                   or Code.Ble or Code.Ble_Un or Code.Ble_S or Code.Ble_Un_S
                   or Code.Beq or Code.Beq_S
                   or Code.Bne_Un or Code.Bne_Un_S)
        {
            // <push left>; <push right>; bXX
            var (leftIns, rightIns) = FindOperandPushers(branch, method, depthAtComparison: 2);
            if (leftIns is null || rightIns is null) return false;

            var right = OperandName(rightIns, method);
            var left  = OperandName(leftIns, method);
            if (right is null || left is null) return false;

            effectiveCode = brCode;
            operands = new ComparisonOperands(left, right);
            return true;
        }

        // Shape B: brfalse / brtrue after cgt/clt/ceq (Roslyn debug-mode lowering).
        if (brCode is not (Code.Brfalse or Code.Brfalse_S or Code.Brtrue or Code.Brtrue_S))
            return false;

        bool isBrtrue = brCode is Code.Brtrue or Code.Brtrue_S;

        // Walk back: brfalse/brtrue ← ldloc ← stloc ← [ldc.i4.0; ceq;] cgt/clt/ceq ← <left> ← <right>
        // (The instructions are in forward order so we walk .Previous from the branch.)
        var cur = branch.Previous;

        // Step 1: skip ldloc / ldloc.s / ldloc.0..3 (the local load that feeds the branch).
        if (cur is null) return false;
        if (!IsLdloc(cur.OpCode.Code)) return false;
        cur = cur.Previous;

        // Step 2: skip stloc / stloc.s / stloc.0..3.
        if (cur is null) return false;
        if (!IsStloc(cur.OpCode.Code)) return false;
        var stlocIns = cur;
        cur = cur.Previous;

        // Step 2.5: detect compound short-circuit ('||' / '&&' lowering). When the value feeding
        // the stloc came from one arm of a merge — C# `||` lowers (in debug) to:
        //   <cond1>; brtrue MERGE_TRUE
        //   <cond2-comparison>; br.s MERGE
        //   MERGE_TRUE: ldc.i4.1
        //   MERGE: stloc V_; ldloc V_; brfalse SAFE
        // — walking straight back from stloc lands on the constant-load arm (`ldc.i4.1`/`ldc.i4.0`),
        // not on the comparison opcode. Walk back through that constant-load to find a `br/br.s`
        // whose target is the stloc; the instruction immediately before that branch is the
        // comparison feeding the OTHER arm. Per spec O5: compound conditions collapse to the
        // SECOND condition's bound; the first condition's bound is captured implicitly by the merge.
        {
            var probe = cur;
            int probeBudget = 5;
            while (probe is not null && probeBudget-- > 0)
            {
                if ((probe.OpCode.Code == Code.Br || probe.OpCode.Code == Code.Br_S)
                    && probe.Operand is Instruction tgt && tgt == stlocIns)
                {
                    var compCandidate = probe.Previous;
                    if (compCandidate is not null && IsComparisonOpcode(compCandidate.OpCode.Code))
                    {
                        cur = compCandidate;   // jump to the second-condition comparison
                    }
                    break;
                }
                probe = probe.Previous;
            }
        }

        // Step 3: optional negation pattern: ceq; ldc.i4.0 (in reverse: ldc.i4.0 is actually BEFORE ceq).
        // In forward IL: cgt; ldc.i4.0; ceq; stloc → so walking back: stloc ← ceq ← ldc.i4.0 ← cgt
        //
        // Discriminator: this is a NOT-negation only when the instruction BEFORE the ldc.i4.0 is itself
        // a comparison opcode (cgt, clt, ceq). If it is an operand-producing instruction (ldarg, ldloc,
        // ldfld, …), then `ldc.i4.0; ceq` is a plain equality-with-zero comparison, not a negation.
        // In that case, leave cur pointing at the ceq so Step 4 handles it as a regular ceq.
        bool negated = false;
        if (cur is not null && cur.OpCode.Code == Code.Ceq)
        {
            var beforeCeq = cur.Previous;
            if (beforeCeq is not null && beforeCeq.OpCode.Code == Code.Ldc_I4_0)
            {
                var beforeLdc = beforeCeq.Previous;
                if (beforeLdc is not null && IsComparisonOpcode(beforeLdc.OpCode.Code))
                {
                    // Negation pattern confirmed: NOT(comparison).
                    negated = true;
                    cur = beforeLdc;   // now points at the actual comparison (cgt/clt/ceq)
                }
                // else: ldc.i4.0 is an operand of `==` (equality-with-zero), not a NOT-negation.
                // cur remains pointing at ceq — Step 4 will handle it as a plain ceq.
            }
            else
            {
                // ceq is the comparison itself (not a negation), proceed normally.
                // cur already points at ceq — will be handled below.
            }
        }

        // Step 4: actual comparison opcode (cgt, clt, ceq).
        if (cur is null) return false;
        var compCode = cur.OpCode.Code;
        if (compCode is not (Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or Code.Ceq))
            return false;

        // Step 5: stack-effect-aware lookup of the two operand pushers. The naive
        // `cgt.Previous` / `Previous.Previous` walk-back fails when an operand is the result of
        // a multi-instruction chain (e.g., `ldflda; call get_Value; stloc; ldloca; call
        // get_Offset; conv.i8` for `this.fileHeader.Value.Offset`). FindOperandPushers walks
        // back from `cur` (the comparison opcode that pops 2) tracking stack-effect deltas.
        var (leftOperandIns, rightOperandIns) = FindOperandPushers(cur, method, depthAtComparison: 2);
        if (rightOperandIns is null || leftOperandIns is null) return false;

        var rightName = OperandName(rightOperandIns, method);
        var leftName  = OperandName(leftOperandIns, method);
        if (rightName is null || leftName is null) return false;

        // Step 6: synthesize the effective branch opcode from (compCode × negated × isBrtrue).
        // The effective opcode represents: "this branch fires when the following condition holds".
        // Firing a branch = going to the target.
        //
        // brfalse fires when result = 0 (condition is FALSE).
        // brtrue  fires when result = 1 (condition is TRUE).
        // negated = NOT was applied to the comparison result via `ldc.i4.0; ceq`.
        //
        // Truth table for whether to negate the underlying comparison:
        //   isBrtrue=false, neg=false → fires when NOT(comp) → negate comp  (e.g. brfalse+cgt → ble)
        //   isBrtrue=false, neg=true  → fires when NOT(NOT(comp)) = comp    (e.g. brfalse+cgt+neg → bgt)
        //   isBrtrue=true,  neg=false → fires when comp                      (e.g. brtrue+cgt → bgt)
        //   isBrtrue=true,  neg=true  → fires when NOT(comp)                 (e.g. brtrue+cgt+neg → ble)
        // So: negate when (isBrtrue == negated).
        bool negateForEffective = isBrtrue == negated;

        effectiveCode = SynthesizeBranchCode(compCode, negateForEffective);
        if (effectiveCode == default) return false;

        operands = new ComparisonOperands(leftName, rightName);
        return true;
    }

    // Map a comparison opcode (cgt/clt/ceq) + negate flag → the equivalent conditional-branch opcode.
    // When negate=false: "branch when cgt is true" → bgt. When negate=true: "branch when cgt is false" → ble.
    private static Code SynthesizeBranchCode(Code compCode, bool negate)
    {
        return (compCode, negate) switch
        {
            (Code.Cgt or Code.Cgt_Un, false) => Code.Bgt_Un,    // fires when left > right
            (Code.Cgt or Code.Cgt_Un, true)  => Code.Ble_Un,    // fires when left <= right
            (Code.Clt or Code.Clt_Un, false) => Code.Blt_Un,    // fires when left < right
            (Code.Clt or Code.Clt_Un, true)  => Code.Bge_Un,    // fires when left >= right
            (Code.Ceq,                false) => Code.Beq,       // fires when left == right
            (Code.Ceq,                true)  => Code.Bne_Un,    // fires when left != right
            _ => default,
        };
    }

    private static bool IsLdloc(Code c) =>
        c is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3;

    private static bool IsStloc(Code c) =>
        c is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3;

    private static bool IsComparisonOpcode(Code code) =>
        code is Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or Code.Ceq;

    private static string? OperandName(Instruction ins, MethodDefinition method)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Ldarg_0: return method.HasThis ? "this" : method.Parameters[0].Name;
            case Code.Ldarg_1: return method.HasThis ? method.Parameters[0].Name : method.Parameters[1].Name;
            case Code.Ldarg_2: return method.HasThis ? method.Parameters[1].Name : method.Parameters[2].Name;
            case Code.Ldarg_3: return method.HasThis ? method.Parameters[2].Name : method.Parameters[3].Name;
            case Code.Ldarg:
            case Code.Ldarg_S:
            case Code.Ldarga:
            case Code.Ldarga_S:
                if (ins.Operand is ParameterDefinition pd) return pd.Name;
                return null;
            case Code.Ldloc:
            case Code.Ldloc_S:
                return LocalName(method, ((VariableDefinition)ins.Operand).Index);
            case Code.Ldloca:
            case Code.Ldloca_S:
                return LocalName(method, ((VariableDefinition)ins.Operand).Index);
            case Code.Ldloc_0: return LocalName(method, 0);
            case Code.Ldloc_1: return LocalName(method, 1);
            case Code.Ldloc_2: return LocalName(method, 2);
            case Code.Ldloc_3: return LocalName(method, 3);
            case Code.Ldfld:
            case Code.Ldflda:
                return BuildDottedFieldChain(ins, method);
            case Code.Ldsfld:
                return ins.Operand is FieldReference sfr ? $"{sfr.DeclaringType.Name}.{sfr.Name}" : null;
            case Code.Ldc_I4_0: return "0";
            case Code.Ldc_I4_1: return "1";
            case Code.Ldc_I4_2: return "2";
            case Code.Ldc_I4_3: return "3";
            case Code.Ldc_I4_4: return "4";
            case Code.Ldc_I4_5: return "5";
            case Code.Ldc_I4_6: return "6";
            case Code.Ldc_I4_7: return "7";
            case Code.Ldc_I4_8: return "8";
            case Code.Ldc_I4_M1: return "-1";
            case Code.Ldc_I4:
            case Code.Ldc_I4_S:
                return ins.Operand?.ToString();

            // Call/Callvirt to a getter — synthesize "{receiver}.{property}". Other calls
            // synthesize the bare method name as a best-effort signal.
            case Code.Call:
            case Code.Callvirt:
                if (ins.Operand is MethodReference mr2)
                {
                    string methodPart = mr2.Name.StartsWith("get_", StringComparison.Ordinal)
                        ? mr2.Name.Substring(4)
                        : mr2.Name;
                    if (mr2.HasThis)
                    {
                        // Receiver was pushed by some preceding instruction. Walk back N=paramCount
                        // pusher slots to find it; conservative: use ins.Previous when paramCount=0,
                        // otherwise leave receiver-prefix off (best-effort — the property name alone
                        // is usually identifying enough for soft-match purposes).
                        if (mr2.Parameters.Count == 0)
                        {
                            var receiver = SkipWhileTrivial(ins.Previous);
                            var basePart = receiver is null ? null : OperandNameForReceiver(receiver, method);
                            return basePart is null ? methodPart : $"{basePart}.{methodPart}";
                        }
                    }
                    return methodPart;
                }
                return null;

            // Conversion: just preserves the operand. Recurse to the predecessor's name.
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
                return ins.Previous is null ? null : OperandName(ins.Previous, method);

            // Additive arithmetic: compose "<L> + <R>" / "<L> - <R>" by stack-effect-aware
            // lookup of the two operand pushers. Used so a comparison left-operand like
            // `(zeroIndexKeyword + 4)` produces a name string the bound-normalization step
            // can decompose (target=zeroIndexKeyword, upper-=4).
            case Code.Add:
            case Code.Add_Ovf:
            case Code.Add_Ovf_Un:
            case Code.Sub:
            case Code.Sub_Ovf:
            case Code.Sub_Ovf_Un:
                {
                    var (l, r) = FindOperandPushers(ins, method, depthAtComparison: 2);
                    if (l is null || r is null) return null;
                    var ln = OperandName(l, method);
                    var rn = OperandName(r, method);
                    if (ln is null || rn is null) return null;
                    bool isAdd = ins.OpCode.Code is Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un;
                    return $"{ln} {(isAdd ? "+" : "-")} {rn}";
                }
        }
        return null;
    }

    private static Instruction? SkipWhileTrivial(Instruction? ins)
    {
        while (ins is not null && ins.OpCode.Code == Code.Nop) ins = ins.Previous;
        return ins;
    }

    // Find the instructions that pushed the right (top of stack) and left (second from top)
    // operands of a 2-operand comparison instruction. Uses a forward symbolic-stack
    // simulation that records, at each instruction, which prior instruction pushed each
    // currently-live stack slot. Robust to call/callvirt with variable arity, conv chains,
    // newobj, and other multi-instruction operand expressions. Returns (null, null) if the
    // simulation can't reach the comparison or the stack is unexpectedly shallow there.
    private static (Instruction? Left, Instruction? Right) FindOperandPushers(
        Instruction comparison, MethodDefinition method, int depthAtComparison)
    {
        if (method.Body is null) return (null, null);

        var offsetToIns = new Dictionary<int, Instruction>();
        foreach (var ins in method.Body.Instructions) offsetToIns[ins.Offset] = ins;

        // Stack of pusher IL offsets (or -1 for "exception handler implicit push").
        var stack = new List<int>();
        foreach (var ins in method.Body.Instructions)
        {
            // Implicit push of caught exception at handler/filter start (matches walker semantics).
            PushImplicitExceptionIfHandlerStart(method, ins, stack);

            if (ins.Offset == comparison.Offset)
            {
                if (stack.Count < depthAtComparison) return (null, null);
                int rightOffset = stack[^1];
                int leftOffset = stack[^2];
                Instruction? leftIns = leftOffset >= 0 && offsetToIns.TryGetValue(leftOffset, out var l) ? l : null;
                Instruction? rightIns = rightOffset >= 0 && offsetToIns.TryGetValue(rightOffset, out var r) ? r : null;
                return (leftIns, rightIns);
            }

            int pops = StackPopsOf(ins);
            int pushes = StackPushesOf(ins);
            for (int i = 0; i < pops && stack.Count > 0; i++) stack.RemoveAt(stack.Count - 1);
            for (int i = 0; i < pushes; i++) stack.Add(ins.Offset);
        }
        return (null, null);
    }

    private static void PushImplicitExceptionIfHandlerStart(MethodDefinition method, Instruction ins, List<int> stack)
    {
        if (method.Body is null || !method.Body.HasExceptionHandlers) return;
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.HandlerType == ExceptionHandlerType.Catch && ins == handler.HandlerStart)
            {
                stack.Add(-1);
                return;
            }
            if (handler.HandlerType == ExceptionHandlerType.Filter
                && (ins == handler.FilterStart || ins == handler.HandlerStart))
            {
                stack.Add(-1);
                return;
            }
        }
    }

    private static int StackPopsOf(Instruction ins)
    {
        var op = ins.OpCode;
        if (op.Code == Code.Call || op.Code == Code.Callvirt)
        {
            if (ins.Operand is MethodReference mr)
                return mr.Parameters.Count + (mr.HasThis ? 1 : 0);
            return 0;
        }
        if (op.Code == Code.Newobj)
        {
            if (ins.Operand is MethodReference mr) return mr.Parameters.Count;
            return 0;
        }
        if (op.Code == Code.Ret)
        {
            // Function returns pop one if non-void, else zero.
            return 0;   // not relevant in our walk-back which doesn't cross method boundaries
        }
        return op.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi
                or StackBehaviour.Popi_popi8 or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8
                or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
            StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi
                or StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4
                or StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
            _ => 0,
        };
    }

    private static int StackPushesOf(Instruction ins)
    {
        var op = ins.OpCode;
        if (op.Code == Code.Call || op.Code == Code.Callvirt)
        {
            if (ins.Operand is MethodReference mr)
                return mr.ReturnType.FullName == "System.Void" ? 0 : 1;
            return 0;
        }
        if (op.Code == Code.Newobj) return 1;
        return op.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8
                or StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
            StackBehaviour.Push1_push1 => 2,
            _ => 0,
        };
    }

    private static string LocalName(MethodDefinition m, int idx)
    {
        // Cecil's VariableDefinition doesn't expose a Name property directly; the name
        // lives in the method's debug information as a VariableDebugInformation entry.
        if (m.Body?.Variables is { } vars && idx < vars.Count)
        {
            var v = vars[idx];
            if (m.DebugInformation?.TryGetName(v, out var debugName) == true
                && !string.IsNullOrEmpty(debugName))
            {
                return debugName;
            }
            return $"loc_{idx}";
        }
        return $"loc_{idx}";
    }

    // Walks backward from a Ldfld/Ldflda instruction through nested chains of:
    //   ldfld/ldflda  → "<base>.<name>"
    //   call get_Value/get_X  → "<base>.<getter-without-prefix>"
    //   ldarg.0       → "this"
    //   ldarg/ldloc/ldfld/etc. → terminal: their OperandName recurses naturally
    // For the input `ldarg.0; ldfld inner; ldfld Offset`, walking back from the second ldfld
    // produces "this.inner.Offset". Returns null if any step in the chain can't be resolved.
    private static string? BuildDottedFieldChain(Instruction ins, MethodDefinition method)
    {
        if (ins.Operand is not FieldReference fr) return null;
        var fieldName = fr.Name;

        // Walk to the receiver (the instruction that pushed the receiver of this ldfld).
        var receiverIns = ins.Previous;
        if (receiverIns is null) return fieldName;

        var basePart = OperandNameForReceiver(receiverIns, method);
        if (basePart is null) return fieldName;
        // Drop the implicit `this.` prefix — fixtures use the C# convention of writing
        // `fileHeader.Value.Offset`, not `this.fileHeader.Value.Offset`.
        if (basePart == "this") return fieldName;
        return $"{basePart}.{fieldName}";
    }

    // Like OperandName but recognises additional opcodes that produce a "receiver" value:
    // ldfld/ldflda chain, call get_Value/get_<X>, plus delegates back to OperandName for leaf forms.
    // For ldloc/ldloca, traces back to the most-recent stloc to that local and recurses on the
    // stored value's source — this recovers the C#-level chain through Roslyn's temp locals
    // (e.g., `ldflda fileHeader; call get_Value; stloc V_14; ldloca V_14; call get_Offset`
    // resolves to `fileHeader.Value.Offset` rather than `loc_14.Offset`).
    private static string? OperandNameForReceiver(Instruction ins, MethodDefinition method)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Ldfld:
            case Code.Ldflda:
                return BuildDottedFieldChain(ins, method);
            case Code.Call:
            case Code.Callvirt:
                if (ins.Operand is MethodReference mr
                    && mr.Name.StartsWith("get_", StringComparison.Ordinal)
                    && mr.Parameters.Count == 0)
                {
                    var prop = mr.Name.Substring(4);   // "get_Value" → "Value"
                    var receiver = ins.Previous;
                    var basePart = receiver is null ? null : OperandNameForReceiver(receiver, method);
                    return basePart is null ? prop : $"{basePart}.{prop}";
                }
                return null;
            case Code.Ldloc:
            case Code.Ldloc_S:
            case Code.Ldloca:
            case Code.Ldloca_S:
            case Code.Ldloc_0:
            case Code.Ldloc_1:
            case Code.Ldloc_2:
            case Code.Ldloc_3:
                {
                    int idx = LocalIndexFromLoad(ins);
                    if (idx < 0) return OperandName(ins, method);
                    var assignedFrom = FindLastStlocValueSource(ins, idx);
                    if (assignedFrom is not null)
                    {
                        var traced = OperandNameForReceiver(assignedFrom, method);
                        if (traced is not null) return traced;
                    }
                    return OperandName(ins, method);
                }
        }
        return OperandName(ins, method);
    }

    private static int LocalIndexFromLoad(Instruction ins) => ins.OpCode.Code switch
    {
        Code.Ldloc_0 => 0,
        Code.Ldloc_1 => 1,
        Code.Ldloc_2 => 2,
        Code.Ldloc_3 => 3,
        Code.Ldloc or Code.Ldloc_S or Code.Ldloca or Code.Ldloca_S
            => ((VariableDefinition)ins.Operand).Index,
        _ => -1,
    };

    private static int LocalIndexFromStore(Instruction ins) => ins.OpCode.Code switch
    {
        Code.Stloc_0 => 0,
        Code.Stloc_1 => 1,
        Code.Stloc_2 => 2,
        Code.Stloc_3 => 3,
        Code.Stloc or Code.Stloc_S
            => ((VariableDefinition)ins.Operand).Index,
        _ => -1,
    };

    // Walk backward from `from` to find the most recent stloc to local `idx`. Returns the
    // instruction that pushed the value being stored (i.e., stloc.Previous), or null.
    private static Instruction? FindLastStlocValueSource(Instruction from, int idx)
    {
        for (var cur = from.Previous; cur != null; cur = cur.Previous)
        {
            if (LocalIndexFromStore(cur) == idx)
            {
                return cur.Previous;   // the value-pusher
            }
        }
        return null;
    }

    // Spec's bound-extraction table. `branchTargetIsFailure = true` means the branch TARGET is the failure
    // side (explicit-else form); `false` means the fall-through is the failure side (compiler-negated form).
    private static EstablishesBound? ReadBoundFromSafeSide(Code opCode, ComparisonOperands ops, bool branchTargetIsFailure)
    {
        // "safeIsTaken" means "the branch fires to the safe side" (safe = branch target).
        // If failure = branch-target (branchTargetIsFailure=true), safe = fall-through → safeIsTaken=false.
        // If failure = fall-through  (branchTargetIsFailure=false), safe = branch-target → safeIsTaken=true.
        bool safeIsTaken = !branchTargetIsFailure;

        string relation;
        string? upper = null, lower = null;

        switch (opCode)
        {
            case Code.Bgt:
            case Code.Bgt_Un:
            case Code.Bgt_S:
            case Code.Bgt_Un_S:
                (relation, lower, upper) = safeIsTaken
                    ? (">",  ops.Right,       (string?)null)
                    : ("<=", (string?)null,   ops.Right);
                break;
            case Code.Blt:
            case Code.Blt_Un:
            case Code.Blt_S:
            case Code.Blt_Un_S:
                (relation, lower, upper) = safeIsTaken
                    ? ("<",  (string?)null,   ops.Right)
                    : (">=", ops.Right,       (string?)null);
                break;
            case Code.Bge:
            case Code.Bge_Un:
            case Code.Bge_S:
            case Code.Bge_Un_S:
                (relation, lower, upper) = safeIsTaken
                    ? (">=", ops.Right,       (string?)null)
                    : ("<",  (string?)null,   ops.Right);
                break;
            case Code.Ble:
            case Code.Ble_Un:
            case Code.Ble_S:
            case Code.Ble_Un_S:
                (relation, lower, upper) = safeIsTaken
                    ? ("<=", (string?)null,   ops.Right)
                    : (">",  ops.Right,       (string?)null);
                break;
            case Code.Beq:
            case Code.Beq_S:
                // single-value: use upper_bound convention per spec.
                (relation, upper) = safeIsTaken
                    ? ("==", ops.Right)
                    : ("!=", ops.Right);
                break;
            case Code.Bne_Un:
            case Code.Bne_Un_S:
                (relation, upper) = safeIsTaken
                    ? ("!=", ops.Right)
                    : ("==", ops.Right);
                break;
            default:
                return null;
        }

        return new EstablishesBound
        {
            Target = ops.Left,
            Relation = relation,
            UpperBound = upper,
            LowerBound = lower,
        };
    }

    // If the bound's target carries a trailing additive offset like "X + N" or "X - N", strip
    // it and adjust the upper/lower bound by the inverse offset. Preserves comparison semantics:
    //   (X + 4) <= Y      ↔  X <= Y - 4
    //   (X - 4) >= Y      ↔  X >= Y + 4
    // This lets the analyzer's natural rendering of `(zeroIndexKeyword + 4) <= data.Length`
    // match a fixture-author bound `zeroIndexKeyword <= data.Length - 4`.
    private static EstablishesBound NormalizeAdditiveOffset(EstablishesBound b)
    {
        var (stripped, offset) = TryStripTrailingOffset(b.Target);
        if (offset == 0) return b;
        return new EstablishesBound
        {
            Target = stripped,
            Relation = b.Relation,
            UpperBound = b.UpperBound is { } u ? ApplyOffset(u, -offset) : null,
            LowerBound = b.LowerBound is { } l ? ApplyOffset(l, -offset) : null,
        };
    }

    private static readonly System.Text.RegularExpressions.Regex TrailingOffsetRegex =
        new(@"^(.+?)\s*([+\-])\s*(\d+)$", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static (string Stripped, long Offset) TryStripTrailingOffset(string s)
    {
        var m = TrailingOffsetRegex.Match(s);
        if (!m.Success) return (s, 0);
        if (!long.TryParse(m.Groups[3].Value, out var n)) return (s, 0);
        return (m.Groups[1].Value, m.Groups[2].Value == "+" ? n : -n);
    }

    private static string ApplyOffset(string bound, long offset)
    {
        if (offset == 0) return bound;
        var m = TrailingOffsetRegex.Match(bound);
        if (m.Success && long.TryParse(m.Groups[3].Value, out var existingN))
        {
            long signed = m.Groups[2].Value == "+" ? existingN : -existingN;
            long combined = signed + offset;
            if (combined == 0) return m.Groups[1].Value;
            return $"{m.Groups[1].Value} {(combined >= 0 ? "+" : "-")} {Math.Abs(combined)}";
        }
        return $"{bound} {(offset >= 0 ? "+" : "-")} {Math.Abs(offset)}";
    }

    /// <summary>
    /// Detects the C# ternary-clamp idiom <c>tainted &lt;op&gt; bound ? tainted : bound</c>
    /// (and the symmetric <c>tainted &lt;op&gt; bound ? bound : tainted</c> form) emitted as a
    /// branch diamond. Both arms must be a single straight-line load followed by a
    /// converging unconditional <c>br</c>. Returns one match per matching diamond in the
    /// method body.
    /// </summary>
    public static IEnumerable<ClampMatch> MatchValueClamps(MethodDefinition method)
    {
        if (method.Body is null) yield break;

        foreach (var br in method.Body.Instructions)
        {
            if (br.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
            if (br.OpCode.Code == Code.Switch) continue;

            var fallthrough = br.Next;
            var jumpTarget = br.Operand as Instruction;
            if (fallthrough is null || jumpTarget is null) continue;

            // Each arm: must be a single load instruction followed by an unconditional `br`
            // (or, for the second arm, the join itself).
            var armA = ClassifyArmForClamp(fallthrough);
            if (armA is null) continue;

            var armB = ClassifyArmForClamp(jumpTarget);
            if (armB is null) continue;
            if (armB.JoinAt != armA.JoinAt) continue;

            // Pre-branch operands: walk back from `br`, skipping over conv.* widening/narrowing
            // casts (e.g. `ldarg.0; conv.i4; ldarg.1; blt.s` for a long-to-int cast).
            // We recover the underlying load instruction for provenance.
            var prev1 = SkipConvBackward(br.Previous);   // operand B (top of stack)
            var prev2 = SkipConvBackward(prev1?.Previous); // operand A (under)
            if (prev1 is null || prev2 is null) continue;

            var provA = OperandProvenance(prev2, method);
            var provB = OperandProvenance(prev1, method);
            if (provA is null || provB is null) continue;

            yield return new ClampMatch
            {
                ComparisonIlOffset = br.Offset,
                JoinIlOffset = armA.JoinAt,
                TaintedOperandProvenance = provA,
                BoundedOperandProvenance = provB,
            };
        }
    }

    private sealed record ClampArm(int JoinAt);

    private static ClampArm? ClassifyArmForClamp(Instruction start)
    {
        var cur = start;
        // Skip any leading nop emitted by Roslyn for sequence points.
        while (cur is not null && cur.OpCode.Code == Code.Nop) cur = cur.Next;
        if (cur is null) return null;

        // Single load instruction.
        if (!IsClampLoadInstruction(cur)) return null;
        var next = cur.Next;
        if (next is null) return null;

        // Allow an optional conv.* (widening/narrowing cast) between load and br.
        // e.g. `ldarg.0; conv.i4; br.s LBL` for a long-to-int ternary.
        if (IsConvInstruction(next))
        {
            next = next.Next;
            if (next is null) return null;
        }

        // Either: an unconditional `br`/`br.s`, or the next instruction IS the join.
        if (next.OpCode.Code is Code.Br or Code.Br_S)
        {
            if (next.Operand is not Instruction join) return null;
            return new ClampArm(join.Offset);
        }
        return new ClampArm(next.Offset);
    }

    /// <summary>
    /// Skip backwards over a single conv.* instruction to recover the underlying load.
    /// Returns <paramref name="ins"/> unchanged if it is not a conv instruction.
    /// </summary>
    private static Instruction? SkipConvBackward(Instruction? ins)
    {
        if (ins is null) return null;
        if (IsConvInstruction(ins)) return ins.Previous;
        return ins;
    }

    private static bool IsConvInstruction(Instruction ins) => ins.OpCode.Code switch
    {
        Code.Conv_I or Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_I8
            or Code.Conv_U or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or Code.Conv_U8
            or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un
            or Code.Conv_Ovf_I or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I4
            or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U2
            or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U8
            or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2_Un
            or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U_Un
            or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4_Un
            or Code.Conv_Ovf_U8_Un => true,
        _ => false,
    };

    private static bool IsClampLoadInstruction(Instruction ins) => ins.OpCode.Code switch
    {
        Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1
            or Code.Ldarg_2 or Code.Ldarg_3 => true,
        Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1
            or Code.Ldloc_2 or Code.Ldloc_3 => true,
        Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2
            or Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6
            or Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I4_M1 => true,
        Code.Ldc_I8 or Code.Ldfld or Code.Ldsfld => true,
        _ => false,
    };

    private static string? OperandProvenance(Instruction ins, MethodDefinition method)
    {
        return ins.OpCode.Code switch
        {
            Code.Ldarg_0 => method.HasThis ? "this" : ParamName(method, 0),
            Code.Ldarg_1 => ParamName(method, method.HasThis ? 0 : 1),
            Code.Ldarg_2 => ParamName(method, method.HasThis ? 1 : 2),
            Code.Ldarg_3 => ParamName(method, method.HasThis ? 2 : 3),
            Code.Ldarg or Code.Ldarg_S when ins.Operand is ParameterDefinition pd => pd.Name,
            Code.Ldloc_0 => $"loc{0}",
            Code.Ldloc_1 => $"loc{1}",
            Code.Ldloc_2 => $"loc{2}",
            Code.Ldloc_3 => $"loc{3}",
            Code.Ldloc or Code.Ldloc_S when ins.Operand is VariableDefinition vd
                => $"loc{vd.Index}",
            Code.Ldfld or Code.Ldsfld when ins.Operand is FieldReference fr => fr.Name,
            Code.Ldc_I4_0 => "0",
            Code.Ldc_I4_1 => "1",
            Code.Ldc_I4_2 => "2",
            Code.Ldc_I4_3 => "3",
            Code.Ldc_I4_4 => "4",
            Code.Ldc_I4_5 => "5",
            Code.Ldc_I4_6 => "6",
            Code.Ldc_I4_7 => "7",
            Code.Ldc_I4_8 => "8",
            Code.Ldc_I4_M1 => "-1",
            Code.Ldc_I4 or Code.Ldc_I4_S => ins.Operand?.ToString(),
            Code.Ldc_I8 => ins.Operand?.ToString(),
            _ => null,
        };
    }

    private static string? ParamName(MethodDefinition m, int index)
        => index >= 0 && index < m.Parameters.Count ? m.Parameters[index].Name : null;
}
