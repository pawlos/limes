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
        // Walk the body for the first `newobj <ExceptionCtor>` and return the declaring type's FullName.
        if (throwHelper.Body is not null)
        {
            foreach (var ins in throwHelper.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Newobj && ins.Operand is MethodReference ctor)
                {
                    return ctor.DeclaringType.FullName;
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

        var branchTargetOutcome = ClassifyArm(target);
        var fallThroughOutcome  = ClassifyArm(fallThrough);

        // "Failure" = the arm that reaches a throw-helper-exit or a ret without further propagation.
        bool targetIsFailure = branchTargetOutcome.IsFailure;
        bool fallIsFailure   = fallThroughOutcome.IsFailure;

        if (targetIsFailure == fallIsFailure)
        {
            // Neither arm (or both) look like failure — not a sanitizer shape.
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
    private static ArmOutcome ClassifyArm(Instruction start)
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
                // A non-throw-helper call means the arm has side effects — not a pure failure body.
                return new ArmOutcome(false, default, null);
            }

            if (cur.OpCode == OpCodes.Throw || cur.OpCode == OpCodes.Rethrow)
            {
                return new ArmOutcome(true, FailureKind.Throw, null);
            }

            if (cur.OpCode == OpCodes.Ret)
            {
                // Only treat this `ret` as an early-return failure when the arm loaded a
                // concrete value (ldc/ldarg) and performed no arithmetic. If neither condition
                // holds it is the normal method exit, not a guard short-circuit.
                bool isEarlyReturn = sawValueLoad && !sawArithmetic;
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

    // --- Full matchers (Task 7) ---

    public static SanitizerMatch? MatchCompareAndThrow(MethodDefinition method)
        => MatchSanitizer(method, requiredFailureKind: FailureKind.Throw);

    public static SanitizerMatch? MatchCompareAndReturnEarly(MethodDefinition method)
        => MatchSanitizer(method, requiredFailureKind: FailureKind.ReturnEarly);

    private static SanitizerMatch? MatchSanitizer(MethodDefinition method, FailureKind requiredFailureKind)
    {
        if (method.Body is null) return null;

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

            string? exception = null;
            if (sides.FailureKind == FailureKind.Throw && sides.ThrowHelper is { } helper)
            {
                var resolved = SafeResolve(helper);
                exception = resolved is not null ? ResolveExceptionType(resolved) : NameSuffixException(helper.Name);
            }

            return new SanitizerMatch
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

        return null;
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
            var rightIns = branch.Previous;
            if (rightIns is null) return false;
            var leftIns = rightIns.Previous;
            if (leftIns is null) return false;

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
        cur = cur.Previous;

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

        // Step 5: the two operands pushed before the comparison.
        var rightOperandIns = cur.Previous;
        if (rightOperandIns is null) return false;
        var leftOperandIns = rightOperandIns.Previous;
        if (leftOperandIns is null) return false;

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
            case Code.Ldarg_S when ins.Operand is ParameterDefinition:
                return ((ParameterDefinition)ins.Operand).Name;
            case Code.Ldloc:
            case Code.Ldloc_S:
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
        }
        return null;
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
        return basePart is null ? fieldName : $"{basePart}.{fieldName}";
    }

    // Like OperandName but recognises additional opcodes that produce a "receiver" value:
    // ldfld/ldflda chain, call get_Value/get_<X>, plus delegates back to OperandName for leaf forms.
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
        }
        return OperandName(ins, method);
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
}
