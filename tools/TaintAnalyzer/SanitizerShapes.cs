using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class BranchSides
{
    public required bool FailureSideIsBranchTarget { get; init; }
    public required FailureKind FailureKind { get; init; }
    public required MethodReference? ThrowHelper { get; init; }   // null when FailureKind == ReturnEarly
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
        // Arithmetic / logic — signals the arm is doing real computation (normal body, not a guard).
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
                 or Code.Conv_U4 or Code.Conv_U8 or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un)
        {
            sawArithmetic = true;
        }
    }

    private static MethodDefinition? SafeResolve(MethodReference mr)
    {
        try { return mr.Resolve(); }
        catch { return null; }
    }
}
