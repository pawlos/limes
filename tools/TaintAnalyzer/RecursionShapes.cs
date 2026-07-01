using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Recognizer table for uncontrolled-recursion detection (CWE-674), mirroring ReadLoopShapes.
// Two questions: is a call a self-recursive edge, and does the body carry a termination guard
// (a visited-set / cycle tracker, or a recursion depth cap)?
public static class RecursionShapes
{
    // Set/dictionary types whose membership operations serve as a cycle-tracking guard —
    // the shape the Microsoft.OpenApi 2.7.5 fix uses (`if (!visited.Add(this)) throw`).
    private static readonly string[] VisitedTypePrefixes =
    {
        "System.Collections.Generic.HashSet",
        "System.Collections.Generic.SortedSet",
        "System.Collections.Generic.ISet",
        "System.Collections.Generic.Dictionary",
        "System.Collections.Generic.SortedDictionary",
        "System.Collections.Generic.IDictionary",
    };

    // A membership operation on a set/dictionary: adding-if-absent or a contains check.
    public static bool IsVisitedSetGuard(MethodReference mr)
    {
        if (mr.Name is not ("Add" or "Contains" or "ContainsKey" or "TryAdd" or "TryGetValue"))
            return false;
        var t = mr.DeclaringType.FullName;
        foreach (var prefix in VisitedTypePrefixes)
            if (t.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        return false;
    }

    // A body carries a termination guard if it tracks visited nodes OR caps recursion depth.
    public static bool GuardPresent(IEnumerable<Instruction> instrs)
    {
        bool hasVisitedGuard = false;
        bool hasAddOrSub = false;      // a depth counter being incremented / decremented
        bool hasThreshold = false;     // a comparison against a non-trivial constant
        bool hasCondBranch = false;

        foreach (var ins in instrs)
        {
            if (ins.OpCode.Code is (Code.Call or Code.Callvirt)
                && ins.Operand is MethodReference mr
                && IsVisitedSetGuard(mr))
                hasVisitedGuard = true;

            if (ins.OpCode.Code is Code.Add or Code.Sub) hasAddOrSub = true;

            if (TryGetI4(ins, out int v) && v >= 2) hasThreshold = true;

            if (ins.OpCode.FlowControl == FlowControl.Cond_Branch
                || ins.OpCode.Code is Code.Clt or Code.Clt_Un or Code.Cgt or Code.Cgt_Un or Code.Ceq)
                hasCondBranch = true;
        }

        // Depth-limit guard: a counter change AND a threshold comparison. Coarse but
        // deterministic; documented limitation — a depth cap without an explicit constant
        // threshold (e.g. compared against a field) is not recognized.
        bool hasDepthGuard = hasAddOrSub && hasThreshold && hasCondBranch;
        return hasVisitedGuard || hasDepthGuard;
    }

    private static bool TryGetI4(Instruction i, out int value)
    {
        value = 0;
        switch (i.OpCode.Code)
        {
            case Code.Ldc_I4_2: value = 2; return true;
            case Code.Ldc_I4_3: value = 3; return true;
            case Code.Ldc_I4_4: value = 4; return true;
            case Code.Ldc_I4_5: value = 5; return true;
            case Code.Ldc_I4_6: value = 6; return true;
            case Code.Ldc_I4_7: value = 7; return true;
            case Code.Ldc_I4_8: value = 8; return true;
            case Code.Ldc_I4_S: if (i.Operand is sbyte sb) { value = sb; return true; } return false;
            case Code.Ldc_I4: if (i.Operand is int iv) { value = iv; return true; } return false;
            default: return false;
        }
    }
}
