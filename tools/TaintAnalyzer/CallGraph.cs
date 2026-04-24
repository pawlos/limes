using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public static class CallGraph
{
    public static ResolvedDispatch ResolveCallSite(
        MethodDefinition containingMethod,
        Instruction callInstruction,
        TypeDefinition? receiverStaticType,
        AssemblyContext context)
    {
        var callee = callInstruction.Operand as MethodReference
            ?? throw new ArgumentException("instruction is not a call", nameof(callInstruction));

        // Non-virtual dispatch.
        if (callInstruction.OpCode != OpCodes.Callvirt)
        {
            return new ResolvedDispatch
            {
                Kind = "direct",
                StaticType = callee.DeclaringType.FullName,
                ResolvedTargets = Array.Empty<string>(),
                ClosureBoundary = false,
            };
        }

        // Virtual dispatch. Two-step resolution.
        var staticType = receiverStaticType ?? SafeResolve(callee.DeclaringType);
        if (staticType is null || !IsWithinAnalyzedAssembly(staticType, context))
        {
            // Receiver class is outside the analyzed assembly — we have no reliable subclass closure.
            return new ResolvedDispatch
            {
                Kind = "virtual",
                StaticType = receiverStaticType != null
                    ? receiverStaticType.FullName
                    : callee.DeclaringType.FullName,
                ResolvedTargets = Array.Empty<string>(),
                ClosureBoundary = true,
            };
        }

        // CHA closure: find every override of `callee` on `staticType` or any of its descendants within the analyzed assembly.
        var targets = new List<string>();
        bool closureBoundary = false;

        foreach (var candidate in DescendantsWithin(staticType, context))
        {
            foreach (var m in candidate.Methods)
            {
                if (!m.IsVirtual) continue;
                if (m.Name != callee.Name) continue;
                if (!ParameterShapesMatch(m, callee)) continue;
                targets.Add($"{m.DeclaringType.FullName}::{m.Name}");
            }
        }

        // Include the exact base-class definition if it is itself non-abstract and matches.
        foreach (var m in staticType.Methods)
        {
            if (!m.IsVirtual) continue;
            if (m.IsAbstract) continue;
            if (m.Name != callee.Name) continue;
            if (!ParameterShapesMatch(m, callee)) continue;
            var key = $"{m.DeclaringType.FullName}::{m.Name}";
            if (!targets.Contains(key, StringComparer.Ordinal))
            {
                targets.Add(key);
            }
        }

        // A non-sealed receiver whose subclass set cannot be closed within the analyzed assembly:
        // if the receiver type is not sealed AND not abstract (i.e. instantiable base), flag closure_boundary = true
        // since an external assembly could subclass it. For abstract base with subclasses all sealed in-assembly,
        // closure is complete.
        if (!staticType.IsSealed && !staticType.IsAbstract)
        {
            closureBoundary = true;
        }
        if (staticType.IsAbstract)
        {
            foreach (var d in DescendantsWithin(staticType, context))
            {
                if (!d.IsSealed && !d.IsAbstract) { closureBoundary = true; break; }
            }
        }

        return new ResolvedDispatch
        {
            Kind = "virtual",
            StaticType = staticType.FullName,
            ResolvedTargets = targets,
            ClosureBoundary = closureBoundary,
        };
    }

    public static bool IsWithinAnalyzedAssembly(TypeDefinition type, AssemblyContext ctx)
        => type.Module.Assembly == ctx.Assembly;

    private static IEnumerable<TypeDefinition> DescendantsWithin(TypeDefinition root, AssemblyContext ctx)
    {
        foreach (var t in ctx.Assembly.MainModule.GetTypes())
        {
            if (t == root) continue;
            if (IsDescendantOf(t, root)) yield return t;
        }
    }

    private static bool IsDescendantOf(TypeDefinition candidate, TypeDefinition ancestor)
    {
        var cur = candidate;
        while (cur?.BaseType is { } baseRef)
        {
            var baseDef = SafeResolve(baseRef);
            if (baseDef is null) return false;
            if (baseDef == ancestor) return true;
            cur = baseDef;
        }
        return false;
    }

    private static bool ParameterShapesMatch(MethodDefinition impl, MethodReference callee)
    {
        if (impl.Parameters.Count != callee.Parameters.Count) return false;
        for (int i = 0; i < impl.Parameters.Count; i++)
        {
            if (impl.Parameters[i].ParameterType.FullName != callee.Parameters[i].ParameterType.FullName)
            {
                return false;
            }
        }
        return true;
    }

    private static TypeDefinition? SafeResolve(TypeReference tr)
    {
        try { return tr.Resolve(); }
        catch { return null; }
    }
}
