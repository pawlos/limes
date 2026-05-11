using Mono.Cecil;
using System.Runtime.CompilerServices;

namespace TaintAnalyzer;

public static class EntryPointEnumerator
{
    public static IEnumerable<SourceMethodEntry> Enumerate(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph)
    {
        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;
                // Candidate predicates and visibility filter come in Tasks 8–12.
                // For now: reject everything (skeleton).
            }
        }
        yield break;
    }

    private static bool HardReject(MethodDefinition m)
    {
        // Compiler-generated.
        if (m.HasCustomAttributes && m.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;

        // Special methods: .ctor, .cctor, op_*, property getters/setters, events.
        if (m.IsConstructor) return true;
        if (m.IsSpecialName) return true;        // op_*, property accessors, event add/remove
        if (m.IsGetter || m.IsSetter) return true;
        if (m.IsAddOn || m.IsRemoveOn || m.IsFire || m.IsOther) return true;

        // No body — abstract, P/Invoke, runtime.
        if (m.Body is null) return true;

        return false;
    }

    private static bool IsCompilerGeneratedType(TypeDefinition t)
    {
        if (t.HasCustomAttributes && t.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;
        // <PrivateImplementationDetails>, <>c__DisplayClass*, <X>d__N
        if (t.Name.StartsWith("<", StringComparison.Ordinal)) return true;
        return false;
    }

    private static IEnumerable<TypeDefinition> AllTypes(AssemblyDefinition asm)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
            yield return t;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
