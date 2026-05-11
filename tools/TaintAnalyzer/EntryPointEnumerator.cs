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
        var byteSourceSet = new HashSet<string>(config.ByteSourceTypes, StringComparer.Ordinal);

        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;

                if (MatchesParameterShape(method, byteSourceSet))
                {
                    yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                }
            }
        }
    }

    private static bool MatchesParameterShape(MethodDefinition m, HashSet<string> byteSourceTypes)
    {
        foreach (var p in m.Parameters)
        {
            var typeFullName = StripModifiers(p.ParameterType.FullName);
            if (byteSourceTypes.Contains(typeFullName)) return true;
        }
        return false;
    }

    // Strip `&` (byref) and `modreq(...)` decoration that Cecil adds for ref/in/out params.
    private static string StripModifiers(string fullName)
    {
        var idx = fullName.IndexOf(" modreq", StringComparison.Ordinal);
        if (idx >= 0) fullName = fullName.Substring(0, idx);
        if (fullName.EndsWith("&", StringComparison.Ordinal))
            fullName = fullName.Substring(0, fullName.Length - 1);
        return fullName;
    }

    // Reuse the canonical signature builder from AssemblyContext (made internal in T7)
    // so emitted signatures round-trip through FindMethod exactly.
    private static string BuildShortSignature(MethodDefinition m)
        => AssemblyContext.BuildShortSignature(m);

    private static bool HardReject(MethodDefinition m)
    {
        if (m.HasCustomAttributes && m.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;
        if (m.IsConstructor) return true;
        if (m.IsSpecialName) return true;
        if (m.IsGetter || m.IsSetter) return true;
        if (m.IsAddOn || m.IsRemoveOn || m.IsFire || m.IsOther) return true;
        if (m.Body is null) return true;
        return false;
    }

    private static bool IsCompilerGeneratedType(TypeDefinition t)
    {
        if (t.HasCustomAttributes && t.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;
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
