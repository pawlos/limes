using Mono.Cecil;

namespace TaintAnalyzer;

// Maps each virtual / abstract method in this assembly to the set of in-assembly
// overrides. Built once on first query and cached. Consumers: ReverseCallGraph
// (Callvirt edge expansion) and TaintWalker.HandleCall (interprocedural walk over
// every override).
//
// System.Object's virtuals (ToString / Equals / GetHashCode / Finalize) are
// denylisted: EnumerateOverrides returns only the static target for them, so
// override expansion does not fan out across every type in the assembly.
public sealed class VirtualOverrideIndex
{
    private static readonly HashSet<string> Denylist = new(StringComparer.Ordinal)
    {
        "System.String System.Object::ToString()",
        "System.Boolean System.Object::Equals(System.Object)",
        "System.Int32 System.Object::GetHashCode()",
        "System.Void System.Object::Finalize()",
    };

    private readonly AssemblyDefinition _assembly;
    private Dictionary<MethodDefinition, List<MethodDefinition>>? _index;

    public VirtualOverrideIndex(AssemblyDefinition assembly)
    {
        _assembly = assembly;
    }

    public IReadOnlyList<MethodDefinition> EnumerateOverrides(MethodReference vRef)
    {
        MethodDefinition? resolved;
        try { resolved = vRef.Resolve(); }
        catch { return Array.Empty<MethodDefinition>(); }
        if (resolved is null) return Array.Empty<MethodDefinition>();

        if (Denylist.Contains(resolved.FullName)) return new[] { resolved };
        if (!(resolved.IsVirtual || resolved.IsAbstract)) return new[] { resolved };

        EnsureIndexBuilt();
        if (!_index!.TryGetValue(resolved, out var overrides))
            return new[] { resolved };

        var result = new List<MethodDefinition>(overrides.Count + 1) { resolved };
        result.AddRange(overrides);
        return result;
    }

    private void EnsureIndexBuilt()
    {
        if (_index is not null) return;
        _index = new Dictionary<MethodDefinition, List<MethodDefinition>>();

        foreach (var type in AllTypes(_assembly))
        foreach (var method in type.Methods)
        {
            // Implicit override: walk the base chain and record this method
            // against every ancestor virtual/abstract method with matching
            // name+signature, in-assembly only. Continues past matches so a
            // deep chain (C overrides B overrides A) registers C against both
            // B and A.
            if (method.IsVirtual && method.IsReuseSlot)
                RecordImplicitOverrides(method);
        }
    }

    private void RecordImplicitOverrides(MethodDefinition method)
    {
        var baseType = method.DeclaringType.BaseType;
        var seenTypes = new HashSet<string>(StringComparer.Ordinal);
        while (baseType is not null && seenTypes.Add(baseType.FullName))
        {
            TypeDefinition? def;
            try { def = baseType.Resolve(); }
            catch { def = null; }
            if (def is null) break;
            if (def.Module.Assembly != _assembly) break;

            foreach (var candidate in def.Methods)
            {
                if (!(candidate.IsVirtual || candidate.IsAbstract)) continue;
                if (!SignatureMatches(candidate, method)) continue;
                AppendOverride(candidate, method);
            }

            baseType = def.BaseType;
        }
    }

    private void AppendOverride(MethodDefinition virt, MethodDefinition concrete)
    {
        if (!_index!.TryGetValue(virt, out var list))
        {
            list = new List<MethodDefinition>();
            _index[virt] = list;
        }
        list.Add(concrete);
    }

    // Match by name + parameter FullName list, stripping Cecil's
    // ` modreq(System.Runtime.InteropServices.InAttribute)` suffix that
    // decorates `in T` parameters. Mirrors AssemblyContext.BuildShortSignature
    // for consistency with the milestone-N rule.
    private static bool SignatureMatches(MethodDefinition a, MethodDefinition b)
    {
        if (a.Name != b.Name) return false;
        if (a.Parameters.Count != b.Parameters.Count) return false;
        for (int i = 0; i < a.Parameters.Count; i++)
        {
            var aKey = StripModreq(a.Parameters[i].ParameterType.FullName);
            var bKey = StripModreq(b.Parameters[i].ParameterType.FullName);
            if (aKey != bKey) return false;
        }
        return true;
    }

    private static string StripModreq(string typeName)
    {
        int idx = typeName.IndexOf(" modreq(", StringComparison.Ordinal);
        return idx >= 0 ? typeName[..idx] : typeName;
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
