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
        // BuildIndex body added in Task 3 + Task 4.
    }
}
