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
        // Cache type-name match per declaring type (computed once per type, queried per method).
        var thisFieldCache = new Dictionary<TypeDefinition, IReadOnlyList<string>?>();

        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;
                if (VisibilityReject(method, callGraph)) continue;
                if (ExclusionReject(method, config)) continue;

                if (MatchesParameterShape(method, byteSourceSet))
                {
                    yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                    continue;
                }

                if (config.IncludeThisField && !method.IsStatic)
                {
                    if (!thisFieldCache.TryGetValue(type, out var seedFields))
                    {
                        seedFields = MatchThisFieldShape(type, config, byteSourceSet);
                        thisFieldCache[type] = seedFields;
                    }
                    if (seedFields is not null)
                    {
                        yield return new SourceMethodEntry
                        {
                            Signature = BuildShortSignature(method),
                            SeedThisFields = seedFields.ToList(),
                        };
                        continue;
                    }
                }

                if (config.IncludeVirtualOverrides &&
                    IsOverrideOfReachableAbstract(method, context.VirtualOverrides, callGraph))
                {
                    yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                    continue;
                }
            }
        }
    }

    private static bool IsOverrideOfReachableAbstract(
        MethodDefinition m, VirtualOverrideIndex overrides, ReverseCallGraph callGraph)
    {
        foreach (var root in overrides.EnumerateAbstractRoots(m))
        {
            if (callGraph.IsReachableFromPublic(root)) return true;
        }
        return false;
    }

    // Returns the list of field names matching ByteSourceTypes if the type's name
    // matches a DecoderTypeNamePattern. Returns null when this-field-shape doesn't
    // apply to this type.
    private static IReadOnlyList<string>? MatchThisFieldShape(
        TypeDefinition type, EnumeratorConfig config, HashSet<string> byteSourceTypes)
    {
        bool nameMatches = config.DecoderTypeNamePatterns.Any(p => GlobMatcher.Matches(p, type.Name));
        if (!nameMatches) return null;

        var matchingFields = type.Fields
            .Where(f => FieldTypeMatchesByteSource(f, byteSourceTypes))
            .Select(f => f.Name)
            .ToList();

        return matchingFields.Count > 0 ? matchingFields : null;
    }

    private static bool FieldTypeMatchesByteSource(FieldDefinition f, HashSet<string> byteSourceTypes)
    {
        if (byteSourceTypes.Contains(f.FieldType.FullName)) return true;
        // Base-type walk for Stream subclass fields too.
        TypeDefinition? def;
        try { def = f.FieldType.Resolve(); }
        catch { def = null; }
        var current = def?.BaseType;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (current is not null && seen.Add(current.FullName))
        {
            if (byteSourceTypes.Contains(current.FullName)) return true;
            TypeDefinition? baseDef;
            try { baseDef = current.Resolve(); }
            catch { baseDef = null; }
            current = baseDef?.BaseType;
        }
        return false;
    }

    private static bool MatchesParameterShape(MethodDefinition m, HashSet<string> byteSourceTypes)
    {
        foreach (var p in m.Parameters)
        {
            var typeRef = p.ParameterType;

            // Strip byref/in/out decoration for matching.
            if (typeRef is ByReferenceType byref) typeRef = byref.ElementType;

            if (byteSourceTypes.Contains(typeRef.FullName)) return true;

            // Walk the base chain. Cecil's Resolve can fail for cross-assembly refs;
            // we treat resolution failure as a match miss and stop walking.
            TypeDefinition? def;
            try { def = typeRef.Resolve(); }
            catch { def = null; }

            var current = def?.BaseType;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (current is not null && seen.Add(current.FullName))
            {
                if (byteSourceTypes.Contains(current.FullName)) return true;
                TypeDefinition? baseDef;
                try { baseDef = current.Resolve(); }
                catch { baseDef = null; }
                current = baseDef?.BaseType;
            }
        }
        return false;
    }

    // Reuse the canonical signature builder from AssemblyContext (made internal in T7)
    // so emitted signatures round-trip through FindMethod exactly.
    private static string BuildShortSignature(MethodDefinition m)
        => AssemblyContext.BuildShortSignature(m);

    private static bool VisibilityReject(MethodDefinition m, ReverseCallGraph callGraph)
    {
        // Public method on a public type → always accept.
        if (m.IsPublic && m.DeclaringType.IsPublic) return false;

        // Private: only callable from inside its declaring type, which has its own
        // public entry points. Reject without consulting the graph.
        if (m.IsPrivate) return true;

        // Internal, public-on-internal-type, protected (family), private-protected
        // (family-and-assembly), protected-internal (family-or-assembly):
        // accept iff some public method reaches them.
        return !callGraph.IsReachableFromPublic(m);
    }

    private static bool ExclusionReject(MethodDefinition m, EnumeratorConfig config)
    {
        var declaringNs = m.DeclaringType.Namespace ?? "";
        foreach (var p in config.ExcludeNamespaces)
        {
            if (GlobMatcher.Matches(p, declaringNs)) return true;
        }

        var declaringName = m.DeclaringType.Name;
        foreach (var p in config.ExcludeTypePatterns)
        {
            if (GlobMatcher.Matches(p, declaringName)) return true;
        }

        foreach (var p in config.ExcludeMethodPatterns)
        {
            if (GlobMatcher.Matches(p, m.Name)) return true;
        }

        return false;
    }

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
