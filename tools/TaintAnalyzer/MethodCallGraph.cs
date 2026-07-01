using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Forward call-graph adjacency over in-assembly edges, used for mutual-recursion (SCC)
// detection. Edge policy mirrors ReverseCallGraph: call/callvirt/newobj, callvirt expanded
// through the virtual-override index, cross-assembly targets dropped, resolution failures
// ignored. Nodes and each node's callee list are ordered by MethodDefinition.FullName so SCC
// discovery is deterministic.
public sealed class MethodCallGraph
{
    public IReadOnlyList<MethodDefinition> Nodes { get; }
    public IReadOnlyDictionary<MethodDefinition, IReadOnlyList<MethodDefinition>> Adjacency { get; }

    public MethodCallGraph(AssemblyDefinition assembly)
    {
        var overrides = new VirtualOverrideIndex(assembly);
        var nodes = AllMethods(assembly)
            .OrderBy(m => m.FullName, StringComparer.Ordinal)
            .ToList();

        var adjacency = new Dictionary<MethodDefinition, IReadOnlyList<MethodDefinition>>();
        foreach (var m in nodes)
        {
            var callees = new HashSet<MethodDefinition>();
            if (m.Body is not null)
            {
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                        continue;
                    if (ins.Operand is not MethodReference mr) continue;

                    if (ins.OpCode == OpCodes.Callvirt)
                    {
                        foreach (var target in overrides.EnumerateOverrides(mr))
                            if (target.Module.Assembly == assembly)
                                callees.Add(target);
                        continue;
                    }

                    MethodDefinition? callee;
                    try { callee = mr.Resolve(); }
                    catch { continue; }
                    if (callee is not null && callee.Module.Assembly == assembly)
                        callees.Add(callee);
                }
            }
            adjacency[m] = callees.OrderBy(c => c.FullName, StringComparer.Ordinal).ToList();
        }

        Nodes = nodes;
        Adjacency = adjacency;
    }

    private static IEnumerable<MethodDefinition> AllMethods(AssemblyDefinition asm)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
        foreach (var m in t.Methods)
            yield return m;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
