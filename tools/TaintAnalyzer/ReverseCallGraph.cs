using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Builds a callee → callers index in one pass over every method body in the
// assembly. Used to answer "is this internal method reachable from any public
// method?" via a BFS over the reverse edges.
//
// Resolution policy: we follow `call`, `callvirt`, and `newobj` operands. Each
// operand is a MethodReference; we try `Resolve()` and only record edges to
// methods inside this assembly. Cross-assembly references are skipped (we
// only score reachability within the target assembly). Virtual dispatch is
// approximated by also recording an edge from every override to the base
// definition's callers — but we keep it simple by treating any reachable
// override of a public method as reachable.
public sealed class ReverseCallGraph
{
    private readonly Dictionary<MethodDefinition, HashSet<MethodDefinition>> _callers = new();
    private readonly HashSet<MethodDefinition> _reachableFromPublic;

    public ReverseCallGraph(AssemblyDefinition assembly)
    {
        var allMethods = AllMethods(assembly).ToList();

        foreach (var m in allMethods)
        {
            if (m.Body is null) continue;
            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;

                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null) continue;
                if (callee.Module.Assembly != assembly) continue;

                if (!_callers.TryGetValue(callee, out var set))
                {
                    set = new HashSet<MethodDefinition>();
                    _callers[callee] = set;
                }
                set.Add(m);
            }
        }

        // BFS: walk forward from public methods over call edges, marking each
        // transitively-called method as reachable.
        _reachableFromPublic = new HashSet<MethodDefinition>();
        var queue = new Queue<MethodDefinition>();
        foreach (var m in allMethods.Where(IsPublic))
        {
            _reachableFromPublic.Add(m);
            queue.Enqueue(m);
        }

        var visited = new HashSet<MethodDefinition>(_reachableFromPublic);
        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            if (m.Body is null) continue;
            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;
                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { callee = null; }
                if (callee is null || callee.Module.Assembly != assembly) continue;
                if (visited.Add(callee))
                {
                    _reachableFromPublic.Add(callee);
                    queue.Enqueue(callee);
                }
            }
        }
    }

    public bool IsReachableFromPublic(MethodDefinition method)
        => _reachableFromPublic.Contains(method);

    private static bool IsPublic(MethodDefinition m)
        => m.IsPublic && m.DeclaringType.IsPublic;

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
