using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Computes the set of methods in this assembly that are transitively reachable
// from any public method on a public type, by forward-BFS over `call`/`callvirt`/
// `newobj` edges. Used by EntryPointEnumerator's visibility filter to accept
// internal methods that are reachable from the public surface and reject orphans.
//
// Resolution policy: each call-site operand is a MethodReference; we Resolve()
// to a MethodDefinition and only follow edges to methods inside this assembly.
// Cross-assembly references are skipped. Resolution failures are silently
// ignored (cross-assembly refs or malformed metadata).
public sealed class ReverseCallGraph
{
    private readonly HashSet<MethodDefinition> _reachableFromPublic;

    public ReverseCallGraph(AssemblyDefinition assembly)
    {
        _reachableFromPublic = new HashSet<MethodDefinition>();
        var queue = new Queue<MethodDefinition>();

        foreach (var m in AllMethods(assembly).Where(IsPublic))
        {
            if (_reachableFromPublic.Add(m))
            {
                queue.Enqueue(m);
            }
        }

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
                catch { continue; }
                if (callee is null || callee.Module.Assembly != assembly) continue;

                if (_reachableFromPublic.Add(callee))
                {
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
