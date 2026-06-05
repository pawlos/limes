using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Computes the set of methods in this assembly that can transitively reach a SQL sink —
// a call site recognized by SinkShapes.IsSqlSinkCall. The SQLi scan profile gates string
// source candidates on membership: only methods that can actually reach a SQL sink are
// worth emitting. Edge policy mirrors ReverseCallGraph (call/callvirt/newobj, in-assembly
// only, callvirt expanded via VirtualOverrideIndex).
public sealed class SqlSinkReachability
{
    private readonly HashSet<MethodDefinition> _reachesSink = new();

    public SqlSinkReachability(AssemblyDefinition assembly)
    {
        var overrides = new VirtualOverrideIndex(assembly);
        var callees = new Dictionary<MethodDefinition, List<MethodDefinition>>();
        var directCallers = new List<MethodDefinition>();

        foreach (var m in AllMethods(assembly))
        {
            if (m.Body is null) continue;
            var outgoing = new List<MethodDefinition>();
            bool isDirect = false;

            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;

                if (SinkShapes.IsSqlSinkCall(mr)) isDirect = true;

                if (ins.OpCode == OpCodes.Callvirt)
                {
                    foreach (var target in overrides.EnumerateOverrides(mr))
                    {
                        if (target.Module.Assembly != assembly) continue;
                        outgoing.Add(target);
                    }
                    continue;
                }

                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null || callee.Module.Assembly != assembly) continue;
                outgoing.Add(callee);
            }

            if (outgoing.Count > 0) callees[m] = outgoing;
            if (isDirect) directCallers.Add(m);
        }

        // Invert caller->callee edges into callee->callers for reverse BFS.
        var callers = new Dictionary<MethodDefinition, List<MethodDefinition>>();
        foreach (var (caller, outs) in callees)
            foreach (var callee in outs)
            {
                if (!callers.TryGetValue(callee, out var list)) { list = new(); callers[callee] = list; }
                list.Add(caller);
            }

        var queue = new Queue<MethodDefinition>();
        foreach (var d in directCallers)
            if (_reachesSink.Add(d)) queue.Enqueue(d);

        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            if (!callers.TryGetValue(m, out var preds)) continue;
            foreach (var p in preds)
                if (_reachesSink.Add(p)) queue.Enqueue(p);
        }
    }

    public bool ReachesSqlSink(MethodDefinition method) => _reachesSink.Contains(method);

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
