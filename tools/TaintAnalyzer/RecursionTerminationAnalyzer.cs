using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Standalone structural pass for CWE-674 (uncontrolled recursion). Detects a direct
// self-recursive call with no cycle/depth guard. Does not use TaintWalker.
//
// Mirrors LoopTerminationAnalyzer's two-question shape, one level up in the call graph:
//   Q1: is there a self-recursive call edge?      (the structural cycle)
//   Q2: is a termination guard present?           (visited-set or depth cap)
//
// Documented limitation: only direct self-recursion (a method that calls itself) is
// detected. Mutual recursion across a call-graph cycle (A -> B -> A) is not yet covered.
public static class RecursionTerminationAnalyzer
{
    public static IReadOnlyList<RecursionFinding> Analyze(AssemblyContext context, MethodDefinition method)
    {
        var findings = new List<RecursionFinding>();
        var resolution = AsyncStateMachineResolver.Resolve(method);
        var body = resolution.Method.Body;
        if (body is null) return findings;

        var instrs = body.Instructions;

        Instruction? selfCall = null;
        foreach (var ins in instrs)
        {
            if (ins.OpCode.Code is not (Code.Call or Code.Callvirt)) continue;
            if (ins.Operand is not MethodReference mr) continue;
            if (!IsSelfCall(mr, method)) continue;
            selfCall = ins;
            break;
        }
        if (selfCall is null) return findings; // Q1: no self-recursive edge

        if (RecursionShapes.GuardPresent(instrs)) return findings; // Q2: guarded

        var callSp = context.GetSequencePoint(resolution.Method, selfCall);
        findings.Add(new RecursionFinding
        {
            Method = $"{method.DeclaringType.FullName}.{method.Name}",
            ResolvedViaAsync = resolution.RedirectedFromAsync,
            CallFile = callSp is null ? "" : Path.GetFileName(callSp.Document.Url),
            CallLine = callSp?.StartLine ?? 0,
        });
        return findings;
    }

    // Mutual recursion (CWE-674): a call-graph cycle of >= 2 methods (SCC), e.g. A -> B -> A.
    // A cycle is reported when it contains at least one enumeration candidate and no member
    // carries a termination guard. Direct self-recursion (1-node SCC with a self-edge) is left
    // to Analyze() above, so only SCCs of size >= 2 are considered here.
    public static IReadOnlyList<RecursionFinding> AnalyzeCycles(
        AssemblyContext context,
        MethodCallGraph callGraph,
        ISet<MethodDefinition> candidates)
    {
        var findings = new List<RecursionFinding>();

        foreach (var scc in StronglyConnectedComponents.Find(callGraph))
        {
            if (scc.Count < 2) continue;
            if (!scc.Any(candidates.Contains)) continue; // scope to the candidate surface

            var members = new HashSet<MethodDefinition>(scc);
            bool guarded = scc.Any(m =>
            {
                var body = AsyncStateMachineResolver.Resolve(m).Method.Body;
                return body is not null && RecursionShapes.GuardPresent(body.Instructions);
            });
            if (guarded) continue;

            var representative = scc.OrderBy(m => m.FullName, StringComparer.Ordinal).First();
            var resolution = AsyncStateMachineResolver.Resolve(representative);
            var edge = FindCycleEdge(resolution.Method, members);
            var edgeSp = edge is null ? null : context.GetSequencePoint(resolution.Method, edge);

            findings.Add(new RecursionFinding
            {
                Method = $"{representative.DeclaringType.FullName}.{representative.Name}",
                Kind = "mutual",
                ResolvedViaAsync = resolution.RedirectedFromAsync,
                Cycle = scc
                    .Select(m => $"{m.DeclaringType.FullName}.{m.Name}")
                    .OrderBy(s => s, StringComparer.Ordinal)
                    .ToList(),
                CallFile = edgeSp is null ? "" : Path.GetFileName(edgeSp.Document.Url),
                CallLine = edgeSp?.StartLine ?? 0,
            });
        }

        return findings;
    }

    // The first call from `method` whose target resolves to another member of the cycle.
    private static Instruction? FindCycleEdge(MethodDefinition method, ISet<MethodDefinition> members)
    {
        var body = method.Body;
        if (body is null) return null;
        foreach (var ins in body.Instructions)
        {
            if (ins.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj)) continue;
            if (ins.Operand is not MethodReference mr) continue;
            MethodDefinition? d;
            try { d = mr.Resolve(); }
            catch { continue; }
            if (d is not null && members.Contains(d)) return ins;
        }
        return null;
    }

    // A call edge is self-recursive when its target is the method under analysis. For async
    // methods we scan the state machine's MoveNext body, whose self-call still targets the
    // original async method definition — so compare against `method`, not the resolved body.
    private static bool IsSelfCall(MethodReference mr, MethodDefinition method)
    {
        if (mr.FullName == method.FullName) return true;
        MethodDefinition? d;
        try { d = mr.Resolve(); }
        catch { return false; }
        return d is not null && d == method;
    }
}
