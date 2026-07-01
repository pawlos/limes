using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class MutualRecursionAnalyzerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private const string Ns = "TaintAnalyzer.Tests.Fixtures.Recursion";

    // Run the SCC pass with every method of the named fixture types treated as a candidate.
    private static IReadOnlyList<RecursionFinding> Cycles(params string[] typeNames)
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var candidates = new HashSet<MethodDefinition>();
        foreach (var tn in typeNames)
        {
            var t = ctx.Assembly.MainModule.GetType($"{Ns}.{tn}");
            foreach (var m in t.Methods) candidates.Add(m);
        }
        var graph = new MethodCallGraph(ctx.Assembly);
        return RecursionTerminationAnalyzer.AnalyzeCycles(ctx, graph, candidates);
    }

    [Fact]
    public void FlagsUnguardedMutualCycle()
    {
        var f = Cycles("MutualA", "MutualB");
        f.Count.ShouldBe(1);
        f[0].Kind.ShouldBe("mutual");
        // Representative is the lexicographically smallest member.
        f[0].Method.ShouldEndWith("MutualA.Resolve");
        f[0].Cycle.ShouldNotBeNull();
        f[0].Cycle!.Count.ShouldBe(2);
        f[0].Cycle!.ShouldContain($"{Ns}.MutualA.Resolve");
        f[0].Cycle!.ShouldContain($"{Ns}.MutualB.Resolve");
    }

    [Fact]
    public void ClearsGuardedMutualCycle()
        => Cycles("GuardedMutualA", "GuardedMutualB").ShouldBeEmpty();

    [Fact]
    public void DirectSelfRecursionIsNotReportedAsCycle()
        => Cycles("ReferenceHolder").ShouldBeEmpty(); // 1-node SCC, left to Analyze()
}
