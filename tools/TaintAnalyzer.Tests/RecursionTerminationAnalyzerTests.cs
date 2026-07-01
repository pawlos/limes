using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RecursionTerminationAnalyzerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static IReadOnlyList<RecursionFinding> Analyze(string typeName, string methodName)
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var t = ctx.Assembly.MainModule.GetType($"TaintAnalyzer.Tests.Fixtures.Recursion.{typeName}");
        var m = t.Methods.First(x => x.Name == methodName);
        return RecursionTerminationAnalyzer.Analyze(ctx, m);
    }

    [Fact]
    public void FlagsSelfRecursionWithoutGuard()
    {
        var f = Analyze("ReferenceHolder", "ResolveTarget");
        f.Count.ShouldBe(1);
        f[0].Method.ShouldEndWith("ReferenceHolder.ResolveTarget");
        f[0].CallLine.ShouldBeGreaterThan(0);
    }

    [Fact]
    public void ClearsRecursionWithVisitedSetGuard()
        => Analyze("GuardedReferenceHolder", "ResolveTarget").ShouldBeEmpty();

    [Fact]
    public void ClearsRecursionWithDepthLimit()
        => Analyze("DepthLimitedHolder", "ResolveTarget").ShouldBeEmpty();

    [Fact]
    public void FlagsRecursiveGetter()
    {
        var f = Analyze("OpenApiReferenceHolder", "get_RecursiveTarget");
        f.Count.ShouldBe(1);
        f[0].Method.ShouldEndWith("OpenApiReferenceHolder.get_RecursiveTarget");
    }

    [Fact]
    public void ClearsNonRecursiveMethod()
        => Analyze("PlainResolver", "Resolve").ShouldBeEmpty();
}
