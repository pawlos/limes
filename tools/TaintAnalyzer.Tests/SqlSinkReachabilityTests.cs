using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqlSinkReachabilityTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName)
        => ctx.Assembly.MainModule.GetTypes()
            .First(t => t.Name == typeName)
            .Methods.First(m => m.Name == methodName);

    [Fact]
    public void DirectCaller_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "DirectSink", "Emit")).ShouldBeTrue();
    }

    [Fact]
    public void TransitiveCaller_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "TransitiveSink", "Run")).ShouldBeTrue();
    }

    [Fact]
    public void NonReachingMethod_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "NoSink", "Compute")).ShouldBeFalse();
    }
}
