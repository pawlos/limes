using Mono.Cecil;
using Shouldly;

namespace TaintAnalyzer.Tests;

public class AsyncStateMachineResolverTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition FindMethod(AssemblyContext ctx, string typeFullName, string name) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == typeFullName && m.Name == name);

    [Fact]
    public void Resolve_NonAsync_ReturnsSameMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var sync = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "Sync");

        var result = AsyncStateMachineResolver.Resolve(sync);

        result.Method.ShouldBeSameAs(sync);
        result.RedirectedFromAsync.ShouldBeFalse();
    }
}
