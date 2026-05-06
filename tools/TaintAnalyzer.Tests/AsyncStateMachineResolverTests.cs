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

    [Fact]
    public void Resolve_AsyncMethod_RedirectsToMoveNext()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var asyncSimple = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "AsyncSimple");

        var result = AsyncStateMachineResolver.Resolve(asyncSimple);

        result.RedirectedFromAsync.ShouldBeTrue();
        result.Method.Name.ShouldBe("MoveNext");
        result.Method.DeclaringType.Name.ShouldStartWith("<AsyncSimple>d__");
    }

    [Fact]
    public void Resolve_AsyncGenericMethod_RedirectsToMoveNextOnGenericInstance()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var asyncGeneric = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "AsyncGeneric");

        var result = AsyncStateMachineResolver.Resolve(asyncGeneric);

        result.RedirectedFromAsync.ShouldBeTrue();
        result.Method.Name.ShouldBe("MoveNext");
        // The Cecil type-reference resolves to the open-generic state machine.
        result.Method.DeclaringType.Name.ShouldStartWith("<AsyncGeneric>d__");
        result.Method.DeclaringType.HasGenericParameters.ShouldBeTrue();
    }
}
