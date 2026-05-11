using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ReverseCallGraphTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Construction_DoesNotThrow()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        graph.ShouldNotBeNull();
    }

    [Fact]
    public void Callers_OfPublicMethod_IncludePublicCaller()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // InternalReachable.Helper is called by PublicEntryPoint.TakesStream.
        var helper = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.InternalReachable", "Helper");
        helper.ShouldNotBeNull();

        graph.IsReachableFromPublic(helper!).ShouldBeTrue();
    }

    [Fact]
    public void OrphanInternal_IsNotReachableFromPublic()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var orphan = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.InternalOrphan", "Orphan");
        orphan.ShouldNotBeNull();

        graph.IsReachableFromPublic(orphan!).ShouldBeFalse();
    }

    [Fact]
    public void PublicMethod_AlwaysReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var pub = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.PublicEntryPoint", "TakesStream");
        pub.ShouldNotBeNull();

        graph.IsReachableFromPublic(pub!).ShouldBeTrue();
    }

    private static MethodDefinition? FindMethod(AssemblyDefinition asm, string typeFullName, string methodName)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
        {
            if (t.FullName != typeFullName) continue;
            return t.Methods.FirstOrDefault(m => m.Name == methodName);
        }
        return null;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
