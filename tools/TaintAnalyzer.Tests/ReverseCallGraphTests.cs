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

    [Fact]
    public void PrivateMethod_NotReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var priv = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.Enumerator.HasPrivateAndProtected",
            "PrivateMethod");
        priv.ShouldNotBeNull();

        graph.IsReachableFromPublic(priv!).ShouldBeFalse();
    }

    [Fact]
    public void ProtectedMethod_NotReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var prot = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.Enumerator.HasPrivateAndProtected",
            "ProtectedMethod");
        prot.ShouldNotBeNull();

        graph.IsReachableFromPublic(prot!).ShouldBeFalse();
    }

    [Fact]
    public void Callvirt_Override_ReachableFromPublicCaller()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var derivedOverride = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleDerived", "Process");

        derivedOverride.ShouldNotBeNull();
        graph.IsReachableFromPublic(derivedOverride!).ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_OverrideOfDenylistedObjectToString_NotEnqueued()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var customToString = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.CustomToString", "ToString");

        customToString.ShouldNotBeNull();
        graph.IsReachableFromPublic(customToString!).ShouldBeFalse();
    }

    [Fact]
    public void Callvirt_ExplicitInterfaceImpl_Reachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var customDispose = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.CustomDisposable", "Dispose");

        customDispose.ShouldNotBeNull();
        graph.IsReachableFromPublic(customDispose!).ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_TransitiveChain_AllOverridesReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var bFoo = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveB", "Foo");
        var cFoo = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveC", "Foo");

        bFoo.ShouldNotBeNull();
        cFoo.ShouldNotBeNull();
        graph.IsReachableFromPublic(bFoo!).ShouldBeTrue();
        graph.IsReachableFromPublic(cFoo!).ShouldBeTrue();
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
