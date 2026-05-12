using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class VirtualOverrideIndexTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void EnumerateOverrides_NonVirtualTarget_ReturnsSingleStatic()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var target = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.NonVirtualTarget::Compute(System.Int32)")!;

        var result = idx.EnumerateOverrides(target).ToList();

        result.Count.ShouldBe(1);
        result[0].FullName.ShouldBe(target.FullName);
    }

    [Fact]
    public void EnumerateOverrides_DenylistedObjectToString_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        // Locate Object::ToString via a callsite — Cecil resolves the operand to the def.
        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForToString::Stringify(System.Object)")!;
        var callvirt = caller.Body.Instructions
            .First(i => i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt);
        var toStringRef = (MethodReference)callvirt.Operand;

        var result = idx.EnumerateOverrides(toStringRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
        result[0].Name.ShouldBe("ToString");
    }

    [Fact]
    public void EnumerateOverrides_DenylistedEquals_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var equalsRef = ResolveMscorlibObjectMethod(ctx.Assembly, "Equals", paramFullName: "System.Object");

        var result = idx.EnumerateOverrides(equalsRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
    }

    [Fact]
    public void EnumerateOverrides_DenylistedGetHashCode_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var ghcRef = ResolveMscorlibObjectMethod(ctx.Assembly, "GetHashCode", paramFullName: null);

        var result = idx.EnumerateOverrides(ghcRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
    }

    [Fact]
    public void EnumerateOverrides_ImplicitOverride_Found()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var baseFoo = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleBase::Process(System.Byte[])")!;
        var derivedFoo = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleDerived::Process(System.Byte[])")!;

        var result = idx.EnumerateOverrides(baseFoo).Select(m => m.FullName).ToList();

        result.ShouldContain(baseFoo.FullName);
        result.ShouldContain(derivedFoo.FullName);
        result.Count.ShouldBe(2);
    }

    [Fact]
    public void EnumerateOverrides_TransitiveChain_AllAncestorsResolveToConcrete()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var topAbstract = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveA::Foo(System.Int32)")!;
        var midOverride = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveB::Foo(System.Int32)")!;
        var leafOverride = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveC::Foo(System.Int32)")!;

        // callvirt TransitiveA::Foo must enumerate B AND C (flattened chain).
        var fromA = idx.EnumerateOverrides(topAbstract).Select(m => m.FullName).ToHashSet();
        fromA.ShouldContain(topAbstract.FullName);
        fromA.ShouldContain(midOverride.FullName);
        fromA.ShouldContain(leafOverride.FullName);

        // callvirt TransitiveB::Foo must enumerate C.
        var fromB = idx.EnumerateOverrides(midOverride).Select(m => m.FullName).ToHashSet();
        fromB.ShouldContain(midOverride.FullName);
        fromB.ShouldContain(leafOverride.FullName);
    }

    [Fact]
    public void EnumerateOverrides_ExplicitInterfaceImpl_Found()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var ifaceBar = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.IExplicitOperation::Bar()")!;

        var result = idx.EnumerateOverrides(ifaceBar).Select(m => m.FullName).ToList();

        result.ShouldContain(ifaceBar.FullName);
        result.ShouldContain(
            "System.Void TaintAnalyzer.Tests.Fixtures.VirtualDispatch.ExplicitImpl::"
            + "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.IExplicitOperation.Bar()");
    }

    [Fact]
    public void EnumerateOverrides_IDisposableDispose_ImplIncluded()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var disposable = ctx.Assembly.MainModule.ImportReference(typeof(System.IDisposable)).Resolve()!;
        var disposeRef = ctx.Assembly.MainModule.ImportReference(
            disposable.Methods.Single(m => m.Name == "Dispose"));

        var result = idx.EnumerateOverrides(disposeRef).Select(m => m.FullName).ToList();

        result.ShouldContain(s => s.Contains("CustomDisposable::Dispose"));
    }

    [Fact]
    public void EnumerateOverrides_IEnumeratorMoveNext_ImplIncluded()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var enumerator = ctx.Assembly.MainModule.ImportReference(
            typeof(System.Collections.IEnumerator)).Resolve()!;
        var moveNextRef = ctx.Assembly.MainModule.ImportReference(
            enumerator.Methods.Single(m => m.Name == "MoveNext"));

        var result = idx.EnumerateOverrides(moveNextRef).Select(m => m.FullName).ToList();

        result.ShouldContain(s => s.Contains("CustomEnumerator::MoveNext"));
    }

    // Helper: build a MethodReference to a System.Object method via the assembly's
    // module so Resolve() works.
    private static MethodReference ResolveMscorlibObjectMethod(
        AssemblyDefinition asm, string name, string? paramFullName)
    {
        var corlib = asm.MainModule.TypeSystem.Object.Resolve()!;
        var m = corlib.Methods.First(mm =>
            mm.Name == name &&
            (paramFullName is null
                ? mm.Parameters.Count == 0
                : mm.Parameters.Count == 1 && mm.Parameters[0].ParameterType.FullName == paramFullName));
        return asm.MainModule.ImportReference(m);
    }
}
