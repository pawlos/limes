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
