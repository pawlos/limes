using Mono.Cecil;
using Shouldly;

namespace TaintAnalyzer.Tests;

public class MathClampTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string name) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                                 && m.Name == name);

    [Fact]
    public void MathMin_TaintedAndConstant_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMin_TaintedAndConstant"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void MathMin_TwoTainted_ReturnsTainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMin_TwoTainted"), taintedParamBitmask: 0b11, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeTrue();
    }

    [Fact]
    public void MathMax_TaintedAndConstant_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMax_TaintedAndConstant"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void MathClamp_TaintedWithConstantBounds_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathClamp_TaintedWithConstantBounds"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void StreamLengthVsLimit_TaintedStreamLength_SetsAppliedValueClamp()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        // Seed only `streamLength` (bit 0) tainted; the ternary clamp must fire on the
        // joined value and untaint it. AppliedValueClamp must reflect that.
        var summary = walker.WalkWithSeed(Find(ctx, "StreamLengthVsLimit"), taintedParamBitmask: 0b01, Array.Empty<string>());

        summary.AppliedValueClamp.ShouldBeTrue();
    }

    [Fact]
    public void MathMin_TaintedAndConstant_DoesNotSetAppliedValueClamp()
    {
        // Math.Min recognizer in HandleCall is NOT a value-clamp shape — only the
        // ternary diamond detected by SanitizerShapes.MatchValueClamps sets the flag.
        // This control case confirms the flag stays false when no diamond exists.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMin_TaintedAndConstant"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.AppliedValueClamp.ShouldBeFalse();
    }
}
