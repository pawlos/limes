using Mono.Cecil;
using Shouldly;

namespace TaintAnalyzer.Tests;

public class ThrowShapeCalleeTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string name) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowShapeCalleeFixtures"
                                 && m.Name == name);

    [Fact]
    public void ThrowValidatesParam_TaintedArg_SetsAppliedThrowShapeSanitiser()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "ThrowValidatesParam"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.AppliedThrowShapeSanitiser.ShouldBeTrue();
    }

    [Fact]
    public void ThrowValidatesParam_UntaintedArg_DoesNotSetFlag()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "ThrowValidatesParam"), taintedParamBitmask: 0b0, Array.Empty<string>());

        summary.AppliedThrowShapeSanitiser.ShouldBeFalse();
    }

    [Fact]
    public void ThrowThenAssign_TaintedArg_SetsAppliedThrowShapeSanitiser()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        // ThrowThenAssign is private — use AllMethods() with full name filter
        var m = ctx.AllMethods().First(x => x.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowShapeCalleeFixtures"
                                         && x.Name == "ThrowThenAssign");
        var summary = walker.WalkWithSeed(m, taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.AppliedThrowShapeSanitiser.ShouldBeTrue();
    }

    [Fact]
    public void ReturnEarlyThenAssign_TaintedArg_DoesNotSetFlag()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var m = ctx.AllMethods().First(x => x.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowShapeCalleeFixtures"
                                         && x.Name == "ReturnEarlyThenAssign");
        var summary = walker.WalkWithSeed(m, taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.AppliedThrowShapeSanitiser.ShouldBeFalse();
    }

    [Fact]
    public void AllocViaThrowValidatedOutParam_TaintedInput_SinkDoesNotFire()
    {
        // When the throw-shape callee validates the tainted param, HandleCall suppresses
        // TaintBufferLikeArgsFromCall so the out-param local is clean in the caller.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "AllocViaThrowValidatedOutParam"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.ReachedSink.ShouldBeFalse();
    }

    [Fact]
    public void AllocViaReturnEarlyOutParam_TaintedInput_SinkFires()
    {
        // Return-early callee does NOT set the flag — byref propagation is NOT suppressed,
        // so the out-param is tainted and the allocation sink fires.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "AllocViaReturnEarlyOutParam"), taintedParamBitmask: 0b1, Array.Empty<string>());

        summary.ReachedSink.ShouldBeTrue();
    }
}
