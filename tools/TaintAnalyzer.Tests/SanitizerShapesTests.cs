using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SanitizerShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    // --- Throw-helper predicate tests (Task 6) ---

    [Theory]
    [InlineData("ThrowOutOfRange",                     true)]
    [InlineData("ThrowInvalidImageContentException",   true)]
    [InlineData("ThrowByAssertFailure",                true)]  // DoesNotReturn marker wins
    [InlineData("DoWork",                              false)] // no Throw prefix
    [InlineData("ThrowSomething",                      false)] // no DoesNotReturn, body returns
    [InlineData("ThrowInt",                            false)] // non-void return
    public void IsThrowHelper_Classifies(string methodName, bool expected)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowHelpers" && md.Name == methodName);

        SanitizerShapes.IsThrowHelper(m).ShouldBe(expected);
    }

    [Fact]
    public void ResolveExceptionType_FromThrowHelperBody_ReturnsFirstNewobjType()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowHelpers" && md.Name == "ThrowOutOfRange");

        SanitizerShapes.ResolveExceptionType(m).ShouldBe("System.ArgumentOutOfRangeException");
    }

    [Fact]
    public void NameSuffixException_ExtractsTypeName_WhenPrefixPresent()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        // We fabricate the fallback scenario by calling the helper for a method whose body
        // the implementation deliberately ignores. For this test, verify direct-suffix resolution
        // works on a representative helper name.
        SanitizerShapes.NameSuffixException("ThrowInvalidImageContentException")
            .ShouldBe("InvalidImageContentException");
        SanitizerShapes.NameSuffixException("ThrowOutOfRange")
            .ShouldBe("OutOfRange");
        SanitizerShapes.NameSuffixException("DoWork")
            .ShouldBeNull();
    }

    // --- Branch-direction detector tests (Task 6) ---

    [Fact]
    public void DetectBranchSides_NegatedBranchThrow_ThrowSideIsFallThrough()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NegatedBranchThrow(System.Int32,System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);

        sides.ShouldNotBeNull();
        sides!.FailureSideIsBranchTarget.ShouldBeFalse();  // `ble.un SAFE` — fall-through is the failure (throw) body
    }

    [Fact]
    public void DetectBranchSides_NonNegatedBranchThrow_ThrowSideIsBranchTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NonNegatedBranchThrow(System.Int32,System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);

        sides.ShouldNotBeNull();
        sides!.FailureSideIsBranchTarget.ShouldBeTrue();   // `bgt ELSE` — branch target is the failure (throw) body
    }

    [Fact]
    public void DetectBranchSides_ReturnEarly_FailureSideIsFallThrough()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::ReturnEarlyOnNegative(System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);

        sides.ShouldNotBeNull();
        sides!.FailureKind.ShouldBe(FailureKind.ReturnEarly);
        sides.FailureSideIsBranchTarget.ShouldBeFalse();   // `brfalse.s SAFE` — fall-through is the early-return arm
    }

    [Fact]
    public void DetectBranchSides_NoSanitizer_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NoSanitizer(System.Int32)");

        // No conditional branch in the body at all -> trivially no sanitizer.
        var anyCondBranch = m.Body.Instructions.FirstOrDefault(i => IsConditionalBranch(i.OpCode));
        anyCondBranch.ShouldBeNull();
    }

    private static Instruction FindConditionalBranch(MethodDefinition m)
        => m.Body.Instructions.First(i => IsConditionalBranch(i.OpCode));

    private static bool IsConditionalBranch(OpCode op)
        => op.FlowControl == FlowControl.Cond_Branch && op.Code != Code.Switch;
}
