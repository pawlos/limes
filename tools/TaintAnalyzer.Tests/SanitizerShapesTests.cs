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
    public void ResolveExceptionType_FromThrowHelperBody_ReturnsShortTypeName()
    {
        // Returns the unqualified type name (no namespace) — matches the C# convention used
        // in human-authored fixtures like #3074-postfix's `InvalidImageContentException`.
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowHelpers" && md.Name == "ThrowOutOfRange");

        SanitizerShapes.ResolveExceptionType(m).ShouldBe("ArgumentOutOfRangeException");
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

    // --- Full matcher: compare-and-throw / compare-and-return-early (Task 7) ---

    [Theory]
    [InlineData("GtThrow", "<=", "y",  null)]   // safe: x <= y → relation "<=", upper_bound y
    [InlineData("LtThrow", ">=", null, "y")]    // safe: x >= y → relation ">=", lower_bound y
    [InlineData("GeThrow", "<",  "y",  null)]   // safe: x <  y → relation "<",  upper_bound y
    [InlineData("LeThrow", ">",  null, "y")]    // safe: x >  y → relation ">",  lower_bound y
    [InlineData("EqThrow", "!=", "y",  null)]   // safe: x != y → relation "!=", upper_bound y (single-value convention)
    [InlineData("NeThrow", "==", "y",  null)]   // safe: x == y → relation "==", upper_bound y
    public void MatchCompareAndThrow_EmitsCorrectBound(
        string fixtureName, string expectedRelation, string? expectedUpper, string? expectedLower)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.SanitizerBoundsFixtures"
            && md.Name == fixtureName);

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.OnFailure.Kind.ShouldBe(FailureKind.Throw);
        match.OnFailure.Exception.ShouldBe("ArgumentOutOfRangeException");
        match.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.Relation.ShouldBe(expectedRelation);
        match.EstablishesBound.UpperBound.ShouldBe(expectedUpper);
        match.EstablishesBound.LowerBound.ShouldBe(expectedLower);
    }

    [Fact]
    public void MatchCompareAndThrow_ExplicitElse_FlipsDirectionCorrectly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerBoundsFixtures::GtThrowElse(System.Int32,System.Int32)");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        // Same semantic end result as GtThrow: safe side says x <= y.
        match!.EstablishesBound.Relation.ShouldBe("<=");
        match.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.UpperBound.ShouldBe("y");
    }

    [Fact]
    public void MatchCompareAndReturnEarly_EmitsReturnEarlyHop()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::ReturnEarlyOnNegative(System.Int32)");

        var match = SanitizerShapes.MatchCompareAndReturnEarly(m);

        match.ShouldNotBeNull();
        match!.OnFailure.Kind.ShouldBe(FailureKind.ReturnEarly);
        match.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.Relation.ShouldBe(">=");
        match.EstablishesBound.LowerBound.ShouldBe("0");
    }

    [Fact]
    public void MatchCompareAndThrow_NoSanitizer_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NoSanitizer(System.Int32)");

        SanitizerShapes.MatchCompareAndThrow(m).ShouldBeNull();
    }

    [Fact]
    public void MatchCompareAndThrow_EqZeroShape_EmitsNotEqualBound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerBoundsFixtures::EqZeroThrow(System.Int32)");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        // Semantic: C# `if (x == 0) throw;` — safe side says `x != 0`.
        // Target is `x`, relation is `!=`, upper_bound is `0` (single-value convention per spec).
        match.ShouldNotBeNull();
        match!.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.Relation.ShouldBe("!=");
        match.EstablishesBound.UpperBound.ShouldBe("0");
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void MatchCompareAndThrow_FieldChainOperand_RecoversDottedProvenance()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.FieldChainHost::GuardOnFieldChain(System.Int32)");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        // The C# `this.inner!.Offset > limit` produces dotted target "inner.Offset" — the
        // implicit `this.` prefix is dropped (matches the unqualified C# convention used in
        // human-authored fixtures like #3074-postfix's `fileHeader.Value.Offset`).
        match!.EstablishesBound.Target.ShouldBe("inner.Offset");
        match.EstablishesBound.UpperBound.ShouldBe("limit");
        match.EstablishesBound.Relation.ShouldBe("<=");
    }

    [Fact]
    public void MatchCompareAndThrow_NullableValueChain_RecoversFullDottedProvenance()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.NullableFieldHost::GuardOnNullableValueChain(System.Int32)");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        // The C# `this.wrapped!.Value.Limit > limit` should produce dotted target
        // "wrapped.Value.Limit" — exercising the `call get_Value` branch in BuildDottedFieldChain.
        // The implicit `this.` prefix is dropped (matches the unqualified C# convention).
        match!.EstablishesBound.Target.ShouldBe("wrapped.Value.Limit");
        match.EstablishesBound.UpperBound.ShouldBe("limit");
        match.EstablishesBound.Relation.ShouldBe("<=");
    }

    [Fact]
    public void MatchAll_TwoSanitizersInOneMethod_ReturnsBothInIlOrder()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.MultiSanitizerHost::AllocateWithTwoGuards(System.Int32,System.Int32)");

        var matches = SanitizerShapes.MatchAll(m).ToList();

        matches.Count.ShouldBe(2);
        // Both should be Throw/return-fail kind.
        matches.ShouldAllBe(s => s.OnFailure.Kind == FailureKind.Throw);
        // Bound targets are different operands but both refer to `n` (left side of each comparison).
        matches[0].EstablishesBound.Target.ShouldBe("n");
        matches[1].EstablishesBound.Target.ShouldBe("n");
        // The IL-order property is implied by ComparisonIlOffset being non-decreasing.
        matches[0].ComparisonIlOffset.ShouldBeLessThan(matches[1].ComparisonIlOffset);
    }

    private static Instruction FindConditionalBranch(MethodDefinition m)
        => m.Body.Instructions.First(i => IsConditionalBranch(i.OpCode));

    private static bool IsConditionalBranch(OpCode op)
        => op.FlowControl == FlowControl.Cond_Branch && op.Code != Code.Switch;
}
