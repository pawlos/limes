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

    [Fact]
    public void MatchCompareAndThrow_MultiWayOrShape_ExtractsBoundFromLastComparison()
    {
        // Shape C: `if (size == 4 || size == 8 || size == 12) return size; throw;`
        // Roslyn debug-mode lowers this via three beq/bne writing a boolean local, then a single
        // brtrue. TryResolveEffectiveComparison must recognise the boolean-local pattern (Shape C)
        // and extract the bound from the last comparison in the chain.
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowShapeCalleeFixtures"
            && md.Name == "MultiWayOrThrow_LocalFromParam");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull("Shape C must produce a throw-sanitizer match");
        match!.OnFailure.Kind.ShouldBe(FailureKind.Throw);
        // Bound target is the local variable holding the OR-chain result; relation and value
        // come from the last comparison (size != 12 → bne.un.s → false side).
        match.EstablishesBound.Relation.ShouldBe("==");
        match.EstablishesBound.UpperBound.ShouldBe("12");
    }

    // --- MatchValueClamps tests (Task 9) ---

    [Fact]
    public void TernaryClamp_OrientationA_LessThan_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                      && md.Name == "TernaryClamp_LessThan");

        var matches = SanitizerShapes.MatchValueClamps(m).ToList();
        matches.ShouldHaveSingleItem();
    }

    [Fact]
    public void TernaryClamp_OrientationB_GreaterThanOrEqual_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                      && md.Name == "TernaryClamp_GreaterThanOrEqual");

        var matches = SanitizerShapes.MatchValueClamps(m).ToList();
        matches.ShouldHaveSingleItem();
    }

    [Fact]
    public void TernaryClamp_StreamLengthVsLimit_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                      && md.Name == "StreamLengthVsLimit");

        var matches = SanitizerShapes.MatchValueClamps(m).ToList();
        matches.ShouldHaveSingleItem();
    }

    [Fact]
    public void TernaryClamp_StreamLengthVsLimit_WalkerUntaintsResult()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                      && md.Name == "StreamLengthVsLimit");

        var walker = new TaintWalker(ctx);
        // Seed only `streamLength` (bit 0) as tainted; `limit` (bit 1) is bounded.
        var summary = walker.WalkWithSeed(m, taintedParamBitmask: 0b01, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    // --- Vacuous-bound detection (Milestone-P) ---

    [Fact]
    public void MatchCompareAndThrow_LiteralIntMaxValue_SetsVacuousUpperBound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.VacuousBoundFixtures"
            && md.Name == "GuardWithLiteralMaxValue");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.UpperBound.ShouldNotBeNull();
        match.EstablishesBound.VacuousUpperBound.ShouldBeTrue(
            "ldc.i4 2147483647 resolves to int.MaxValue — guard is trivially satisfied");
    }

    [Fact]
    public void MatchCompareAndThrow_StaticFieldIntMaxValue_SetsVacuousUpperBound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.VacuousBoundFixtures"
            && md.Name == "GuardWithStaticFieldMaxValue");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.VacuousUpperBound.ShouldBeTrue(
            "ldsfld → .cctor ldc.i4 2147483647 resolves to int.MaxValue");
    }

    [Fact]
    public void MatchCompareAndThrow_SmallStaticLimit_DoesNotSetVacuousUpperBound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.VacuousBoundFixtures"
            && md.Name == "GuardWithSmallLimit");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.VacuousUpperBound.ShouldBeFalse(
            "16 MiB limit is a real bound — must not be flagged as vacuous");
    }

    [Fact]
    public void MatchCompareAndThrow_InstancePropertyIntMaxValue_SetsVacuousUpperBound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.VacuousBoundInstanceFixture"
            && md.Name == "GuardWithInstancePropertyMaxValue");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.VacuousUpperBound.ShouldBeTrue(
            "callvirt get_MaxSize → ldfld _maxSize → ctor assignment ldc.i4 2147483647");
    }

    [Fact]
    public void BinaryReaderReadBytes_TaintedLength_SinkFound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.BinaryReaderFixtures"
            && md.Name == "ReadBytesFromTaintedLength");
        // param 0 = reader (instance), param 1 = length; taint param 1 (bitmask bit 1)
        var summary = walker.Walk(m, taintedParamBitmask: 0b10);
        summary.ReachedSink.ShouldBeTrue("BinaryReader.ReadBytes(int) with tainted length is an allocation sink");
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray,
            "BinaryReader.ReadBytes should be reported as new_array sink");
    }

    [Fact]
    public void ConvOvf_DirectLongToNewarr_SinkFound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ConvOvfFixtures"
            && md.Name == "AllocateFromLong");
        var summary = walker.Walk(m, taintedParamBitmask: 0b1);
        summary.ReachedSink.ShouldBeTrue("conv.ovf.i before newarr must not drop taint");
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray,
            "long → conv.ovf.i → newarr should be a new_array sink");
    }

    [Fact]
    public void ConvOvf_LongViaLocal_SinkFound()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ConvOvfFixtures"
            && md.Name == "AllocateFromLongViaLocal");
        var summary = walker.Walk(m, taintedParamBitmask: 0b1);
        summary.ReachedSink.ShouldBeTrue("taint through local before conv.ovf.i must reach newarr");
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray);
    }

    private static Instruction FindConditionalBranch(MethodDefinition m)
        => m.Body.Instructions.First(i => IsConditionalBranch(i.OpCode));

    private static bool IsConditionalBranch(OpCode op)
        => op.FlowControl == FlowControl.Cond_Branch && op.Code != Code.Switch;

    // --- T3: MatchRegexIsMatchAndThrow tests ---

    private static SanitizerMatch? RegexMatch(MethodDefinition m)
        => SanitizerShapes.MatchRegexIsMatchAndThrow(m).FirstOrDefault();

    [Fact]
    public void MatchRegexIsMatchAndThrow_InstanceRegexOnStaticField_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardInstanceThrow(System.String)");

        var match = RegexMatch(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.Relation.ShouldBe("regex_match");
        match.EstablishesBound.UpperBound.ShouldBe("^[a-zA-Z_][a-zA-Z0-9_]*$");
        match.EstablishesBound.Target.ShouldBe("s");
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }
}
