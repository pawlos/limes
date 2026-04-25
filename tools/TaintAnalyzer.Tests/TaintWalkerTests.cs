using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class TaintWalkerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Walk_TaintedParamReachesNewarr_RecordsSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();

        var sinkHop = summary.Hops.Last();
        sinkHop.Role.ShouldBe(HopRole.Sink);
        sinkHop.SinkKind.ShouldBe(SinkKind.Allocation);
        sinkHop.SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_NoTaintedInput_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodNoTaint()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse();
        summary.Hops.OfType<HopRecord>().Where(h => h.Role == HopRole.Sink).ShouldBeEmpty();
    }

    [Fact]
    public void Walk_StoresTaintedValueToThisField_RecordsFieldInSummary()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::StoreToField(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("payloadSize");
    }

    [Fact]
    public void Walk_ReadsPreTaintedThisField_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // Seed `this.payloadSize` as tainted via the TaintWalker's external-seed API (added in this task).
        var method = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromField()")!;
        var summary = walker.WalkWithSeed(method,
            taintedParamBitmask: 0b0,
            taintedThisFields: new[] { "payloadSize" });

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.Last().SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_ReadsUntaintedThisField_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromSafeConstant()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse();
    }

    [Fact]
    public void Walk_TaintedReceiverLdfld_ProducesTaintedValueReachingSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // Caller passes `host` as param 0 of AllocateFromTaintedHost (static, bitmask bit 0 = param 0).
        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromTaintedHost(TaintAnalyzer.Tests.Fixtures.FieldTaintHost)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.Last().SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_CallsHelperThatStoresToThisField_MergesFieldTaint()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodStore(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("stored");
    }

    [Fact]
    public void Walk_HelperReturnsTaintedValue_SinkFires()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodTaintedReturn(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Walk_MemoizesByMethodAndBitmask()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodStore(System.Int32)")!;
        var first = walker.Walk(m, 0b1);
        var second = walker.Walk(m, 0b1);

        // Same object reference: memoized.
        second.ShouldBeSameAs(first);

        // Different bitmask: different summary.
        var zero = walker.Walk(m, 0b0);
        zero.ShouldNotBeSameAs(first);
    }

    [Fact]
    public void Walk_WithSanitizerOnPath_RecordsSanitizerHopAndStillReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SanitizerInContext::SanitizedAllocate(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sanitizer);
        var sanitizerHop = summary.Hops.First(h => h.Role == HopRole.Sanitizer);
        sanitizerHop.EstablishesBound.ShouldNotBeNull();
        sanitizerHop.EstablishesBound!.Relation.ShouldBe("<=");
        sanitizerHop.OnFailure.ShouldNotBeNull();
        sanitizerHop.OnFailure!.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void Walk_PreFix_SynthesizesSanitizerAbsence()
    {
        // The intra-method allocation fixture from Task 9 has no sanitizer on the path; the walker
        // should emit exactly one sanitizer_absence entry.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.Absences.ShouldHaveSingleItem();
        var absence = summary.Absences[0];
        absence.TaintedValue.ShouldNotBeNullOrEmpty();
        absence.ExpectedCheck.ShouldContain("must be bounded before reaching");
    }

    [Fact]
    public void GetSequencePoint_UsesFallbackForHiddenInstructions()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!;

        // `nop` in Debug IL may or may not have a sequence point. Regardless, GetSequencePoint must
        // never return null for the *first* instruction of a non-trivial Debug body — the method-prologue
        // sequence point falls on `ldarg`/`nop`/`stloc`.
        var first = m.Body.Instructions.First();
        var sp = ctx.GetSequencePoint(m, first);
        sp.ShouldNotBeNull();
        sp!.StartLine.ShouldBeGreaterThan(0);
    }

    [Fact]
    public void Walk_TwoSanitizersOneSink_EmitsBothSanitizerHopsBeforeSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.MultiSanitizerHost::AllocateWithTwoGuards(System.Int32,System.Int32)")!,
            taintedParamBitmask: 0b1);   // n is tainted, max is not

        summary.ReachedSink.ShouldBeTrue();
        var sanitizerHops = summary.Hops.Where(h => h.Role == HopRole.Sanitizer).ToList();
        sanitizerHops.Count.ShouldBe(2);
        // Both sanitizer hops appear before the sink in the hop list.
        var sinkIdx = summary.Hops.ToList().FindIndex(h => h.Role == HopRole.Sink);
        sinkIdx.ShouldBeGreaterThan(0);
        var hopList = summary.Hops.ToList();
        hopList.IndexOf(sanitizerHops[0]).ShouldBeLessThan(sinkIdx);
        hopList.IndexOf(sanitizerHops[1]).ShouldBeLessThan(sinkIdx);
        // No absence emitted (sanitizers present).
        summary.Absences.ShouldBeEmpty();
    }
}
