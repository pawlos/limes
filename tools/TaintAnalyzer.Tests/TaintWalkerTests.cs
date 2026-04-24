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
}
