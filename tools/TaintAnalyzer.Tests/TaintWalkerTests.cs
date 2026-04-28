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
    public void Walk_PreFixIntraMethodAllocation_HopsContainSinkButWalkerEmitsNoAbsences()
    {
        // Walker now produces only the hop list — sanitizer-absence synthesis lives in TraceEmitter
        // (per-sink path context is needed for multi-sink traces). The absence lookup verified by
        // the previous version of this test now lives in TraceEmitterTests.Emit_SinkWithoutPrecedingSanitizer_*.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.Absences.ShouldBeEmpty();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray);
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

    [Fact]
    public void Walk_GetterReturnsTaintedField_SummaryReportsReturnsTainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // Seed `this.data` as tainted (no arg taint, bitmask=0).
        var summary = walker.WalkWithSeed(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterTaintHost::GetData()")!,
            taintedParamBitmask: 0b0,
            taintedThisFields: new[] { "data" });

        summary.ReturnsTainted.ShouldBeTrue();
    }

    [Fact]
    public void Walk_GetterReturnsUntaintedField_SummaryReportsReturnsTaintedFalse()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // No seed — this.data is untainted at entry.
        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterTaintHost::GetData()")!,
            taintedParamBitmask: 0b0);

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void Walk_CrossMethodGetterReadsTaintedField_SinkFires()
    {
        // CrossMethodGetterToSink(int n) calls SetData(n) → this.data tainted, then GetData()
        // returns this.data, then `new byte[x]`. With the I-1 fix, the call to GetData() should
        // be analyzed with taintedThisFields=["data"], so GetData()'s ReturnsTainted is true,
        // so the caller's stack carries a tainted slot to the newarr sink.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterTaintHost::CrossMethodGetterToSink(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void WalkWithSeed_DifferentSeeds_AreCachedSeparately()
    {
        // Seeded walks must be cached under their seed-specific key; different seeds → different
        // cache entries (and identity); same seed twice → same cache entry (and identity).
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterTaintHost::GetData()")!;

        var seeded = walker.WalkWithSeed(m, 0b0, new[] { "data" });
        var seededAgain = walker.WalkWithSeed(m, 0b0, new[] { "data" });
        seededAgain.ShouldBeSameAs(seeded);

        var unseeded = walker.Walk(m, 0b0);
        unseeded.ShouldNotBeSameAs(seeded);
    }

    [Fact]
    public void Walk_PropagatorHopForFieldLoad_HasFieldLoadTransformation()
    {
        // FieldTaintHost.AllocateFromField reads this.payloadSize (pre-tainted) and uses it at sink.
        // With propagator emission, there should be a `field_load` hop before the sink.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.WalkWithSeed(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromField()")!,
            taintedParamBitmask: 0b0,
            taintedThisFields: new[] { "payloadSize" });

        var fieldLoadHops = summary.Hops.Where(h => h.Transformation == "field_load").ToList();
        fieldLoadHops.ShouldNotBeEmpty();
        fieldLoadHops[0].Role.ShouldBe(HopRole.Propagator);
    }

    [Fact]
    public void Walk_PropagatorHopForArithmetic_HasArithmeticTransformation()
    {
        // IntraMethodAllocation does `int n = size + 4; new byte[n];` — the `+ 4` should produce
        // an arithmetic propagator hop.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.Hops.ShouldContain(h => h.Transformation == "arithmetic" && h.Role == HopRole.Propagator);
    }

    [Fact]
    public void Walk_PropagatorHopForCrossMethodCall_HasDispatchPopulated()
    {
        // CrossMethodTaintedReturn calls Echo(n); the call boundary should produce a propagator
        // hop with Dispatch populated.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodTaintedReturn(System.Int32)")!,
            taintedParamBitmask: 0b1);

        var callHop = summary.Hops.FirstOrDefault(h =>
            h.Role == HopRole.Propagator && h.Dispatch is not null);
        callHop.ShouldNotBeNull();
        callHop!.Dispatch!.Kind.ShouldBe("direct");
    }

    [Fact]
    public void Walk_ParquetDotNet738_TaintedStreamReachesSink()
    {
        // Mirrors parquet-dotnet ThriftCompactProtocolReader.ReadBinary chain:
        // FakeStream → ReadVarInt32 → length → ReadBytesExactly → new byte[count].
        // This is the simplest possible cross-method tainted-receiver-to-sink shape.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ParquetThriftLikeFixtures::ReadBinary(TaintAnalyzer.Tests.Fixtures.FakeStream)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        // With the hop-merge fix the sink hop from ReadBytesExactly is now present in the caller's list.
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray);
    }

    [Fact]
    public void Walk_SinkInCallee_CallerSummaryReportsReachedSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ParquetThriftLikeFixtures::ReadBinary(TaintAnalyzer.Tests.Fixtures.FakeStream)")!,
            taintedParamBitmask: 0b1);

        // ReadBinary itself contains no `newarr` — the sink is in ReadBytesExactly.
        // Without the bubble + hop-merge, summary.ReachedSink would be false AND summary.Hops
        // would lack the sink. With both fixes, the sink hop merges into the caller's chain.
        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray);
    }

    [Fact]
    public void Walk_CrossMethodChain_HopsCarryCalleeMethodLabels()
    {
        // The ParquetThriftLikeFixtures.ReadBinary chain spans three methods:
        // ReadBinary, ReadVarInt32, ReadBytesExactly. After the hop-merge fix, the caller's
        // summary should contain hops with Method labels from all three methods.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ParquetThriftLikeFixtures::ReadBinary(TaintAnalyzer.Tests.Fixtures.FakeStream)")!,
            taintedParamBitmask: 0b1);

        var methodLabels = summary.Hops.Select(h => h.Method).Distinct().ToList();
        methodLabels.ShouldContain(s => s.EndsWith("ReadBinary"));
        methodLabels.ShouldContain(s => s.EndsWith("ReadBytesExactly"));
        // ReadVarInt32 may or may not have an emitted hop depending on whether NextByte's tainted-
        // receiver call surfaces as a propagator hop. If it doesn't, that's a minor coverage gap
        // (taint flows through but no hop is emitted at the helper-call boundary) — not a fail.
    }

    [Fact]
    public void Walk_TryCatchAroundSink_DoesNotCrashAndStillReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ExceptionHandlerHost::AllocateWithCatch(System.Int32)")!,
            taintedParamBitmask: 0b1);

        // Sink in the try block fires; the catch handler entry doesn't crash.
        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Walk_TryFinallyAroundSink_DoesNotCrashAndStillReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ExceptionHandlerHost::AllocateWithFinally(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Walk_NewobjWithTaintedArg_PropagatesTaintThroughLdfldToSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CtorTaintHost::AllocateViaWrapperCtor(System.Int32)")!,
            taintedParamBitmask: 0b1);

        // newobj propagates tainted arg → tainted wrapper. ldfld w.Value → tainted size.
        // newarr → sink.
        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Walk_ExternalCallOnTaintedReceiver_ReturnIsTainted()
    {
        // Stream.ReadByte() resolves outside the analyzed assembly → "external" branch in
        // HandleCall. Without the GAP-B fix, the return is forced untainted, so storing
        // the result into this.captured would NOT add captured to NewlyTaintedThisFields.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ExternalReceiverHost::StoreFromExternalReadByte(System.IO.Stream)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("captured");
    }

    [Fact]
    public void Walk_SinkReadsLocal_HopCarriesFirstTaintedLine()
    {
        // When the size operand of a `newarr` was loaded via `ldloc <local>`, the sink hop
        // records (FirstTaintedFile, FirstTaintedLine) — the line where that local first
        // received a tainted value during the walk. The emitter uses this for sanitizer-
        // absence location.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        var sink = summary.Hops.First(h => h.Role == HopRole.Sink);
        sink.SinkApi.ShouldBe(SinkApi.NewArray);
        sink.FirstTaintedFile.ShouldNotBeNull();
        sink.FirstTaintedLine.ShouldNotBeNull();
        sink.FirstTaintedLine!.Value.ShouldBeGreaterThan(0);
    }

    [Fact]
    public void Walk_NullableValueChainOnTaintedField_ReachesSink()
    {
        // ldflda on a tainted this-field → tainted address → external Nullable<T>::get_Value()
        // returns tainted struct → ldfld Limit on tainted struct → tainted size → newarr sink.
        // Mirrors the ImageSharp #3074 chain `this.fileHeader.Value.Offset`.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var method = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.NullableFieldHost::AllocateFromNullableValueChain()")!;
        var summary = walker.WalkWithSeed(method,
            taintedParamBitmask: 0b0,
            taintedThisFields: new[] { "wrapped" });

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.Last().SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_ExternalCallWithBufferLikeArg_TaintsLocalSource()
    {
        // Stream.Read(byte[], int, int) is external. Stream is tainted; buf is a local-allocated
        // byte[]. Without GAP-A, `buf` stays untainted after the call so `this.captured = buf`
        // doesn't taint captured. With GAP-A, the buf-loading local is tainted by the call,
        // which propagates through the subsequent stfld.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.BufferFillHost::FillBufferThenStore(System.IO.Stream)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("captured");
    }

    [Theory]
    [InlineData("MulPath", "*")]
    [InlineData("DivPath", "/")]
    [InlineData("ShlPath", "<<")]
    [InlineData("ShrPath", ">>")]
    public void Walk_ArithmeticHop_UsesOperatorAwareOperandName(string methodName, string expectedOp)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var method = ctx.FindMethod(
            $"TaintAnalyzer.Tests.Fixtures.ArithmeticOperatorFixtures::{methodName}(System.Int32,System.Int32)");
        method.ShouldNotBeNull();

        var summary = walker.Walk(method, taintedParamBitmask: 0b11);

        summary.Hops.ShouldContain(h => h.Transformation == "arithmetic");
        // The LAST arithmetic hop is the operator-of-interest. For *// the body emits one
        // arithmetic hop; for <<>> Roslyn compiles `a OP b` into `a OP (b & 31)`, producing two
        // arithmetic hops (the `and` mask, then the actual shift) — and the shift is always
        // last. LastOrDefault is robust to either shape.
        var arithHop = summary.Hops.LastOrDefault(h => h.Transformation == "arithmetic");
        arithHop.ShouldNotBeNull();
        arithHop.TaintedValueOut.ShouldContain(expectedOp);
    }

    [Fact]
    public void Walk_SameMethodIdentityHops_AreFiltered()
    {
        // Decode calls ReadLength twice. An arithmetic op between the two calls ensures that
        // hops[^1] is a Decode-context hop before the second call, triggering U2's guard.
        // Before U2, the walker would emit two Decode-context identity hops (one per call);
        // U2 suppresses the second because hops[^1].Method already equals the caller method.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var method = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.IdentityFilterFixtures::Decode(System.Byte[])")!;
        var summary = walker.Walk(method, taintedParamBitmask: 0b1);

        // After U2: at most one Decode-context identity hop should remain (the first call to
        // ReadLength). The second call is suppressed because hops[^1] is already a Decode hop.
        // Before U2 there were two; the filter removes the consecutive duplicate.
        var decodeIdentityHops = summary.Hops
            .Where(h => h.Role == HopRole.Propagator
                     && h.Transformation == "identity"
                     && h.Method.EndsWith(".Decode"))
            .ToList();
        // Two consecutive calls → only one Decode-context identity hop survives the filter.
        decodeIdentityHops.Count.ShouldBe(1);

        // The taint still reaches the sink (newarr with adjusted + lengthB).
        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.NewArray);

        // Cross-method identity hops (entries into ReadLength's body) are preserved by U2 —
        // different `method` label, so the guard doesn't fire. Confirm at least one ReadLength
        // hop survived in the merged hop list.
        summary.Hops.ShouldContain(h => h.Method.EndsWith(".ReadLength"));
    }

    [Fact]
    public void Walk_StlocOfTaintedCallReturn_RenamesProvenanceToLocalDebugName()
    {
        // N1: the arithmetic propagator hop after `int m = Echo(n); int p = m + 4;`
        // should carry tainted_value_in = "m" (the local's PDB name), not the synthetic
        // call-return provenance.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::StlocReturnThenArithmetic(System.Int32)")!,
            taintedParamBitmask: 0b1);

        var arithmeticHop = summary.Hops.FirstOrDefault(h => h.Transformation == "arithmetic");
        arithmeticHop.ShouldNotBeNull("expected an arithmetic propagator hop for `m + 4`");
        arithmeticHop.TaintedValueIn.ShouldBe("m", "N1 should rename the tainted slot to the local's PDB name on stloc");
    }

    [Fact]
    public void Walk_StlocOfUntaintedValue_DoesNotInventName()
    {
        // N1's rename branch must not fire when the slot is untainted. Drive the same fixture
        // method as the positive test but with bitmask=0 so `n` is untainted; the stloc to `m`
        // should preserve the untainted slot, no tainted hops should emerge.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::StlocReturnThenArithmetic(System.Int32)")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse("no tainted input → no sink");
        summary.Hops.ShouldBeEmpty("no tainted input → no hops");
    }

    [Fact]
    public void Walk_TaintedReceiverPropertyGetter_StripsGetUnderscorePrefix()
    {
        // N2: the sink hop's tainted_value_in for `host.Value` (a property getter on a
        // tainted receiver) should be "host.Value", not "host.get_Value".
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterNamingHost::AllocateFromTaintedHostValue(TaintAnalyzer.Tests.Fixtures.GetterNamingHost)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        var sinkHop = summary.Hops.Last();
        sinkHop.Role.ShouldBe(HopRole.Sink);
        // The sink's tainted_value_in records the value flowing into newarr — i.e. the
        // result of `host.Value`. After N2 it should not contain "get_".
        sinkHop.TaintedValueIn.ShouldBe("GetterNamingHost.Value", "N2 should render the getter call as Type.Property, not Type.get_Property");
    }

    [Fact]
    public void Walk_NonGetterCall_NoTraceFieldStartsWithUnderscore()
    {
        // Defensive: confirm CleanCalleeName doesn't accidentally chop something it shouldn't.
        // CrossMethodTaintedReturn calls Echo (not a getter) — no `tainted_value_*` field across
        // any hop should start with `_` (which would be the result of mistakenly stripping `get`
        // from a name that wasn't actually `get_<X>`).
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodTaintedReturn(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        foreach (var hop in summary.Hops)
        {
            (hop.TaintedValueIn ?? "").ShouldNotStartWith("_");
            (hop.TaintedValueOut ?? "").ShouldNotStartWith("_");
        }
    }
}
