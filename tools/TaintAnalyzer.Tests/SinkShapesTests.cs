using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SinkShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    [Fact]
    public void MatchNewArr_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::NewByteArray(System.Int32)");

        var newarr = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Newarr);
        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("size"));

        var match = SinkShapes.MatchNewArr(newarr, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.NewArray);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchNewArr_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::NewByteArray(System.Int32)");
        var newarr = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Newarr);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchNewArr(newarr, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchArrayPoolRent_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::ArrayPoolRent(System.Int32)");

        var callRent = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Rent" &&
            mr.DeclaringType.FullName.StartsWith("System.Buffers.ArrayPool", StringComparison.Ordinal));

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);               // the ArrayPool<byte>.Shared receiver
        stack.Push(StackSlot.TaintedWith("size"));     // the `size` arg

        var match = SinkShapes.MatchArrayPoolRent(callRent, stack);
        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.ArrayPoolRent);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchArrayPoolRent_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::ArrayPoolRent(System.Int32)");
        var callRent = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Rent");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchArrayPoolRent(callRent, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchReadOnlySpanSlice_EitherArgTainted_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::SliceSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32,System.Int32)");

        var callSlice = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Slice" &&
            mr.DeclaringType.FullName.StartsWith("System.ReadOnlySpan", StringComparison.Ordinal));

        // Stack layout for a ROS<T>::Slice(int,int) instance call: [this, start, length]
        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                   // receiver
        stack.Push(StackSlot.TaintedWith("start"));        // tainted start
        stack.Push(StackSlot.Untainted);                   // untainted length

        var match = SinkShapes.MatchReadOnlySpanSlice(callSlice, stack);
        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SpanAccess);
        match.Api.ShouldBe(SinkApi.SpanSlice);
        match.SizeProvenance.ShouldBe("start");
    }

    [Fact]
    public void MatchReadOnlySpanSlice_LengthTainted_StartUntainted_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::SliceSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32,System.Int32)");
        var callSlice = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr && mr.Name == "Slice");

        // Stack: [receiver, start (untainted), length (tainted)] — length sits at Peek(0).
        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                    // receiver
        stack.Push(StackSlot.Untainted);                    // untainted start
        stack.Push(StackSlot.TaintedWith("length"));        // tainted length

        var match = SinkShapes.MatchReadOnlySpanSlice(callSlice, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SpanAccess);
        match.Api.ShouldBe(SinkApi.SpanSlice);
        match.SizeProvenance.ShouldBe("length");
    }

    [Fact]
    public void MatchReadOnlySpanSlice_BothArgsUntainted_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::SliceSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32,System.Int32)");
        var callSlice = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr && mr.Name == "Slice");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchReadOnlySpanSlice(callSlice, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchNewArr_NonNewarrInstruction_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");
        var anyInstruction = m.Body.Instructions.First();

        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("x"));

        SinkShapes.MatchNewArr(anyInstruction, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchReadOnlySpanIndex_TaintedIndex_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SpanIndexFixtures::IndexSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32)");
        var callItem = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr && mr.Name == "get_Item");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                  // receiver (ReadOnlySpan)
        stack.Push(StackSlot.TaintedWith("idx"));         // tainted index

        var match = SinkShapes.MatchReadOnlySpanIndex(callItem, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SpanAccess);
        match.Api.ShouldBe(SinkApi.SpanIndex);
        match.SizeProvenance.ShouldBe("idx");
    }

    [Fact]
    public void MatchReadOnlySpanIndex_UntaintedIndex_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SpanIndexFixtures::IndexSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32)");
        var callItem = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr && mr.Name == "get_Item");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchReadOnlySpanIndex(callItem, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchLocalloc_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::StackallocBytes(System.Int32)");

        var localloc = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Localloc);
        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("size"));

        var match = SinkShapes.MatchLocalloc(localloc, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.Stackalloc);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchLocalloc_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::StackallocBytes(System.Int32)");
        var localloc = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Localloc);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchLocalloc(localloc, stack).ShouldBeNull();
    }
}
