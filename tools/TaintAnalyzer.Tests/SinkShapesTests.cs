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

    [Fact]
    public void MatchCommandTextSetter_DbCommandSubtype_Tainted_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignCommandText(System.Data.Common.DbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver (the DbCommand)
        stack.Push(StackSlot.TaintedWith("sql"));              // value (Peek(0))

        var match = SinkShapes.MatchCommandTextSetter(setter, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }

    [Fact]
    public void MatchCommandTextSetter_DirectIDbCommand_Tainted_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignViaInterface(System.Data.IDbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("sql"));              // value

        var match = SinkShapes.MatchCommandTextSetter(setter, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }

    [Fact]
    public void MatchCommandTextSetter_Untainted_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignCommandText(System.Data.Common.DbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.Untainted);                       // value — untainted

        SinkShapes.MatchCommandTextSetter(setter, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchCommandTextSetter_NonDbType_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignUnrelatedCommandText(TaintAnalyzer.Tests.Fixtures.UnrelatedCommandTextHolder,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("value"));            // value tainted, but type isn't DB

        SinkShapes.MatchCommandTextSetter(setter, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchCommandTextSetter_ResolveFailure_FallbackHeuristic_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Synthesize a MethodReference whose declaring type is in the Npgsql namespace
        // and ends with "Command" but cannot be resolved (no Npgsql assembly loaded).
        var module = ctx.Assembly.MainModule;
        var stringType = module.TypeSystem.String;
        var voidType = module.TypeSystem.Void;
        var declaringType = new Mono.Cecil.TypeReference("Npgsql", "NpgsqlCommand", module, module);
        var setter = new Mono.Cecil.MethodReference("set_CommandText", voidType, declaringType)
        {
            HasThis = true,
        };
        setter.Parameters.Add(new Mono.Cecil.ParameterDefinition(stringType));
        var ins = Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Callvirt, setter);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("sql"));              // value

        var match = SinkShapes.MatchCommandTextSetter(ins, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }

    [Fact]
    public void MatchCommandTextSetter_ResolveFailure_NoFallback_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Unresolvable declaring type with namespace NOT in the DB-provider list.
        // Type name ends in "Command" so the name half of the heuristic passes,
        // but namespace doesn't qualify — overall fallback must reject.
        var module = ctx.Assembly.MainModule;
        var stringType = module.TypeSystem.String;
        var voidType = module.TypeSystem.Void;
        var declaringType = new Mono.Cecil.TypeReference("Acme.Logging", "LogCommand", module, module);
        var setter = new Mono.Cecil.MethodReference("set_CommandText", voidType, declaringType)
        {
            HasThis = true,
        };
        setter.Parameters.Add(new Mono.Cecil.ParameterDefinition(stringType));
        var ins = Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Callvirt, setter);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.TaintedWith("value"));

        SinkShapes.MatchCommandTextSetter(ins, stack).ShouldBeNull();
    }

    [Fact]
    public void TryHandleInterpolatedStringAppend_TaintedValue_TaintsHandlerLocal()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.InterpolatedStringFixtures::DoFormat(System.String)");

        // DoFormat has two AppendFormatted calls (5-part interpolation); pick the first.
        var call = m.Body.Instructions.First(i =>
            i.OpCode == Mono.Cecil.Cil.OpCodes.Call &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendFormatted" &&
            mr.DeclaringType.FullName == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.TaintedWith("x") };
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeTrue();
        // The handler local is V_0 (first local in the synthesized method body).
        state.Locals.ShouldContainKey(0);
        state.Locals[0].Tainted.ShouldBeTrue();
        state.Locals[0].Provenance.ShouldBe("InterpolatedString(x)");
    }

    [Fact]
    public void TryHandleInterpolatedStringAppend_UntaintedValue_NoStateChange()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.InterpolatedStringFixtures::DoFormat(System.String)");

        var call = m.Body.Instructions.First(i =>
            i.OpCode == Mono.Cecil.Cil.OpCodes.Call &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendFormatted" &&
            mr.DeclaringType.FullName == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.Untainted };
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeFalse();
        state.Locals.ShouldBeEmpty();
    }
}
