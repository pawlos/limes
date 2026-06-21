using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ReadLoopShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    // Resolve the async state machine MoveNext for a fixture method and return its call instructions.
    private static List<MethodReference> CallsIn(string typeName, string methodName)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var t = ctx.Assembly.MainModule.GetType($"TaintAnalyzer.Tests.Fixtures.Loop.{typeName}");
        var m = t.Methods.First(x => x.Name == methodName);
        var body = AsyncStateMachineResolver.Resolve(m).Method.Body;
        return body.Instructions
            .Where(i => i.OpCode.Code is Code.Call or Code.Callvirt && i.Operand is MethodReference)
            .Select(i => (MethodReference)i.Operand)
            .ToList();
    }

    [Fact]
    public void RecognizesPipeReaderReadAsync()
    {
        var read = CallsIn("PipeLoops", "PipeNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).FirstOrDefault(r => r is not null);
        read!.Kind.ShouldBe(ReadKind.PipeReader);
        read.Api.ShouldBe("pipe_reader_read_async");
    }

    [Fact]
    public void RecognizesPipeCompletionSignal()
    {
        CallsIn("PipeLoops", "PipeWithCheck").Any(ReadLoopShapes.IsPipeCompletionSignal).ShouldBeTrue();
        CallsIn("PipeLoops", "PipeNoCheck").Any(ReadLoopShapes.IsPipeCompletionSignal).ShouldBeFalse();
    }

    [Fact]
    public void RecognizesStreamAndSocketReads()
    {
        CallsIn("StreamLoops", "StreamNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).Any(r => r?.Kind == ReadKind.StreamInt && r.Api == "stream_read")
            .ShouldBeTrue();
        CallsIn("StreamLoops", "SocketNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).Any(r => r?.Kind == ReadKind.StreamInt && r.Api == "socket_receive")
            .ShouldBeTrue();
    }

    [Fact]
    public void IgnoresUnrelatedCalls()
    {
        // PipeNoCheck has several calls (ReadAsync, AdvanceTo, get_Buffer, get_Length, get_End);
        // only the ReadAsync is a recognized read — the rest must be ignored.
        var calls = CallsIn("PipeLoops", "PipeNoCheck");
        calls.Count(c => c.Name == "AdvanceTo").ShouldBeGreaterThan(0);
        calls.Count(c => ReadLoopShapes.RecognizeRead(c) is not null).ShouldBe(1);
    }
}
