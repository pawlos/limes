using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class LoopTerminationAnalyzerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static IReadOnlyList<LoopFinding> Analyze(string typeName, string methodName)
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var t = ctx.Assembly.MainModule.GetType($"TaintAnalyzer.Tests.Fixtures.Loop.{typeName}");
        var m = t.Methods.First(x => x.Name == methodName);
        return LoopTerminationAnalyzer.Analyze(ctx, m);
    }

    [Fact]
    public void FlagsPipeReadLoopWithoutCompletionCheck()
    {
        var f = Analyze("PipeLoops", "PipeNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("pipe_reader_read_async");
        f[0].ResolvedViaAsync.ShouldBeTrue();
        f[0].Method.ShouldEndWith("PipeLoops.PipeNoCheck");
    }

    [Fact]
    public void ClearsPipeReadLoopWithCompletionCheck()
        => Analyze("PipeLoops", "PipeWithCheck").ShouldBeEmpty();

    [Fact]
    public void ClearsSingleReadNotInLoop()
        => Analyze("PipeLoops", "PipeSingleRead").ShouldBeEmpty();

    [Fact]
    public void ClearsLoopWithNoRead()
        => Analyze("PlainLoops", "LoopNoRead").ShouldBeEmpty();

    [Fact]
    public void FlagsStreamReadLoopWithoutZeroCheck()
    {
        var f = Analyze("StreamLoops", "StreamNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("stream_read");
    }

    [Fact]
    public void ClearsStreamReadLoopWithZeroCheck()
        => Analyze("StreamLoops", "StreamWithCheck").ShouldBeEmpty();

    [Fact]
    public void FlagsSocketReceiveLoopWithoutZeroCheck()
    {
        var f = Analyze("StreamLoops", "SocketNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("socket_receive");
    }
}
