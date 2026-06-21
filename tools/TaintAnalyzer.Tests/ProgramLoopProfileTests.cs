using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ProgramLoopProfileTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static (int code, string outText, string errText) Run(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Program.Run(args, o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public void LoopProfile_FlagsNoCheckLoops_ClearsCheckedOnes()
    {
        var (code, outText, _) = Run(FixturePath, "--scan", "--scan-profile", "loop");
        code.ShouldBe(0);
        outText.ShouldContain("cwe: 835");
        outText.ShouldContain("PipeLoops.PipeNoCheck");
        outText.ShouldContain("StreamLoops.StreamNoCheck");
        outText.ShouldContain("StreamLoops.SocketNoCheck");
        outText.ShouldContain("InternalMiddleware.OnConnectedAsync");
        outText.ShouldNotContain("PipeWithCheck");
        outText.ShouldNotContain("StreamWithCheck");
        outText.ShouldNotContain("PipeSingleRead");
        outText.ShouldNotContain("LoopNoRead");
    }

    [Fact]
    public void LoopProfile_RequiresScan()
    {
        // With --rules (not --scan), the specific guard fires; without either, the earlier
        // usage guard rejects first. Both are exit-2 rejections — assert the specific one here.
        var (code, _, errText) = Run(FixturePath, "--rules", "r.yaml", "--scan-profile", "loop");
        code.ShouldBe(2);
        errText.ShouldContain("--scan-profile requires --scan");
    }

    [Fact]
    public void LoopProfile_RejectsEmitRules()
    {
        var (code, _, errText) = Run(FixturePath, "--scan", "--scan-profile", "loop", "--emit-rules", "x.yaml");
        code.ShouldBe(2);
        errText.ShouldContain("--emit-rules");
    }
}
