using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

// e2e for the NAudio.Extras.LoopStream loop-termination fixture (naudio/NAudio#1338, CWE-835).
// Build the artifacts with scripts/build-naudio-loopstream.sh; tests skip when absent.
public class NAudioLoopStreamFixtureTests
{
    private static string RepoRoot
    {
        get
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 5 && d?.Parent is not null; i++) d = d.Parent;
            return d!.FullName;
        }
    }

    private static string Dll(string variant) =>
        Path.Combine(RepoRoot, "artifacts", $"naudio-loopstream-1338-{variant}", "NAudio.Extras.dll");

    private static string RunLoop(string dll)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        Program.Run(new[] { dll, "--scan", "--scan-profile", "loop" }, o, e)
            .ShouldBe(0, $"stderr: {e}");
        return o.ToString();
    }

    [Fact]
    public void Prefix_FlagsLoopStreamRead()
    {
        var dll = Dll("prefix");
        if (!File.Exists(dll)) return; // artifact not built in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("cwe: 835");
        outText.ShouldContain("method: NAudio.Extras.LoopStream.Read");
        outText.ShouldContain("api: stream_read");
        outText.ShouldContain("completion_signal: absent");
    }

    [Fact]
    public void Postfix_ProducesNoFindings()
    {
        var dll = Dll("postfix");
        if (!File.Exists(dll)) return; // artifact not built in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("findings: []");
        outText.ShouldNotContain("LoopStream.Read");
    }
}
