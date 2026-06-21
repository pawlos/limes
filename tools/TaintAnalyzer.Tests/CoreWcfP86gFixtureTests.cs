using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class CoreWcfP86gFixtureTests
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

    private static string Dll(string ver) =>
        Path.Combine(RepoRoot, "artifacts", $"corewcf-netframing-{ver}", "CoreWCF.NetFramingBase.dll");

    private static string RunLoop(string dll)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        Program.Run(new[] { dll, "--scan", "--scan-profile", "loop", "--no-symbols" }, o, e)
            .ShouldBe(0, $"stderr: {e}");
        return o.ToString();
    }

    [Fact]
    public void Prefix_1_9_0_FlagsBothFramingMiddlewares()
    {
        var dll = Dll("1.9.0");
        if (!File.Exists(dll)) return; // artifact not materialized in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("cwe: 835");
        outText.ShouldContain("api: pipe_reader_read_async");
        outText.ShouldContain("DuplexFramingMiddleware.OnConnectedAsync");
        outText.ShouldContain("SingletonFramingMiddleware.OnConnectedAsync");
    }

    [Fact]
    public void Postfix_1_9_1_ProducesNoFindings()
    {
        var dll = Dll("1.9.1");
        if (!File.Exists(dll)) return; // artifact not materialized in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("findings: []");
        outText.ShouldNotContain("DuplexFramingMiddleware");
    }
}
