using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class SqliInterpolatedFixtureTests
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

    [Fact]
    public void SqliInterpolatedPrefix_TraceContainsSqlInjectionSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-interpolated-prefix", "InterpolatedSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-interpolated-prefix", "rules.yaml");

        if (!File.Exists(dllPath))
        {
            // Build artifact not materialized in this checkout. Skip silently.
            return;
        }

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-interp-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(
                new[] { dllPath, "--rules", rulesPath, "--output", outPath },
                stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_text");
            trace.ShouldContain("InterpolatedSqliPoc.SearchService");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
