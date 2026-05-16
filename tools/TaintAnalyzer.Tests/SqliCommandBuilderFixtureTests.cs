using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class SqliCommandBuilderFixtureTests
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
    public void SqliCommandBuilderPrefix_TraceContainsCommandBuilderSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-command-builder-prefix", "CommandBuilderSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-command-builder-prefix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-cb-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(
                new[] { dllPath, "--rules", rulesPath, "--output", outPath },
                stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_builder_append");
            trace.ShouldContain("CommandBuilderSqliPoc.SearchFragment");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
