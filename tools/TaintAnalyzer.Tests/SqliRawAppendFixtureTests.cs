using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliRawAppendFixtureTests
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
    public void SqliRawAppendPrefix_TraceContainsRawSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-raw-append-prefix", "RawAppendSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-raw-append-prefix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-raw-append-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(new[] { dllPath, "--rules", rulesPath, "--output", outPath }, stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_builder_append_raw");
            trace.ShouldContain("RawAppendSqliPoc.DictionaryKeyFragment");
            trace.ShouldContain("expected_check:");   // nothing guards the value
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
