using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliQuoteEscapeFixtureTests
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
    public void SqliQuoteEscapePostfix_TraceContainsEscapeSanitizerNoSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-quote-escape-postfix", "QuoteEscapeSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-quote-escape-postfix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-quote-escape-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(new[] { dllPath, "--rules", rulesPath, "--output", outPath }, stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("transformation: sql_quote_escape");
            trace.ShouldContain("sql_quote_escaped(_key)");
            trace.ShouldContain("QuoteEscapeSqliPoc.DictionaryKeyFragment");
            trace.ShouldNotContain("kind: sql_injection");
            trace.ShouldNotContain("\nsink:");
            trace.ShouldNotContain("expected_check:");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
