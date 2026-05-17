using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class MartenVmw2PostfixFixtureTests
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
    public void MartenVmw2Postfix_TraceContainsSanitizerNoSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "marten-8.37", "Marten.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "marten-vmw2-postfix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // Marten 8.37 not materialized in fresh checkouts

        var noPdbMarker = Path.Combine(RepoRoot, "artifacts", "marten-8.37", ".nopdb-marker");
        var noSymbols = File.Exists(noPdbMarker);

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"marten-vmw2-postfix-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--rules", rulesPath, "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            var rc = Program.Run(args.ToArray(), stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("relation: regex_match");
            trace.ShouldContain("[a-zA-Z_]");  // a substring of the expected pattern
            trace.ShouldContain("Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment");
            trace.ShouldNotContain("kind: sql_injection");
            trace.ShouldNotContain("\nsink:");
            // sanitizer_absence is empty for the patched form.
            trace.ShouldNotContain("expected_check:");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
