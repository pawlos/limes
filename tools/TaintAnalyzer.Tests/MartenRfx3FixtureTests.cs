using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

// Marten GHSA-rfx3-98h7-v3xp (CVE-2026-75513). Prefix is 8.37.0 — the build that PATCHED the
// earlier GHSA-vmw2 advisory but is still vulnerable to this one. Postfix is 9.13.0, the first
// release carrying the quote-doubling fix (there is no 8.x backport).
public class MartenRfx3FixtureTests
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

    private static string RunTrace(string artifactDir, string fixtureDir)
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", artifactDir, "Marten.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", fixtureDir, "rules.yaml");
        if (!File.Exists(dllPath)) return "";   // artifact not materialized in fresh checkouts

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", artifactDir, ".nopdb-marker"));
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"{fixtureDir}-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--rules", rulesPath, "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            Program.Run(args.ToArray(), new StringWriter(), stderr).ShouldBe(0, $"stderr: {stderr}");
            return File.ReadAllText(outPath);
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }

    [Fact]
    public void MartenRfx3Prefix_837_ReportsRawAppendSink()
    {
        var trace = RunTrace("marten-8.37", "marten-rfx3-prefix");
        if (trace.Length == 0) return;

        trace.ShouldContain("kind: sql_injection");
        trace.ShouldContain("api: sql_command_builder_append_raw");
        trace.ShouldContain("DictionaryContainsKeyFilter");
        trace.ShouldContain("_keyText");
    }

    [Fact]
    public void MartenRfx3Postfix_913_ReportsEscapeSanitizerNoSink()
    {
        var trace = RunTrace("marten-9.13", "marten-rfx3-postfix");
        if (trace.Length == 0) return;

        trace.ShouldContain("transformation: sql_quote_escape");
        trace.ShouldContain("sql_quote_escaped(_keyText)");
        trace.ShouldContain("DictionaryContainsKeyFilter");
        trace.ShouldNotContain("kind: sql_injection");
        trace.ShouldNotContain("\nsink:");
        trace.ShouldNotContain("expected_check:");
    }
}
