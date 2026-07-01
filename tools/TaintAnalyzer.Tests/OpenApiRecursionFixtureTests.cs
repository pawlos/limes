using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

// e2e for the Microsoft.OpenApi BaseOpenApiReferenceHolder recursion fixture
// (GHSA-v5pm-xwqc-g5wc / CVE-2026-49451, CWE-674). Build the artifacts with
// scripts/build-microsoft-openapi-v5pm.sh; tests skip when absent.
public class OpenApiRecursionFixtureTests
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
        Path.Combine(RepoRoot, "artifacts", $"microsoft-openapi-v5pm-{variant}", "Microsoft.OpenApi.dll");

    // The default config excludes Microsoft.*; the fixture lives in Microsoft.OpenApi.*, so we
    // point at a config that keeps only System.* excluded.
    private static string Config =>
        Path.Combine(RepoRoot, "fixtures", "microsoft-openapi-v5pm-enumerator-config.yaml");

    private static string RunRecursion(string dll)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        Program.Run(new[] { dll, "--scan", "--scan-profile", "recursion", "--enumerator-config", Config }, o, e)
            .ShouldBe(0, $"stderr: {e}");
        return o.ToString();
    }

    [Fact]
    public void Prefix_FlagsRecursiveTarget()
    {
        var dll = Dll("prefix");
        if (!File.Exists(dll)) return; // artifact not built in this checkout

        var outText = RunRecursion(dll);
        outText.ShouldContain("cwe: 674");
        outText.ShouldContain("method: Microsoft.OpenApi.Models.References.BaseOpenApiReferenceHolder.get_RecursiveTarget");
        outText.ShouldContain("recursion: self");
        outText.ShouldContain("guard: absent");
    }

    [Fact]
    public void Postfix_ProducesNoFindings()
    {
        var dll = Dll("postfix");
        if (!File.Exists(dll)) return; // artifact not built in this checkout

        var outText = RunRecursion(dll);
        outText.ShouldContain("findings: []");
        outText.ShouldNotContain("cwe: 674");
    }
}
