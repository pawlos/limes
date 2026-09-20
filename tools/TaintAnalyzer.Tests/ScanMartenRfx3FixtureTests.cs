using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

// Cold-scan lock for Marten GHSA-rfx3-98h7-v3xp: no hand-written source entry, the candidate is
// enumerated by `--scan --scan-profile sqli` and the finding follows from the raw-append sink.
public class ScanMartenRfx3FixtureTests
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

    private static string ColdScan(string artifactDir)
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", artifactDir, "Marten.dll");
        if (!File.Exists(dllPath)) return "";

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", artifactDir, ".nopdb-marker"));
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"scan-rfx3-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--scan", "--scan-profile", "sqli", "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            Program.Run(args.ToArray(), new StringWriter(), stderr).ShouldBe(0, $"scan stderr: {stderr}");
            return File.ReadAllText(outPath);
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }

    // Returns the single YAML document whose source method is DictionaryContainsKeyFilter.Apply,
    // or "" when the scan produced none.
    private static string DictionaryFilterDocument(string trace)
        => trace.Split("\n---\n")
                .FirstOrDefault(d => d.Contains("method: Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter.Apply")
                                  && d.Contains("role: source"))
           ?? "";

    [Fact]
    public void ScanSqli_837_RediscoversDictionaryContainsKeyFilter_Cold()
    {
        var trace = ColdScan("marten-8.37");
        if (trace.Length == 0) return;

        var doc = DictionaryFilterDocument(trace);
        doc.ShouldNotBeEmpty("cold sqli scan of Marten 8.37 must surface DictionaryContainsKeyFilter.Apply");
        doc.ShouldContain("api: sql_command_builder_append_raw");
        doc.ShouldContain("_keyText");
    }

    [Fact]
    public void ScanSqli_913_DoesNotFlagDictionaryContainsKeyFilter()
    {
        var trace = ColdScan("marten-9.13");
        if (trace.Length == 0) return;

        // The method may still be enumerated (it is sink-reachable), but the quote-escape
        // sanitizer must stop it short of a sink.
        var doc = DictionaryFilterDocument(trace);
        if (doc.Length == 0) return;   // not enumerated at all is also a pass
        doc.ShouldNotContain("kind: sql_injection");
    }
}
