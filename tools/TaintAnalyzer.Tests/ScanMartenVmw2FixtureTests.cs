using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ScanMartenVmw2FixtureTests
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
    public void ScanSqli_RediscoversFullTextWhereFragment_Cold()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "marten-8.36", "Marten.dll");
        if (!File.Exists(dllPath)) return;  // artifact not materialized in this checkout

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", "marten-8.36", ".nopdb-marker"));

        // (1) --emit-rules: the candidate set contains Apply with its string seed fields,
        //     discovered cold — no hand-written source entry.
        var emitPath = Path.Combine(Path.GetTempPath(), $"scan-marten-emit-{Guid.NewGuid()}.yaml");
        var outPath = Path.Combine(Path.GetTempPath(), $"scan-marten-trace-{Guid.NewGuid()}.yaml");
        try
        {
            var stderr1 = new StringWriter();
            var emitArgs = new List<string>
                { dllPath, "--scan", "--scan-profile", "sqli", "--emit-rules", emitPath };
            if (noSymbols) emitArgs.Add("--no-symbols");
            Program.Run(emitArgs.ToArray(), new StringWriter(), stderr1)
                .ShouldBe(0, $"emit-rules stderr: {stderr1}");

            var emitted = File.ReadAllText(emitPath);
            emitted.ShouldContain(
                "Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)");
            emitted.ShouldContain("_regConfig");

            // (2) end-to-end scan produces the SQL sink finding cold.
            var stderr2 = new StringWriter();
            var scanArgs = new List<string>
                { dllPath, "--scan", "--scan-profile", "sqli", "--output", outPath };
            if (noSymbols) scanArgs.Add("--no-symbols");
            Program.Run(scanArgs.ToArray(), new StringWriter(), stderr2)
                .ShouldBe(0, $"scan stderr: {stderr2}");

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("api: sql_command_builder_append");
            trace.ShouldContain("FullTextWhereFragment");
        }
        finally
        {
            if (File.Exists(emitPath)) File.Delete(emitPath);
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
