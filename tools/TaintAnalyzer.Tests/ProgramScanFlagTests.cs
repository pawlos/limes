using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ProgramScanFlagTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Scan_WithoutOtherFlags_ProducesTraceOnStdout()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(new[] { FixturePath, "--scan" }, stdout, stderr);

        rc.ShouldBe(0);
        // Trace YAML emitted to stdout. The fixture assembly may produce findings or not;
        // the important thing is the trace document exists.
        stdout.ToString().ShouldContain("vuln_id");
    }

    [Fact]
    public void Scan_AndRules_AreMutuallyExclusive()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(
            new[] { FixturePath, "--scan", "--rules", "x.yaml" }, stdout, stderr);

        rc.ShouldBe(2);
        stderr.ToString().ShouldContain("--scan");
    }

    [Fact]
    public void NeitherScanNorRules_IsUsageError()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(new[] { FixturePath }, stdout, stderr);

        rc.ShouldBe(2);
    }
}
