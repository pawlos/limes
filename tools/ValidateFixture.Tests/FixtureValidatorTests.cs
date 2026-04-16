using Shouldly;
using SixLabors.TaintAnalyzer.ValidateFixture;
using Xunit;

namespace SixLabors.TaintAnalyzer.ValidateFixture.Tests;

public class FixtureValidatorTests
{
    [Theory]
    [InlineData("vuln_id", "FX001")]
    [InlineData("fix_commit", "FX002")]
    [InlineData("fix_pr", "FX003")]
    [InlineData("description", "FX004")]
    [InlineData("source", "FX005")]
    [InlineData("sink", "FX006")]
    [InlineData("path", "FX007")]
    [InlineData("sanitizer_absence", "FX008")]
    public void EmptyInput_ReportsMissingRequiredField(string fieldName, string code)
    {
        var diagnostics = new FixtureValidator().Validate("{}", snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == code && d.Message.Contains(fieldName));
    }

    [Fact]
    public void MalformedYaml_ReportsFX000()
    {
        // ":::not yaml:::" is parsed by YamlDotNet as a valid mapping, so use a
        // genuinely unparseable sequence literal instead.
        var diagnostics = new FixtureValidator().Validate("[invalid yaml", snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX000");
    }
}
