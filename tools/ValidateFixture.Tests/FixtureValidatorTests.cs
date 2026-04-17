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

    [Fact]
    public void PathNode_InvalidRole_ReportsFX010()
    {
        var yaml = BuildYaml(pathRole: "hatstand");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX010" && d.Message.Contains("role") && d.Message.Contains("hatstand"));
    }

    [Fact]
    public void PathNode_InvalidTransformation_ReportsFX011()
    {
        var yaml = BuildYaml(pathTransformation: "transmute");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX011" && d.Message.Contains("transformation") && d.Message.Contains("transmute"));
    }

    [Fact]
    public void PathNode_InvalidDispatchKind_ReportsFX012()
    {
        var yaml = BuildYaml(pathDispatchKind: "telepathy");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX012" && d.Message.Contains("dispatch.kind") && d.Message.Contains("telepathy"));
    }

    [Fact]
    public void ValidMinimalFixture_ReportsNoDiagnostics()
    {
        var yaml = File.ReadAllText("TestData/minimal_valid.yaml");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldBeEmpty();
    }

    private static string BuildYaml(
        string pathRole = "propagator",
        string pathTransformation = "identity",
        string pathDispatchKind = "direct")
        => $$"""
           vuln_id: test
           fix_commit: 0000000000000000000000000000000000000000
           fix_pr: https://example/pr/1
           description: test
           source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
           sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
           path:
             - hop: 0
               method: M
               file: f
               line: 1
               role: {{pathRole}}
               tainted_value_in: x
               transformation: {{pathTransformation}}
               tainted_value_out: x
               dispatch: { kind: {{pathDispatchKind}} }
           sanitizer_absence: []
           """;
}
