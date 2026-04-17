using Shouldly;
using TaintAnalyzer.ValidateFixture;
using Xunit;

namespace TaintAnalyzer.ValidateFixture.Tests;

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

    [Fact]
    public void PathNode_MissingLine_ReportsFX020()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path:
              - hop: 0
                method: M
                file: f
                role: propagator
                tainted_value_in: x
                transformation: identity
                tainted_value_out: x
                dispatch: { kind: direct }
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX020" && d.Message.Contains("path[0].line"));
    }

    [Fact]
    public void SanitizerAbsence_MissingExpectedCheck_ReportsFX030()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence:
              - location: f:3
                tainted_value: x
                present_pre_fix: false
                present_post_fix: true
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX030" && d.Message.Contains("expected_check"));
    }

    [Fact]
    public void FileRef_NotInSnippetsDir_ReportsFX040()
    {
        using var temp = new TempDirectory();
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: missing.cs, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: missing.cs, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path:
              - hop: 0
                method: M
                file: missing.cs
                line: 5
                role: propagator
                tainted_value_in: x
                transformation: identity
                tainted_value_out: x
                dispatch: { kind: direct }
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: temp.Path);
        diagnostics.ShouldContain(d => d.Code == "FX040" && d.Message.Contains("missing.cs"));
    }

    [Fact]
    public void FileRef_LineOutOfRange_ReportsFX041()
    {
        using var temp = new TempDirectory();
        File.WriteAllText(Path.Combine(temp.Path, "present.cs"), "line1\nline2\n");
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: present.cs, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: present.cs, line: 1, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path:
              - hop: 0
                method: M
                file: present.cs
                line: 99
                role: propagator
                tainted_value_in: x
                transformation: identity
                tainted_value_out: x
                dispatch: { kind: direct }
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: temp.Path);
        diagnostics.ShouldContain(d => d.Code == "FX041" && d.Message.Contains("path[0]") && d.Message.Contains("99"));
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("fixture-tests-").FullName;
        public void Dispose() { try { Directory.Delete(Path, recursive: true); } catch { /* ignore */ } }
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
