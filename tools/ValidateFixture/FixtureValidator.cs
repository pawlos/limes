using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SixLabors.TaintAnalyzer.ValidateFixture;

public sealed record Diagnostic(string Code, string Message);

public sealed class FixtureValidator
{
    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public IReadOnlyList<Diagnostic> Validate(string yaml, string? snippetsDir)
    {
        var diagnostics = new List<Diagnostic>();

        FixtureDocument? doc;
        try
        {
            doc = s_deserializer.Deserialize<FixtureDocument>(yaml);
        }
        catch (YamlException ex)
        {
            diagnostics.Add(new Diagnostic("FX000", $"malformed YAML: {ex.Message}"));
            return diagnostics;
        }

        if (doc is null)
        {
            diagnostics.Add(new Diagnostic("FX000", "document is empty"));
            return diagnostics;
        }

        Require(doc.VulnId, "FX001", "vuln_id", diagnostics);
        Require(doc.FixCommit, "FX002", "fix_commit", diagnostics);
        Require(doc.FixPr, "FX003", "fix_pr", diagnostics);
        Require(doc.Description, "FX004", "description", diagnostics);
        Require(doc.Source, "FX005", "source", diagnostics);
        Require(doc.Sink, "FX006", "sink", diagnostics);
        Require(doc.Path, "FX007", "path", diagnostics);
        Require(doc.SanitizerAbsence, "FX008", "sanitizer_absence", diagnostics);

        return diagnostics;
    }

    private static void Require<T>(T? value, string code, string name, List<Diagnostic> diagnostics)
    {
        if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
        {
            diagnostics.Add(new Diagnostic(code, $"missing required field: {name}"));
        }
    }
}
