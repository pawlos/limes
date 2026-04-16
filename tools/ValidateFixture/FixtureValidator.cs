namespace SixLabors.TaintAnalyzer.ValidateFixture;

public sealed record Diagnostic(string Code, string Message);

public sealed class FixtureValidator
{
    public IReadOnlyList<Diagnostic> Validate(string yaml, string? snippetsDir)
    {
        var diagnostics = new List<Diagnostic>();
        if (!yaml.Contains("vuln_id"))
        {
            diagnostics.Add(new Diagnostic("FX001", "missing required field: vuln_id"));
        }
        return diagnostics;
    }
}
