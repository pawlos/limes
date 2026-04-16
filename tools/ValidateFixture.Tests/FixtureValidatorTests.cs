using Shouldly;
using SixLabors.TaintAnalyzer.ValidateFixture;
using Xunit;

namespace SixLabors.TaintAnalyzer.ValidateFixture.Tests;

public class FixtureValidatorTests
{
    [Fact]
    public void EmptyInput_ReturnsMissingVulnIdDiagnostic()
    {
        var validator = new FixtureValidator();
        var diagnostics = validator.Validate(yaml: "{}", snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX001" && d.Message.Contains("vuln_id"));
    }
}
