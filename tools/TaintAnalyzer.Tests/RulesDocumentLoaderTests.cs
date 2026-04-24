using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RulesDocumentLoaderTests
{
    [Fact]
    public void Load_ValidDocument_PopulatesFields()
    {
        const string yaml = """
            vuln_id: imagesharp-3074
            source_methods:
              - SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
            """;

        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBe("imagesharp-3074");
        doc.SourceMethods.ShouldHaveSingleItem();
        doc.SourceMethods[0].ShouldContain("BmpDecoderCore::Decode");
    }

    [Fact]
    public void Load_MissingSourceMethods_Throws()
    {
        const string yaml = "vuln_id: imagesharp-3074\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("source_methods");
        ex.Message.ShouldContain("required");
    }

    [Fact]
    public void Load_EmptySourceMethodsList_Throws()
    {
        const string yaml = """
            vuln_id: imagesharp-3074
            source_methods: []
            """;

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("source_methods");
        ex.Message.ShouldContain("empty");
    }

    [Fact]
    public void Load_OmittedVulnId_IsNull()
    {
        const string yaml = """
            source_methods:
              - Ns.Type::M(System.Int32)
            """;

        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBeNull();
    }

    [Theory]
    [InlineData("NoDoubleColon(Arg)", "missing '::'")]
    [InlineData("Ns.Type::Method", "missing '(' / ')'")]
    [InlineData("Ns.Type::Method(Arg", "missing '(' / ')'")]
    [InlineData("Ns.Type::Method Arg)", "no spaces")]
    [InlineData("Ns.Type::(Arg)", "empty method name")]
    [InlineData("::Method(Arg)", "empty declaring type")]
    public void Load_MalformedSignature_ThrowsWithActionableMessage(string sig, string expectedMessageFragment)
    {
        var yaml = $"source_methods:\n  - {sig}\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain(sig);
        ex.Message.ShouldContain(expectedMessageFragment);
    }

    [Fact]
    public void Load_MalformedYaml_ThrowsWithContext()
    {
        const string yaml = "source_methods:\n  - [broken\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("YAML");
    }
}
