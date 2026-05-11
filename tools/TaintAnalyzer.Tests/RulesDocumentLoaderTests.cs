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
        doc.SourceMethods![0].Signature.ShouldContain("BmpDecoderCore::Decode");
        doc.SourceMethods[0].SeedThisFields.ShouldBeNull();
    }

    [Fact]
    public void Load_ObjectFormSourceMethod_ParsesSignatureAndSeedThisFields()
    {
        const string yaml = """
            vuln_id: parquet-dotnet-738
            source_methods:
              - signature: Parquet.Meta.Proto.ThriftCompactProtocolReader::ReadBinary()
                seed_this_fields:
                  - _inputStream
            """;

        var doc = RulesDocument.Load(yaml);

        doc.SourceMethods.ShouldHaveSingleItem();
        doc.SourceMethods![0].Signature.ShouldContain("ThriftCompactProtocolReader::ReadBinary");
        doc.SourceMethods[0].SeedThisFields.ShouldNotBeNull();
        doc.SourceMethods[0].SeedThisFields!.ShouldContain("_inputStream");
    }

    [Fact]
    public void Load_MixedScalarAndObjectEntries_BothShapesCoexist()
    {
        // Backward compatibility: a single rules file may mix the v0 string form with the
        // v0.1 object form. The first entry has no seed fields; the second seeds a `this`-field.
        const string yaml = """
            source_methods:
              - Ns.A::Plain(System.Int32)
              - signature: Ns.B::WithSeed()
                seed_this_fields: [field1, field2]
            """;

        var doc = RulesDocument.Load(yaml);

        doc.SourceMethods!.Count.ShouldBe(2);
        doc.SourceMethods[0].Signature.ShouldBe("Ns.A::Plain(System.Int32)");
        doc.SourceMethods[0].SeedThisFields.ShouldBeNull();
        doc.SourceMethods[1].Signature.ShouldBe("Ns.B::WithSeed()");
        doc.SourceMethods[1].SeedThisFields.ShouldBe(new[] { "field1", "field2" });
    }

    [Fact]
    public void Load_ObjectFormMissingSignature_Throws()
    {
        const string yaml = """
            source_methods:
              - seed_this_fields: [_inputStream]
            """;

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("'signature'");
    }

    [Fact]
    public void Load_ObjectFormMalformedSignature_StillValidatesShape()
    {
        // Signature shape validation applies to the object form too — Cecil-incompatible
        // signatures should still error out at startup with an actionable message.
        const string yaml = """
            source_methods:
              - signature: NoDoubleColon(Arg)
                seed_this_fields: [_x]
            """;

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("missing '::'");
    }

    [Fact]
    public void Load_ObjectFormEmptySeedFieldName_Throws()
    {
        const string yaml = """
            source_methods:
              - signature: Ns.T::M()
                seed_this_fields:
                  - ""
            """;

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("seed_this_fields");
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
    public void Load_EmptySourceMethodsList_AcceptsAndReturnsEmpty()
    {
        const string yaml = """
            vuln_id: scan-empty
            source_methods: []
            """;

        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBe("scan-empty");
        doc.SourceMethods.ShouldNotBeNull();
        doc.SourceMethods!.ShouldBeEmpty();
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
        // Genuinely malformed YAML — unterminated single-quoted scalar — should surface as a
        // YAML-parser error wrapped with the `malformed YAML:` prefix.
        const string yaml = "source_methods:\n  - 'unterminated\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("YAML");
    }
}
