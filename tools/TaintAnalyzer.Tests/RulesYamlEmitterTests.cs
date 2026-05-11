using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RulesYamlEmitterTests
{
    [Fact]
    public void Emit_ScalarEntries_ProducesYamlList()
    {
        var entries = new List<SourceMethodEntry>
        {
            new() { Signature = "Foo.Bar::Baz(System.IO.Stream)" },
            new() { Signature = "Foo.Bar::Qux(System.Byte[])" },
        };

        var yaml = RulesYamlEmitter.Emit("scan-foo", entries);

        yaml.ShouldContain("vuln_id: scan-foo");
        yaml.ShouldContain("Foo.Bar::Baz(System.IO.Stream)");
        yaml.ShouldContain("Foo.Bar::Qux(System.Byte[])");
    }

    [Fact]
    public void Emit_WithSeedFields_ProducesMappingForm()
    {
        var entries = new List<SourceMethodEntry>
        {
            new()
            {
                Signature = "Foo.MyReader::Read()",
                SeedThisFields = new List<string> { "_input" },
            },
        };

        var yaml = RulesYamlEmitter.Emit("scan-foo", entries);

        yaml.ShouldContain("signature: Foo.MyReader::Read()");
        yaml.ShouldContain("seed_this_fields:");
        yaml.ShouldContain("- _input");
    }

    [Fact]
    public void Emit_EmptyEntries_ProducesEmptyList()
    {
        var yaml = RulesYamlEmitter.Emit("scan-empty", new List<SourceMethodEntry>());

        yaml.ShouldContain("vuln_id: scan-empty");
        yaml.ShouldContain("source_methods: []");
    }

    [Fact]
    public void Emit_RoundTripsThroughRulesDocumentLoad()
    {
        var entries = new List<SourceMethodEntry>
        {
            new() { Signature = "Foo.Bar::Baz(System.IO.Stream)" },
            new()
            {
                Signature = "Foo.MyReader::Read()",
                SeedThisFields = new List<string> { "_input" },
            },
        };

        var yaml = RulesYamlEmitter.Emit("scan-rt", entries);
        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBe("scan-rt");
        doc.SourceMethods.ShouldNotBeNull();
        doc.SourceMethods!.Count.ShouldBe(2);
        doc.SourceMethods[0].Signature.ShouldBe("Foo.Bar::Baz(System.IO.Stream)");
        doc.SourceMethods[1].Signature.ShouldBe("Foo.MyReader::Read()");
        doc.SourceMethods[1].SeedThisFields.ShouldNotBeNull();
        doc.SourceMethods[1].SeedThisFields!.ShouldContain("_input");
    }

    [Fact]
    public void Emit_EmptyEntries_RoundTrips()
    {
        var yaml = RulesYamlEmitter.Emit("scan-empty", new List<SourceMethodEntry>());
        var doc = RulesDocument.Load(yaml);

        doc.SourceMethods.ShouldNotBeNull();
        doc.SourceMethods!.ShouldBeEmpty();
    }
}
