using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class EnumeratorConfigTests
{
    [Fact]
    public void Default_ContainsExpectedByteSourceTypes()
    {
        var cfg = EnumeratorConfig.Default;

        cfg.ByteSourceTypes.ShouldContain("System.IO.Stream");
        cfg.ByteSourceTypes.ShouldContain("System.IO.BinaryReader");
        cfg.ByteSourceTypes.ShouldContain("System.Byte[]");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlySpan`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlySequence`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.Memory`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlyMemory`1<System.Byte>");
    }

    [Fact]
    public void Default_ContainsExpectedDecoderPatterns()
    {
        EnumeratorConfig.Default.DecoderTypeNamePatterns.ShouldBe(
            new[] { "*Reader", "*Decoder", "*Deserializer", "*Parser" });
    }

    [Fact]
    public void Default_ExcludesBclNamespacesAndTestPatterns()
    {
        EnumeratorConfig.Default.ExcludeNamespaces.ShouldBe(new[] { "System.*", "Microsoft.*" });
        EnumeratorConfig.Default.ExcludeTypePatterns.ShouldBe(new[] { "*Test*", "*Mock*" });
        EnumeratorConfig.Default.ExcludeMethodPatterns.ShouldBe(new[] { "ToString", "GetHashCode", "Equals" });
    }

    [Fact]
    public void Default_IncludeThisFieldIsFalse()
    {
        EnumeratorConfig.Default.IncludeThisField.ShouldBeFalse();
    }

    [Fact]
    public void Load_EmptyDocument_EqualsDefault()
    {
        var cfg = EnumeratorConfig.Load("");

        cfg.ByteSourceTypes.ShouldBe(EnumeratorConfig.Default.ByteSourceTypes);
        cfg.DecoderTypeNamePatterns.ShouldBe(EnumeratorConfig.Default.DecoderTypeNamePatterns);
        cfg.ExcludeNamespaces.ShouldBe(EnumeratorConfig.Default.ExcludeNamespaces);
    }

    [Fact]
    public void Load_PartialOverride_KeepsOtherDefaults()
    {
        const string yaml = """
            byte_source_types:
              - My.Custom.Stream
            """;

        var cfg = EnumeratorConfig.Load(yaml);

        cfg.ByteSourceTypes.ShouldBe(new[] { "My.Custom.Stream" });
        // Defaults preserved for unspecified keys.
        cfg.ExcludeNamespaces.ShouldBe(new[] { "System.*", "Microsoft.*" });
    }

    [Fact]
    public void Load_EmptyExcludeList_AllowsAllNamespaces()
    {
        const string yaml = "exclude_namespaces: []\n";

        var cfg = EnumeratorConfig.Load(yaml);

        cfg.ExcludeNamespaces.ShouldBeEmpty();
    }

    [Fact]
    public void Load_UnknownKeys_AreIgnored()
    {
        const string yaml = """
            byte_source_types:
              - Foo
            unknown_future_key: bar
            """;

        var cfg = EnumeratorConfig.Load(yaml);

        cfg.ByteSourceTypes.ShouldBe(new[] { "Foo" });
    }

    [Fact]
    public void Load_MalformedYaml_Throws()
    {
        const string yaml = "byte_source_types: [unterminated";

        var ex = Should.Throw<EnumeratorConfigException>(() => EnumeratorConfig.Load(yaml));
        ex.InnerException.ShouldNotBeNull();
        ex.InnerException.ShouldBeAssignableTo<YamlDotNet.Core.YamlException>();
    }
}
