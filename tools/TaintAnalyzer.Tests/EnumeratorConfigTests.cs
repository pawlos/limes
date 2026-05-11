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
}
