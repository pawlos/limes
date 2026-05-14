using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer;

public sealed class EnumeratorConfig
{
    public IReadOnlyList<string> ByteSourceTypes { get; init; } = s_defaultByteSourceTypes;
    public IReadOnlyList<string> DecoderTypeNamePatterns { get; init; } = s_defaultDecoderTypeNamePatterns;
    public IReadOnlyList<string> ExcludeNamespaces { get; init; } = s_defaultExcludeNamespaces;
    public IReadOnlyList<string> ExcludeTypePatterns { get; init; } = s_defaultExcludeTypePatterns;
    public IReadOnlyList<string> ExcludeMethodPatterns { get; init; } = s_defaultExcludeMethodPatterns;
    public bool IncludeThisField { get; init; }
    public bool IncludeVirtualOverrides { get; init; }

    private static readonly string[] s_defaultByteSourceTypes =
    {
        "System.IO.Stream",
        "System.IO.BinaryReader",
        "System.Byte[]",
        "System.ReadOnlySpan`1<System.Byte>",
        "System.ReadOnlySequence`1<System.Byte>",
        "System.Memory`1<System.Byte>",
        "System.ReadOnlyMemory`1<System.Byte>",
    };

    private static readonly string[] s_defaultDecoderTypeNamePatterns =
        { "*Reader", "*Decoder", "*Deserializer", "*Parser" };

    private static readonly string[] s_defaultExcludeNamespaces =
        { "System.*", "Microsoft.*" };

    private static readonly string[] s_defaultExcludeTypePatterns =
        { "*Test*", "*Mock*" };

    private static readonly string[] s_defaultExcludeMethodPatterns =
        { "ToString", "GetHashCode", "Equals" };

    private static readonly IDeserializer s_deserializer =
        new DeserializerBuilder()
            .IgnoreUnmatchedProperties()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

    public static EnumeratorConfig Default { get; } = new();

    public static EnumeratorConfig Load(string yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return Default;
        }

        Raw? raw;
        try
        {
            raw = s_deserializer.Deserialize<Raw>(yaml);
        }
        catch (YamlException ex)
        {
            throw new EnumeratorConfigException($"malformed enumerator-config: {ex.Message}", ex);
        }

        raw ??= new Raw();
        return new EnumeratorConfig
        {
            ByteSourceTypes = (IReadOnlyList<string>?)raw.ByteSourceTypes ?? s_defaultByteSourceTypes,
            DecoderTypeNamePatterns = (IReadOnlyList<string>?)raw.DecoderTypeNamePatterns ?? s_defaultDecoderTypeNamePatterns,
            ExcludeNamespaces = (IReadOnlyList<string>?)raw.ExcludeNamespaces ?? s_defaultExcludeNamespaces,
            ExcludeTypePatterns = (IReadOnlyList<string>?)raw.ExcludeTypePatterns ?? s_defaultExcludeTypePatterns,
            ExcludeMethodPatterns = (IReadOnlyList<string>?)raw.ExcludeMethodPatterns ?? s_defaultExcludeMethodPatterns,
        };
    }

    // Private helper class for YAML deserialization. Lists are nullable so we can
    // distinguish "key missing" (fall back to default) from "key present but empty"
    // (use the empty list).
    private sealed class Raw
    {
        public List<string>? ByteSourceTypes { get; set; }
        public List<string>? DecoderTypeNamePatterns { get; set; }
        public List<string>? ExcludeNamespaces { get; set; }
        public List<string>? ExcludeTypePatterns { get; set; }
        public List<string>? ExcludeMethodPatterns { get; set; }
    }
}

public sealed class EnumeratorConfigException : Exception
{
    public EnumeratorConfigException(string message) : base(message) { }
    public EnumeratorConfigException(string message, Exception inner) : base(message, inner) { }
}
