namespace TaintAnalyzer;

public sealed class EnumeratorConfig
{
    public IReadOnlyList<string> ByteSourceTypes { get; init; } = s_defaultByteSourceTypes;
    public IReadOnlyList<string> DecoderTypeNamePatterns { get; init; } = s_defaultDecoderTypeNamePatterns;
    public IReadOnlyList<string> ExcludeNamespaces { get; init; } = s_defaultExcludeNamespaces;
    public IReadOnlyList<string> ExcludeTypePatterns { get; init; } = s_defaultExcludeTypePatterns;
    public IReadOnlyList<string> ExcludeMethodPatterns { get; init; } = s_defaultExcludeMethodPatterns;
    public bool IncludeThisField { get; init; }

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

    public static EnumeratorConfig Default { get; } = new();
}
