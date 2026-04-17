namespace SixLabors.TaintAnalyzer.ValidateFixture;

public static class Vocabularies
{
    public static readonly HashSet<string> Roles = new(StringComparer.Ordinal)
    {
        "source", "propagator", "sanitizer", "sink",
    };

    public static readonly HashSet<string> Transformations = new(StringComparer.Ordinal)
    {
        "identity", "read_stream", "field_load", "arithmetic",
        "cast", "array_index", "stream_offset",
    };

    public static readonly HashSet<string> DispatchKinds = new(StringComparer.Ordinal)
    {
        "direct", "virtual", "interface", "async_continuation",
        "delegate", "reflection", "unknown",
    };
}
