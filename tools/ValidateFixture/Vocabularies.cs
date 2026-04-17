using System.Collections.Frozen;

namespace TaintAnalyzer.ValidateFixture;

public static class Vocabularies
{
    public static readonly FrozenSet<string> Roles = new HashSet<string>(StringComparer.Ordinal)
    {
        "source", "propagator", "sanitizer", "sink",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> Transformations = new HashSet<string>(StringComparer.Ordinal)
    {
        "identity", "read_stream", "field_load", "arithmetic",
        "cast", "array_index", "stream_offset",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> DispatchKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "direct", "virtual", "interface", "async_continuation",
        "delegate", "reflection", "unknown",
    }.ToFrozenSet(StringComparer.Ordinal);
}
