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

    public static readonly FrozenSet<string> Relations = new HashSet<string>(StringComparer.Ordinal)
    {
        "<", "<=", "==", "!=", ">=", ">",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> FailureKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "throw", "return_early", "clamp", "skip",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "allocation", "span_access",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
        "http_content_read", "http_client_read",
    }.ToFrozenSet(StringComparer.Ordinal);
}
