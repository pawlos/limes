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
        "cast", "array_index", "stream_offset", "sql_quote_escape",
    }.ToFrozenSet(StringComparer.Ordinal);

    // Sanitizers that rewrite the value instead of bounding it. They carry no establishes_bound
    // and no on_failure, so FX023's required-field check does not apply to them.
    public static readonly FrozenSet<string> ValueTransformingSanitizers = new HashSet<string>(StringComparer.Ordinal)
    {
        "sql_quote_escape",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> DispatchKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "direct", "virtual", "interface", "async_continuation",
        "delegate", "reflection", "unknown",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> Relations = new HashSet<string>(StringComparer.Ordinal)
    {
        "<", "<=", "==", "!=", ">=", ">", "regex_match",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> FailureKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "throw", "return_early", "clamp", "skip",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "allocation", "span_access", "sql_injection",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
        "http_content_read", "http_client_read",
        "sql_command_text", "sql_command_builder_append", "sql_command_builder_append_raw",
    }.ToFrozenSet(StringComparer.Ordinal);
}
