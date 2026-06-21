namespace TaintAnalyzer;

// A CWE-835 finding: a read loop with no completion check. Not a taint path.
public sealed class LoopFinding
{
    public required string Method { get; init; }          // user-facing "Namespace.Type.Method"
    public required string ReadApi { get; init; }          // e.g. "pipe_reader_read_async"
    public required bool ResolvedViaAsync { get; init; }
    public required string LoopFile { get; init; }
    public required int LoopLine { get; init; }
    public required string ReadFile { get; init; }
    public required int ReadLine { get; init; }
}
