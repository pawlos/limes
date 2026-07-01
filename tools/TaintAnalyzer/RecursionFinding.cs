namespace TaintAnalyzer;

// A CWE-674 finding: recursion with no cycle/depth guard. Not a taint path.
//   Kind "self"   — a method that calls itself directly.
//   Kind "mutual" — a call-graph cycle (SCC of >= 2 methods, e.g. A -> B -> A); `Cycle` lists
//                   the member methods and `Method` is the lexicographically smallest of them.
public sealed class RecursionFinding
{
    public required string Method { get; init; }          // user-facing "Namespace.Type.Method"
    public required bool ResolvedViaAsync { get; init; }
    public required string CallFile { get; init; }         // the recursive call site
    public required int CallLine { get; init; }
    public string Kind { get; init; } = "self";
    public IReadOnlyList<string>? Cycle { get; init; }      // set only for Kind == "mutual"
}
