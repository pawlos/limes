using Mono.Cecil;

namespace TaintAnalyzer;

// Mutable state threaded through TaintWalker's forward pass over one method body.
public sealed class TaintState
{
    public SymbolicStack Stack { get; } = new();

    // Local variable taint by `VariableDefinition.Index`.
    public Dictionary<int, StackSlot> Locals { get; } = new();

    // Argument taint (by index; 0 = `this` for instance methods).
    public Dictionary<int, StackSlot> Args { get; } = new();

    // Field taint on the `this` receiver, keyed by `FieldDefinition.FullName`.
    public Dictionary<string, StackSlot> ThisFields { get; } = new();

    // Static-field taint, keyed by `FieldDefinition.FullName`.
    public Dictionary<string, StackSlot> StaticFields { get; } = new();

    // First (file:line) at which a local was assigned a tainted value during this method's
    // forward walk. Linear walking visits all branches sequentially and a single local can be
    // re-assigned across branches with different tainted provenances; the LAST stloc's
    // provenance wins on the symbolic stack. For sanitizer-absence location, however, we want
    // the *earliest* point at which taint enters the local — that's where a guard would
    // semantically belong (matching the human-authored fixtures).
    public Dictionary<int, (string File, int Line, string Provenance)> FirstLocalTaintLine { get; } = new();
}
