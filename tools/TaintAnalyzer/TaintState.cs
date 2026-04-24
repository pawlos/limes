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
}
