namespace TaintAnalyzer;

public readonly record struct StackSlot(bool Tainted, string Provenance)
{
    public static readonly StackSlot Untainted = new(false, "");

    // Sentinel "this" slot — used to seed Args[0] for instance methods so the walker can
    // reliably identify `this`-rooted receivers regardless of how complex the value expression
    // before a stfld/call is. (FindStfldReceiverSource's previous-previous heuristic broke for
    // `this.F = methodCall(args)` — multi-instruction value expressions push the call result
    // between ldarg.0 and stfld.)
    public static readonly StackSlot ThisRef = new(false, "this");

    public static StackSlot TaintedWith(string provenance) => new(true, provenance);
}

public sealed class SymbolicStack
{
    private readonly StackSlot[] _slots = new StackSlot[64];
    public int Depth { get; private set; }

    public void Push(StackSlot s)
    {
        if (Depth >= _slots.Length)
        {
            throw new InvalidOperationException("symbolic stack overflow");
        }
        _slots[Depth++] = s;
    }

    public StackSlot Pop()
    {
        if (Depth == 0)
        {
            throw new InvalidOperationException("symbolic stack underflow");
        }
        return _slots[--Depth];
    }

    public StackSlot Peek(int offsetFromTop = 0)
    {
        int idx = Depth - 1 - offsetFromTop;
        if (idx < 0)
        {
            throw new InvalidOperationException("symbolic stack underflow on peek");
        }
        return _slots[idx];
    }

    public bool AnyTainted()
    {
        for (int i = 0; i < Depth; i++)
        {
            if (_slots[i].Tainted) return true;
        }
        return false;
    }

    public void Clear() => Depth = 0;
}
