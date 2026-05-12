// VirtualDispatchFixtures — types for VirtualOverrideIndex, ReverseCallGraph,
// and TaintWalker callvirt-override tests. Compiled into the Fixtures DLL and
// loaded via Cecil — not referenced as source.

namespace TaintAnalyzer.Tests.Fixtures.VirtualDispatch;

// ---- Non-virtual baseline ----

public class NonVirtualTarget
{
    public int Compute(int x) => x * 2;
}

// ---- Implicit override chain (A -> B -> C) ----

public abstract class TransitiveA
{
    public abstract int Foo(int x);
}

public abstract class TransitiveB : TransitiveA
{
    public override int Foo(int x) => x + 1;
}

public class TransitiveC : TransitiveB
{
    public override int Foo(int x) => x + 2;
}

// ---- Simple implicit override (abstract + 1 concrete) ----

public abstract class SimpleBase
{
    public abstract void Process(byte[] data);
}

public class SimpleDerived : SimpleBase
{
    public override void Process(byte[] data) { }
}

// ---- Two-override fan-out for TaintWalker merge tests ----

public abstract class TwoOverrideBase
{
    // arg is a tainted-byte-source candidate
    public abstract byte[] Read(byte[] input);
}

public class CleanOverride : TwoOverrideBase
{
    public override byte[] Read(byte[] input) => System.Array.Empty<byte>();
}

public class TaintingOverride : TwoOverrideBase
{
    // Allocation sink driven by input.Length — flows tainted byte-array length
    // into newarr; TaintWalker should record ReachedSink + ReturnsTainted.
    public override byte[] Read(byte[] input) => new byte[input.Length];
}

public class ThrowingOverride : TwoOverrideBase
{
    public override byte[] Read(byte[] input)
    {
        if (input.Length > 1024) throw new System.IO.InvalidDataException();
        return new byte[input.Length];
    }
}

// ---- Explicit interface implementations ----

public interface IExplicitOperation
{
    void Bar();
}

public class ExplicitImpl : IExplicitOperation
{
    void IExplicitOperation.Bar() { }
}

public class CustomDisposable : System.IDisposable
{
    public void Dispose() { }
}

public class CustomEnumerator : System.Collections.IEnumerator
{
    public object Current => null!;
    public bool MoveNext() => false;
    public void Reset() { }
}

// ---- Object.ToString override (denylist target) ----

public class CustomToString
{
    public override string ToString() => "custom";
}

// ---- modreq(InAttribute) parameter override ----

public abstract class InParamBase
{
    public abstract void Accept(in int value);
}

public class InParamDerived : InParamBase
{
    public override void Accept(in int value) { }
}

// ---- Callsite hosts for ReverseCallGraph + TaintWalker tests ----

public class PublicCallerForOverride
{
    private readonly SimpleBase _target;
    public PublicCallerForOverride(SimpleBase target) => _target = target;
    public void Call(byte[] data) => _target.Process(data); // callvirt SimpleBase::Process
}

public class PublicCallerForToString
{
    public string Stringify(object o) => o.ToString() ?? "";  // callvirt Object::ToString
}

public class PublicCallerForDispose
{
    public void Run(System.IDisposable d) => d.Dispose();     // callvirt IDisposable::Dispose
}

public class PublicCallerForTransitive
{
    public int Run(TransitiveA a, int x) => a.Foo(x);         // callvirt TransitiveA::Foo
}

public class PublicCallerForTwoOverride
{
    public byte[] Run(TwoOverrideBase t, byte[] data) => t.Read(data); // callvirt TwoOverrideBase::Read
}

// Caller that uses `call` (not callvirt) on a virtual — verifies opcode-gated trigger.
// C# emits `call` for `base.X()` invocations.
public class BaseCallSite : TransitiveB
{
    public int CallBaseDirectly(int x) => base.Foo(x); // call TransitiveB::Foo (not callvirt)
}
