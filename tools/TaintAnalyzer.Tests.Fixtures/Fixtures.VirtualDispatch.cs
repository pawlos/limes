// VirtualDispatchFixtures — types for VirtualOverrideIndex, ReverseCallGraph,
// and TaintWalker callvirt-override tests. Compiled into the Fixtures DLL and
// loaded via Cecil — not referenced as source.

namespace TaintAnalyzer.Tests.Fixtures.VirtualDispatch;

// ---- Non-virtual baseline ----

public class NonVirtualTarget
{
    public int Compute(int x) => x * 2;
}

// ---- Non-abstract virtual base + override (S2 regression guard) ----
// EnumerateAbstractRoots(NonAbstractVirtualDerived::Compute) must return empty:
// the root is `virtual` not `abstract`.

public class NonAbstractVirtualBase
{
    public virtual void Compute(int x) { }
}

public class NonAbstractVirtualDerived : NonAbstractVirtualBase
{
    public override void Compute(int x) { }
}

// ---- Implicit override chain (A -> B -> C) ----

public abstract class TransitiveA
{
    public abstract int Foo(int x);
}

internal abstract class TransitiveB : TransitiveA
{
    public override int Foo(int x) => x + 1;
}

internal class TransitiveC : TransitiveB
{
    public override int Foo(int x) => x + 2;
}

// ---- Simple implicit override (abstract + 1 concrete) ----

public abstract class SimpleBase
{
    public abstract void Process(byte[] data);
}

internal class SimpleDerived : SimpleBase
{
    public override void Process(byte[] data) { }
}

// ---- Explicit interface implementations ----

public interface IExplicitOperation
{
    void Bar();
}

internal class ExplicitImpl : IExplicitOperation
{
    void IExplicitOperation.Bar() { }
}

internal class CustomDisposable : System.IDisposable
{
    public void Dispose() { }
}

internal class CustomEnumerator : System.Collections.IEnumerator
{
    public object Current => null!;
    public bool MoveNext() => false;
    public void Reset() { }
}

// ---- Object.ToString override (denylist target) ----

internal class CustomToString
{
    public override string ToString() => "custom";
}

// ---- modreq(InAttribute) parameter override ----

public abstract class InParamBase
{
    public abstract void Accept(in int value);
}

internal class InParamDerived : InParamBase
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
    public string Stringify(object o) => o.ToString()!;  // callvirt Object::ToString
}

public class PublicCallerForDispose
{
    public void Run(System.IDisposable d) => d.Dispose();     // callvirt IDisposable::Dispose
}

public class PublicCallerForTransitive
{
    public int Run(TransitiveA a, int x) => a.Foo(x);         // callvirt TransitiveA::Foo
}

// Caller that uses `call` (not callvirt) on a virtual — verifies opcode-gated trigger.
// C# emits `call` for `base.X()` invocations.
internal class BaseCallSite : TransitiveB
{
    public int CallBaseDirectly(int x) => base.Foo(x); // call TransitiveB::Foo (not callvirt)
}
