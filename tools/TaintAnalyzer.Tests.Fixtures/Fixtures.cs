using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace TaintAnalyzer.Tests.Fixtures;

// Fixture 1: a minimal class with one identifiable method for AssemblyContext tests.
// Future tasks extend this file with additional types; this file is the single
// sibling-csproj source per the milestone-C spec.
public static class SimpleShapes
{
    public static int Identity(int x) => x;
}

public static class SinkFixtures
{
    // newarr shape: `new byte[size]` — emits `newarr`.
    public static byte[] NewByteArray(int size) => new byte[size];

    // ArrayPool.Rent shape.
    public static byte[] ArrayPoolRent(int size) => ArrayPool<byte>.Shared.Rent(size);

    // ReadOnlySpan<T>.Slice shape. Wraps a byte[] to a ROS<byte>, then slices.
    public static ReadOnlySpan<byte> SliceSpan(ReadOnlySpan<byte> src, int start, int length)
        => src.Slice(start, length);
}

// Throw-helpers — various shapes the predicate must classify.
public static class ThrowHelpers
{
    [DoesNotReturn]
    public static void ThrowOutOfRange(string name)
        => throw new ArgumentOutOfRangeException(name);

    [DoesNotReturn]
    public static void ThrowInvalidImageContentException(string msg)
        => throw new InvalidOperationException(msg);

    // Starts with "Throw", has [DoesNotReturn], but does NOT actually throw on all paths.
    // Predicate should still accept (DoesNotReturn takes precedence).
    [DoesNotReturn]
    public static void ThrowByAssertFailure()
    {
        // Intentionally empty — will raise ExecutionEngineException at runtime; still marked DoesNotReturn.
        throw new InvalidOperationException("unreachable");
    }

    // Non-throw-helpers — predicate must reject each.
    public static void DoWork() { }                              // no Throw prefix
    public static void ThrowSomething() { }                      // name OK but no DoesNotReturn, body returns
    public static int  ThrowInt() { throw new Exception(); }     // non-void return
}

// Sanitizer fixtures — different shapes the matcher must recognize.
public static class SanitizerFixtures
{
    // Shape A: compiler-negated branch (`if (x > y) throw` → IL `ble.un SAFE; <throw>; SAFE:`).
    public static void NegatedBranchThrow(int x, int y)
    {
        if (x > y)
        {
            ThrowHelpers.ThrowOutOfRange(nameof(x));
        }
    }

    // Shape B: explicit else branch (`if (x <= y) { /*safe*/ } else { throw }` →
    // typically IL `bgt ELSE; /*safe*/ br END; ELSE: <throw>; END:`).
    public static void NonNegatedBranchThrow(int x, int y)
    {
        if (x <= y)
        {
            // safe body, intentionally empty
        }
        else
        {
            ThrowHelpers.ThrowOutOfRange(nameof(x));
        }
    }

    // Shape C: return-early — `if (x < 0) return;`
    public static int ReturnEarlyOnNegative(int x)
    {
        if (x < 0) return -1;
        return x * 2;
    }

    // Shape D: no sanitizer — straight-line code, for negative tests.
    public static int NoSanitizer(int x) => x * 2;
}

// Each method has exactly one conditional branch, all with `x` as the left operand and `y` as the right,
// a throw-helper on the failure side. The matcher should produce (target=x, relation/upper|lower=y).
public static class SanitizerBoundsFixtures
{
    // Compiler-negated / Roslyn-idiomatic forms (semantic operator shown in the C# source;
    // Roslyn typically emits the equivalent-but-reversed IL opcode branching to the THROW body).
    public static void GtThrow(int x, int y) { if (x >  y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x <= y
    public static void LtThrow(int x, int y) { if (x <  y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x >= y
    public static void GeThrow(int x, int y) { if (x >= y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x <  y
    public static void LeThrow(int x, int y) { if (x <= y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x >  y
    public static void EqThrow(int x, int y) { if (x == y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x != y
    public static void NeThrow(int x, int y) { if (x != y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x == y

    // Explicit-else form (branch-target = throw).
    public static void GtThrowElse(int x, int y)
    {
        if (x <= y) { /* safe */ }
        else { ThrowHelpers.ThrowOutOfRange(nameof(x)); }
    }

    // Zero-equality form: `if (x == 0) throw`. Debug IL: `ldarg.0; ldc.i4.0; ceq; ...; brfalse SAFE;`.
    // The inner ldc.i4.0 is an operand of `==`, not a NOT-negation.
    public static void EqZeroThrow(int x) { if (x == 0) ThrowHelpers.ThrowOutOfRange(nameof(x)); }
}

// Abstract base + two concrete subclasses for CHA tests.
public abstract class Reader
{
    public abstract int Read(byte[] buffer, int offset, int count);
}

public sealed class BufferedReader : Reader       // sealed — CHA closure to exactly one target
{
    public override int Read(byte[] buffer, int offset, int count) => count;
}

public sealed class NetworkReader : Reader        // a second subclass, also sealed
{
    public override int Read(byte[] buffer, int offset, int count) => 0;
}

// Non-sealed non-abstract concrete class — external assemblies could subclass it,
// so a virtual call with this as the receiver type sets closure_boundary=true.
public class OpenBase
{
    public virtual int Compute(int x) => x + 1;
}

public static class CallGraphFixtures
{
    // Virtual call where the local is typed as the sealed subclass — flow-type narrowing
    // should pick this up and resolve to exactly one target (`BufferedReader.Read`).
    public static int ReadViaNarrowedLocal(byte[] buf)
    {
        BufferedReader r = new BufferedReader();   // local typed as sealed subclass
        return r.Read(buf, 0, buf.Length);
    }

    // Virtual call where the local is typed as the abstract base — no narrowing.
    // CHA closure within the analyzed assembly must find both overrides; since the
    // analyzed assembly contains both, closure_boundary = false and two resolved targets.
    public static int ReadViaAbstract(Reader r, byte[] buf)
        => r.Read(buf, 0, buf.Length);

    // Direct (static) call.
    public static int DirectCall()
        => SimpleShapes.Identity(1);

    // Virtual call into an external type (System.IO.Stream.ReadByte) — unresolvable within assembly.
    public static int ExternalVirtualCall(System.IO.Stream s) => s.ReadByte();

    // Virtual call where receiver is typed as a non-sealed non-abstract class.
    // Subclassing from external assemblies is possible → closure_boundary should be true.
    public static int CallViaOpenBase(int n)
    {
        OpenBase b = new OpenBase();
        return b.Compute(n);
    }
}

public static class WalkerFixtures
{
    // Straight-line taint: tainted param `size` flows through a local into `new byte[size]`.
    public static byte[] IntraMethodAllocation(int size)
    {
        int n = size + 4;                // arithmetic transformation
        byte[] buf = new byte[n];        // newarr sink, tainted size
        return buf;
    }

    // Negative: no tainted input reaches newarr.
    public static byte[] IntraMethodNoTaint()
    {
        return new byte[16];
    }
}

public sealed class FieldTaintHost
{
    public int payloadSize;
    public int safeConstant = 16;

    // Stores tainted `size` to `this.payloadSize`. Walker should mark `payloadSize` as newly tainted on `this`.
    public void StoreToField(int size)
    {
        this.payloadSize = size;
    }

    // Reads `this.payloadSize` (pre-tainted by caller's summary) and uses it at a sink.
    public byte[] AllocateFromField()
    {
        return new byte[this.payloadSize];
    }

    // Reads `this.safeConstant` — should not be tainted since no caller has tainted it.
    public byte[] AllocateFromSafeConstant()
    {
        return new byte[this.safeConstant];
    }

    // Static variant: receives a tainted `FieldTaintHost` and loads its `payloadSize` to allocate.
    // Exercises the "receiver slot is tainted → ldfld propagates taint" path distinct from
    // the `this.field` path covered elsewhere.
    public static byte[] AllocateFromTaintedHost(FieldTaintHost host)
    {
        return new byte[host.payloadSize];
    }
}
