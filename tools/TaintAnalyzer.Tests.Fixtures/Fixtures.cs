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
