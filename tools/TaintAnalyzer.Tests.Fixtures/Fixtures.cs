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

    // Localloc shape: `Span<byte> buf = stackalloc byte[size];` — emits `localloc`.
    // Returning `Length` (not the buffer) keeps the buffer's lifetime confined to this method,
    // which is what real callers do; the IL shape is what the analyzer cares about.
    public static int StackallocBytes(int size)
    {
        Span<byte> buf = stackalloc byte[size];
        return buf.Length;
    }
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

public sealed class SanitizerInContext
{
    // `n` tainted → sanitizer hop → sink. Sanitizer does not clear taint (per spec), so sink still fires.
    public byte[] SanitizedAllocate(int n)
    {
        if (n > 1024) ThrowHelpers.ThrowOutOfRange(nameof(n));
        return new byte[n];
    }
}

public sealed class CrossMethodHost
{
    public int stored;

    // Cross-method: caller passes tainted `n` to helper; helper stores to this.stored.
    public void CrossMethodStore(int n)
    {
        StoreHelper(n);
    }

    public void StoreHelper(int n)
    {
        this.stored = n;
    }

    // Cross-method: caller reads this.stored (pre-tainted via StoreHelper) and uses at sink.
    public byte[] CrossMethodAllocate()
    {
        StoreHelper(1);         // untainted constant; stored becomes untainted in isolation
        return new byte[this.stored];
    }

    // Tainted return: helper returns its tainted arg; caller uses the return at a sink.
    public byte[] CrossMethodTaintedReturn(int n)
    {
        int m = Echo(n);
        return new byte[m];
    }

    private static int Echo(int x) => x;

    // Exercises milestone-F N1: tainted call-return is stloc'd to local `m`, then `m + 4`
    // produces an arithmetic propagator hop. Without N1, the arithmetic hop's
    // `tainted_value_in` is the synthetic call-return provenance (e.g. "CrossMethodHost.Echo(n)").
    // With N1, it should be the local name "m".
    public byte[] StlocReturnThenArithmetic(int n)
    {
        int m = Echo(n);
        int p = m + 4;
        return new byte[p];
    }
}

public sealed class FieldChainHost
{
    public Inner? inner;

    public sealed class Inner
    {
        public int Offset;
    }

    // Comparison left operand is `this.inner.Offset`-style chain.
    // The C# expression `this.inner!.Offset` compiles to `ldarg.0; ldfld inner; ldfld Offset` in
    // Debug IL — we don't need the actual Nullable<T>.Value indirection to exercise the chain,
    // a non-null reference field with a value field on it produces the same multi-ldfld pattern.
    public void GuardOnFieldChain(int limit)
    {
        if (this.inner!.Offset > limit)
        {
            ThrowHelpers.ThrowOutOfRange(nameof(limit));
        }
    }
}

public static class SpanIndexFixtures
{
    public static byte IndexSpan(ReadOnlySpan<byte> src, int idx)
    {
        return src[idx];
    }
}

public sealed class MultiSanitizerHost
{
    public int payloadSize;

    // Two sanitizers in one method, both throwing if their respective check fails.
    // Mirrors ImageSharp's #3074 ReadInfoHeader shape (two guards then an allocation).
    public byte[] AllocateWithTwoGuards(int n, int max)
    {
        if (n < 0)   ThrowHelpers.ThrowOutOfRange(nameof(n));
        if (n > max) ThrowHelpers.ThrowOutOfRange(nameof(n));
        return new byte[n];
    }
}

public sealed class GetterTaintHost
{
    public int data;

    // Getter: returns this.data; takes no args. ReturnsTainted should be true when called
    // with a pre-tainted state.ThisFields["data"]. WalkWithSeed exercises this directly.
    public int GetData() => this.data;

    // Caller: pre-taint this.data via SetData(tainted), then GetData() returns tainted, sink fires.
    public void SetData(int value)
    {
        this.data = value;
    }

    public byte[] CrossMethodGetterToSink(int n)
    {
        SetData(n);                // taints this.data
        int x = GetData();         // returns this.data (tainted), but bitmask=0 since GetData has no args
        return new byte[x];        // sink — must fire
    }
}

public sealed class NullableFieldHost
{
    public InnerStruct? wrapped;

    public struct InnerStruct
    {
        public int Limit;
    }

    // Mirrors the ImageSharp #3074 shape: this.<Nullable_field>.Value.<scalar>.
    // Debug IL: ldarg.0; ldflda wrapped; call get_Value; ldfld Limit; ldarg.1; cgt; brfalse SAFE; throw...
    public void GuardOnNullableValueChain(int limit)
    {
        if (this.wrapped!.Value.Limit > limit)
        {
            ThrowHelpers.ThrowOutOfRange(nameof(limit));
        }
    }

    // Reads `this.wrapped.Value.Limit` (when wrapped is pre-tainted via the seed API) and
    // allocates with that size. Verifies ldflda + Nullable<T>::get_Value chain preserves taint
    // (the actual #3074 shape: this.fileHeader.Value.Offset → arithmetic → new byte[]).
    public byte[] AllocateFromNullableValueChain()
    {
        return new byte[this.wrapped!.Value.Limit];
    }
}

// Stand-in for a stream-like API. In-assembly so the walker can recurse into its methods.
public sealed class FakeStream
{
    private int _pos;

    public int NextByte()
    {
        // Simplified read: returns a byte from an internal buffer. Real semantics don't matter —
        // the walker treats this as "instance method on a stream-like type, returns int."
        return _pos++;
    }
}

public sealed class ExceptionHandlerHost
{
    // Method with a try/catch — used to verify the walker doesn't crash on handler entry.
    public byte[] AllocateWithCatch(int size)
    {
        try
        {
            return new byte[size];
        }
        catch (Exception)
        {
            return Array.Empty<byte>();
        }
    }

    // Method with a try/finally — Finally handlers DO NOT receive the exception object.
    // Verifies the walker doesn't push a phantom slot for Finally.
    public byte[] AllocateWithFinally(int size)
    {
        try
        {
            return new byte[size];
        }
        finally
        {
            // no-op
        }
    }
}

public sealed class CtorTaintHost
{
    public sealed class SizeWrapper
    {
        public int Value;
        public SizeWrapper(int value) { Value = value; }
    }

    // newobj with a tainted constructor arg → the new object reference is tainted.
    // Reading w.Value via ldfld on a tainted receiver should propagate taint to the result.
    public byte[] AllocateViaWrapperCtor(int size)
    {
        var w = new SizeWrapper(size);
        return new byte[w.Value];
    }
}

// Tainted-receiver external call: System.IO.Stream.ReadByte() is unresolved against the
// analyzed assembly, so the walker hits the "external" branch in HandleCall. Without the
// external-tainted-input → tainted-return fix, the chain `taintedStream.ReadByte()` drops
// taint at the call boundary; with the fix, captured field ends up newly tainted.
public sealed class ExternalReceiverHost
{
    public int captured;

    public void StoreFromExternalReadByte(System.IO.Stream s)
    {
        int n = s.ReadByte();
        this.captured = n;
    }
}

// Buffer-fill semantics: System.IO.Stream.Read(byte[], int, int) is an external call where
// receiver (stream) is tainted and the buffer arg is mutated by the call. Our model
// approximates this by tainting the local that produced the buffer arg (since we don't
// track per-method mutation summaries). Without GAP-A, `this.captured = buf` doesn't add
// captured to NewlyTaintedThisFields; with GAP-A, it does.
public sealed class BufferFillHost
{
    public byte[]? captured;

    public void FillBufferThenStore(System.IO.Stream s)
    {
        byte[] buf = new byte[16];
        _ = s.Read(buf, 0, 16);
        this.captured = buf;
    }
}

// Drives U2 (same-method identity-hop filter). The decoder body invokes ReadLength twice;
// between the two calls it performs an arithmetic op that emits a Decode-context hop.
// That arithmetic hop becomes hops[^1] before the second ReadLength call, so U2's
// same-method guard fires and suppresses the redundant second Decode/identity hop.
// ReadLength delegates to ReadByte so its walk emits a ReadLength-context identity hop —
// those callee hops are preserved because their method label differs from Decode's.
public static class IdentityFilterFixtures
{
    public static int[] Decode(byte[] stream)
    {
        var lengthA = ReadLength(stream);
        var adjusted = lengthA + lengthA;    // arithmetic — emits a Decode/arithmetic hop
        var lengthB = ReadLength(stream);    // U2 fires: hops[^1] is Decode/arithmetic
        return new int[adjusted + lengthB];  // sink — array allocation with tainted size
    }

    public static int ReadLength(byte[] s) => ReadByte(s, 0);

    public static int ReadByte(byte[] s, int index) => s[index];
}

// Drives U3 (operator-aware operand-name rendering for arithmetic hops).
public static class ArithmeticOperatorFixtures
{
    public static int MulPath(int a, int b) => a * b;
    public static int DivPath(int a, int b) => a / b;
    public static int ShlPath(int a, int b) => a << b;
    public static int ShrPath(int a, int b) => a >> b;
}

// Mirrors parquet-dotnet ThriftCompactProtocolReader.ReadBinary → ReadBytesExactly
// (issue #738: uncontrolled `new byte[]` from user-controlled varint length).
public static class ParquetThriftLikeFixtures
{
    public static byte[] ReadBinary(FakeStream stream)
    {
        int length = ReadVarInt32(stream);
        return ReadBytesExactly(length);
    }

    private static int ReadVarInt32(FakeStream stream)
    {
        return stream.NextByte();
    }

    private static byte[] ReadBytesExactly(int count)
    {
        return new byte[count];   // ← the unbounded allocation sink
    }
}

// Milestone-F N2 fixtures — exercise property-getter naming.
public sealed class GetterNamingHost
{
    public int Value => 0;

    // Uses a property getter on a tainted receiver. Without N2, the call's synthetic
    // provenance is "host.get_Value"; with N2, it should be "host.Value".
    public static byte[] AllocateFromTaintedHostValue(GetterNamingHost host)
    {
        return new byte[host.Value];
    }
}

// Milestone-G N3 fixtures — instance-sizer arithmetic attribution gap.
//
// InstanceSizer stores tainted inputs in this-fields via its constructor.
// AllocateViaInstanceSizer creates a local InstanceSizer, then calls TotalBytes()
// on it. Without N3, the walk of TotalBytes sees no tainted inputs (bitmask=0,
// seedFields=[] because the receiver is a local, not caller's `this`), so the
// `*` instruction never emits an arithmetic hop. With N3 the receiver's
// this-fields are seeded, enabling the arithmetic hop to fire.
public sealed class InstanceSizerFixture
{
    private readonly int _count;
    private readonly int _stride;

    public InstanceSizerFixture(int count, int stride)
    {
        _count = count;
        _stride = stride;
    }

    public int TotalBytes() => _count * _stride;
}

public static class InstanceSizerHost
{
    public static byte[] AllocateViaInstanceSizer(int count, int stride)
    {
        var sizer = new InstanceSizerFixture(count, stride);
        int total = sizer.TotalBytes();
        return new byte[total];
    }
}

// Milestone-G U10 fixtures — per-walk callee-expansion guard.
public static class U10DoubleCallFixtures
{
    // Emits exactly one arithmetic hop (mul). Used to detect duplicates.
    internal static int Double(int x) => x * 2;

    // Calls Double twice with the same tainted arg.
    // U10 must ensure Double's arithmetic hop appears exactly once in the walk.
    public static byte[] CallHelperTwice(int n)
    {
        int a = Double(n);
        int b = Double(n);
        return new byte[a + b];
    }
}

// Milestone-H fixtures — taint_from_external_returns source annotation.
public static class ExternalReturnTaintFixtures
{
    // Calls System.IO.Path.GetFullPath (external static, no receiver, no tainted args).
    // Without TaintFromExternalReturns: path is untainted → new byte[] doesn't fire.
    // With TaintFromExternalReturns=["Path::GetFullPath"]: path is tainted → NewArray fires.
    public static byte[] AllocFromExternalPathResult()
    {
        var path = System.IO.Path.GetFullPath(".");
        return new byte[path.Length];
    }
}

// Milestone-H fixtures — HTTP content read sink shapes.
public static class HttpClientReadFixtures
{
    // Calls HttpClient.GetStringAsync (in System.Net.Http.HttpClient, external to analyzed assembly).
    // MatchHttpRead fires unconditionally on the GetStringAsync call → HttpClientRead sink.
    // Without TaintFromExternalReturns: result is untainted, new byte[] doesn't fire.
    // With TaintFromExternalReturns=["HttpClient::GetStringAsync"]: result is tainted,
    // result.Length tainted, new byte[result.Length] fires as NewArray.
    public static byte[] AllocFromHttpGetString()
    {
        using var client = new System.Net.Http.HttpClient();
        var result = client.GetStringAsync("http://example.com").GetAwaiter().GetResult();
        return new byte[result.Length];
    }

    // ReadAsStreamAsync returns a Stream handle — it does NOT allocate a large buffer.
    // MatchHttpRead must NOT fire; the downstream sink (if any) is wherever the stream is read.
    public static System.IO.Stream ReadAsStreamAsync_ReturnsStream(System.Net.Http.HttpContent content)
        => content.ReadAsStreamAsync().GetAwaiter().GetResult();

    // GetStreamAsync — same reasoning: returns a lazy network stream, no buffer allocation.
    // MatchHttpRead must NOT fire.
    public static System.IO.Stream GetStreamAsync_ReturnsStream()
    {
        using var client = new System.Net.Http.HttpClient();
        return client.GetStreamAsync("http://example.com").GetAwaiter().GetResult();
    }
}

// Fixtures for AsyncStateMachineResolver tests. Each method is intentionally minimal —
// the resolver only inspects custom attributes and the state-machine type structure.
public static class AsyncSourceFixtures
{
    // Sync method — no AsyncStateMachineAttribute. Resolver returns this method unchanged.
    public static int Sync(int x) => x + 1;

    // Plain async method. Compiler emits `[AsyncStateMachine(typeof(<AsyncSimple>d__N))]`
    // on the stub and lowers the body into the nested type's MoveNext.
    public static async System.Threading.Tasks.Task<int> AsyncSimple(int x)
    {
        await System.Threading.Tasks.Task.Yield();
        return x + 1;
    }

    // Generic async method — state machine type is generic (<AsyncGeneric>d__N`1).
    public static async System.Threading.Tasks.Task<T> AsyncGeneric<T>(T x)
    {
        await System.Threading.Tasks.Task.Yield();
        return x;
    }
}

public static class AsyncSinkFixtures
{
    // An async method that posts to an HttpClient and reads the response body unbounded.
    // Mirrors the OpAmp PlainHttpTransport.SendAsync pre-fix shape exactly enough to drive
    // the analyzer's async-source resolution + MatchHttpRead sink end-to-end.
    public static async System.Threading.Tasks.Task<byte[]> AsyncReadResponse(
        System.Net.Http.HttpClient client, byte[] body, System.Threading.CancellationToken token)
    {
        using var content = new System.Net.Http.ByteArrayContent(body);
        var response = await client.PostAsync("https://example.invalid/", content, token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
    }
}

// Fixtures for MatchValueClamp tests. Each method produces a specific IL diamond/call
// shape that the sanitizer matcher must recognise (or, for negative cases, must reject).
public static class ClampFixtures
{
    // Orientation A — the canonical OTel HttpClientHelpers.GetBufferLength shape.
    // C# emits this as `clt; brfalse LBL_K; ldarg.0; br LBL_join; LBL_K: ldarg.1; LBL_join:`
    public static int TernaryClamp_LessThan(int tainted, int limit)
        => tainted < limit ? tainted : limit;

    // Orientation B — flipped condition, same semantics.
    public static int TernaryClamp_GreaterThanOrEqual(int tainted, int limit)
        => tainted >= limit ? limit : tainted;

    // Negative — both operands tainted; the result is still bounded by the smaller of two
    // attacker-controlled values, which we conservatively treat as still tainted.
    public static int TernaryClamp_BothTainted(int x, int y) => x < y ? x : y;

    // Mirrors the GetBufferLength inner branch: `(int)stream.Length < limit ? (int)stream.Length : limit`.
    // We synthesise stream.Length via a parameter whose taint shape we control in the test.
    public static int StreamLengthVsLimit(long streamLength, int limit)
        => (int)streamLength < limit ? (int)streamLength : limit;

    // Math.Min / Max / Clamp shapes for the HandleCall recognizer.
    public static int MathMin_TaintedAndConstant(int tainted) => System.Math.Min(tainted, 4096);
    public static int MathMin_TwoTainted(int x, int y) => System.Math.Min(x, y);
    public static int MathMax_TaintedAndConstant(int tainted) => System.Math.Max(tainted, 0);
    public static int MathClamp_TaintedWithConstantBounds(int tainted) => System.Math.Clamp(tainted, 0, 4096);
}

// Fixtures for AppliedThrowShapeSanitiser: callees that validate a tainted param via throw
// before (or without) using it, so the caller can skip byref taint propagation.
public static class ThrowShapeCalleeFixtures
{
    // Callee: validates `length` via throw before returning it.
    // When walked with bit-0 tainted, AppliedThrowShapeSanitiser must be true.
    public static int ThrowValidatesParam(int length)
    {
        if (length > 1000)
            ThrowHelpers.ThrowOutOfRange(nameof(length));
        return length;
    }

    // Callee: validates `source` via throw, then writes to out-param.
    // Throw fires BEFORE the assignment — fixed shape (analogous to NBMP 1.1.62).
    private static int ThrowThenAssign(int source, out int dest)
    {
        if (source > 1000)
            ThrowHelpers.ThrowOutOfRange(nameof(source));
        dest = source;
        return 0;
    }

    // Callee: return-early (NOT throw) on invalid input, then writes to out-param.
    // AppliedThrowShapeSanitiser must be false (ReturnEarly, not Throw).
    private static int ReturnEarlyThenAssign(int source, out int dest)
    {
        if (source > 1000)
        {
            dest = 0;
            return -1;
        }
        dest = source;
        return 0;
    }

    // Caller via throw-shape callee: sink must NOT fire when AppliedThrowShapeSanitiser suppresses byref.
    public static byte[] AllocViaThrowValidatedOutParam(int n)
    {
        ThrowThenAssign(n, out int size);
        return new byte[size];
    }

    // Caller via return-early callee: sink MUST fire (byref propagation not suppressed).
    public static byte[] AllocViaReturnEarlyOutParam(int n)
    {
        ReturnEarlyThenAssign(n, out int size);
        return new byte[size];
    }

    // Multi-way OR (Shape C): `size` is a local assigned directly from parameter `n`.
    // Debug-mode Roslyn lowers `if (size==4||size==8||size==12)` as three beq/bne instructions
    // writing a boolean local, then a single brtrue. The bound target is the local, not the param;
    // ThrowShapeSanitisesATaintedParam must trace it back to `n` via the last stloc.
    public static int MultiWayOrThrow_LocalFromParam(int n)
    {
        int size = n;
        if (size == 4 || size == 8 || size == 12)
            return size;
        throw new ArgumentException("bad size");
    }

    // Callee: validates via multi-way-OR throw shape, writes to out-param.
    private static void MultiWayOrThrowThenWriteOut(int source, out int dest)
    {
        int size = source;
        if (size == 4 || size == 8 || size == 12) { dest = size; return; }
        throw new ArgumentException("bad size");
    }

    // End-to-end test: callee's throw-shape on tainted param suppresses byref propagation,
    // so the caller's allocation from the out-param must NOT fire the sink.
    public static int[] AllocViaMultiWayOrValidatedOutParam(int n)
    {
        MultiWayOrThrowThenWriteOut(n, out int size);
        return new int[size];
    }
}

// Milestone-N fixtures — in-parameter (modreq) short-signature lookup.
// Cecil encodes `in T` as "T& modreq(System.Runtime.InteropServices.InAttribute)".
// BuildShortSignature must strip the modifier so FindMethod accepts "T&" from rules.yaml.
public static class InParamFixtures
{
    // Simple value-type `in` parameters — Cecil emits modreq for each.
    public static int SumByRef(in int a, in int b) => a + b;

    // Reference-type `in` parameter — same modreq encoding.
    public static int StringLength(in string s) => s.Length;
}
