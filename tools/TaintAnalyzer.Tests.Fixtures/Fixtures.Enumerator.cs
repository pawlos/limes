// EnumeratorFixtures — types for EntryPointEnumerator tests.
// Visible to Cecil only (the test project does not reference Fixtures source);
// internal types are deliberately reachable / unreachable per their name.

namespace TaintAnalyzer.Tests.Fixtures.Enumerator;

// ---- Parameter-shape fixtures ----

public class StreamReaderShape
{
    public void Read(System.IO.Stream s) { }
}

public class FileStreamReaderShape
{
    public void Read(System.IO.FileStream s) { }
}

public class SpanByteReaderShape
{
    public void Read(System.ReadOnlySpan<byte> s) { }
}

public class StringReaderShape
{
    // Should NOT be picked up by default config (string is not in defaults).
    public void Read(string s) { }
}

public class SpanIntReaderShape
{
    // Should NOT be picked up (ReadOnlySpan<int> ≠ ReadOnlySpan<byte>).
    public void Read(System.ReadOnlySpan<int> s) { }
}

public class ByteArrayReaderShape
{
    public void Read(byte[] s) { }
}

public class BinaryReaderShape
{
    public void Read(System.IO.BinaryReader r) { }
}

// ---- This-field-shape fixtures ----

// Name matches *Decoder glob; has a Stream field — must be picked up by this-field-shape.
public class StreamInputDecoder
{
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

public class NotADecoderType
{
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

// Name matches the *Decoder suffix glob, but the type has no byte-source field —
// must NOT be picked up by this-field-shape even with --include-this-field.
public class EmptyDecoder
{
    public string ReadString() => "";
}

// ---- Visibility-filter fixtures ----

public class PublicEntryPoint
{
    public void TakesStream(System.IO.Stream s) => InternalReachable.Helper(s);
}

internal static class InternalReachable
{
    internal static void Helper(System.IO.Stream s) { }
}

internal static class InternalOrphan
{
    internal static void Orphan(System.IO.Stream s) { }
}

public class HasPrivateAndProtected
{
    private void PrivateMethod(System.IO.Stream s) { }
    protected void ProtectedMethod(System.IO.Stream s) { }
}

// ---- S1 visibility-matrix fixtures: family flavors x reachability ----

// (1) protected (Cecil IsFamily) reachable from public on same type — must accept.
public class FamilyReachable
{
    public void EntryPoint(System.IO.Stream s) => Helper(s);
    protected void Helper(System.IO.Stream s) { }
}

// (2) protected, no public caller in assembly — must reject (reachability gate).
public class FamilyUnreachable
{
    protected void Helper(System.IO.Stream s) { }
}

// (3) private protected (Cecil IsFamilyAndAssembly) reachable from public — accept.
public class FamilyAndAssemblyReachable
{
    public void EntryPoint(System.IO.Stream s) => Helper(s);
    private protected void Helper(System.IO.Stream s) { }
}

// (4) private protected, no public caller — reject.
public class FamilyAndAssemblyUnreachable
{
    private protected void Helper(System.IO.Stream s) { }
}

// (5) protected internal (Cecil IsFamilyOrAssembly) reachable from public — accept.
public class FamilyOrAssemblyReachable
{
    public void EntryPoint(System.IO.Stream s) => Helper(s);
    protected internal void Helper(System.IO.Stream s) { }
}

// (6) protected internal, no public caller — reject.
public class FamilyOrAssemblyUnreachable
{
    protected internal void Helper(System.IO.Stream s) { }
}

// (7) private, reachable from public on same type — must STILL reject (private bucket).
public class PrivateReachable
{
    public void EntryPoint(System.IO.Stream s) => Helper(s);
    private void Helper(System.IO.Stream s) { }
}

// ---- Hard-filter fixtures ----

public class HasCtorWithStream
{
    public HasCtorWithStream(System.IO.Stream s) { }
    // Normal public method co-located with the ctor; the enumerator must accept
    // this even though the ctor on the same type is hard-rejected.
    public void NormalMethod(System.IO.Stream s) { }
}

public class HasPropertyTakingStream
{
    private System.IO.Stream _backing = System.IO.Stream.Null;
    public System.IO.Stream Backing { get => _backing; set => _backing = value; }
}

public abstract class HasAbstractMethod
{
    public abstract void Read(System.IO.Stream s);
}
