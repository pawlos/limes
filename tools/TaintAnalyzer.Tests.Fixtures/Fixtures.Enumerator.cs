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
    public void Read(string s) { }
}

public class SpanIntReaderShape
{
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

public class DecoderWithStreamField
{
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

public class NotADecoderType
{
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

public class DecoderWithoutStreamField
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

// ---- Hard-filter fixtures ----

public class HasCtorWithStream
{
    public HasCtorWithStream(System.IO.Stream s) { }
    public void Op_NotMatchedEither(System.IO.Stream s) { }
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
