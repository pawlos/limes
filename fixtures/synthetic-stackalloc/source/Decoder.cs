using System.IO;

namespace SyntheticStackalloc;

public sealed class WireProcessor
{
    public byte[] Process(Stream stream)
    {
        var reader = new WireReader(stream);
        ushort recordCount = reader.ReadU16();
        Span<byte> scratch = stackalloc byte[recordCount];
        return scratch.ToArray();
    }
}

internal sealed class WireReader
{
    private readonly Stream _stream;

    public WireReader(Stream stream)
    {
        _stream = stream;
    }

    public ushort ReadU16()
    {
        int hi = _stream.ReadByte();
        int lo = _stream.ReadByte();
        return (ushort)((hi << 8) | lo);
    }
}
