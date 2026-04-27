using System.IO;

namespace SyntheticCalleeArithmetic;

public sealed class WireDecoder
{
    public byte[] Decode(Stream stream)
    {
        var reader = new WireReader(stream);
        ushort recordCount = reader.ReadU16();
        ushort recordStride = reader.ReadU16();
        int totalBytes = PayloadSizer.RecordsAreaBytes(recordCount, recordStride);
        return new byte[totalBytes];
    }
}

internal static class PayloadSizer
{
    internal static int RecordsAreaBytes(ushort count, ushort stride)
    {
        return (int)count * (int)stride;
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
