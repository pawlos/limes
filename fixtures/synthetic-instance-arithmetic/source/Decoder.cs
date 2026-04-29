using System.IO;

namespace SyntheticInstanceArithmetic;

// Reproducer for the instance-sizer arithmetic-attribution gap.
//
// PayloadSizer is an INSTANCE class; its inputs enter via constructor fields
// (_count, _stride), not direct parameters of TotalBytes(). The expected
// trace must contain an arithmetic hop inside TotalBytes at the `*` site.
// Without the fix, the walker produces only an identity hop at the call
// boundary (sizer.TotalBytes()) because the in-assembly walk of TotalBytes
// runs with bitmask=0 and empty seedFields — _count and _stride appear
// untainted, so the mul instruction never fires emission.

public sealed class WireDecoder
{
    public byte[] Decode(Stream stream)
    {
        ushort count = ReadU16(stream);
        ushort stride = ReadU16(stream);
        var sizer = new InstanceSizer(count, stride);
        int total = sizer.TotalBytes();
        return new byte[total];
    }

    private static ushort ReadU16(Stream stream)
    {
        return (ushort)(stream.ReadByte() << 8 | stream.ReadByte());
    }
}

internal sealed class InstanceSizer
{
    private readonly ushort _count;
    private readonly ushort _stride;

    public InstanceSizer(ushort count, ushort stride)
    {
        _count = count;
        _stride = stride;
    }

    // The dangerous arithmetic: u16 × u16 can overflow to ~2 GiB.
    // This is the site the triager needs to see in the trace.
    public int TotalBytes()
    {
        return (int)_count * (int)_stride;
    }
}
