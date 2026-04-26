# parquet-dotnet #738 — unbounded byte[length] allocation

## Summary

`Parquet.Meta.Proto.ThriftCompactProtocolReader.ReadBinary` reads a Thrift
VarInt32 length prefix from the input stream, then immediately allocates
`new byte[length]` via `Stream.ReadBytesExactly`. No validation between the
length read and the allocation. A crafted Parquet input specifying a huge
length drives the process to `OutOfMemoryException` (denial-of-service).

Upstream issue: <https://github.com/aloneguid/parquet-dotnet/issues/738>.
Pre-fix snapshot SHA: `006fba12174d4fb68bd5fbc3898928c3b75d556b`. The bug
remains unfixed in the upstream repo at the time of fixture authoring;
`fix_commit` and `fix_evidence` are intentionally empty.

## Trace

```
ThriftCompactProtocolReader.ReadBinary  (source: this._inputStream)
   │  this.fileHeader.HasValue && stream.Position > Offset - colorMapSizeBytes
   ├─ field_load → _inputStream                      (line 107)
   ├─ read_stream → length (via ReadVarInt32)        (line 44, attacker-controlled)
   ▼
ReadBytesExactly(stream, length)                     (line 113, no bound)
   ▼
StreamExtensions.ReadBytesExactly
   │  byte[] tmp = new byte[count]                   (line 47, allocation sink)
```

## Source

- **Method:** `Parquet.Meta.Proto.ThriftCompactProtocolReader::ReadBinary()`
- **File:** `src/Parquet/Meta/Proto/ThriftCompactProtocolReader.cs:105`
- **Tainted inputs:** `_inputStream` (this-field) — seeded via the rules
  document's `seed_this_fields: [_inputStream]`.

## Sink

- **Method:** `Parquet.Extensions.StreamExtensions::ReadBytesExactly(System.IO.Stream,System.Int32)`
- **File:** `src/Parquet/Extensions/StreamExtensions.cs:47`
- **Kind:** allocation / new_array
- **Size expression:** `count`

## Sanitizer absence

A single absence at `ThriftCompactProtocolReader.cs:113` — the unbounded call
site immediately after `ReadVarInt32` returns. The expected fix is to verify
`length >= 0 && length <= some-cap` before allocation, or to bound it against
the remaining stream length.
