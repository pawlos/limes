# ImageSharp #3074 — Taint trace narrative

This document is the narrative companion to `trace.yaml`. It walks the
source-to-sink taint path hop by hop, cites pre-fix and post-fix source lines
verbatim, and records schema questions that surfaced during trace construction.
A reader unfamiliar with the bug should be able to read this end-to-end and
satisfy themselves that the fixture faithfully captures the vulnerability.

---

## 1. Summary

The SixLabors/ImageSharp BMP decoder (pre-fix commit
`461c021608802370374afabd5d3c2720b3e46f04~1`) allocates a palette buffer whose
size is derived directly from `bfOffBits`, the 4-byte pixel-data offset field
at byte 10 of the BMP file header. The decoder reads that field from the stream
with no upper-bound check against the actual stream length, computes
`colorMapSizeBytes = bfOffBits - 14 - infoHeaderSize`, and then executes
`palette = new byte[colorMapSizeBytes]`. Because `bfOffBits` is fully
attacker-controlled, a crafted file with an enormous offset value causes the
runtime to attempt a multi-gigabyte heap allocation, exhausting process memory.
The one-line fix (PR #3075) inserts a guard immediately before the arithmetic:
if `this.fileHeader.Value.Offset > stream.Length`, throw
`InvalidImageContentException` before the subtraction ever executes.

---

## 2. BMP header reference

The BMP file header is 14 bytes (`BmpFileHeader.Size = 14`). It is immediately
followed by the info header (40 bytes for `BITMAPINFOHEADER`; larger for
extended variants). The color map, when present, fills the gap between the end
of the info header and the start of pixel data.

| File offset | Field name   | Width   | Role in this vulnerability |
|-------------|--------------|---------|----------------------------|
| 0           | `bfType`     | 2 bytes | Magic `0x424D` (`"BM"`); determines `fileMarkerType`. |
| 2           | `bfSize`     | 4 bytes | Total file size. Not used in color-map size computation. |
| 6           | `bfReserved1`| 2 bytes | Reserved; ignored. |
| 8           | `bfReserved2`| 2 bytes | Reserved; ignored. |
| **10**      | **`bfOffBits`** | **4 bytes** | **File offset of pixel data. Stored as `fileHeader.Value.Offset`. This is the attacker-controlled value that drives the bug.** |
| 14          | `biSize`     | 4 bytes | Info header size (40, 52, 56, 108, or 124). Stored as `infoHeader.HeaderSize`. Subtracted from `Offset` to compute color-map size. |
| 46          | `biClrUsed`  | 4 bytes | Color count in palette. If 0, the decoder falls back to the `bfOffBits`-based calculation — the vulnerable branch. |

Color-map size formula (vulnerable): `colorMapSizeBytes = bfOffBits - 14 - biSize`.
If `bfOffBits` is larger than the actual stream, `colorMapSizeBytes` is a large
positive integer and the subsequent `new byte[colorMapSizeBytes]` throws OOM.

---

## 3. Hop-by-hop walkthrough

### Source — `Decode`, line 128

**trace.yaml path:** `source` node, `kind: decoder_entry`.

The taint enters at the public decoder entry point. The `stream` parameter
carries raw bytes from the untrusted input file; everything read from it is
attacker-controlled.

Pre-fix lines 128–133
(`fixtures/imagesharp-3074/prefix-snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs`):

```csharp
// line 128
protected override Image<TPixel> Decode<TPixel>(BufferedReadStream stream, CancellationToken cancellationToken)
{
    Image<TPixel>? image = null;
    try
    {
        // line 133 — tainted stream forwarded to header reader
        int bytesPerColorMapEntry = this.ReadImageHeaders(stream, out bool inverted, out byte[] palette);
```

Taint state at **entry**: `stream` — unbounded attacker bytes.
Taint state at **exit**: same `stream` forwarded to `ReadImageHeaders`.

This node is the source because `stream` has no validated envelope at this
point; the decoder has not yet read any bytes.

---

### Hop 0 — `Decode` → `ReadImageHeaders` call, line 133

**trace.yaml path:** `path[0]`, `transformation: identity`.

`Decode` passes `stream` unmodified as the first argument to
`ReadImageHeaders`. No bytes are read here; this is a pure call-graph edge.
Dispatch is `direct` (non-virtual call to a private method on the same class;
IL `call` instruction). The `resolved_targets` list is empty because a `direct`
edge has exactly one statically known target with no CHA needed.

Taint state at **entry**: `stream`.
Taint state at **exit**: `stream` (identity — value unchanged, scope changed).

---

### Hop 1 — `ReadImageHeaders` → `ReadFileHeader` call, line 1523

**trace.yaml path:** `path[1]`, `transformation: identity`.

`ReadImageHeaders` is the top-level header-parsing method. Its first action
(when `this.skipFileHeader` is false) is to call `ReadFileHeader(stream)` at
line 1523.

Pre-fix lines 1519–1523:

```csharp
// line 1519
private int ReadImageHeaders(BufferedReadStream stream, out bool inverted, out byte[] palette)
{
    if (!this.skipFileHeader)
    {
        // line 1523 — tainted stream forwarded to file-header reader
        this.ReadFileHeader(stream);
    }
```

Taint state at **entry**: `stream`.
Taint state at **exit**: `stream` forwarded to `ReadFileHeader`; after the call
returns, `this.fileHeader` holds parsed header bytes — now also tainted.

This hop is a propagator: it does not read bytes itself, merely delegates the
stream to the method that will.

---

### Hop 2 — `ReadFileHeader`: stream.Read into buffer, line 1480

**trace.yaml path:** `path[2]`, `transformation: read_stream`.

`ReadFileHeader` allocates a stack buffer of exactly `BmpFileHeader.Size` (14)
bytes and calls `stream.Read` to fill it. The attacker-controlled bytes now sit
in `buffer`. `BmpFileHeader.Parse(buffer)` then copies them into `this.fileHeader`.

Pre-fix lines 1477–1487:

```csharp
// line 1477
private void ReadFileHeader(BufferedReadStream stream)
{
    Span<byte> buffer = stackalloc byte[BmpFileHeader.Size];
    // line 1480 — virtual call: attacker bytes flow from stream into buffer
    stream.Read(buffer, 0, BmpFileHeader.Size);

    short fileTypeMarker = BinaryPrimitives.ReadInt16LittleEndian(buffer);
    switch (fileTypeMarker)
    {
        case BmpConstants.TypeMarkers.Bitmap:
            this.fileMarkerType = BmpFileMarkerType.Bitmap;
            // line 1487 — Parse copies buffer bytes into this.fileHeader
            this.fileHeader = BmpFileHeader.Parse(buffer);
```

Taint state at **entry**: `stream`.
Taint state at **exit**: `this.fileHeader` (aggregate `Nullable<BmpFileHeader>`)
is populated with attacker-controlled bytes, including `Offset` at buffer[10..13].

**Virtual dispatch / CHA closure.** The call `stream.Read(buffer, 0, BmpFileHeader.Size)`
is a `callvirt` on a `BufferedReadStream` variable. The static type at the call
site is `SixLabors.ImageSharp.IO.BufferedReadStream`. Class-hierarchy analysis
is trivial here: `BufferedReadStream` is declared
`internal sealed class BufferedReadStream : Stream` (sealed), so no subclass
can exist within or outside the assembly. The CHA closure therefore contains
exactly one concrete target: `SixLabors.ImageSharp.IO.BufferedReadStream.Read`.
`closure_boundary` is `false` — the resolved target stays within the ImageSharp
assembly set. This is recorded in `trace.yaml` under `path[2].dispatch`.

---

### Hop 3 — Field load: `this.fileHeader.Value.Offset`, line 1551

**trace.yaml path:** `path[3]`, `transformation: field_load`.

Back in `ReadImageHeaders`, after `ReadFileHeader` returns, the code enters a
branch for `BmpFileMarkerType.Bitmap` files with a low bit-depth and with
`biClrUsed == 0`. At line 1551 it accesses `this.fileHeader.Value.Offset` to
extract the scalar pixel-data offset from the tainted aggregate struct.

Pre-fix lines 1548–1551:

```csharp
                    case BmpFileMarkerType.Bitmap:
                        if (this.fileHeader.HasValue)
                        {
                            // line 1551 — field load: scalar Offset extracted from tainted struct
                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
```

Taint state at **entry**: `this.fileHeader` (aggregate, tainted).
Taint state at **exit**: `this.fileHeader.Value.Offset` (scalar `int`, tainted).

This hop models the narrowing from the whole parsed header struct to the
specific field the vulnerability depends on. See Open question O4 for the
schema question around `Nullable<T>.Value`.

---

### Hop 4 — Arithmetic: computing `colorMapSizeBytes`, line 1551

**trace.yaml path:** `path[4]`, `transformation: arithmetic`.

On the same source line, `this.fileHeader.Value.Offset` is used as the leading
operand of a subtraction that produces `colorMapSizeBytes`. The two subtracted
constants (`BmpFileHeader.Size = 14`, `this.infoHeader.HeaderSize`, typically
40) are both bounded, so the result inherits the taint of `Offset` with no
upper-bound constraint.

```csharp
                            // line 1551 — arithmetic: attacker-controlled Offset minus two small constants
                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
```

Taint state at **entry**: `this.fileHeader.Value.Offset` (scalar, unbounded).
Taint state at **exit**: `colorMapSizeBytes` (scalar `int`, unbounded).

If `Offset` is, say, `0x7FFFFFFF` (max `int`) and the info header is 40 bytes,
`colorMapSizeBytes` evaluates to `2147483647 - 14 - 40 = 2147483593` (~2 GB).
No bounds check exists between this line and the allocation.

Note: hops 3 and 4 share the same `file:line` (`src__...__BmpDecoderCore.cs:1551`)
because both transformations are encoded in the single source expression
`this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize`.
The schema handles this correctly — each hop has an independent `hop` index and
different `tainted_value_in` / `tainted_value_out` labels.

---

### Sink — `new byte[colorMapSizeBytes]`, line 1600

**trace.yaml path:** `sink` node, `kind: allocation`, `api: new_array`.

`colorMapSizeBytes` reaches the array allocation with no intervening check.

Pre-fix lines 1590–1600:

```csharp
        if (colorMapSizeBytes > 0)
        {
            // Make sure, that we will not read pass the bitmap offset (starting position of image data).
            if (this.fileHeader.HasValue && stream.Position > this.fileHeader.Value.Offset - colorMapSizeBytes)
            {
                BmpThrowHelper.ThrowInvalidImageContentException(
                    $"Reading the color map would read beyond the bitmap offset. Either the color map size of '{colorMapSizeBytes}' is invalid or the bitmap offset.");
            }

            // line 1600 — SINK: attacker-controlled size used directly as allocation length
            palette = new byte[colorMapSizeBytes];
```

The guard at line 1594 checks whether the *current stream position* would
overshoot the bitmap offset during the read — but it does not check whether the
offset is within the stream at all. When `Offset` exceeds `stream.Length`, the
guard condition `stream.Position > Offset - colorMapSizeBytes` may evaluate
false (because the subtraction wraps or because `stream.Position` is small),
and execution falls through to `new byte[colorMapSizeBytes]`.

Taint state at **entry**: `colorMapSizeBytes` — attacker-controlled, unbounded.
Taint state at **exit**: `palette` — heap allocation of attacker-specified size;
OOM if large enough.

---

## 4. Sanitizer absence

The fix added an explicit bounds check immediately before the vulnerable
arithmetic (post-fix lines 1551–1557). Below is a side-by-side view.

### Pre-fix (line 1548–1552)

```csharp
                    case BmpFileMarkerType.Bitmap:
                        if (this.fileHeader.HasValue)
                        {
                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
                        }
```

There is no check that `this.fileHeader.Value.Offset` is within the stream
before it is used as the leading operand of the subtraction.

### Post-fix (lines 1548–1558, commit `461c021`)

```csharp
                    case BmpFileMarkerType.Bitmap:
                        if (this.fileHeader.HasValue)
                        {
                            if (this.fileHeader.Value.Offset > stream.Length)
                            {
                                BmpThrowHelper.ThrowInvalidImageContentException(
                                    $"Pixel data offset {this.fileHeader.Value.Offset} exceeds file size {stream.Length}.");
                            }

                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
                        }
```

The added guard establishes `this.fileHeader.Value.Offset <= stream.Length`
before the subtraction executes. Given that `BmpFileHeader.Size` (14) and
`this.infoHeader.HeaderSize` (>= 40) are both positive, `colorMapSizeBytes` is
now bounded above by `stream.Length - 54`, which is bounded by the actual file
size. This makes the allocation safe.

**Why the pre-fix guard at line 1594 is insufficient.** The check
`stream.Position > this.fileHeader.Value.Offset - colorMapSizeBytes` is a
read-overrun guard, not an OOM guard. It operates on values derived from the
already-unbounded `colorMapSizeBytes`. It does not prevent the allocation itself
from being enormous; it only prevents a subsequent `stream.Read` of that buffer
from seeking past the offset marker. In practice it can also fail to trigger
because the subtraction `Offset - colorMapSizeBytes` algebraically cancels to
`BmpFileHeader.Size + infoHeader.HeaderSize`, a small constant, which
`stream.Position` (also small, just past the headers) is unlikely to exceed.

---

## 5. Open schema questions

The following questions surfaced during construction of this trace. They are
recorded here so the schema's v1 freeze (after additional fixtures exist) can
address them with concrete evidence from multiple bugs rather than from one.

### O1 — `taint_value_state` for sanitizer bounds — **RESOLVED in milestone B**

Resolved by `fixtures/imagesharp-3074-postfix/` and the schema-v0.1 extension
documented in `docs/superpowers/specs/2026-04-17-imagesharp-3074-postfix-trace-design.md`.
Sanitizer nodes now carry `establishes_bound` (`target`, `relation`, `upper_bound`)
and `on_failure` (`kind`, `exception`) fields capturing the observable effect of
the bounds-establishing check. Downstream hops do not carry inherited state;
forward-folding of bounds is the analyzer's responsibility, not the fixture's.
Original text preserved below for historical reference.

> The v0 schema has no field to express what invariant a sanitizer establishes
> about the tainted value (e.g., `bounded_by: stream.Length`). This trace does
> not exercise a sanitizer node (none is present pre-fix), so the gap is not
> painful here. It will become painful when encoding a *post-fix* trace or any
> trace where a partial sanitizer (e.g., `Math.Min(offset, maxSafeSize)`) is
> present but insufficient. Proposal: add an optional `sanitizer_kind` field and
> a `bounded_by` expression to nodes with `role: sanitizer`. Not needed for this
> fixture; flagged for v1.

### O2 — Aggregate vs. scalar taint representation

The jump from `this.fileHeader` (a `Nullable<BmpFileHeader>` aggregate
containing all 14 header bytes) to `this.fileHeader.Value.Offset` (the scalar
`int` at buffer[10..13]) is modeled as a dedicated `field_load` hop (path[3]).
This felt natural: the aggregate carries taint from the point it was populated
(`ReadFileHeader`), and the scalar is extracted explicitly at the use site. The
one awkward aspect is that hops 3 and 4 share a source line (line 1551), which
is permitted by the schema but may confuse automated line-based tools that
assume one hop per line. No schema change is required; the `hop` index is the
canonical key, not the line number.

### O3 — Async / `MoveNext` dispatch

The BMP decoder is fully synchronous. No `await` expressions appear on the
source-to-sink path; the `async_continuation` dispatch kind defined in v0 is
not exercised by this trace. This is expected. The kind is retained in the
schema for use by traces of async decoders (e.g., WebP, PNG). No action needed.

### O4 — `Nullable<T>.Value` as a transformation kind

Hop 3 uses `transformation: field_load` to model `this.fileHeader.Value.Offset`.
There are actually two access steps collapsed onto one line:
`this.fileHeader.Value` (unwrapping `Nullable<BmpFileHeader>`, a runtime no-op
if `HasValue` is true) followed by `.Offset` (a genuine struct field load).
The schema's `field_load` kind covers both without ambiguity for this trace
because the `HasValue` guard is on the enclosing `if` branch (line 1549), and
the unwrap cannot throw at that point. However, if a future trace has a
nullable dereference that is itself the interesting step (e.g., the null case
is a taint escape), `field_load` may be under-specified. One option: add a
`nullable_unwrap` transformation kind to distinguish the `Nullable<T>.Value`
access from a plain struct field load. Not needed here; flagged for v1.

### O5 — Compound sanitizer conditions (new in milestone A)

Surfaced by `fixtures/imagesharp-3079-postfix/` and the schema-v0.2 extension
documented in
`docs/superpowers/specs/2026-04-17-imagesharp-3079-trace-design.md`. Fix checks
of the form `if (A < 0 || A + N > data.Length) return;` are disjunctions of two
conditions, but `establishes_bound` records one bound pair. Milestone A
collapses such disjunctions to the meaningful single bound with the full check
text preserved in `note:`. Deferred until an analyzer needs to read compound
conditions mechanically.
