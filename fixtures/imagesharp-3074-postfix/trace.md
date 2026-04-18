# ImageSharp #3074 — Post-fix taint trace narrative

This document is the narrative companion to `trace.yaml` for the *post-fix*
state of the ImageSharp BMP decoder vulnerability. It walks the source-to-sink
taint path hop by hop, cites post-fix source lines verbatim, and records the
resolution status of the open schema questions that surfaced during the pre-fix
trace. A reader unfamiliar with the bug should be able to read this end-to-end
and satisfy themselves that the fix faithfully eliminates the vulnerability.

Compare with `fixtures/imagesharp-3074-prefix/trace.md` for the pre-fix
perspective. Hops 0–2 are structurally identical between the two traces; the
new material begins at hop 3, where the field load now sits inside the
sanitizer's condition, and at hop 4, which is the sanitizer itself.

---

## 1. Summary

The SixLabors/ImageSharp BMP decoder (pre-fix) allocated a palette buffer whose
size was derived directly from `bfOffBits`, the 4-byte pixel-data offset field
at byte 10 of the BMP file header (`fileHeader.Value.Offset` in the C# code).
The decoder read that field from the stream with no upper-bound check against
the actual stream length, computed
`colorMapSizeBytes = bfOffBits - 14 - infoHeaderSize`, and then executed
`palette = new byte[colorMapSizeBytes]`. Because `bfOffBits` is fully
attacker-controlled, a crafted file with an enormous offset value caused the
runtime to attempt a multi-gigabyte heap allocation, exhausting process memory.

The fix (PR #3075, merge commit `461c021608802370374afabd5d3c2720b3e46f04`)
inserts a single `if`-check at post-fix line 1551: if
`this.fileHeader.Value.Offset > stream.Length`, the decoder calls
`BmpThrowHelper.ThrowInvalidImageContentException` and aborts — before the
arithmetic at line 1557 ever executes. The attacker can no longer induce OOM:
any out-of-range `Offset` aborts the decode with a well-typed exception, and
the fall-through path carries the invariant `Offset <= stream.Length` into the
subsequent computation.

---

## 2. BMP header reference

The BMP file header is 14 bytes (`BmpFileHeader.Size = 14`). It is immediately
followed by the info header (40 bytes for `BITMAPINFOHEADER`; larger for
extended variants). The color map, when present, fills the gap between the end
of the info header and the start of pixel data.

| File offset | Field name      | Width   | Role in this vulnerability |
|-------------|-----------------|---------|----------------------------|
| 0           | `bfType`        | 2 bytes | Magic `0x424D` (`"BM"`); determines `fileMarkerType`. |
| 2           | `bfSize`        | 4 bytes | Total file size. Not used in color-map size computation. |
| 6           | `bfReserved1`   | 2 bytes | Reserved; ignored. |
| 8           | `bfReserved2`   | 2 bytes | Reserved; ignored. |
| **10**      | **`bfOffBits`** | **4 bytes** | **File offset of pixel data. Stored as `fileHeader.Value.Offset`. This is the attacker-controlled value that drives the bug.** |
| 14          | `biSize`        | 4 bytes | Info header size (40, 52, 56, 108, or 124). Stored as `infoHeader.HeaderSize`. Subtracted from `Offset` to compute color-map size. |
| 46          | `biClrUsed`     | 4 bytes | Color count in palette. If 0, the decoder falls back to the `bfOffBits`-based calculation — the vulnerable branch. |

Color-map size formula: `colorMapSizeBytes = bfOffBits - 14 - biSize`.
Pre-fix: if `bfOffBits` exceeds the actual stream length, `colorMapSizeBytes`
is a large positive integer and the subsequent `new byte[colorMapSizeBytes]`
throws OOM. Post-fix: the check at line 1551 ensures `bfOffBits <= stream.Length`
before this formula runs.

---

## 3. Hop-by-hop walkthrough

### Source — `Decode`, line 128

**trace.yaml path:** `source` node, `kind: decoder_entry`.

The taint enters at the public decoder entry point. The `stream` parameter
carries raw bytes from the untrusted input file; everything read from it is
attacker-controlled.

Post-fix lines 128–133
(`fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs`):

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

Post-fix lines 1519–1523:

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
in `buffer`. `BmpFileHeader.Parse(buffer)` then copies them into
`this.fileHeader`.

Post-fix lines 1477–1487:

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

Crucially, in the post-fix code this field load appears physically inside the
sanitizer's condition expression. The first occurrence of
`this.fileHeader.Value.Offset` on line 1551 is the operand of the
`> stream.Length` comparison — the guard. The field load is still modeled as a
separate propagator hop (hop 3) because the taint transition from the aggregate
`fileHeader` struct to the scalar `Offset` is a distinct semantic step, even
though it shares the line number with the sanitizer hop that follows it.

Post-fix lines 1548–1555:

```csharp
                    case BmpFileMarkerType.Bitmap:
                        if (this.fileHeader.HasValue)
                        {
                            // line 1551 — field load: scalar Offset extracted from tainted struct
                            if (this.fileHeader.Value.Offset > stream.Length)
                            {
                                BmpThrowHelper.ThrowInvalidImageContentException(
                                    $"Pixel data offset {this.fileHeader.Value.Offset} exceeds file size {stream.Length}.");
                            }
```

Taint state at **entry**: `this.fileHeader` (aggregate, tainted).
Taint state at **exit**: `this.fileHeader.Value.Offset` (scalar `int`, tainted).

This hop models the narrowing from the whole parsed header struct to the
specific field the vulnerability depends on. See open question O4 for the
schema question around `Nullable<T>.Value`.

---

### Hop 4 — Sanitizer: `Offset <= stream.Length` guard, line 1551

**trace.yaml path:** `path[4]`, `role: sanitizer`.

This is the central narrative beat of the post-fix trace and the primary
difference from the pre-fix path. The fix's guard sits on the same line as the
field load (line 1551) because the condition expression references the freshly
loaded scalar.

Post-fix lines 1551–1555:

```csharp
                            // line 1551 — sanitizer: Offset checked against stream.Length
                            if (this.fileHeader.Value.Offset > stream.Length)
                            {
                                BmpThrowHelper.ThrowInvalidImageContentException(
                                    $"Pixel data offset {this.fileHeader.Value.Offset} exceeds file size {stream.Length}.");
                            }
```

**`establishes_bound` block.** The YAML records:

```yaml
establishes_bound:
  target: fileHeader.Value.Offset
  relation: "<="
  upper_bound: stream.Length
```

This captures the sanitizer's observable contribution to the taint analysis. On
the fall-through path (the `if` condition evaluated false), the runtime has
confirmed that `fileHeader.Value.Offset <= stream.Length`. The fixture records
this as a declared bound on the tainted value; a forward-folding analyzer can
use it to prove that the arithmetic at hop 5 yields a safe result.

**`on_failure` block.** The YAML records:

```yaml
on_failure:
  kind: throw
  exception: InvalidImageContentException
```

This captures what happens when the check fails: control transfers to
`BmpThrowHelper.ThrowInvalidImageContentException`, which throws an
`InvalidImageContentException`. Operationally, the decode aborts — the
remaining path nodes (hops 5 and the sink) are only reachable via the
fall-through branch where the bound holds. The taint-flow analysis's response
is symmetric: it restricts its reachability analysis of downstream nodes to that
fall-through branch.

**Dispatch.** `BmpThrowHelper.ThrowInvalidImageContentException` is a static
method on a helper type. The call is `dispatch.kind: direct` — no virtual
resolution is needed, and the call site's IL is a `call` (not `callvirt`)
instruction.

**Schema note — downstream state.** Downstream path nodes (hop 5, the sink) do
not carry an inherited `bounded_by` annotation in the fixture. This is by design
per the milestone B spec's option (ii) choice: the fixture records what each hop
*observably* does, and the analyzer is responsible for folding the bound forward
from the sanitizer into subsequent nodes. The fixture's role is to provide the
oracle; the bound-propagation logic is the analyzer's concern.

Taint state at **entry**: `fileHeader.Value.Offset` (scalar, unbounded).
Taint state at **exit**: `fileHeader.Value.Offset` (scalar, bounded above by
`stream.Length` on the fall-through path; execution does not reach this point
on the throw path).

---

### Hop 5 — Arithmetic: computing `colorMapSizeBytes`, line 1557

**trace.yaml path:** `path[5]`, `transformation: arithmetic`.

The arithmetic that was the pre-fix vulnerability's immediate precursor to the
sink still executes here, but now under the bound established by hop 4.

Post-fix line 1557:

```csharp
                            // line 1557 — arithmetic: Offset (now bounded) minus two small constants
                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
```

The two subtracted quantities — `BmpFileHeader.Size` (the constant 14) and
`this.infoHeader.HeaderSize` (the info header size, constrained by the BMP spec
to 40, 52, 56, 108, or 124) — are both small positive constants. Because hop 4
established `Offset <= stream.Length`, a forward-folding analyzer can derive:

```
colorMapSizeBytes <= stream.Length - BmpFileHeader.Size - infoHeader.HeaderSize
                  <= stream.Length - 14 - 40
                  == stream.Length - 54
```

This is bounded by the actual file size and is therefore safe for realistic
inputs. The allocation at the sink can no longer be coerced to multi-gigabyte
values by a crafted `Offset`.

Taint state at **entry**: `this.fileHeader.Value.Offset` (scalar, bounded by
`stream.Length` via hop 4's sanitizer).
Taint state at **exit**: `colorMapSizeBytes` (scalar `int`, tainted, bounded
above by `stream.Length - 54` for typical info header sizes).

---

### Sink — `new byte[colorMapSizeBytes]`, line 1606

**trace.yaml path:** `sink` node, `kind: allocation`, `api: new_array`.

`colorMapSizeBytes` reaches the array allocation. Unlike the pre-fix path, the
value arriving here is implicitly bounded because hop 4 bounded `Offset`.

Post-fix lines 1596–1606:

```csharp
        if (colorMapSizeBytes > 0)
        {
            // Make sure, that we will not read pass the bitmap offset (starting position of image data).
            if (this.fileHeader.HasValue && stream.Position > this.fileHeader.Value.Offset - colorMapSizeBytes)
            {
                BmpThrowHelper.ThrowInvalidImageContentException(
                    $"Reading the color map would read beyond the bitmap offset. Either the color map size of '{colorMapSizeBytes}' is invalid or the bitmap offset.");
            }

            // line 1606 — SINK: colorMapSizeBytes is bounded by stream.Length - 54
            palette = new byte[colorMapSizeBytes];
```

Taint state at **entry**: `colorMapSizeBytes` — attacker-influenced, but bounded
above by `stream.Length - BmpFileHeader.Size - infoHeader.HeaderSize`.
Taint state at **exit**: `palette` — heap allocation of a size that cannot
exceed the actual file size minus header overhead.

Compare with the pre-fix sink, where `colorMapSizeBytes` was unbounded and
`palette = new byte[colorMapSizeBytes]` would attempt a multi-gigabyte
allocation for a crafted file. The post-fix trace's `sanitizer_absence` list is
empty (`[]`); the sanitizer is present and effective.

---

## 4. Sanitizer presence

This section corresponds to the pre-fix trace's "Sanitizer absence" section. It
shows the material difference between the two code states.

**Pre-fix (vulnerable)** —
`fixtures/imagesharp-3074-prefix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs:1548-1552`:

```csharp
                    case BmpFileMarkerType.Bitmap:
                        if (this.fileHeader.HasValue)
                        {
                            colorMapSizeBytes = this.fileHeader.Value.Offset - BmpFileHeader.Size - this.infoHeader.HeaderSize;
                        }
```

There is no check that `this.fileHeader.Value.Offset` is within the stream
before it is used as the leading operand of the subtraction. The field load and
the arithmetic occupy the same single statement on line 1551 of the pre-fix
file.

**Post-fix (guarded)** —
`fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs:1548-1557`:

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

The added `if`-block establishes `this.fileHeader.Value.Offset <= stream.Length`
on the fall-through path before the subtraction runs.

**Why the check is sufficient.** Given the bound `Offset <= stream.Length`:

- `BmpFileHeader.Size` is the compile-time constant 14.
- `infoHeader.HeaderSize` is constrained by the BMP specification to the set
  {40, 52, 56, 108, 124}; the minimum is 40.
- Therefore `colorMapSizeBytes = Offset - 14 - HeaderSize <= stream.Length - 54`.

The allocation `new byte[colorMapSizeBytes]` is bounded above by
`stream.Length - 54`. It can still fail with `OutOfMemoryException` if
`stream.Length` itself is large enough to challenge the runtime heap — but that
is a property of the input file's size, not of an unchecked field. The attacker
can no longer request a multi-gigabyte allocation from a tiny file with a
fabricated `Offset`.

**Why the pre-fix guard at line 1594–1603 is insufficient (for reference).** The
check `stream.Position > this.fileHeader.Value.Offset - colorMapSizeBytes` is a
read-overrun guard, not an OOM guard. It operates on values derived from the
already-unbounded `colorMapSizeBytes`. It does not prevent the allocation itself
from being enormous; it only prevents a subsequent `stream.Read` of that buffer
from seeking past the offset marker. In practice it can also fail to trigger
because the subtraction `Offset - colorMapSizeBytes` algebraically cancels to
`BmpFileHeader.Size + infoHeader.HeaderSize`, a small constant, which
`stream.Position` (also small, just past the headers) is unlikely to exceed.

---

## 5. Open schema questions — resolution status

### O1 — `taint_value_state` for sanitizer bounds — **RESOLVED in this milestone**

The v0 schema had no field to express what invariant a sanitizer establishes
about the tainted value. This trace is the first to exercise a sanitizer node.
The resolution chosen in milestone B is:

- Add `establishes_bound` (sub-fields: `target`, `relation`, `upper_bound`) to
  sanitizer nodes. This records the observable effect of a bounds-establishing
  check: after hop 4 executes on the fall-through path, `fileHeader.Value.Offset`
  is known to satisfy `<= stream.Length`.
- Add `on_failure` (sub-fields: `kind`, `exception`) to sanitizer nodes. This
  records the control-flow consequence of a failed check: `throw` with
  `InvalidImageContentException`.
- Downstream hops do **not** carry an inherited bounded-state annotation. The
  fixture records what each hop observably does; forward-propagation of bounds
  into downstream hops is the analyzer's responsibility, not the fixture's. This
  is the option (ii) choice from the milestone B brainstorm.

### O2 — Adjacent same-line hops — still open

The `field_load` (hop 3) + `sanitizer` (hop 4) + `arithmetic` (hop 5) split
now spans three hops across two source lines (1551 and 1557). Hop 3 and hop 4
share line 1551 because the field load is physically inside the condition
expression of the sanitizer. This three-hop split on two lines is slightly
clunky but correct — each hop has an independent `hop` index and distinct
`tainted_value_in` / `tainted_value_out` labels. A later milestone may explore
collapsing adjacent same-line hops into a compound node, but that would require
schema changes that are out of scope here.

### O3 — Async / `MoveNext` dispatch — still open

The BMP decoder is fully synchronous. No `await` expressions appear on the
source-to-sink path; the `async_continuation` dispatch kind defined in v0 is
not exercised by this trace. This is expected and unchanged from the pre-fix
assessment.

### O4 — `Nullable<T>.Value` as a transformation kind — still open

Hop 3 uses `transformation: field_load` to model `this.fileHeader.Value.Offset`.
There are actually two access steps collapsed onto one line: `this.fileHeader.Value`
(unwrapping `Nullable<BmpFileHeader>`, a runtime no-op when `HasValue` is true)
followed by `.Offset` (a genuine struct field load). The schema's `field_load`
kind covers both without ambiguity here because the `HasValue` guard is on the
enclosing `if` branch (line 1549), and the unwrap cannot throw at that point.
The distinction did not affect O1's resolution. If a future trace has a nullable
dereference that is itself the interesting step, a dedicated `nullable_unwrap`
transformation kind may become warranted. Deferred.

### O5 — Compound sanitizer conditions (new in milestone A)

Surfaced by `fixtures/imagesharp-3079-postfix/` and the schema-v0.2 extension
documented in
`docs/superpowers/specs/2026-04-17-imagesharp-3079-trace-design.md`. Fix checks
of the form `if (A < 0 || A + N > data.Length) return;` are disjunctions of two
conditions, but `establishes_bound` records one bound pair. Milestone A
collapses such disjunctions to the meaningful single bound with the full check
text preserved in `note:`. Deferred until an analyzer needs to read compound
conditions mechanically.
