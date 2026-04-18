# ImageSharp #3079 — Pre-fix taint trace narrative

This document is the narrative companion to `trace.yaml` for the *pre-fix*
state of the ImageSharp PNG iTXt decoder vulnerability. It walks the
source-to-sink taint path hop by hop, cites pre-fix source lines verbatim, and
records two missing sanitizers whose absence permits attacker-crafted iTXt
chunks to trigger unhandled exceptions. A reader unfamiliar with the bug should
be able to read this end-to-end and satisfy themselves that the fixture
faithfully captures the vulnerability and that the two `return_early` guards
added by the fix are necessary and sufficient to close it.

Compare with `fixtures/imagesharp-3079-postfix/trace.md` for the post-fix
perspective. The first two path hops (source → hop 0 → hop 1) are structurally
identical between the two traces. The pre-fix path has no sanitizer nodes: what
the post-fix trace calls hop 2 (sanitizer 1) and hop 4 (sanitizer 2) are simply
absent here, and the sink is reached directly from hop 2 (the second `field_load`
propagator, renumbered because the sanitizer hops are missing).

---

## 1. Summary

The SixLabors/ImageSharp PNG decoder (pre-fix) parsed iTXt (International Text)
chunks without validating that the attacker-supplied chunk body was long enough
to contain all variable-length fields it subsequently indexed into. The method
`ReadInternationalTextChunk` located the null terminator ending the English
keyword (`zeroIndexKeyword = data.IndexOf((byte)0)`), then immediately used that
value as an offset into `data` to read the compression flag, compression method,
and language tag — without first confirming that `data` was long enough to hold
those fields past `zeroIndexKeyword`. A truncated iTXt chunk body where
`data.Length == zeroIndexKeyword + 1` (payload ends immediately after the keyword
null terminator) causes `data[zeroIndexKeyword + 1]` to read one byte past the
end of the span, throwing `IndexOutOfRangeException`.

Later in the same method, the code called
`data.Slice(translatedKeywordStartIdx, translatedKeywordLength)` where
`translatedKeywordLength` came from `data[translatedKeywordStartIdx..].IndexOf((byte)0)`.
`IndexOf` returns `-1` when no null byte is found — passing `-1` as the `length`
argument to `Span.Slice` throws `ArgumentOutOfRangeException`. Either exception
propagates unhandled from the PNG decode pipeline, producing a denial-of-service
crash.

The fix (PR #3081, merge commit `89face0b8930068f43db1064a0c00e2170993549`) adds
two `if (...) return;` early-return guards. The first, at post-fix line 1939,
checks `zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length` — ensuring
the chunk body extends far enough past the keyword null for the compression flag,
compression method, and the start of the language tag. The second, at post-fix
line 1969, checks `translatedKeywordLength < 0` before passing the value to
`data.Slice`. Together they close both unhandled-exception DoS vectors.

This vulnerability is distinct from #3074's heap-exhaustion bug. Both flow
untrusted data from the decoder entry point into a size-driving expression, but
#3074's sink is an allocation (`new byte[colorMapSizeBytes]`) whereas #3079's
sink is a span slice (`data.Slice(translatedKeywordStartIdx,
translatedKeywordLength)`). Both belong to the same class of untrusted-size
taint flows; the schema differences that arise from modeling them are discussed
in sections 3 and 5.

---

## 2. PNG chunk reference

Every PNG file begins with an 8-byte signature (`\x89PNG\r\n\x1a\n`) that the
decoder skips before processing chunk data. The body of the file is a sequence
of self-describing chunks. Each chunk has the following four-field framing:

| Offset within chunk | Field  | Width   | Meaning |
|---------------------|--------|---------|---------|
| 0                   | Length | 4 bytes | Number of bytes in the Data field. Does not include type, itself, or CRC. |
| 4                   | Type   | 4 bytes | ASCII label, e.g. `IHDR`, `IDAT`, `iTXt`. |
| 8                   | Data   | N bytes | Chunk payload; N = Length field above. |
| 8 + N               | CRC    | 4 bytes | CRC-32 over Type + Data. |

The `InternationalText` chunk (`iTXt`) carries multilingual text metadata.
Its Data field has the following layout per the PNG specification:

| Field              | Width      | Encoding | Description |
|--------------------|------------|----------|-------------|
| Keyword            | 1–79 bytes | Latin-1  | Human-readable text label. |
| Null separator     | 1 byte     | —        | `0x00`. Terminates the keyword. |
| Compression flag   | 1 byte     | —        | `0` = uncompressed, `1` = compressed. |
| Compression method | 1 byte     | —        | `0` = zlib/deflate (the only defined value). |
| Language tag       | variable   | ASCII    | BCP 47 language tag, may be empty. |
| Null separator     | 1 byte     | —        | `0x00`. Terminates the language tag. |
| Translated keyword | variable   | UTF-8    | Keyword text in the indicated language. |
| Null separator     | 1 byte     | —        | `0x00`. Terminates the translated keyword. |
| Text               | variable   | UTF-8    | The actual text content. |

All of the variable-length fields can be zero bytes long (except the keyword,
which must be 1–79 bytes). Because no field advertises its own length — each is
delimited by a `0x00` null byte found by scanning forward — an attacker can
craft a chunk whose Data payload ends anywhere, making every subsequent field's
offset unpredictable from the decoder's perspective. The bug exploits exactly
this property: a truncated Data payload can make `IndexOf` return -1 (no null
found), and the pre-fix code used that -1 result as an array index or as the
`length` argument to `Span.Slice`.

---

## 3. Hop-by-hop walkthrough

The pre-fix path has three path hops and no sanitizer nodes. The trace.yaml
models this as `source` → `path[0]` (hop 0) → `path[1]` (hop 1) → `path[2]`
(hop 2) → `sink`, with an empty `sanitizer_absence`-compensated gap at the two
locations where the post-fix sanitizers live.

### Source — `Decode`, line 168

**trace.yaml path:** `source` node, `kind: decoder_entry`.

The taint enters at the public decoder entry point. The `stream` parameter
carries raw bytes from the untrusted PNG file; everything parsed from it is
attacker-controlled. In particular, chunk lengths and chunk payloads are read
with no prior validation against any upper bound.

Pre-fix lines 168–175
(`fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`):

```csharp
// line 168
protected override Image<TPixel> Decode<TPixel>(BufferedReadStream stream, CancellationToken cancellationToken)
{
    uint frameCount = 0;
    ImageMetadata metadata = new();
    PngMetadata pngMetadata = metadata.GetPngMetadata();
    this.currentStream = stream;
    this.currentStream.Skip(8);
```

Taint state at **entry**: `stream` — unbounded attacker bytes.
Taint state at **exit**: same `stream` forwarded into the chunk-dispatch loop.

This node is the source because `stream` has received no validated envelope at
this point. The 8-byte signature skip at line 175 reads but does not validate
the signature against any length constraint relevant to subsequent field reads.

---

### Hop 0 — `Decode` → `ReadInternationalTextChunk` call, line 300

**trace.yaml path:** `path[0]`, `role: propagator`, `transformation: identity`.

Inside the chunk-dispatch loop, `Decode` reads each chunk header, switches on
the chunk type, and for `PngChunkType.InternationalText` calls
`ReadInternationalTextChunk` with `chunk.Data.GetSpan()` — the raw chunk body
as a `ReadOnlySpan<byte>`. That span is the tainted `data` that flows through
the rest of the trace.

Pre-fix lines 299–301:

```csharp
                        case PngChunkType.InternationalText:
                            // line 300 — tainted chunk body forwarded to ReadInternationalTextChunk
                            this.ReadInternationalTextChunk(metadata, chunk.Data.GetSpan());
                            break;
```

Taint state at **entry**: `stream` / `chunk.Data` — attacker-controlled bytes.
Taint state at **exit**: `data` (the span passed to `ReadInternationalTextChunk`).

Dispatch is `direct` — `ReadInternationalTextChunk` is a private instance method
on the same class; the IL instruction is `call`, not `callvirt`. No CHA is
required; `resolved_targets` is empty.

---

### Hop 1 — `zeroIndexKeyword` field load, line 1929

**trace.yaml path:** `path[1]`, `role: propagator`, `transformation: field_load`.

The first thing `ReadInternationalTextChunk` does (after a metadata-skip guard)
is call `data.IndexOf((byte)0)` to locate the null terminator that ends the
English keyword. The return value — a signed integer, potentially -1 if no null
is found — is stored in `zeroIndexKeyword`. This is the taint's first
transformation from the opaque span aggregate to a scalar that drives downstream
indexing.

Pre-fix lines 1921–1934:

```csharp
// line 1921
private void ReadInternationalTextChunk(ImageMetadata metadata, ReadOnlySpan<byte> data)
{
    if (this.skipMetadata)
    {
        return;
    }

    PngMetadata pngMetadata = metadata.GetPngMetadata();
    // line 1929 — field_load: taint flows from data span to scalar zeroIndexKeyword
    int zeroIndexKeyword = data.IndexOf((byte)0);
    if (zeroIndexKeyword is < PngConstants.MinTextKeywordLength or > PngConstants.MaxTextKeywordLength)
    {
        return;
    }
```

Taint state at **entry**: `data` (span of attacker-controlled bytes).
Taint state at **exit**: `zeroIndexKeyword` (scalar `int`, attacker-controlled;
the existing range-check at line 1930 constrains it to
`[MinTextKeywordLength, MaxTextKeywordLength]`, but does not constrain it
relative to `data.Length`).

The `field_load` transformation models the narrowing from the span aggregate to
the integer result of `IndexOf`. The range-check at line 1930 establishes
`zeroIndexKeyword >= MinTextKeywordLength > 0`, so `zeroIndexKeyword` is positive
at this point. However, the check does not verify that `data` is long enough to
hold `zeroIndexKeyword + 1` through `zeroIndexKeyword + 3` — the fields the code
reads immediately after.

---

### Hop 2 — `translatedKeywordLength` field load, line 1958

**trace.yaml path:** `path[2]`, `role: propagator`, `transformation: field_load`.

After the keyword-length range-check, the method reads the compression flag and
method directly from `data`, then advances through the language tag fields to
compute `translatedKeywordStartIdx`. It then calls
`data[translatedKeywordStartIdx..].IndexOf((byte)0)` to find the null terminator
of the translated keyword. The result can legitimately be -1 if the span slice
contains no null byte — the dangerous value that flows into the sink.

Pre-fix lines 1948–1959:

```csharp
        int langStartIdx = zeroIndexKeyword + 3;
        int languageLength = data[langStartIdx..].IndexOf((byte)0);
        if (languageLength < 0)
        {
            return;
        }

        string language = PngConstants.LanguageEncoding.GetString(data.Slice(langStartIdx, languageLength));

        // line 1957
        int translatedKeywordStartIdx = langStartIdx + languageLength + 1;
        // line 1958 — field_load: taint flows from data slice to scalar translatedKeywordLength
        int translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0);
        // line 1959 — SINK: no guard here; translatedKeywordLength may be -1
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

Taint state at **entry**: `data` (span, attacker-controlled);
`translatedKeywordStartIdx` (derived from prior `IndexOf` results, themselves
attacker-influenced through `zeroIndexKeyword` and `languageLength`).
Taint state at **exit**: `translatedKeywordLength` (scalar `int`,
attacker-controlled; value is -1 if the span contains no null byte).

Note that the language-tag `IndexOf` at line 1949 does have a guard
(`if (languageLength < 0) return;`) which prevents the language-tag slice from
being negative. The analogous guard for `translatedKeywordLength` is the one
that is missing — it was added by the fix.

This is a second `field_load` hop — the same pattern as hop 1 — because the
transformation is again from a span aggregate to an integer result of `IndexOf`.

---

### Sink — `data.Slice(translatedKeywordStartIdx, translatedKeywordLength)`, line 1959

**trace.yaml path:** `sink` node, `kind: span_access`, `api: span_slice`.

`translatedKeywordLength` reaches the `Span.Slice` call as the `length`
argument. Pre-fix, no guard precedes this call, so `translatedKeywordLength`
can be -1, causing `ArgumentOutOfRangeException`.

Pre-fix line 1959:

```csharp
        // line 1959 — SINK: translatedKeywordLength (potentially -1) passed as Slice length
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

Taint state at **entry**: `translatedKeywordLength` — attacker-influenced,
unchecked, potentially -1.
Taint state at **exit**: would be `translatedKeyword` — a string decoded from
the span slice — but the code throws `ArgumentOutOfRangeException` before the
string is produced when `translatedKeywordLength == -1`.

**Sink class distinction.** This sink is `kind: span_access` / `api: span_slice`,
as opposed to #3074's sink which is `kind: allocation` / `api: new_array`. Both
are triggered by an attacker-controlled size value, but the failure modes differ:

- `new_array` with a large attacker value → `OutOfMemoryException` (heap exhaustion).
- `Span.Slice` with a negative attacker value → `ArgumentOutOfRangeException`
  (invalid argument).

The framing differs from an allocation-like sink: there is no OOM risk here.
The DoS surface is the *throw* itself — an unhandled exception escaping the
decode pipeline. The throw happens immediately at the `Span.Slice` call when
`translatedKeywordLength < 0`; the decoder does not survive to do any heap work.

There is also a latent `IndexOutOfRangeException` vector from the pre-fix
direct indexing at `data[zeroIndexKeyword + 1]` and `data[zeroIndexKeyword + 2]`
(lines 1935 and 1941) — exploitable when the chunk body ends immediately after
the keyword null terminator. That vector is guarded by sanitizer 1 in the
post-fix; its absence is described in section 4.

---

## 4. Sanitizer absence

This section shows what is *not* in the pre-fix code at each of the two
locations where the fix inserted guards, and what the post-fix inserts there.
The two `sanitizer_absence` entries in `trace.yaml` record these positions
with their `expected_check` text quoted from the YAML below.

### Sanitizer 1 absence — `zeroIndexKeyword + 4 <= data.Length`

**trace.yaml reference:** `sanitizer_absence[0]`, location
`src__ImageSharp__Formats__Png__PngDecoderCore.cs:1935`.

Expected check (from `trace.yaml`):

> Before reading data[zeroIndexKeyword + 1] / data[zeroIndexKeyword + 2] / etc.,
> verify zeroIndexKeyword + 4 <= data.Length. Fix adds:
> 'if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length) return;'.

**Pre-fix** — lines 1929–1941. After the keyword-length range-check the method
proceeds directly to `data[zeroIndexKeyword + 1]` with no check that the chunk
body extends past `zeroIndexKeyword`:

```csharp
        // line 1929
        int zeroIndexKeyword = data.IndexOf((byte)0);
        if (zeroIndexKeyword is < PngConstants.MinTextKeywordLength or > PngConstants.MaxTextKeywordLength)
        {
            return;
        }

        // line 1935 — no guard here; data[zeroIndexKeyword + 1] may be out of range
        byte compressionFlag = data[zeroIndexKeyword + 1];
        if (compressionFlag is not (0 or 1))
        {
            return;
        }

        byte compressionMethod = data[zeroIndexKeyword + 2];
```

If `data.Length == zeroIndexKeyword + 1` (the chunk body ends immediately after
the keyword null terminator), then `data[zeroIndexKeyword + 1]` reads one byte
past the end of the span and throws `IndexOutOfRangeException`. The same applies
to `data[zeroIndexKeyword + 2]` at line 1941.

**Post-fix** — same file, post-fix snippet, lines 1934–1948. A guard is
inserted between the keyword-length check and the first direct index operation:

```csharp
        // line 1934
        int zeroIndexKeyword = data.IndexOf((byte)0);
        if (zeroIndexKeyword is < PngConstants.MinTextKeywordLength or > PngConstants.MaxTextKeywordLength)
        {
            return;
        }

        // line 1940 — NEW: ensures data[zeroIndexKeyword + 1..3] are all in bounds
        if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length)
        {
            return; // Not enough data for keyword + null + flag + method + language.
        }

        byte compressionFlag = data[zeroIndexKeyword + 1];
```

**What this check establishes.** On the fall-through path:
`zeroIndexKeyword + 4 <= data.Length`, so `data[zeroIndexKeyword + 1]`,
`data[zeroIndexKeyword + 2]`, and `data[zeroIndexKeyword + 3]` are all within
bounds (the third is the first byte of the language tag or its null terminator).

**Dead left branch.** The condition `zeroIndexKeyword < 0` is never true at
this point: the range-check at the line above already returned early if
`zeroIndexKeyword < MinTextKeywordLength`, and `MinTextKeywordLength > 0`.
So the left disjunct is dead code — the effective condition is just
`zeroIndexKeyword + 4 > data.Length`. In the pre-fix state, the absence of
the entire compound condition means neither the dead left disjunct nor the
live right disjunct is evaluated. See open question O5 in section 5.

---

### Sanitizer 2 absence — `translatedKeywordLength >= 0`

**trace.yaml reference:** `sanitizer_absence[1]`, location
`src__ImageSharp__Formats__Png__PngDecoderCore.cs:1959`.

Expected check (from `trace.yaml`):

> Before data.Slice(translatedKeywordStartIdx, translatedKeywordLength),
> verify translatedKeywordLength >= 0. Fix adds:
> 'if (translatedKeywordLength < 0) return;'.

**Pre-fix** — lines 1957–1959. The `IndexOf` result is used immediately as the
`Slice` length with no intervening check:

```csharp
        // line 1957
        int translatedKeywordStartIdx = langStartIdx + languageLength + 1;
        // line 1958 — IndexOf result stored; potentially -1 if no null found
        int translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0);
        // line 1959 — SINK (pre-fix): translatedKeywordLength flows directly to Slice; no guard
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

If `data[translatedKeywordStartIdx..]` contains no null byte, `IndexOf`
returns -1, and `data.Slice(translatedKeywordStartIdx, -1)` throws
`ArgumentOutOfRangeException` immediately. Note the contrast with the language
tag's `IndexOf` at line 1949, which does check `if (languageLength < 0) return;`
— the identical guard was simply not written for the translated-keyword case.

**Post-fix** — same file, post-fix snippet, lines 1967–1974. A guard is
inserted between the `IndexOf` call and the `Slice` call:

```csharp
        // line 1967
        int translatedKeywordStartIdx = langStartIdx + languageLength + 1;
        // line 1968 — IndexOf result (potentially -1) stored in translatedKeywordLength
        int translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0);
        // line 1969 — NEW: guard against -1
        if (translatedKeywordLength < 0)
        {
            return;
        }

        // line 1974 — SINK (post-fix): translatedKeywordLength is now >= 0
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

**What this check establishes.** On the fall-through path:
`translatedKeywordLength >= 0`. Because `Span<T>.Slice(int start, int length)`
requires `length >= 0` and `start + length <= span.Length`, and the `IndexOf`
return value for a found element is always a valid index within the searched
span, the non-negative guarantee is sufficient to prevent the
`ArgumentOutOfRangeException` that was the sink's failure mode.

This is a lower-bound sanitizer, in contrast to sanitizer 1's upper-bound check.
The schema's `relation` field (`<=` for upper, `>=` for lower) covers both; this
trace's `sanitizer_absence` entries record `expected_check` text describing each,
without needing a separate schema extension for the direction.

---

## 5. Open schema questions — resolution status

The following questions carry over from the #3074 and #3079 post-fix traces.
Full text for each is in `fixtures/imagesharp-3079-postfix/trace.md` section 5.
The pre-fix trace adds no new questions beyond confirming O5's status.

### O1 — `taint_value_state` for sanitizer bounds — resolved in milestone B

The `establishes_bound` and `on_failure` fields added in milestone B to cover
#3074's sanitizer are exercised by the post-fix trace of this bug (#3079
post-fix), confirming their generality across both `throw` and `return_early`
failure kinds, and across both upper-bound and lower-bound checks. The pre-fix
trace has no sanitizer nodes and thus does not exercise these fields. Cross-
reference only; no additional schema change is needed.

### O2 — Adjacent same-line hops and span aggregate → scalar — still open

The `data` span (aggregate) → `zeroIndexKeyword` (scalar) and `data` →
`translatedKeywordLength` (scalar) transformations at hops 1 and 2 both use
`transformation: field_load`. This mirrors #3074's `Nullable<T>.Value.Offset`
pattern: a structured value (the span) produces a scalar via an operation that
the schema collapses to `field_load`. The PNG case is arguably cleaner —
`IndexOf` is explicitly a search that returns a scalar index — but the schema
label is the same. No new pressure on O2.

### O3 — Async / `MoveNext` dispatch — still open

The PNG decoder is fully synchronous on the path traced here. No `await`
expressions appear between the source and the sink. Unchanged from the #3074
assessment.

### O4 — `Nullable<T>.Value` as a transformation kind — still open

#3079 does not traverse `Nullable<T>.Value`. The `field_load` transformations
here are direct `IndexOf` calls on `ReadOnlySpan<byte>`, with no nullable
unwrapping. This trace adds no new pressure on O4.

### O5 — Compound sanitizer conditions — status in pre-fix context

In the post-fix trace (section 5 of `fixtures/imagesharp-3079-postfix/trace.md`),
O5 discusses the disjunction `zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length`
in sanitizer 1, where the left disjunct is dead. That discussion is relevant
only when the sanitizer is present to model. In the pre-fix state the sanitizer
is absent entirely — neither disjunct exists — so the schema complication of
representing a compound condition does not arise here.

However, O5 is still open across the fixture set as a whole. The analogous
question will surface in any post-fix trace whose sanitizer uses a non-trivial
boolean expression. Per the task plan, the #3074 and #3079 pre-fix trace.md
files (this document and `fixtures/imagesharp-3074-prefix/trace.md`) will
receive O5 annotations in task A12. For now, noting the status: **irrelevant
in pre-fix; still open in schema; A12 to annotate**.
