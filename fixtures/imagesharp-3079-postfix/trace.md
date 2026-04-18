# ImageSharp #3079 — Post-fix taint trace narrative

This document is the narrative companion to `trace.yaml` for the *post-fix*
state of the ImageSharp PNG iTXt decoder vulnerability. It walks the
source-to-sink taint path hop by hop, cites post-fix source lines verbatim,
and records the resolution status of the open schema questions that carry over
from #3074 plus one new question (O5) introduced by this trace's compound
sanitizer condition. A reader unfamiliar with the bug should be able to read
this end-to-end and satisfy themselves that the two `return_early` guards
faithfully eliminate the out-of-range span access.

Compare with `fixtures/imagesharp-3079-prefix/trace.md` for the pre-fix
perspective. The first two hops (source → hop 0 → hop 1) are structurally
identical between the two traces; the new material begins at hop 2 (the first
`return_early` sanitizer) and hop 4 (the second), which are absent from the
pre-fix path.

---

## 1. Summary

The SixLabors/ImageSharp PNG decoder (pre-fix) parsed iTXt (International
Text) chunks without validating that the attacker-supplied chunk body was long
enough to contain all variable-length fields it subsequently indexed into. The
method `ReadInternationalTextChunk` located the null terminator ending the
English keyword (`zeroIndexKeyword = data.IndexOf((byte)0)`), then immediately
used that value as an offset into `data` to read the compression flag, method,
and language tag — without first confirming that `data` was long enough to
hold those fields. Later in the same method it called
`data.Slice(translatedKeywordStartIdx, translatedKeywordLength)` where
`translatedKeywordLength` came from a second `IndexOf` that returns `-1` on
failure; passing `-1` as the `Slice` length argument throws
`ArgumentOutOfRangeException`. A crafted PNG with a truncated iTXt chunk body
could trigger this path, crashing the decode pipeline with an unhandled
exception — a denial-of-service vector.

The fix (PR #3081, commit `89face0b8930068f43db1064a0c00e2170993549`) adds two
`if (...) return;` guards. The first, at post-fix line 1939, checks that the
chunk body extends at least four bytes past `zeroIndexKeyword` — enough room
for the keyword null terminator, compression flag, compression method, and the
start of the language tag. The second, at post-fix line 1969, checks that
`translatedKeywordLength >= 0` before passing it to `data.Slice`. Together
they close the unhandled-exception DoS surface: an attacker can no longer make
the decoder throw `IndexOutOfRangeException` (from direct indexing past the
span end) or `ArgumentOutOfRangeException` (from a negative `Slice` length).

This vulnerability is distinct from #3074's heap-exhaustion bug. Both flow
untrusted data from the decoder entry point into a size-driving expression,
but #3074's sink is an allocation (`new byte[colorMapSizeBytes]`) whereas
#3079's sink is a span slice (`data.Slice(translatedKeywordStartIdx,
translatedKeywordLength)`). Both belong to the same class of untrusted-size
taint flows; the schema differences that arise from modeling them are discussed
in sections 3 and 5.

---

## 2. PNG chunk reference

Every PNG file begins with an 8-byte signature (`\x89PNG\r\n\x1a\n`) that the
decoder skips before processing chunk data. The body of the file is a sequence
of self-describing chunks. Each chunk has the following four-field framing:

| Offset within chunk | Field       | Width   | Meaning |
|---------------------|-------------|---------|---------|
| 0                   | Length      | 4 bytes | Number of bytes in the Data field. Does not include type, itself, or CRC. |
| 4                   | Type        | 4 bytes | ASCII label, e.g. `IHDR`, `IDAT`, `iTXt`. |
| 8                   | Data        | N bytes | Chunk payload; N = Length field above. |
| 8 + N               | CRC         | 4 bytes | CRC-32 over Type + Data. |

The `InternationalText` chunk (`iTXt`) carries multilingual text metadata.
Its Data field has the following layout per the PNG specification:

| Field                | Width         | Encoding | Description |
|----------------------|---------------|----------|-------------|
| Keyword              | 1–79 bytes    | Latin-1  | Human-readable text label. |
| Null separator       | 1 byte        | —        | `0x00`. Terminates the keyword. |
| Compression flag     | 1 byte        | —        | `0` = uncompressed, `1` = compressed. |
| Compression method   | 1 byte        | —        | `0` = zlib/deflate (the only defined value). |
| Language tag         | variable      | ASCII    | BCP 47 language tag, may be empty. |
| Null separator       | 1 byte        | —        | `0x00`. Terminates the language tag. |
| Translated keyword   | variable      | UTF-8    | Keyword text in the indicated language. |
| Null separator       | 1 byte        | —        | `0x00`. Terminates the translated keyword. |
| Text                 | variable      | UTF-8    | The actual text content. |

All of the variable-length fields can be zero bytes long (except the keyword,
which must be 1–79 bytes). Because no field advertises its own length — each
is delimited by a `0x00` null byte found by scanning forward — an attacker
can craft a chunk whose Data payload ends anywhere, making every subsequent
field's offset unpredictable from the decoder's perspective. The bug exploits
exactly this property: a truncated Data payload can make `IndexOf` return -1
(no null found), and the decoder's pre-fix code used that -1 result as an
array index or as the `length` argument to `Span.Slice`.

---

## 3. Hop-by-hop walkthrough

### Source — `Decode`, line 168

**trace.yaml path:** `source` node, `kind: decoder_entry`.

The taint enters at the public decoder entry point. The `stream` parameter
carries raw bytes from the untrusted PNG file; everything parsed from it is
attacker-controlled. In particular, chunk lengths and chunk payloads are read
with no prior validation against any upper bound.

Post-fix lines 168–175
(`fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`):

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

Post-fix lines 299–302:

```csharp
                        case PngChunkType.InternationalText:
                            // line 300 — tainted chunk body forwarded to ReadInternationalTextChunk
                            this.ReadInternationalTextChunk(metadata, chunk.Data.GetSpan());
                            break;
```

Taint state at **entry**: `stream` / `chunk.Data` — attacker-controlled bytes.
Taint state at **exit**: `data` (the span passed to `ReadInternationalTextChunk`).

Dispatch is `direct` — `ReadInternationalTextChunk` is a private instance
method on the same class; the IL instruction is `call`, not `callvirt`. No
CHA is required; `resolved_targets` is empty.

---

### Hop 1 — `zeroIndexKeyword` field load, line 1934

**trace.yaml path:** `path[1]`, `role: propagator`, `transformation: field_load`.

The first thing `ReadInternationalTextChunk` does (after a metadata-skip guard)
is call `data.IndexOf((byte)0)` to locate the null terminator that ends the
English keyword. The return value — a signed integer, potentially -1 if no null
is found — is stored in `zeroIndexKeyword`. This is the taint's first
transformation from the opaque span aggregate to a scalar that drives
downstream indexing.

Post-fix lines 1926–1937:

```csharp
// line 1926
private void ReadInternationalTextChunk(ImageMetadata metadata, ReadOnlySpan<byte> data)
{
    if (this.skipMetadata)
    {
        return;
    }

    PngMetadata pngMetadata = metadata.GetPngMetadata();
    // line 1934 — field_load: taint flows from data span to scalar zeroIndexKeyword
    int zeroIndexKeyword = data.IndexOf((byte)0);
    if (zeroIndexKeyword is < PngConstants.MinTextKeywordLength or > PngConstants.MaxTextKeywordLength)
    {
        return;
    }
```

Taint state at **entry**: `data` (span of attacker-controlled bytes).
Taint state at **exit**: `zeroIndexKeyword` (scalar `int`, attacker-controlled;
the existing range-check at line 1935 constrains it to
`[MinTextKeywordLength, MaxTextKeywordLength]`, but `MinTextKeywordLength > 0`
so the value is positive at this point).

The `field_load` transformation models the narrowing from the span aggregate
to the integer result of `IndexOf`. The pre-existing range-check at line 1935
establishes `zeroIndexKeyword >= MinTextKeywordLength > 0`, which matters for
understanding sanitizer 1 (see hop 2 below).

---

### Hop 2 — Sanitizer 1: `zeroIndexKeyword + 4 <= data.Length` guard, line 1939

**trace.yaml path:** `path[2]`, `role: sanitizer`, `on_failure: return_early`.

This is the fix's first new guard. It checks that the chunk body contains at
least `zeroIndexKeyword + 4` bytes — i.e., that there is enough room beyond
the keyword null terminator for the compression flag (1 byte), compression
method (1 byte), and the start of the language tag (at least 1 null byte).
Without this check, the pre-fix code blindly indexed `data[zeroIndexKeyword + 1]`
through `data[zeroIndexKeyword + 3]`, which throws `IndexOutOfRangeException`
if the chunk is truncated.

Post-fix lines 1939–1943:

```csharp
        // line 1939 — sanitizer 1: establishes zeroIndexKeyword + 4 <= data.Length
        if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length)
        {
            return; // Not enough data for keyword + null + flag + method + language.
        }
```

Taint state at **entry**: `zeroIndexKeyword` (positive, bounded in
`[MinTextKeywordLength, MaxTextKeywordLength]` by the prior check, but not
bounded relative to `data.Length`).
Taint state at **exit** (fall-through): `zeroIndexKeyword` with the additional
invariant `zeroIndexKeyword <= data.Length - 4`.

**`establishes_bound` block:**

```yaml
establishes_bound:
  target: zeroIndexKeyword
  relation: "<="
  upper_bound: "data.Length - 4"
```

On the fall-through path the runtime has confirmed
`zeroIndexKeyword + 4 <= data.Length`, equivalently
`zeroIndexKeyword <= data.Length - 4`. This bound makes the immediately
following direct accesses `data[zeroIndexKeyword + 1]` and
`data[zeroIndexKeyword + 2]` safe.

**`on_failure` block:**

```yaml
on_failure:
  kind: return_early
```

When the condition is true the method silently returns. There is no exception
thrown; the decode of this particular chunk is abandoned and the caller
(`Decode`) continues to the next chunk. This is the primary schema difference
from #3074's sanitizer, which used `on_failure: { kind: throw, exception:
InvalidImageContentException }`. Here the failure mode is a silent no-op,
consistent with ImageSharp's policy that malformed ancillary chunk metadata
should be skipped rather than treated as a fatal decode error.

**The disjunction and the dead left branch (open question O5).** The condition
is written `zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length`. The
left disjunct (`zeroIndexKeyword < 0`) is dead: the prior range-check at line
1935 already establishes `zeroIndexKeyword >= MinTextKeywordLength > 0`, so
`zeroIndexKeyword` is always positive here. The meaningful new contribution is
the right disjunct, `zeroIndexKeyword + 4 > data.Length`. The fixture collapses
to the single effective bound in `establishes_bound` and preserves the full
source text in the `note:` field. This is open question O5 — see section 5.

---

### Hop 3 — `translatedKeywordLength` field load, line 1968

**trace.yaml path:** `path[3]`, `role: propagator`, `transformation: field_load`.

After the sanitizer-1 fall-through, the method advances through the language
tag fields and computes `translatedKeywordStartIdx`, then searches for the null
terminator ending the translated keyword. The `IndexOf` returns -1 if the span
slice `data[translatedKeywordStartIdx..]` contains no null byte.

Post-fix lines 1965–1970:

```csharp
        string language = PngConstants.LanguageEncoding.GetString(data.Slice(langStartIdx, languageLength));

        int translatedKeywordStartIdx = langStartIdx + languageLength + 1;
        // line 1968 — field_load: taint flows from data slice to scalar translatedKeywordLength
        int translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0);
        // line 1969 — sanitizer 2 (below)
        if (translatedKeywordLength < 0)
```

Taint state at **entry**: `data` (span, attacker-controlled);
`translatedKeywordStartIdx` (derived from prior `IndexOf` results, which are
themselves attacker-influenced through `zeroIndexKeyword` and `languageLength`).
Taint state at **exit**: `translatedKeywordLength` (scalar `int`,
attacker-controlled; value is -1 if the span contains no null byte).

This is a second `field_load` hop — the same pattern as hop 1 — because the
transformation is again from a span aggregate to an integer result of `IndexOf`.
The result can legitimately be -1, which is the dangerous value that sanitizer 2
guards against.

---

### Hop 4 — Sanitizer 2: `translatedKeywordLength >= 0` guard, line 1969

**trace.yaml path:** `path[4]`, `role: sanitizer`, `on_failure: return_early`.

This is the fix's second new guard. It checks that `translatedKeywordLength >= 0`
before the value is passed to `data.Slice` as the `length` argument. Pre-fix,
`data.Slice(translatedKeywordStartIdx, translatedKeywordLength)` was called
unconditionally; passing -1 as the length throws `ArgumentOutOfRangeException`.

Post-fix lines 1969–1972:

```csharp
        // line 1969 — sanitizer 2: establishes translatedKeywordLength >= 0
        if (translatedKeywordLength < 0)
        {
            return;
        }
```

Taint state at **entry**: `translatedKeywordLength` (scalar, potentially -1 if
`IndexOf` found no null byte).
Taint state at **exit** (fall-through): `translatedKeywordLength >= 0`.

**`establishes_bound` block:**

```yaml
establishes_bound:
  target: translatedKeywordLength
  relation: ">="
  lower_bound: "0"
```

This is a lower-bound check, unlike sanitizer 1's upper-bound. The taint
analysis schema handles both through the `relation` field (`<=` for upper,
`>=` for lower). This is the first trace in the fixture set to record a
lower-bound sanitizer; it adds no new schema pressure beyond confirming that
the `relation` + `lower_bound` pair is sufficient to express it.

**`on_failure` block:**

```yaml
on_failure:
  kind: return_early
```

Same silent-return behavior as sanitizer 1. Control does not reach the sink if
`translatedKeywordLength < 0`.

---

### Sink — `data.Slice(translatedKeywordStartIdx, translatedKeywordLength)`, line 1974

**trace.yaml path:** `sink` node, `kind: span_access`, `api: span_slice`.

`translatedKeywordLength` reaches the `Span.Slice` call as the `length`
argument. In the post-fix code this value is guaranteed to be >= 0 by hop 4's
sanitizer, so the call is safe. In the pre-fix code it could be -1, causing
`ArgumentOutOfRangeException`.

Post-fix lines 1972–1975:

```csharp
        }

        // line 1974 — SINK: translatedKeywordLength (now >= 0) passed as Slice length
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

Taint state at **entry**: `translatedKeywordLength` — attacker-influenced,
bounded below by 0 via hop 4's sanitizer.
Taint state at **exit**: `translatedKeyword` — a string decoded from the
span slice; the span operation itself cannot throw because the length is
non-negative.

**Sink class distinction.** This sink is `kind: span_access` / `api: span_slice`,
as opposed to #3074's sink which is `kind: allocation` / `api: new_array`. Both
are triggered by an attacker-controlled size value, but the failure modes differ:

- `new_array` with a large attacker value → `OutOfMemoryException` (heap exhaustion).
- `Span.Slice` with a negative attacker value → `ArgumentOutOfRangeException`
  (invalid argument). With an out-of-range positive value it would instead be
  `ArgumentOutOfRangeException` from the slice exceeding the span bounds.

The pre-fix path also had a latent `IndexOutOfRangeException` risk from
`data[zeroIndexKeyword + 1]` when the span was truncated — that is guarded by
sanitizer 1 before the flow even reaches hop 3.

The post-fix trace's `sanitizer_absence` list is empty (`[]`); both sanitizers
are present and effective.

---

## 4. Sanitizer presence

This section shows the code diff for each sanitizer — what was present in the
pre-fix state at the position where the guard should have been, and what the
post-fix state inserts there.

### Sanitizer 1 — `zeroIndexKeyword + 4 <= data.Length`

**Pre-fix** — `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`,
lines 1929–1938. The method proceeds directly to indexing `data` after the
keyword-length range-check, with no check that the chunk body is long enough
to contain the fixed-size fields at the offsets it is about to read:

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
```

If `data.Length == zeroIndexKeyword + 1` (i.e., the chunk body ends immediately
after the keyword null terminator), then `data[zeroIndexKeyword + 1]` reads one
byte past the end of the span and throws `IndexOutOfRangeException`.

**Post-fix** — same file, post-fix snippet, lines 1934–1945. The new guard
is inserted between the keyword-length check and the first direct index
operation:

```csharp
        // line 1934
        int zeroIndexKeyword = data.IndexOf((byte)0);
        if (zeroIndexKeyword is < PngConstants.MinTextKeywordLength or > PngConstants.MaxTextKeywordLength)
        {
            return;
        }

        // line 1939 — NEW: ensures data[zeroIndexKeyword + 1..3] are all in bounds
        if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length)
        {
            return; // Not enough data for keyword + null + flag + method + language.
        }

        byte compressionFlag = data[zeroIndexKeyword + 1];
```

**What this check establishes.** On the fall-through path:
`zeroIndexKeyword + 4 <= data.Length`, so `data[zeroIndexKeyword + 1]`,
`data[zeroIndexKeyword + 2]`, and `data[zeroIndexKeyword + 3]` are all within
bounds.

**Dead left branch.** The condition `zeroIndexKeyword < 0` is never true at
this point: the range-check at the line above already returned early if
`zeroIndexKeyword < MinTextKeywordLength`, and `MinTextKeywordLength > 0`.
So the left disjunct is dead code — the condition is equivalent to just
`zeroIndexKeyword + 4 > data.Length`. The fixture records the full source
text in the YAML `note:` field and collapses `establishes_bound` to the
single meaningful bound. See open question O5 in section 5.

---

### Sanitizer 2 — `translatedKeywordLength >= 0`

**Pre-fix** — `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`,
lines 1957–1959. The `IndexOf` result is used immediately as the `Slice`
length with no intervening check:

```csharp
        // line 1957
        int translatedKeywordStartIdx = langStartIdx + languageLength + 1;
        int translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0);
        // line 1959 — SINK (pre-fix): translatedKeywordLength may be -1
        string translatedKeyword = PngConstants.TranslatedEncoding.GetString(data.Slice(translatedKeywordStartIdx, translatedKeywordLength));
```

If `data[translatedKeywordStartIdx..]` contains no null byte, `IndexOf`
returns -1, and `data.Slice(translatedKeywordStartIdx, -1)` throws
`ArgumentOutOfRangeException` immediately.

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
requires `length >= 0` and `start + length <= span.Length`, and the
`IndexOf` return value for a found element is always a valid index within the
searched span, the non-negative guarantee is sufficient to prevent the
`ArgumentOutOfRangeException` that was the sink's failure mode.

---

## 5. Open schema questions — resolution status

### O1 — `taint_value_state` for sanitizer bounds — resolved in milestone B

The `establishes_bound` and `on_failure` fields added in milestone B to cover
#3074's sanitizer are exercised again here, confirming their generality across
both `throw` and `return_early` failure kinds, and across both upper-bound and
lower-bound checks. No additional schema change is needed for #3079. Cross-
reference only.

### O2 — Adjacent same-line hops and span aggregate → scalar — still open

The `data` span (aggregate) → `zeroIndexKeyword` (scalar) and `data` →
`translatedKeywordLength` (scalar) transformations at hops 1 and 3 both use
`transformation: field_load`. This mirrors #3074's `Nullable<T>.Value.Offset`
pattern: a structured value (the span, or the nullable struct) produces a
scalar via an operation that the schema collapses to `field_load`. The PNG
case is arguably cleaner — `IndexOf` is explicitly a search that returns a
scalar index — but the schema label is the same. No new pressure on O2.

### O3 — Async / `MoveNext` dispatch — still open

The PNG decoder is fully synchronous on the path traced here. No `await`
expressions appear between the source and the sink. Unchanged from the #3074
assessment.

### O4 — `Nullable<T>.Value` as a transformation kind — still open

#3079 does not traverse `Nullable<T>.Value`. The `field_load` transformations
here are direct `IndexOf` calls on `ReadOnlySpan<byte>`, with no nullable
unwrapping. This trace adds no new pressure on O4.

### O5 — Compound sanitizer conditions — NEW in this trace

Sanitizer 1's check is `if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length)`.
This is a disjunction of two sub-conditions, but `establishes_bound` records
only one bound pair (`target: zeroIndexKeyword`, `relation: <=`,
`upper_bound: data.Length - 4`). The left disjunct is dead — the prior
range-check already ensures `zeroIndexKeyword >= MinTextKeywordLength > 0` —
so collapsing to the single effective right-side bound is correct here.

The schema question is what to do when a sanitizer condition is a non-trivial
boolean expression — a conjunction, a disjunction with live branches, or a
compound relational expression — and the fixture must express what the
fall-through path has established. Options include:

- **Single bound with note (current):** Record the most restrictive or most
  meaningful bound; preserve full source text in `note:`. Simple; loses
  structured information about the other disjunct or conjunct.
- **Bound list:** Allow `establishes_bound` to be a list, with each entry
  tagged as the condition established by the fall-through of the full
  expression. More expressive; requires schema change.
- **Condition expression:** Record a boolean expression string that an analyzer
  can parse. Maximally expressive; imposes a mini-language burden.

For this milestone the fixture uses option 1 (single bound with note). The
dead-left-branch case is common in defensive coding (authors sometimes write
`x < 0 || x > limit` out of habit even when an earlier check has already
ruled out the negative case) and a mechanical analyzer will want to recognize
and collapse it. Deferred until an analyzer needs to consume compound
conditions structurally.
