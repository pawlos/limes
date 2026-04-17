# Milestone A — Pre/post-fix trace of ImageSharp #3079

**Status:** Approved 2026-04-17 (awaiting post-write review before execution).
**Predecessors:** Milestone 1 (`2026-04-16-imagesharp-3074-trace-design.md`), Milestone B (`2026-04-17-imagesharp-3074-postfix-trace-design.md`).
**Successor:** Milestone C — tech choice for the analyzer (Roslyn / Cecil-dnlib / ILLink), informed by the combined schema pressure from M1 + B + A.

## Context

Milestone 1 produced the *pre-fix* trace of #3074 (BMP decoder OOM). Milestone B produced the *post-fix* corollary, introducing sanitizer-node fields `establishes_bound` and `on_failure` (schema v0.1) and resolving open question **O1**. Both fixtures model allocation sinks (`sink.kind: allocation`, `sink.api: new_array`) and sanitizers that fail via `throw`.

This milestone traces ImageSharp issue #3079 (PNG iTXt chunk insufficient-data reads, fix PR #3081, merge commit `89face0b8`). Different schema pressure from #3074:

1. The fix's sanitizers `return` rather than `throw` — exercises `FailureKind: return_early`.
2. The sink is span indexing / slicing, not an allocation — forces a new `SinkKinds: span_access` value and new `SinkApis: {span_index, span_slice}` values.
3. One sanitizer establishes a *lower* bound (`translatedKeywordLength >= 0`) — activates the `LowerBound` POCO field that was reserved but unused in M1+B.
4. The fix's checks contain disjunctions (`A < 0 || A + 4 > data.Length`) — records a new open question **O5** (compound sanitizer conditions). Deferred; addressed by collapsing to the meaningful single bound and preserving full text in `note:`.

## Goals

1. Produce `fixtures/imagesharp-3079-prefix/` and `fixtures/imagesharp-3079-postfix/` as sibling fixtures, symmetric with the #3074 pair.
2. Extend the v0.1 schema *additively* to v0.2: close the currently-unvalidated sink vocabulary; add `access_expression` for span sinks; relax sanitizer completeness to accept a lower-bound-only sanitizer.
3. Establish `return_early` and `span_access` as first-class test oracles for the eventual analyzer.
4. Surface (and defer) open question O5.

## Non-goals

- No analyzer code.
- No tech-choice decision (still milestone C).
- No resolution of O2, O3, O4 — #3079 does not pressure them.
- No modifications to the shared ImageSharp clone.
- No renaming of `size_expression` or other breaking schema changes. v0.1 fixtures must continue to validate unchanged.

## Scope and approach

### Which site within #3079?

#3079's fix adds *three* `return_early` checks across two methods:
- Site 1 in `ReadCompressedTextChunk` — one check.
- Sites 2 and 3 in `ReadInternationalTextChunk` — two checks on one linear path.

Traced: **sites 2+3** only. One fixture pair modelling `ReadInternationalTextChunk` end-to-end. The two sanitizer hops sit on the same `path[]` array; sanitizer 1 gates *reachability* to the sink (returning early stops execution before the slice), sanitizer 2 bounds *the slice argument* directly. One sink (`data.Slice(...)`). Rejected: three separate fixtures (effort-heavy; sites 1 and 2 have the same schema pressure), site 1 alone (no multi-sanitizer exercise), site 3 alone (no `return_early` + disjunction pressure).

### Pre-fix + post-fix pair

Both are authored, mirroring the M1 + B pair. Pre-fix has no sanitizer hops and two `sanitizer_absence` entries (one per missing check). Post-fix has the same source → sink but with two sanitizer hops interleaved.

### Commit pinning

- **Post-fix** pinned to `89face0b8` (fix merge) via `git show 89face0b8:src/ImageSharp/Formats/Png/PngDecoderCore.cs`.
- **Pre-fix** pinned to `89face0b8^1` (main-side parent) via `git show 89face0b8^1:...`. Shallow-clone-safe (the main-side parent is expected to be accessible, matching the #3074 precedent; if it isn't, fall back to reverse-applying the fix diff).

Provenance recorded in each snippet's `.meta.json`:

```json
{
  "source_path": "src/ImageSharp/Formats/Png/PngDecoderCore.cs",
  "recovered_against_sha": "<89face0b8 or its main-parent>",
  "recovery_method": "git-show-at-fix-merge | git-show-at-pre-merge-parent",
  "sha256": "<computed at implementation time>"
}
```

### Directory layout

```
fixtures/imagesharp-3079-prefix/
  fix-files.txt
  trace.yaml
  trace.md
  snippets/
    src__ImageSharp__Formats__Png__PngDecoderCore.cs
    src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json
fixtures/imagesharp-3079-postfix/
  fix-files.txt
  trace.yaml
  trace.md
  snippets/
    src__ImageSharp__Formats__Png__PngDecoderCore.cs
    src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json
```

Each `fix-files.txt`: one line, `src/ImageSharp/Formats/Png/PngDecoderCore.cs`.

## Schema v0.1 → v0.2 additions

Additive. Every existing fixture validates unchanged.

### Two new closed vocabularies

```csharp
public static readonly FrozenSet<string> SinkKinds = new HashSet<string>(StringComparer.Ordinal)
{
    "allocation",
    "span_access",
}.ToFrozenSet(StringComparer.Ordinal);

public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
{
    "new_array", "array_pool_rent", "alloc_hglobal",
    "memory_pool_rent", "stackalloc",
    "span_index", "span_slice",
}.ToFrozenSet(StringComparer.Ordinal);
```

### New POCO field on `PathNode`

```csharp
[YamlMember(Alias = "access_expression")] public string? AccessExpression { get; init; }
```

Parallels `size_expression`. Populated on span-access sinks.

### New diagnostic codes

- **FX015** — closed-vocab enforcement. Emitted when `sink.kind` is set but not in `SinkKinds`, or `sink.api` is set but not in `SinkApis`. Diagnostic messages:
  - `"invalid value '<v>' at sink.kind; allowed: allocation, span_access"`
  - `"invalid value '<v>' at sink.api; allowed: alloc_hglobal, array_pool_rent, memory_pool_rent, new_array, span_index, span_slice, stackalloc"` (sorted ordinal).

- **FX024** — sink completeness + kind/api coupling. On the `sink` top-level object (NOT per-hop):
  - If `sink.kind == "allocation"`:
    - `sink.api` must be in `{new_array, array_pool_rent, alloc_hglobal, memory_pool_rent, stackalloc}`.
    - `sink.size_expression` must be populated.
    - Diagnostic if violated: `"sink declares kind 'allocation' but api '<v>' is not an allocation api"` or `"sink with kind 'allocation' requires size_expression"`.
  - If `sink.kind == "span_access"`:
    - `sink.api` must be in `{span_index, span_slice}`.
    - `sink.access_expression` must be populated.
    - Diagnostic if violated: mirror-symmetric.
  - If `sink.kind` is absent or FX015-invalid, FX024 does not emit (it would be double-reporting).

- **FX023 refinement** — the existing FX023 rule required `UpperBound` specifically on every sanitizer node. Relaxed: FX023 now requires **at least one** of `UpperBound` or `LowerBound` (still requires `target`, `relation`, and `on_failure.kind`; still requires `on_failure.exception` when `on_failure.kind == "throw"`).

  When `relation ∈ {>, >=}`, the meaningful bound is `lower_bound`. When `relation ∈ {<, <=}`, the meaningful bound is `upper_bound`. Validator does not enforce this coupling — it accepts any combination. The fixture author is trusted to pair them sensibly. (We can tighten later if a bug produces a bad pairing.)

  **Test migration:** the M2 test `SanitizerNode_MissingRequiredField_ReportsFX023` has a `[InlineData("upper_bound", "establishes_bound.upper_bound")]` row that asserts "missing upper_bound alone produces FX023". After the refinement, missing upper_bound alone (with lower_bound also absent) still produces FX023, but with a different message (now about "at least one of upper_bound or lower_bound"). Update that InlineData row to accommodate the new message shape, or split the test: remove the upper_bound row from the existing theory, add a new `SanitizerNode_MissingBothBounds_ReportsFX023` fact. Retain all other FX023 rows unchanged.

### Backwards compatibility audit

- M1 pre-fix fixture (`imagesharp-3074-prefix/trace.yaml`): `sink.kind: allocation`, `sink.api: new_array`, `size_expression: colorMapSizeBytes`. No sanitizer hops. Passes FX015, FX024. FX023 trivially satisfied (no sanitizer nodes).
- M2 post-fix fixture (`imagesharp-3074-postfix/trace.yaml`): same sink shape as M1; one sanitizer hop with `upper_bound: stream.Length`. FX023 still passes (UpperBound present — the refinement allows UpperBound alone).

Both satisfy v0.2 without modification.

## Trace shape

### Post-fix `trace.yaml`

Approximate hop sequence (exact post-fix line numbers verified during implementation):

1. **source:** `PngDecoderCore.Decode<TPixel>(BufferedReadStream stream, CancellationToken)`.
2. **Hops 0..N-1 (chunk dispatch):** the PNG decoder's chunk-loop calls `ReadChunk(stream)`, which reads a chunk type and a `data` span, then dispatches to per-chunk handlers. 2–4 propagator hops expected. The last hop before entering `ReadInternationalTextChunk` forwards `data` to it.
3. **Hop N (entry):** first hop inside `ReadInternationalTextChunk(metadata, data)` — either a propagator for the `data` parameter itself or the first operation that touches it (`int zeroIndexKeyword = data.IndexOf((byte)0);`). Transformation `read_stream` or `identity` depending on framing.
4. **Hop N+1 — Sanitizer 1:** the fix's new check at post-fix line ~1941. Fields:
   - `role: sanitizer`
   - `establishes_bound: { target: zeroIndexKeyword, relation: "<=", upper_bound: "data.Length - 4" }`
   - `on_failure: { kind: return_early }` (no `exception` field — not required when `kind != throw`)
   - `note:` records the full check text, including the redundant `zeroIndexKeyword < 0` disjunct that is dead under the prior range-check.
5. **Hops N+2..N+k (between sanitizers):** propagators for the reads guarded by sanitizer 1 — `compressionFlag = data[zeroIndexKeyword + 1]`, etc. — followed by computation of `translatedKeywordStartIdx` and `translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0)`.
6. **Hop N+k+1 — Sanitizer 2:** the fix's new check at post-fix line ~1970. Fields:
   - `role: sanitizer`
   - `establishes_bound: { target: translatedKeywordLength, relation: ">=", lower_bound: "0" }`
   - `on_failure: { kind: return_early }`
   - `note:` records the single-condition check.
7. **Sink:** `data.Slice(translatedKeywordStartIdx, translatedKeywordLength)` at post-fix line ~1976. Fields:
   - `kind: span_access`
   - `api: span_slice`
   - `access_expression: "data.Slice(translatedKeywordStartIdx, translatedKeywordLength)"`

`sanitizer_absence: []`.

### Pre-fix `trace.yaml`

Same source → same propagator chain → same sink. `path[]` contains the same propagator hops but NO sanitizer hops. `sanitizer_absence` has TWO entries:

```yaml
sanitizer_absence:
  - location: src__...PngDecoderCore.cs:<pre-fix line where sanitizer 1 should have been>
    expected_check: "Before reading data[zeroIndexKeyword + 1], verify zeroIndexKeyword + 4 <= data.Length."
    tainted_value: zeroIndexKeyword
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: 89face0b8
      added_lines: src/ImageSharp/Formats/Png/PngDecoderCore.cs:<post-fix range>
  - location: src__...PngDecoderCore.cs:<pre-fix line where sanitizer 2 should have been>
    expected_check: "Before data.Slice(translatedKeywordStartIdx, translatedKeywordLength), verify translatedKeywordLength >= 0."
    tainted_value: translatedKeywordLength
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: 89face0b8
      added_lines: src/ImageSharp/Formats/Png/PngDecoderCore.cs:<post-fix range>
```

## Narrative (`trace.md`)

Structure mirrors M1/M2's `trace.md` (summary / header reference / hop-by-hop / sanitizer presence or absence / open questions). PNG-specific deltas:

- **PNG chunk structure reference** replaces the BMP header reference. Covers the PNG signature (8 bytes), the chunk framing (length / type / data / CRC), and the iTXt chunk's internal layout (keyword / null / compression flag / method / language tag / null / translated keyword / null / text).
- **"`return_early` failure kind"** — post-fix narrative explains that on sanitizer failure, the handler silently skips the malformed chunk; downstream analysis should treat the sink as unreachable on the failure branch, not terminated via an exception.
- **"Lower bounds"** — post-fix narrative explains why sanitizer 2 uses `LowerBound` (the failure mode is `IndexOf` returning -1, i.e., the tainted value can be negative; the sanitizer restores the invariant `value >= 0`).
- **"Span-access sinks"** — new section distinguishing span-access from allocation sinks. Notes that the DoS surface here is an unhandled `IndexOutOfRangeException` or `ArgumentOutOfRangeException`, not heap exhaustion.
- **Open questions** — add **O5** (compound sanitizer conditions); mark O2/O3/O4 still open with no new pressure from this fixture; reference O1's resolution in M2.

## Done criteria

1. Both #3079 fixtures validate `OK`.
2. Both #3074 fixtures still validate `OK` (no regression from v0.1 → v0.2).
3. Validator gains FX015 + FX024 and refines FX023 (accept UpperBound OR LowerBound); all tests green. Estimated ~6 new tests, 1 M2 test updated.
4. `dotnet build --no-incremental` — 0 warnings, 0 errors.
5. Post-fix `trace.md` explains `return_early`, lower bounds, span-access sinks; a reader unfamiliar with the bug can follow it end-to-end.
6. O5 recorded in both #3079 `trace.md` files and noted in both #3074 `trace.md` files' open-questions sections (cross-reference, not full text).
7. Shared ImageSharp clone untouched.

## Open questions after milestone A

- **O1** — resolved in milestone B.
- **O2** — still open; no new pressure from this fixture.
- **O3** — still open; #3079 is synchronous, same as #3074.
- **O4** — still open; #3079 does not traverse a `Nullable<T>.Value`.
- **O5 — NEW** — compound sanitizer conditions (`A < 0 || A + 4 > data.Length`). Current `establishes_bound` records one bound pair. Milestone A collapses disjunctions to the meaningful single bound, with full check text in `note:`. Deferred until an analyzer actually needs to read compound conditions mechanically.

## Execution plan outline

(Full plan authored in the writing-plans step.)

1. Extend schema: add `SinkKinds` and `SinkApis` vocabs; add `AccessExpression` property on `PathNode`.
2. TDD FX015 (invalid `sink.kind` / invalid `sink.api`).
3. TDD FX024 (sink kind/api/expression coupling — allocation requires size_expression; span_access requires access_expression).
4. Refine FX023: update M2's upper_bound-missing test, add a new "missing both bounds" test, relax the validator to accept UpperBound OR LowerBound.
5. Extract post-fix snippet at `89face0b8`; write `.meta.json`.
6. Extract pre-fix snippet at `89face0b8^1`; write `.meta.json`.
7. Author post-fix `trace.yaml` with two sanitizer hops and span_slice sink. Validate green.
8. Author pre-fix `trace.yaml` with two `sanitizer_absence` entries. Validate green.
9. Author post-fix `trace.md` and pre-fix `trace.md`.
10. Annotate M1 and M2 `trace.md` with O5 cross-reference.
11. Final cross-check: all four fixtures green; build clean.
