# Milestone E — strict-mode bonus recovery + stackalloc sink kind

**Status:** Approved 2026-04-28.
**Predecessors:**
- Milestone D (`2026-04-27-milestone-d-design.md`) — FX064 budget + emission noise reduction; closed at 1/4 strict-passes (synthetic only) against a ≥3/4 target.
- Milestone-D backlog (`docs/superpowers/plans/2026-04-26-milestone-d-backlog.md`) — six entries; this milestone takes three of them (cross-method sink dedup, strict-mode hop dedup, stackalloc sink kind).
**Successor:** Milestone F — addresses the remaining backlog entries (tainted-value naming, parquet-dotnet round-trip, U1.c redesign), plus whatever new findings emerge from milestone-E's strict-mode tally.

## Context

Milestone D shipped a tiered required/bonus structure. Required gate met (4/4 fixtures pass `--compare` non-strict, no regression). Bonus gate underdelivered: 1/4 strict-passes, vs the ≥3/4 spec target. Milestone-D's revision-history tally:

| Fixture | D_a / D_strict-ceiling | H_a / H_strict-ceiling | Strict |
|---|---|---|---|
| `imagesharp-3074-prefix`  | 3 / ≤1   | 103   / ≤10 | ❌ |
| `imagesharp-3074-postfix` | 3 / ≤1   | 107   / ≤12 | ❌ |
| `imagesharp-3079-prefix`  | 51 / ≤1  | 20084 / ≤6  | ❌ |
| `synthetic-callee-arithmetic` | 1 / ≤1 | 5 / ≤8 | ✅ |

The ImageSharp #3074 fixtures fail on **both** axes — D_a (sink-document count) and H_a (total hops). Milestone-D's U1.a deduplicated sinks at the same `(method, line)`, but the three `new byte[colorMapSizeBytes]` sinks in `BmpDecoderCore.ReadFileHeader` fire at distinct lines, so U1.a couldn't collapse them. Milestone-D's U2 filtered same-method identity hops at call boundaries, but in-method identity chains spanning distinct lines (lines 1487/1494/1495/1496 in #3074-prefix's document 1) survived.

#3079 is a separate problem driven by sibling-guard sanitizers and a deeper call graph — needs the U1.c redesign that milestone-D attempted, reverted, and deferred. Out of scope here.

This spec covers three coupled work units:

1. **Cross-method sink-document dedup (U8).** Replace U1.a's `(method, line)` dedup key with `(method, sink-shape, primary-operand-name)`. Collapses #3074's three same-operand sink calls into one document. Drops `D_a` for both #3074 fixtures from 3 → 1.
2. **Adjacent identical-tuple hop dedup (U9).** Post-build pass over each document's `pathHops` slice. Two sub-rules: drop adjacent same-method identity hops; drop adjacent hops where `(method, file, line, transformation, tainted_value_in)` are all equal. Both rules in one pass; first match wins. Targets `H_a` for the #3074 fixtures; expected to flip them to strict-pass if the reduction lands in the 8–10 range.
3. **`stackalloc T[N]` sink kind (U7).** Add `Localloc` opcode matcher to `SinkShapes`; extend `SinkApi` enum with `stackalloc`; closed-vocab entry. New synthetic fixture demonstrating an attacker-controlled-size `stackalloc byte[N]`.

## Goals

1. Analyzer's `TraceEmitter` extends U1.a → U8 (operand-aware dedup key) and adds U9 (adjacent-tuple hop pass). Both run unconditionally regardless of `--strict`.
2. Analyzer's `SinkShapes` recognizes `localloc` as an attacker-controlled allocation sink, with `kind: allocation` + `api: stackalloc`.
3. New committed fixture `fixtures/synthetic-stackalloc/` exercises the canonical "u16 from stream → `stackalloc byte[count]`" pattern.
4. Required gate: `--compare` non-strict exits 0 on all 5 fixtures (4 existing + new). No regression.
5. Bonus gate: `--compare --strict` exits 0 on **≥4 of 5** fixture pairs. Integer recorded.

## Non-goals

- **#3079 strict-pass.** Driven by U1.c redesign; carries to milestone-F.
- **parquet-dotnet round-trip.** Still backlog; carries.
- **Tainted-value naming.** Still backlog (`loc_3`, `BmpInfoHeader.get_ProfileSize`); carries.
- **U2 redesign or removal.** U9 is complementary; U2's call-boundary filter stays. Together they cover both filter loci (call-boundary + in-method-adjacency).
- **Validator changes.** FX064 (milestone-D's budget) is unchanged. All bonus gains come from analyzer-side hop reduction. Validator's tests stay green by construction.
- **Per-fixture budget overrides.** FX064's two-formula choice remains global. Bonus tier still records the honest integer.
- **Async / `MoveNext` modelling, points-to analysis** — preserved milestone-D non-goals.

## Architecture

### Project layout

No changes to `TaintAnalyzer.sln` membership. All edits localized to existing project files. One new fixture directory contains a standalone `Decoder.csproj` outside the solution, built by a dedicated script (mirrors `synthetic-callee-arithmetic`).

```
tools/
  TaintAnalyzer/
    SinkShapes.cs              (modified — U7 Localloc matcher)
    TraceEmitter.cs            (modified — U8 sink-dedup key, U9 hop-dedup pass)
    HopRecord.cs               (modified — SinkApi.Stackalloc enum value)
  TaintAnalyzer.Tests/
    SinkShapesTests.cs         (new test cases — U7)
    TraceEmitterTests.cs       (new test cases — U8 + U9)
  TaintAnalyzer.Tests.Fixtures/
    Fixtures.cs                (new test methods — stackalloc + adjacent-tuple-hop shapes)

fixtures/
  synthetic-stackalloc/        (NEW)
    rules.yaml
    trace.yaml                 (ground truth — authored after U7+U8+U9 land)
    source/
      Decoder.csproj
      Decoder.cs
      README.md
    snippets/decoder-snippet.txt

scripts/
  build-synthetic-stackalloc.sh  (NEW)
```

Possibly-modified ground truth (one-line FX061 reconciliations after U9 lands): `fixtures/imagesharp-3074-prefix/trace.yaml`, `fixtures/imagesharp-3074-postfix/trace.yaml`. These are *trace-shape* updates — same source, same sink, hop list collapsed by U9. Not a fixture redesign. `imagesharp-3079-prefix/trace.yaml` is *not* expected to change (milestone-E doesn't target #3079).

The branch convention from milestone-D continues: milestone-E lives on a fresh `milestone-e` branch, branched from `milestone-d` so the work builds on top of milestone-D's analyzer. Milestone-d is preserved separately. Both branches eventually fold into `main` together.

### Component changes

#### U7 — `stackalloc T[N]` sink kind

`SinkShapes.cs` gains a matcher for `Code.Localloc`. IL semantics: localloc pops a 32-bit unsigned size from the evaluation stack, allocates that many bytes on the current stack frame, pushes a native int pointer. The matcher fires when the size operand at the localloc site is tainted.

Sink-hop fields:
- `kind: allocation` — same `kind` as `new_array`. Stackalloc is an attacker-controlled allocation; the triage signal is identical.
- `api: stackalloc` — distinguishes from heap allocations where it matters.
- `size_expression: <operand-name>` — same shape as `new_array`'s size_expression.
- `file:line` — sequence point of the `localloc` instruction.

`HopRecord.cs` (analyzer-side) extends:
- `SinkApi` enum gets a `Stackalloc` value. Currently the enum is `{NewArray, ArrayPoolRent, SpanSlice, SpanIndex}`; U7 adds `Stackalloc`. The `SinkShapes` matcher emits this for `Localloc` instructions.

The validator-side `SinkApis` closed vocab in `tools/ValidateFixture/Vocabularies.cs` already includes `"stackalloc"` (added in milestone-A; see `2026-04-17-imagesharp-3079-trace-design.md`'s schema v0.2 section). No validator change needed for U7 — only the analyzer-side enum addition.

The synthetic fixture's source uses `Span<byte> scratch = stackalloc byte[recordCount];` to anchor the IL. Cecil emits `localloc` for that statement.

#### U8 — Cross-method sink-document dedup

Replaces U1.a's `(method, line)` dedup key in `TraceEmitter.Emit` with `(method, sink-shape, primary-operand-name)`:

- `method` = sink hop's method label.
- `sink-shape` = `(SinkKind, SinkApi)` tuple, e.g. `(allocation, new_array)`, `(span_access, span_slice)`, `(allocation, stackalloc)`.
- `primary-operand-name` = the load-bearing operand string. Resolution order:
  1. `sink_hop.size_expression` if non-empty (allocation sinks).
  2. First-arg of `sink_hop.access_expression` if non-empty (span sinks; e.g. `data` from `data.Slice(start, len)`).
  3. `sink_hop.tainted_value_in` as fallback (defensive — every sink hop has this).

For each group sharing the key, emit one document — the first sink hop in IL order (same selection rule U1.a used).

**Worked example (`imagesharp-3074-prefix`):** all three of `BmpDecoderCore.ReadFileHeader`'s `new byte[colorMapSizeBytes]` calls share key `(BmpDecoderCore.ReadFileHeader, (allocation, new_array), colorMapSizeBytes)` → collapse to one document. `D_a` drops 3 → 1.

Edge cases:
- Same method, same shape, *different* operand names (e.g. `new byte[a]` and `new byte[b]` adjacent on one source line) → different keys, both emitted. Correct.
- Same operand name in *different* methods → different keys, both emitted. Correct.
- Sink fires inside a callee helper — emits in the callee's method, not the caller's. U8 doesn't merge across helpers; that's U1.c-redesign territory (milestone-F).

#### U9 — Adjacent identical-tuple hop dedup

Runs in `TraceEmitter.Emit` after the per-document `pathHops` list is built (so after U2's call-boundary filter and U8's sink-document group selection). One linear pass over `pathHops`, repeated until no adjacent pair matches:

- **Rule 1 (identity special case):** `hop[i+1].transformation == "identity"` AND `hop[i+1].method == hop[i].method` → drop `hop[i+1]`. Same predicate as milestone-D's U2, but applied to consecutive hops in the document's path slice (catches in-method identity chains spanning distinct lines that U2 misses).
- **Rule 2 (general tuple match):** `(method, file, line, transformation, tainted_value_in)` of `hop[i+1]` equals that of `hop[i]` → drop `hop[i+1]`. Catches non-identity adjacent repeats (e.g. two `field_load` hops emitting the same tuple).

Rules check in order; first match drops `hop[i+1]`. `hop:` indices renumbered after the pass (already handled by `PathNodeFromHop`).

**What's never collapsed by construction:** source hops (one per doc), sink hops (one per doc), sanitizer hops (different role; preserves the FX063 / FX023 audit trail). The pass operates only on propagator hops; rules' predicates fall through for source/sink/sanitizer roles by shape (transformation values like `read_stream` for source don't match `identity`; sanitizer hops have unique `(method, line, role)` triples that don't repeat as adjacent propagators).

**Expected impact on `imagesharp-3074-prefix`:** ground truth `H_g=5`; current `H_a=103` (post-U2). Bloat is dominated by in-method identity chains in `BmpDecoderCore.ReadFileHeader` and helpers — Rule 1 catches those. Realistic landing: `H_a` somewhere in the 8–15 range. Strict ceiling is `2·H_g=10`, so the strict-pass is genuinely a coin-flip on whether U9's reduction lands tightly enough.

**Why not also reconsider U2:** U2 specifically filters at call-boundary identity-hop emission inside the walker. Those hops never enter the in-memory hop list. U9 operates on the post-emission slice. The two filters target different stages and don't overlap; U2 stays as is.

### New fixture: `fixtures/synthetic-stackalloc/`

Self-contained synthetic decoder exercising the canonical `stackalloc byte[count]` shape. Source committed in-tree under `source/`; built locally via `scripts/build-synthetic-stackalloc.sh`.

Source shape (informally):

```csharp
public sealed class WireProcessor {
    public byte[] Process(Stream stream) {
        var reader = new WireReader(stream);
        ushort recordCount = reader.ReadU16();
        Span<byte> scratch = stackalloc byte[recordCount];   // <-- localloc sink
        // copy into a heap byte[] so the method has a well-defined return.
        return scratch.ToArray();
    }
}
internal sealed class WireReader {
    private readonly Stream _stream;
    public WireReader(Stream stream) { _stream = stream; }
    public ushort ReadU16() {
        int hi = _stream.ReadByte();
        int lo = _stream.ReadByte();
        return (ushort)((hi << 8) | lo);
    }
}
```

`rules.yaml` names `WireProcessor.Process(System.IO.Stream)` as the source.

Ground-truth `trace.yaml` is a single document:
- Source hop at `Process(Stream)` entry.
- Propagator hop into `WireReader.ReadU16` (cross-method identity — preserved by U2 because methods differ).
- Sink hop with `kind: allocation`, `api: stackalloc`, `size_expression: recordCount`, `file:line` pointing at the `stackalloc byte[recordCount]` site.
- One `sanitizer_absence` entry — `recordCount` not bounded before the `stackalloc`.

By construction: `D_g=1`, `H_g=1` (just the cross-method propagator into `WireReader.ReadU16`; source/sink/sanitizer_absence don't count toward `path[].Count`, per `Comparator.CompareBudget`). Strict ceiling `H_a ≤ 2·H_g = 2`. The analyzer should emit one propagator hop for the same shape, so `H_a=1` and the fixture passes strict by construction.

Target framework: `net8.0`, matching `synthetic-callee-arithmetic` and the ImageSharp fixtures.

### Validator semantics

FX060–FX064 unchanged from milestone-D. The `--strict` flag is unchanged. No new diagnostics. Validator-side test count from milestone-D (61) stays as the baseline; any test additions in milestone-E that touch the validator are out of scope by spec.

## Success criteria

### Required (hard gate)

1. `dotnet build TaintAnalyzer.sln` from clean — 0 errors, 0 warnings on analyzer/validator code.
2. `dotnet test TaintAnalyzer.sln` — all green. Final test counts captured in the implementation-complete revision-history entry.
3. `--compare` (non-strict) exits 0 on **5 fixtures**:
   - `imagesharp-3074-prefix`
   - `imagesharp-3074-postfix`
   - `imagesharp-3079-prefix`
   - `synthetic-callee-arithmetic`
   - `synthetic-stackalloc` (new)
4. The new fixture's ground-truth `trace.yaml` contains a sink hop with `api: stackalloc` whose `file:line` resolves to the `stackalloc byte[recordCount]` instruction. Verified by reading the file (FX015/FX024 enforce vocab + coupling; the round-trip via `--compare` confirms the analyzer emits the same shape).
5. `--compare --strict` runs without crashing on all 5 fixtures (FX064 failure allowed; cannot throw or hang).

### Bonus (tiered)

`--compare --strict` exits 0 on **≥ 4 of 5** fixture pairs. The integer is recorded in the implementation-complete revision-history entry.

By construction:
- `synthetic-callee-arithmetic` and `synthetic-stackalloc` should pass strict (small, designed to fit budget).
- `imagesharp-3074-prefix` and `imagesharp-3074-postfix` are the U8+U9 targets.
- `imagesharp-3079-prefix` is **not** a milestone-E strict target.

Underdelivery framing:
- 2/5 strict-passes → U8+U9 didn't move the needle on the ImageSharp fixtures. Likely U9's reduction landed too modest.
- 3/5 → U9's hop reduction barely missed one of the 3074 fixtures (e.g. `H_a=11` against ≤10).
- 4/5 → spec target hit.
- 5/5 → #3079 unexpectedly flipped, which would be a happy surprise but isn't expected.

## Decisions / Premises

1. **U7's `kind` is `allocation`, not a new `stack_allocation`.** Stackalloc is an attacker-controlled-size allocation; the triage signal is identical to `new_array`. The `api: stackalloc` distinguishes where it matters. Avoids enum fragmentation.
2. **U8's dedup key is operand-aware, not shape-only.** `(method, sink-shape, primary-operand-name)` rather than `(method, sink-shape)`. Preserves genuinely-different-operand sinks (e.g. `new byte[a]` and `new byte[b]` adjacent) while collapsing same-operand cases (the actual #3074 pattern).
3. **U9 has two sub-rules in one pass; first match wins.** The identity-special-case is necessary because in-method identity hops span distinct lines (the milestone-D U2 finding); a tuple-only rule would miss them. The general-tuple case catches non-identity adjacent repeats. No role-special-casing needed — predicates fall through for source/sink/sanitizer by shape.
4. **U9 runs unconditionally**, not just under `--strict`. Cost: existing fixtures may need ground-truth hop-list updates. Benefit: what the user reads in the YAML is what the validator counts. Aligns with milestone-D's reasoning for keeping U2 as a real hop-list filter rather than a strict-mode-only validator pass.
5. **U8 + U9 are coupled.** U8 alone can flip 3074's `D_a` but not `H_a`; U9 alone can flip `H_a` but not `D_a`. Both are required to flip 3074 to strict-pass. If we have to defer one, we defer both — partial landing wouldn't move the bonus number.
6. **#3079 strict-pass stays out of scope.** The 51-document blow-up there is driven by sibling-guard sanitizers (bounding `compressionFlag` while the sink uses `translatedKeywordLength`) — the same dynamic that forced U1.c's revert. Hitting ≥4/5 strict-passes is achievable from synthetic + stackalloc + #3074 pre/post; #3079 stays the milestone-F target.

## Execution plan outline

(Detailed plan to be authored after this spec is approved — `docs/superpowers/plans/2026-04-28-milestone-e.md`.)

1. U7 (`SinkShapes` Localloc matcher + `Vocabularies.SinkApi.Stackalloc` + tests + Fixtures.cs IL shape). Land first; structurally simplest, no interaction with U8/U9.
2. U8 (extend U1.a in `TraceEmitter.Emit` with operand-aware key + tests). Verify `D_a` for #3074 prefix/postfix drops to 1 via direct inspection.
3. U9 (post-build hop dedup pass in `TraceEmitter.Emit` + tests). Verify `H_a` for #3074 fixtures lands in target range; one-line ground-truth reconciliations on #3074 trace.yaml files if `--compare` flags FX061.
4. Synthetic fixture scaffold — `Decoder.csproj` + source + build script — mirroring `synthetic-callee-arithmetic`. Build verified.
5. Run analyzer against the new fixture; capture output as ground-truth `trace.yaml`. Spot-check that the sink hop has `api: stackalloc` at the localloc site.
6. Final cross-check: required gate (clean build, full test suite, `--compare` non-strict on all 5 fixtures). Bonus tally: count `--compare --strict` exit-0 fixtures.
7. Update spec status line + revision-history entry with implementation-complete date and bonus integer.

## Self-review

Walking the requirements:
- *Cross-method sink-document dedup:* "U8 — Cross-method sink-document dedup" + criterion #3 (`--compare` exit 0 across all 5 fixtures relies on U8 not over-collapsing legitimate distinct sinks).
- *Strict-mode hop reduction:* "U9 — Adjacent identical-tuple hop dedup" + bonus-gate target.
- *Stackalloc sink kind:* "U7 — `stackalloc T[N]` sink kind" + "New fixture" section + criterion #4.
- *Required-gate preservation:* Required-gate items 1–5 (no regression on existing fixtures + new fixture round-trips).
- *Bonus integer:* Required-gate item #5 (`--strict` runs without crashing) + bonus-gate text.
- *Non-goals listed:* #3079, parquet-dotnet, tainted-value naming, U2 redesign, validator changes, per-fixture overrides, async / points-to.

Open questions deferred to plan-writing:
- Whether U9's renumbering uses the existing `PathNodeFromHop` index passed in, or a separate counter (likely existing — implementation detail).
- Whether the synthetic fixture should additionally exercise a `Span<T>(ptr, length)` wrap on the localloc result (potential Span-aware sink interaction) or stay stackalloc-only. Default: stackalloc-only — keeps the fixture small and on-message.
- `primary-operand-name` resolution order for U8 in the unlikely case all three fields are empty (defensive — record an FX0NN-style assertion or just emit the document without dedup; plan-level detail).

## Revision history

- **2026-04-28** — Initial spec; approved pending plan authoring.
