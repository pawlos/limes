# Milestone D — Trace quality + over-emission budget

**Status:** Implementation complete 2026-04-27. Required gate met (4/4 fixtures pass `--compare` non-strict). Bonus tier underdelivered: 1/4 strict-passes (synthetic only) vs. ≥3/4 target. See revision history for the full tally and the milestone-E carry-overs.
**Predecessors:**
- Milestone C (`2026-04-19-taint-analyzer-mvp-design.md`) — Cecil-based analyzer reproducing #3074 pre/post and #3079 pre.
- Milestone-D backlog (`docs/superpowers/plans/2026-04-26-milestone-d-backlog.md`) — six entries; this milestone takes four of them.
**Successor:** Milestone E — addresses the remaining backlog entries (tainted-value naming, parquet-dotnet round-trip), plus whatever new findings emerge from milestone-D's strict-mode tally.

## Context

Milestone-C closed with the analyzer reproducing #3074 pre-fix, #3074 post-fix, and #3079 pre-fix at `--compare` exit 0. But the bonus (#3079) only landed after FX062 was relaxed to ground-truth-as-subset-of-analyzer-output, and a backlog-stocking pass after milestone-C close-out surfaced that the analyzer's output is technically passing while being effectively unusable for human triage on real codebases:

- `imagesharp-3079-prefix` emits **115 trace documents** for **1** in ground truth, with sinks across `PixelBlender`, `PixelOperations`, `ProcessInterlacedRgbScanline`, etc. — every reachable `Span<T>.Slice` with a tainted argument.
- `imagesharp-3074-prefix` emits **3 documents** for **1** in ground truth, with one document containing **47 hops** for what reads as a 3-hop story; **101** and **113** in the other two.
- Identity-only hops dominate every emitted path (e.g. `tainted_value_in: BmpInfoHeader.get_ProfileSize, transformation: identity` chains carry no triage-relevant signal).
- The blind-test demo from 2026-04-26 surfaced that load-bearing arithmetic inside callee return paths is not attributed at all — the trace shows the call-boundary identity hop but not the `*` site that drives the dangerous size.

`--compare` exit 0 alone can't catch any of this because milestone-C's relaxed FX062 only enforces "ground truth ⊆ analyzer output". Milestone D adds the complementary check (FX064 budget) and reduces emission noise enough that the strict version of that check passes on most existing fixtures.

This spec covers four coupled decisions:

1. **Validator-side budget (FX064).** Add `--compare --strict` mode with a default-soft / strict-hard budget on emitted document and hop counts. Default mode preserves the milestone-C contract (no `--compare` regression).
2. **Sink-document dedup (U1.a only).** Collapse multiple sink hops at the same `(sink-method, sink-line)` into a single document in `TraceEmitter`. The companion U1.c (sanitizer-suppressed-path pruning) was scoped here originally but de-scoped during execution — see revision history; deferred to milestone-E. Reframed from the original "load-bearing-operand predicate" wording — `SinkShapes` already enforces load-bearing-operand-only matching (verified `tools/TaintAnalyzer/SinkShapes.cs:21,45,78,109` — receiver is never inspected); the actual root cause of the document explosion is callee-sink hops accumulating into the caller's flat hop list (`TaintWalker.cs:875-878`) and `TraceEmitter` emitting one document per sink hop (`TraceEmitter.cs:50-203`).
3. **Hop-list bloat reduction.** Drop same-method identity propagator hops at emission time inside `TaintWalker`. Cross-method identity hops (call-boundary signal) are preserved. Reframed from the original "same-method same-line" wording — most identity-bloat hops are at distinct lines within the same method (re-reading the #3074 trace confirmed: hops 4-7 of document 1 all in `ReadFileHeader` but at lines 1487/1494/1495/1496), so the line-equality predicate would filter almost nothing.
4. **Arithmetic transform attribution.** Extend the existing arithmetic-emission paths in `TaintWalker` to cover `mul`/`mul.ovf`/`div`/`shl`/`shr` with file:line pinned to the IL site, plus `OperandName` composition for the same opcodes.

## Goals

1. Validator gains FX064 (over-emission budget) with default-soft and strict modes; `Program.cs` learns `--strict`.
2. Analyzer's `TraceEmitter` dedupes sink documents at the same `(method, line)` (U1.a). `TaintWalker` drops same-method identity propagators (U2) and correctly attributes arithmetic transforms (`mul`/`mul.ovf`/`div`/`shl`/`shr`) in callee bodies (U3). U1.c (sanitizer-suppressed-path pruning) was attempted, reverted, and deferred to milestone-E — see revision history.
3. New committed fixture `fixtures/synthetic-callee-arithmetic/` exercises the canonical "u16×u16 multiply through a sizing-helper class" pattern that motivated the trace-attribution backlog entry.
4. Required gate: non-strict `--compare` exit 0 on all existing fixtures plus the new one (no regression).
5. Bonus gate: strict `--compare` exit 0 on ≥ 3 of 4 fixture pairs. The integer is recorded.

## Non-goals

- **Tainted-value naming.** MethodReference display names (`BmpInfoHeader.get_ProfileSize`) and unresolved local slots (`loc_3`) in `tainted_value_*` fields stay as is. Backlog item; milestone-E.
- **parquet-dotnet round-trip.** Ground-truth and rules.yaml committed in milestone-C; materialize script and end-to-end run deferred to milestone-E.
- **Validator-side document deduplication.** Could collapse documents that share path prefixes presentation-wise, but does nothing for the underlying analyzer over-emission. Skipped in favor of analyzer-side fixes.
- **Async / `MoveNext` modelling.** Preserved milestone-C non-goal. Sync overloads only.
- **Points-to analysis for non-`this` object-field taint.** Preserved milestone-C non-goal.
- **Per-fixture budget overrides.** FX064 uses the same formula across fixtures; no fixture-specific tuning. If a fixture won't fit, it doesn't pass strict — that's the whole point of the bonus tier.

## Architecture

### Project layout

No changes to `TaintAnalyzer.sln` membership. All edits are localized to existing project files. One new fixture directory contains a standalone `Decoder.csproj` that lives outside the solution and is built by a dedicated script (mirrors the way existing ImageSharp fixtures get their DLLs from out-of-tree builds).

```
tools/
  TaintAnalyzer/
    TaintWalker.cs             (modified — U2 same-method identity filter, U3 arithmetic ops)
    TraceEmitter.cs            (modified — U1.a sink dedup; U1.c reverted)
  TaintAnalyzer.Tests/
    TaintWalkerTests.cs        (new tests added — U2 + U3)
    TraceEmitterTests.cs       (new tests added — U1.a)
  TaintAnalyzer.Tests.Fixtures/
    Fixtures.cs                (new methods exercising U2/U3 IL shapes)
  ValidateFixture/
    FixtureValidator.cs        (modified — FX064)
    Program.cs                 (modified — --strict flag)
  ValidateFixture.Tests/
    FixtureValidatorTests.cs   (new CompareTests/FX064 cases)

fixtures/
  synthetic-callee-arithmetic/    (NEW)
    rules.yaml
    trace.yaml                    (ground truth)
    source/
      Decoder.csproj
      Decoder.cs
      README.md
    snippets/
      decoder-snippet.txt

scripts/
  build-synthetic-callee-arithmetic.sh  (NEW)
```

### Component changes

#### U1 — Sink-document dedup (U1.a only; U1.c de-scoped to milestone-E)

`TraceEmitter.Emit` gains one filter applied to the per-sink loop that emits one document per sink hop:

**U1.a — `(sink.method, sink.line)` dedup.** Group sink hops by `(method, line)` before emitting documents. For each group, emit one document — the first sink hop in IL order. Trivially safe: if two sinks at the same `(method, line)` differ in their tainted operand or value chain, the trace's sink-hop content reflects whichever fired first; the alternative would be emitting near-identical documents that differ only in `tainted_value_in`. This filter alone bounds output by the count of distinct sink call sites in the analyzed assembly.

**U1.c (de-scoped).** A companion filter — "suppress emitting a document when the path source-to-sink contains a sanitizer that bounds the sink's transitive value chain" — was scoped here originally and reverted during execution. Reason: U1.c reuses the existing chain-walker (`BuildTransitiveValueChainTokens`), which fires on the same shape that defines a *post-fix fixture's* sanitized sink. Suppressing those documents semantically breaks the post-fix fixtures' purpose ("demonstrate analyzer recognizes the fix"). Meanwhile #3079 — the over-emission target U1.c was supposed to help — has mostly *sibling-guard* sanitizers (bounding `compressionFlag` while the sink uses `translatedKeywordLength`) that don't overlap the chain, so U1.c barely reduces noise there. Net-negative trade. Deferred to milestone-E for redesign that distinguishes "fixture-author-meaningful sanitizer bound" from "noisy sibling-guard". See revision history dated 2026-04-27 for the decision detail.

Edge cases:
- Multiple ground-truth documents pointing at the same `(method, line)`: not present in any current fixture; U1.a would collapse them in the analyzer output, and FX061 would fail on the missing doc. Acceptable for milestone-D — re-evaluate if such a fixture is authored.

**Why emitter-side, not analyzer-side (`TaintWalker`).** U1.a is a presentation decision — the analyzer's in-memory hop list is still useful for FX064's hop counting (in fact, FX064 sees post-filter counts since it reads the emitted YAML). Putting the filter in the walker would make hop counts diverge between in-memory and emitted output, complicating debugging.

#### U2 — Identity-hop emission filter

In `TaintWalker`'s call-boundary identity-hop emission path (`TaintWalker.cs:869`), skip emission when **both** hold:

1. `transformation == "identity"`,
2. `method` equals the previous emitted hop's `method` (the call boundary is intra-method — both caller and callee share the caller's method label, which happens for tail-position helper calls within the same enclosing method).

Source, sink, sanitizer, and non-identity propagator hops (`field_load`, `cast`, `arithmetic`, `read_stream`) are never filtered. Cross-method identity hops are preserved (different `method`). Hop indices are renumbered sequentially in `TraceEmitter.PathNodeFromHop` so `hop: N` stays dense after filtering.

Why not the original four-condition predicate (which also required same-line and value-name unchanged): re-reading the #3074-prefix trace showed that hops 4-7 of document 1 are all in `ReadFileHeader` but at distinct lines (1487/1494/1495/1496), with `tainted_value_*` shifting between method-call display names. The line-equality predicate would filter almost nothing. The simpler "same method + identity" predicate is more aggressive but preserves the cross-method call-graph signal which is what triagers actually use to navigate the trace.

Trade-off acknowledged: same-method renames like `stream → ReadFileHeader` (showing what the call returned) are dropped. Triagers can recover this from the next non-identity hop in the same method (e.g., a subsequent `field_load` that names the produced local) or by reading the source. Net win: ~30-50% hop reduction on #3074 traces.

#### U3 — Arithmetic transform attribution

`TaintWalker`'s existing arithmetic-emission path covers `add`/`or` plus shift composition for `OperandName`. Extend the **opcode set** that triggers a propagator hop with `transformation: arithmetic` to:

- `Mul`, `Mul_Ovf`, `Mul_Ovf_Un`
- `Div`, `Div_Un`
- `Shl`, `Shr`, `Shr_Un`
- (existing) `Add`, `Add_Ovf`, `Add_Ovf_Un`, `Sub`, `Sub_Ovf`, `Sub_Ovf_Un`, `Or`

The hop's `file:line` is `AssemblyContext.GetSequencePoint(instr)` for the arithmetic instruction, **not** the surrounding call-boundary line. Emission is **once per expression-result-stored-to-local**, not once per IL op — a chained expression like `width * height + offset` produces one hop with composed `OperandName`, not three.

`OperandName` Add/Sub composition (added in milestone-C) extends to `Mul`/`Div`/`Shl`/`Shr` so the trace renders e.g. `recordCount * recordStride` instead of `loc_3`.

Cross-method machinery: the existing memoization cache is rebuilt fresh per analyzer run. U3's emission changes are picked up automatically.

#### U4 — FX064 budget diagnostic

`FixtureValidator.Compare` after FX060–FX063 runs. Counts:
- `D_a` = analyzer-output document count, `D_g` = ground-truth document count.
- `H_a` = total hops summed across all analyzer-output documents.
- `H_g` = total hops summed across all ground-truth documents.

| Mode | Doc ceiling | Hop ceiling |
|---|---|---|
| default | `D_a ≤ 3·D_g + 1` | `H_a ≤ 5·H_g + 10` |
| `--strict` | `D_a ≤ D_g` | `H_a ≤ 2·H_g` |

Default-mode breach: print `FX064: budget exceeded — D_a=N (≤M), H_a=N (≤M)` to stderr; **exit code unchanged** (preserves milestone-C contract). Strict-mode breach: same diagnostic, exit code 1.

`Program.cs` adds a `--strict` flag to `--compare`. With `--strict`, FX064 promotes from warning to error; FX060/FX061/FX062/FX063 are unchanged by the flag.

Edge cases:
- `H_g == 0` (defensive — shouldn't occur on real fixtures): ceiling collapses to the constant term (10 default, 0 strict). Strict-mode failure with `H_g == 0` and `H_a > 0` is intentional.
- Multi-document ground truth: not present today, but the formula sums across documents, so it works if introduced.
- Equality at the ceiling counts as pass (`≤`, not `<`).

### New fixture: `fixtures/synthetic-callee-arithmetic/`

A small self-contained synthetic decoder that exercises the canonical "u16×u16 multiply through a sizing-helper class" pattern. Source committed in-tree under `source/`; built locally via `scripts/build-synthetic-callee-arithmetic.sh` (no `git archive` since it's our own code).

Source shape (informally):

```csharp
public sealed class WireDecoder {
    private readonly Stream _stream;
    public WireDecoder(Stream stream) { _stream = stream; }
    public byte[] Decode() {
        var reader = new WireReader(_stream);
        ushort recordCount  = reader.ReadU16();
        ushort recordStride = reader.ReadU16();
        int totalBytes = PayloadSizer.RecordsAreaBytes(recordCount, recordStride);
        return new byte[totalBytes];   // <-- new_array sink
    }
}
internal static class PayloadSizer {
    internal static int RecordsAreaBytes(ushort count, ushort stride)
        => (int)count * (int)stride;   // <-- arithmetic propagator hop expected here
}
internal sealed class WireReader {
    private readonly Stream _stream;
    public WireReader(Stream stream) { _stream = stream; }
    public ushort ReadU16() { /* read 2 bytes, compose */ }
}
```

`rules.yaml` names `WireDecoder.Decode` as the source. Ground-truth `trace.yaml` is a single document with a propagator hop carrying `transformation: arithmetic`, `file: source/Decoder.cs`, `line` pointing at the `*` operator's IL sequence point in `RecordsAreaBytes`. Hop count is small enough to easily fit `--strict` budget.

### Validator `--compare` semantics

FX060–FX063 unchanged from milestone-C (including the relaxed FX062 subset-match). FX064 added per U4. The `--strict` flag is positional with the `--compare` subcommand; existing CLI invocations without `--strict` behave identically to today.

## Success criteria

### Required (hard gate)

1. `dotnet build TaintAnalyzer.sln` from clean — 0 errors, 0 warnings on analyzer/validator code.
2. `dotnet test TaintAnalyzer.sln` — all green. Final test counts captured in the implementation-complete revision-history entry.
3. `--compare` (non-strict) exits 0 on **4 fixtures**:
   - `imagesharp-3074-prefix`
   - `imagesharp-3074-postfix`
   - `imagesharp-3079-prefix`
   - `synthetic-callee-arithmetic` (new)
4. The new fixture's ground-truth `trace.yaml` contains a propagator hop with `transformation: arithmetic` whose `file:line` resolves to the `*` operator instruction in `PayloadSizer.RecordsAreaBytes`. Verified by reading the file (not by `--compare` alone — the `--compare` machinery doesn't enforce transformation kind beyond FX063 sanitizer hops).
5. `--compare --strict` runs without crashing on all 4 fixtures (it can fail with FX064 — that's allowed; it cannot throw or hang).

### Bonus (tiered)

`--compare --strict` exits 0 on **≥ 3 of 4** fixture pairs. The integer is recorded in the implementation-complete revision-history entry.

By construction:
- `synthetic-callee-arithmetic` is expected to pass strict (small, canonical, ground truth authored after U1+U2+U3 land).
- `imagesharp-3074-prefix` and `imagesharp-3074-postfix` are the most likely strict-passers among ImageSharp fixtures (smaller paths, fewer reachable sinks).
- `imagesharp-3079-prefix` is the stretch goal (deepest hole; current 115×96-hop output).

If only the synthetic fixture passes strict and the ImageSharp ones don't, milestone-D underdelivered the reduction work; the integer recording makes that explicit.

## Decisions / Premises

1. **Default-soft FX064.** Required-gate preservation depends on default-mode FX064 not changing exit codes. Without this, the milestone-D required gate would already fail on existing fixtures the moment U4 lands. The trade-off is that "FX064 in default mode" is a warning the user has to read; we accept that.
2. **U1 lives in `TraceEmitter`, not `TaintWalker`.** The dedup filter is a presentation decision over the in-memory hop list. Putting it in the walker would silently change `MethodSummary.Hops` content (which is cached via memoization, used by FX064 hop-counting indirectly, and useful for analyzer debugging). Emitter-side keeps the in-memory model intact.
3. **U1.a takes the first sink at each `(method, line)`.** When two sink shapes happen to fire at the same line (rare; implies adjacent sink-shape calls on one source line), the first one wins. Safer than a "merge" strategy that would have to invent a synthesized hop.
4. **U2 simplified to "same method + identity"** (dropped same-line and value-name conditions). Re-reading actual #3074 traces showed the line-equality and rename-equality predicates would filter ~0 hops; the simpler predicate filters ~30-50% on the same traces. Trade-off: in-method renames are dropped, recoverable from adjacent non-identity hops.
6. **Once per expression for arithmetic, not once per IL op.** A `*` followed by `+` produces one hop, not two. Heuristic: emit when the result of the arithmetic chain is stored to a local or returned. Intermediate stack values don't emit. This matches how the existing Add/Or path already behaves.
7. **No fixture-specific budget tuning.** FX064's two-formula choice is global. A fixture either passes strict or it doesn't; we don't carve out exceptions. The bonus integer is the honest signal.
8. **#3079 strict-pass is not the success bar.** The 115-document blow-up needs aggressive cross-method dedup that's plausibly out of scope for milestone-D's reduction work. Hitting ≥ 3 of 4 strict-passes is achievable with synthetic + #3074-prefix + #3074-postfix; #3079 stays the stretch goal.

## Execution plan outline

(Detailed plan to be authored after this spec is approved — `docs/superpowers/plans/<date>-milestone-d.md`.)

1. Scaffold `--strict` flag + FX064 default-warning + tests. Land first; required-gate preservation built in from the start.
2. U2 (same-method identity filter at `TaintWalker.cs:869`) + U3 (arithmetic ops + OperandName composition) in one chunk — both touch `TaintWalker`.
3. U1.a in `TraceEmitter.Emit` — sink dedup loop. (U1.c was attempted, then reverted; deferred to milestone-E.)
4. Build script + fixture scaffold for `synthetic-callee-arithmetic`. Source authored, build verified.
5. Run analyzer against the new fixture; capture output as the ground-truth `trace.yaml`. Spot-check that the arithmetic propagator hop is present at the expected line.
6. Final cross-check: required gate (clean build, full test suite, `--compare` non-strict on all 4 fixtures, fixture trace inspection). Bonus tally: count `--compare --strict` exit-0 fixtures.
7. Update spec status line + revision-history entry with implementation-complete date and bonus integer.

## Self-review

Walking the requirements:
- *FX064 default-soft / strict-hard:* Section "U4 — FX064 budget diagnostic" + "Validator `--compare` semantics" + criterion #5 in required gate.
- *Sink-document over-emission reduction:* Section "U1 — Sink-document dedup (U1.a only; U1.c de-scoped to milestone-E)". Falsifiable via unit tests for `(method, line)` dedup, and via strict-mode tally on the existing fixtures.
- *Hop-list bloat reduction:* Section "U2 — Identity-hop emission filter". Falsifiable via unit tests + strict-mode tally on #3074.
- *Arithmetic transform attribution:* Section "U3 — Arithmetic transform attribution". Falsifiable via the new fixture's ground-truth trace + criterion #4.
- *No regression:* Required-gate item #3 (non-strict exits 0 on existing fixtures).
- *Bonus integer:* Required-gate item #5 (`--strict` runs without crashing) + bonus-gate text.
- *New fixture:* Section "New fixture" + scripts/build-synthetic-callee-arithmetic.sh + criterion #4.
- *Non-goals listed:* tainted-value naming, parquet-dotnet, validator dedup, async, points-to, per-fixture budget overrides.

Open questions deferred to plan-writing:
- Exact set of `OperandName` composition rules for chained operators (precedence handling). Plan-level detail.
- Whether the synthetic fixture's source should be `net8.0` (matching ImageSharp fixtures) or `net10.0` (matching the analyzer). `net8.0` is more representative of real-world targets.

## Revision history

- **2026-04-27** — Initial spec; approved pending review.
- **2026-04-27 (correction, same day).** Pre-plan code-reading pass surfaced two design errors:
  - **U1 reframed.** Original text described a "load-bearing-operand sink predicate" that the existing code (`SinkShapes.cs:21,45,78,109`) already implements. Actual root cause of the document explosion is callee-sink hops accumulating in the caller's flat hop list (`TaintWalker.cs:875-878`) plus per-sink document emission in `TraceEmitter`. Replaced with U1.a (`(method, line)` dedup) + U1.c (sanitizer-suppressed-path pruning) — both filters live in `TraceEmitter`, not `TaintWalker`. The `Decisions / Premises` section now records this rationale (premise 2 + premise 3 + premise 4).
  - **U2 simplified.** Original four-condition predicate (identity + name-unchanged + same-method + same-line) would have filtered ~zero hops on real traces — re-reading the #3074 trace showed in-method identity-hop chains span distinct lines. Simplified to "same method + identity"; preserves cross-method identity (call-boundary signal) but drops in-method renames. Premise 5 records the trade-off.
  - **#3079 strict-pass framed as out of scope.** The 115-document blow-up there is driven by cross-method dedup that's deliberately out of milestone-D's reduction scope. ≥ 3 of 4 strict-passes (the bonus criterion) is achievable from synthetic + #3074 pre/post; #3079 stays the stretch goal. Premise 8 records this.
- **2026-04-27 (de-scope, same day).** U1.c (sanitizer-suppressed-path pruning) was implemented in Task 5, reviewed, and reverted. Reason: U1.c reuses the existing chain-walker (`BuildTransitiveValueChainTokens`), which fires on the same shape that defines a *post-fix fixture's* sanitized sink — suppressing those documents semantically breaks the post-fix fixtures' purpose. To keep `--compare` exit 0 the implementer changed the post-fix ground truth to point at a different sink (`ProfileSize`), which papered over the conflict rather than resolving it. Meanwhile #3079 — the over-emission target U1.c was supposed to help — has mostly *sibling-guard* sanitizers (bounding `compressionFlag` while the sink uses `translatedKeywordLength`) that don't overlap the chain, so U1.c barely reduces noise there. Reverted via `git revert c916ea5` → ac55e42; deferred to milestone-E for redesign that distinguishes "fixture-author-meaningful sanitizer bound" from "noisy sibling-guard". Plan Task 5 marked deferred. Bonus tier likely takes a hit on #3079.
- **2026-04-27 (implementation complete, same day).** All four work units landed (U1.a, U2, U3, U4); U1.c reverted as above.
  - **Build/tests.** Clean build 0/0 across the solution. Full test suite green: 110 (TaintAnalyzer.Tests) + 61 (ValidateFixture.Tests) = **171** tests, 0 failures, 0 skips.
  - **Required gate met:** `--compare` non-strict exits 0 on all four fixture pairs (`imagesharp-3074-prefix`, `imagesharp-3074-postfix`, `imagesharp-3079-prefix`, `synthetic-callee-arithmetic`).
  - **Bonus gate result:** **1/4** strict-passes — only `synthetic-callee-arithmetic` passes `--compare --strict`. Per-fixture detail (D_a vs strict ceiling, H_a vs strict ceiling):
    | Fixture | D_a / D_g_strict | H_a / H_g_strict | Strict |
    |---|---|---|---|
    | imagesharp-3074-prefix  | 3 / ≤1   | 103   / ≤10 | ❌ |
    | imagesharp-3074-postfix | 3 / ≤1   | 107   / ≤12 | ❌ |
    | imagesharp-3079-prefix  | 51 / ≤1  | 20084 / ≤6  | ❌ |
    | synthetic-callee-arithmetic | 1 / ≤1 | 5 / ≤8 | ✅ |
  - **Underdelivery vs target:** spec premise 8 set the achievable bar at "synthetic + #3074 pre/post = 3/4"; we hit only 1/4. Drivers:
    1. **#3074-prefix and #3074-postfix still emit 3 documents each** (vs ≤1 strict ceiling). U1.a deduplicates by `(method, line)` but the three sinks fire at *distinct lines* in `ReadFileHeader`. The right knob would be cross-method dedup or load-bearing-operand-aware suppression — both deferred to milestone-E.
    2. **#3074 hop counts (103/107) blow past the strict ceiling** (≤10/≤12). U2's same-method identity filter is too narrow; in practice, the hop bloat in `BmpDecoderCore.Decode` traces is dominated by cross-method identity hops *between* `Decode → ReadImageHeaders → ReadInfoHeader → ...` and by non-identity field-load propagators that U2 doesn't touch. Milestone-E should add a "strict-mode-only" hop filter that dedupes adjacent hops where `(method, file:line, transformation)` are all equal.
    3. **#3079's 51 documents × ~400 hops/doc = ~20K hops.** Same root cause as #3074 plus a deeper call graph; needs the cross-method dedup work U1.c was supposed to help with (but couldn't, given the chain-walker conflict noted above).
  - **Bonus carry-over to milestone-E backlog:** add three concrete entries — (a) "cross-method sink-document dedup at distinct lines within the same method", (b) "strict-mode hop dedup on (method, line, transformation) tuples", (c) "U1.c redesign that distinguishes meaningful sanitizer bounds from sibling guards". Plus (d) the existing `stackalloc T[N]` sink-kind carry-over already noted during Task 5 (sink-kind backlog item).
  - **Trace-quality wins (qualitative).** U2 + U3 deliver clearly even where the strict budget doesn't pass. The synthetic fixture demonstrates the milestone's headline result: arithmetic propagator hops now point at the `*` operator's IL site inside callee bodies (`PayloadSizer.RecordsAreaBytes:21`, `tainted_value_out=count*stride`) rather than the call boundary in the caller. The blind-test-demo gap that motivated the milestone is closed for the synthetic shape. Re-running the same demo on real ImageSharp fixtures should show the gap closed there too — milestone-E will verify.
