# Milestone D — Backlog

Inputs feeding milestone-D scope. Populated as findings emerge during
milestone-C exit testing and ad-hoc experiments. Each entry should be enough
to recover context cold; concrete file/line pointers preferred over prose.

---

## Trace attribution: surface intra-callee arithmetic transformations

**Status.** Open. Discovered 2026-04-26 during a blind-test experiment
(general-purpose agent authored a small fictional `Pmsg.Protocol`
parser; analyzer was run blind against the resulting DLL).

**Finding.** The analyzer correctly detects unbounded `new byte[totalBytes]`
end-to-end, with absence emitted at the right line and the correct tainted
local. But the trace doesn't include a propagator hop for the **load-bearing
arithmetic transformation** that actually computes the dangerous size.

In the blind-test case, that transformation is
`PayloadSizer.RecordsAreaBytes`:

```csharp
return (int)recordCount * (int)recordStride;   // u16 * u16 → int, overflow-prone
```

This is the multiplication that lets a u16×u16 input drive a ~2 GiB
allocation. Taint *flows through* the call boundary correctly (the cross-
method machinery from milestone-C handles it), but the arithmetic step is
invisible in the trace — the only hops emitted around it are the call-
boundary `identity` hops.

**Why it matters.** Detection works without this; diagnostics suffer. A
human reading the trace can see "unbounded `byte[totalBytes]`" but can't see
*where* the dangerous transform happens — they'd have to open
`PayloadSizer` and find it themselves. For real-world triage, attributing
the transform is the more useful signal (it's where the fix goes).

**Reference fixture.** `/tmp/blind-test-demo/` contained the demo at the
time of writing. Not committed. Reproducing requires re-spawning the
authoring agent (or re-creating manually) — the path-shape is canonical
enough (multi-hop u16×u16 multiply through a sizing-helper class) that
authoring a permanent regression fixture is probably worth it as part of
this task.

**Implementation sketch.**

- TaintWalker currently emits propagator hops on stloc-to-tainted-local and
  on certain field/cast operations (search for `Transformation = "arithmetic"`
  emission sites). Inside callees, the value-introducing arithmetic *does*
  fire emission, but the hop's `Method` is the callee — and when the merged
  flat hop list is built, those callee hops are present.
- Need to verify what's actually happening in the blind-test trace:
  the WireReader byte-shifting hops *do* show up (lines 33–34 of
  WireReader.cs in the trace) but `PayloadSizer.RecordsAreaBytes`'
  multiplication does not. Likely cause: the `*` happens on a return path
  where the symbolic stack handling of `mul` / `mul.ovf` doesn't trigger
  the same propagator-emit path that `add` / `or` / shifts do.
- Cross-check `OperandName` Add/Sub composition (added in milestone-C for
  bound normalization) — `Mul`/`Div`/`Shl`/`Or` may need analogous
  handling so the operand-name resolution surfaces the underlying locals.
- Consider: when a callee's tainted return is consumed by the caller's
  stloc, emit a propagator hop pinned to the `*` instruction's sequence
  point even if the call-boundary hop already covered it. Two hops (the
  call boundary + the value-introducing transform) is fine; the transform
  hop is the one a triager wants.

**Definition of done.**

1. A regression fixture (committed) where the load-bearing arithmetic is
   in a helper method's return value. Could be a trimmed-down version of
   the Pmsg blind-test demo.
2. Analyzer trace for that fixture contains a propagator hop with
   `transformation: arithmetic` whose `file:line` points at the actual
   `*` / `+` / `<<` site, not just the call boundary.
3. ImageSharp / parquet-dotnet fixtures still `--compare` exit 0.

---

## Sink-set blow-up: emit one document per ground-truth pair, not per reachable sink

**Status.** Open. Discovered 2026-04-27 during milestone-D backlog-stocking
pass over the existing fixture traces.

**Finding.** The analyzer emits one trace document per (source, sink) pair
it discovers. On real codebases this explodes:

| Fixture | Ground-truth docs | Analyzer-emitted docs | Output size |
|---|---|---|---|
| imagesharp-3074-prefix  | 1 | 3   | 3.3 KLoC |
| imagesharp-3074-postfix | 1 | 3   | 3.4 KLoC |
| imagesharp-3079-prefix  | 1 | 115 | 710 KLoC |

The #3079 case is the most striking: 115 documents covering sinks
across `PixelBlender`, `PixelOperations`, `ProcessInterlacedRgbScanline`,
`HexConverter`, etc. — every `Span<T>.Slice` reachable from
`PngDecoderCore.Decode` with a tainted argument, regardless of whether
the slice receiver/length was actually attacker-derived through that
path. The actual vulnerability (`ReadInternationalTextChunk:1959`) is in
there somewhere but a triager has to find it.

**Why it matters.** This is the single biggest barrier to using the
analyzer on real codebases at scale. `--compare` against a curated
ground-truth still passes (FX062 was relaxed to subset-match in
milestone-C), but the human-readable output is unactionable: thousands
of paths to read for one real bug. Detection works; signal-to-noise
ratio doesn't.

**Reference fixture.** `fixtures/imagesharp-3079-prefix/` —
reproduces the 115-document blow-up. `--compare` still exits 0 thanks
to FX062 subset-match.

**Implementation sketch.**

- The first lever is filtering at the sink-discovery boundary. `TaintWalker`
  currently emits a sink hop whenever a tainted operand reaches a sink
  shape; consider tightening to require that the *load-bearing* tainted
  operand for that sink shape (the size operand for `new_array`, the
  start/length for `span_slice`) is on a path with at least one tainted
  arithmetic transform — bare-pass-through receivers don't count.
- The second lever is post-processing: cluster emitted documents by
  (sink-method, sink-line) and dedupe paths that share a prefix; keep
  the document with the most informative path for each cluster.
- A third lever is value-flow narrowing: many of the 115 sinks share the
  same propagator chain at the start. Identify the chain's bifurcation
  point and emit only the documents whose tainted value at the
  bifurcation point is distinct.
- Whatever the fix, validator should grow a complementary
  *over-emission* check (see also the "FX062 subset-match hides
  over-emission" entry below).

**Definition of done.**

1. Analyzer emits ≤ N documents on `imagesharp-3079-prefix` with a
   defensible bound — target N ≤ 5 (the "right" number is 1, but a
   small over-emission factor is acceptable as long as every emitted
   document is plausibly load-bearing).
2. `imagesharp-3074-prefix` and `imagesharp-3074-postfix` continue to
   `--compare` exit 0; emitted-document count drops from 3 to 1 (or
   stays at ≤ 2 with strong justification).
3. New analyzer-component test covering the blow-up shape (a synthetic
   tree of reachable sinks where only one is load-bearing).

---

## Hop-list bloat: identity chains dominate the path

**Status.** Open. Discovered 2026-04-27 during the same backlog-stocking
pass.

**Finding.** Even within a single trace document, the path is dominated
by `transformation: identity` hops. Hop-count distribution across the
existing fixtures (analyzer output vs. ground truth):

| Document | Ground-truth hops | Analyzer hops |
|---|---|---|
| imagesharp-3074-prefix #1                | ~3 | 47  |
| imagesharp-3074-prefix #2 (alt sink)     | —  | 101 |
| imagesharp-3074-prefix #3 (alt sink)     | —  | 113 |
| imagesharp-3079-prefix smallest document | 3  | 96  |

Spot-reading the #3074 prefix path: hops 0–10 are mostly stream-read
through `BmpDecoderCore.ReadFileHeader` / `ReadImageHeaders` / `Decode`
where every hop has `transformation: identity` and the `tainted_value`
flickers between `stream`, `BmpDecoderCore.ReadImageHeaders`, `this`,
`StreamExtensions.Read`, `Span'1.op_Implicit`, `BmpFileHeader.Parse`,
etc. — most carry no information beyond "the call happened and taint
flowed through it."

**Why it matters.** The trace stops being a story and becomes a log.
Distinct from the trace-attribution-gap entry at the top: that one is
about *missing* hops (load-bearing arithmetic invisible); this one is
about *spurious* hops (identity chains crowding out real transforms).

**Reference fixture.** `fixtures/imagesharp-3074-prefix/` — 47-hop
document for what reads as a 3-hop story in ground truth.

**Implementation sketch.**

- `TraceEmitter` already has hop records before serialization. Add a
  post-processing pass that collapses runs of `transformation: identity`
  hops where the `tainted_value` is a method-reference name (rather
  than a meaningful local) — the user doesn't want to see the
  `Span'1.op_Implicit` step.
- Be careful not to drop call-boundary identity hops that *do*
  contribute (a call from caller A into callee B that stays on a
  tainted path is real signal even if it's "identity"). One heuristic:
  keep identity hops where `method` differs from the previous hop's
  `method` (cross-method boundaries) and drop the rest.
- Consider whether the fix overlaps with the existing trace-attribution
  entry: if callee arithmetic emits proper propagator hops, some of the
  identity-chain bloat may resolve naturally because the path shifts to
  meaningful transforms. Investigate that overlap before designing.

**Definition of done.**

1. `imagesharp-3074-prefix` document hop-count drops from 47 to ≤ 8.
2. `imagesharp-3079-prefix` smallest-document hop-count drops from 96
   to ≤ 10.
3. Ground-truth `--compare` still exits 0 (the ground-truth hops
   targeted by FX061/FX063 are preserved; only the spurious extras go
   away).

---

## Tainted-value names use MethodReference strings instead of locals/parameters

**Status.** Open. Discovered 2026-04-27 during the same backlog-stocking
pass.

**Finding.** The `tainted_value_in` / `tainted_value_out` fields on
analyzer-emitted hops frequently carry MethodReference display names
where a local or parameter name was expected. Examples from the
existing traces:

- `tainted_value_in: BmpInfoHeader.get_ProfileSize`
- `tainted_value_in: Span'1.op_Implicit`
- `tainted_value_in: StreamExtensions.Read`
- `tainted_value_in: PngDecoderCore.TryReadChunk`
- `tainted_value_in: Equals`

A triager reading this can guess that `BmpInfoHeader.get_ProfileSize`
means "the value loaded by calling the `ProfileSize` getter", but the
useful name is the *local that received it* — `profileSize`,
`headerProfileSize`, etc. — which is in PDB. (Other hops in the same
trace successfully resolve `infoHeader`, `fileHeader`, `currentStream`,
so the resolver works for some shapes and fails for others.)

A separate but related sub-finding: sanitizer hops sometimes carry
opaque `loc_N` names. Hop 3 of `imagesharp-3074-prefix` document 1:
`tainted_value_in: loc_3`, `establishes_bound.target: loc_3`. Hop 2 of
`imagesharp-3079-prefix` document 1: target=`loc_12`. The variable is
named in PDB; the symbolic-stack value just lost the binding by the
time the sanitizer-shape matcher reads it.

**Why it matters.** Names are how a triager navigates the trace. The
ground truth uses `data`, `zeroIndexKeyword`, `translatedKeywordLength`,
`profileSize` — all readable. The analyzer's trace forces the reader
to mentally translate `Span'1.op_Implicit` back into "the implicit
conversion from `Span<byte>` to `ReadOnlySpan<byte>` of the buffer
produced by `StreamExtensions.Read`" — which is a slog.

**Reference fixture.** Any of the existing traces; `imagesharp-3074-prefix`
document 1 is concentrated enough to use as the regression target.

**Implementation sketch.**

- `OperandName` resolution in `TaintWalker` currently uses MethodRef
  display names as a fallback when the symbolic-stack value can't be
  resolved to a local/parameter/field. Extend the resolver: when a
  method-call return value is immediately stored to a local, attribute
  the value to that local's debug name on subsequent uses.
- For the `loc_N` cases, instrument the resolver to log which sites
  fall through to `loc_N` and trace back to the IL shape. Likely
  candidates: the `ldloc.s` of a local that was the target of a
  branch-direction comparison (i.e. inside the sanitizer-shape walk-
  back). The matcher reads the operand off the stack but loses the
  local binding when it normalizes the comparison form.
- Audit `OperandName` for property-getter naming: prefer
  `instance.Property` to `Type.get_Property` (so `fileHeader.Value`
  beats `fileHeader.get_Value`).

**Definition of done.**

1. New regression fixture (committed) with multi-hop method-call return
   values stored to named locals; analyzer trace uses the local names,
   not MethodRef display names.
2. The existing `imagesharp-3074-prefix` and `-3079-prefix` traces no
   longer contain `tainted_value_*: <Type>.<methodName>` shapes for
   values that have a local-storage destination on the same line.
3. No `loc_N` names appear in `establishes_bound.target` or the
   sanitizer hop's `tainted_value_*` fields when the underlying local
   has a PDB name. `--compare` still exits 0 on existing fixtures.

---

## FX062 subset-match hides over-emission

**Status.** Open. Discussion needed before scoping. Discovered
2026-04-27 as a meta-observation: each of the three findings above
could be added without breaking the existing `--compare` exit-0 bar,
which means the validator isn't catching the fact that output quality
is poor.

**Finding.** Milestone-C relaxed FX062 from set-equality to ground-
truth-as-subset-of-analyzer-output (recorded in the spec's 2026-04-27
revision-history entry). That was the right call to land the bonus:
analyzer over-reports rather than under-reports, which is the safer
direction. But it leaves a gap: there is currently no validator
diagnostic for *gratuitous* over-emission. As long as ground-truth
hops/absences are present, the analyzer can also emit thousands of
unrelated paths and still pass.

**Why it matters.** Without a counter-pressure check in the validator,
every analyzer regression toward more noise is silent. Milestone-D
work on the three findings above needs a way to *measure* progress;
right now the only signal is human reading.

**Reference fixture.** Same as the sink-set-blow-up entry —
`imagesharp-3079-prefix` is the most extreme case (115 documents
emitted, 1 expected, `--compare` exit 0).

**Implementation sketch.**

- Add a soft FX064 ("budget exceeded") diagnostic to `--compare`:
  warn (or fail, behind a flag) when emitted-document count > N ×
  ground-truth count, or when total emitted-hop-count exceeds a
  similar bound. Default N might be 3–5; `--strict` would tighten.
- Open question: does the budget belong on the validator side or
  inside the analyzer (refuse to emit > N documents per source)?
  Validator-side keeps the analyzer simple and gives a knob; analyzer-
  side is more honest about the underlying problem. Probably both, in
  different roles.
- This entry should probably be tackled *first* in milestone-D so the
  other findings have a measurable target.

**Definition of done.**

1. `--compare` grows an FX064 (budget) diagnostic with a documented
   formula and a clear failure message.
2. With FX064 active, the existing fixtures show the over-emission
   gap (i.e. failing in `--strict` mode) — proving the diagnostic
   actually fires.
3. Spec note added explaining the milestone-C subset-match decision
   and milestone-D's compensating budget check.

---

## parquet-dotnet #738 round-trip not yet exercised

**Status.** Open. Operational gap rather than analyzer bug.

**Finding.** `fixtures/parquet-dotnet-738/` has `rules.yaml` and
`trace.yaml` (committed in `c017468`), but there is no
`scripts/materialize-parquet-dotnet-738.sh` and no analyzer run has
been performed against the actual parquet-dotnet build. The fixture
is a forward-looking ground truth without a comparator partner.

**Why it matters.** Until the round-trip happens, we don't know
whether the analyzer reproduces the parquet-dotnet finding unchanged
or surfaces a new component-level gap (like #3079 did during
milestone-C bonus). It's also the cheapest way to widen the analyzer's
exercised-codebase footprint beyond ImageSharp.

**Reference fixture.** `fixtures/parquet-dotnet-738/` — already
committed.

**Implementation sketch.**

- Author `scripts/materialize-parquet-dotnet-738.sh` mirroring the
  ImageSharp materialize scripts: `git archive | tar -x` from a shared
  parquet-dotnet clone (path TBD — confirm a shared clone exists
  similar to the ImageSharp one, or arrange one), `dotnet build -c
  Debug`, drop output under `artifacts/<sha>/`.
- Run analyzer against the resulting DLL with the existing
  `rules.yaml`. Compare to ground truth. If `--compare` exits non-zero,
  diagnostics feed milestone-D scoping the same way #3079 did.
- If component changes are needed, decide whether they go in
  milestone-D or get folded into one of the entries above.

**Definition of done.**

1. Materialize script committed; runs cleanly against the shared
   parquet-dotnet clone.
2. Analyzer run + `--compare` outcome recorded: PASS unchanged OR
   FAIL with diagnostics captured and (if applicable) a new backlog
   entry opened.
3. If PASS: add parquet-dotnet to the regression set referenced by
   the other entries' "Definition of done".

---

## Carry-overs added during milestone-D execution

The four entries below were opened while executing milestone-D and
**did not land in milestone-D**. Milestone-E should pick them up
alongside the un-tackled entries above (tainted-value naming,
parquet-dotnet round-trip).

### stackalloc T[N] is not modeled as a sink

**Why this matters.** `stackalloc byte[N]` (and the `Span<T>` /
`new Span<T>(stackalloc...)` shapes built on top of it) has the same
attacker-controlled-size problem as `new byte[N]`, but the analyzer
currently models only heap allocations as `sink_kind: allocation /
sink_api: new_array`. Real .NET parsers (especially performance-
oriented ones — System.Text.Json, System.Buffers, image decoders)
use `stackalloc T[N]` for small-temporary buffers; an unchecked
`stackalloc[attackerControlledLength]` is a stack overflow primitive.
The analyzer is currently silent on these sites.

**Surface area.** Cecil opcode is `Localloc`. The size operand is on
the IL stack at the localloc instruction. Need a new `SinkShapes`
entry (`stackalloc`) and a sink-kind enum value (`stack_allocation`
or extend `allocation` with an `api: stackalloc`).

**Definition of done.**

1. `stackalloc N` (where N is tainted) emits a sink hop with
   appropriate `kind` / `api` / `size_expression`.
2. At least one fixture exercises it. A small synthetic fixture
   along the lines of synthetic-callee-arithmetic is enough; if a
   real ImageSharp/parquet site exists, prefer that.
3. `--compare` non-strict still passes on existing fixtures.

(Origin: surfaced during milestone-D Task 5 as a "what about
stackalloc?" question. The user explicitly flagged it for the
milestone-D follow-up backlog.)

### Cross-method sink-document dedup at distinct lines within the same method

**Why this matters.** Milestone-D's U1.a deduplicates sink documents
that fire at the same `(method, line)`. But the #3074-prefix /
postfix traces still emit 3 documents — the three sinks fire at
*distinct lines* in `BmpDecoderCore.ReadFileHeader` (line ~1487 vs
~1494 vs ~1495 / ~1496). Milestone-D's strict-mode bonus tally
recorded `D_a=3 (≤1)` for both #3074 fixtures, well outside the
strict ceiling. The right knob is dedup on `(method, sink-shape,
load-bearing-operand-name)` rather than `(method, line)` — multiple
sinks for the same logical operation in adjacent statements should
collapse.

**Definition of done.**

1. Strict-mode `--compare` on `imagesharp-3074-prefix` passes
   (`D_a ≤ D_g`).
2. Strict-mode `--compare` on `imagesharp-3074-postfix` passes.
3. Decision recorded for whether the new dedup uses the same
   chain-walker primitives U1.c reused (and thus risks the same
   post-fix-fixture conflict that forced U1.c's revert), or a
   simpler operand-name-equality rule that sidesteps the
   chain-walker.

### Strict-mode hop dedup on `(method, line, transformation)` tuples

**Why this matters.** Milestone-D's U2 filters *same-method identity
hops at the call boundary*, but the #3074 traces still emit 103/107
hops vs strict ceilings of 10/12. The dominant bloat in those traces
is **adjacent hops where `(method, file:line, transformation)` are
all equal**, generated by repeated propagator emissions inside loops
or tight call sequences. A coarser strict-only filter that collapses
runs of identical-tuple hops would land most of the strict-mode
gap on #3074. Default-mode would keep the existing behavior so the
in-memory hop list stays usable for debugging and the milestone-C
required-gate semantics are preserved.

**Definition of done.**

1. `H_a` for `imagesharp-3074-prefix` drops to `≤2 · H_g` under
   strict mode.
2. Same for `imagesharp-3074-postfix`.
3. Default-mode hop counts unchanged across all fixtures (no FX0NN
   regressions).

### U1.c redesign — meaningful sanitizer bound vs sibling guard

**Why this matters.** Milestone-D Task 5 implemented U1.c
("suppress documents whose path contains a sanitizer that bounds
the sink's transitive value chain") via the existing chain-walker,
then reverted it. Reason: the chain-walker fires on the same shape
that defines a *post-fix fixture's sanitized sink*, so suppressing
those documents semantically breaks the post-fix fixtures' purpose.
Meanwhile #3079 — the over-emission target — has mostly *sibling-
guard* sanitizers (bounding `compressionFlag` while the sink uses
`translatedKeywordLength`) that don't overlap the chain anyway.
A redesign needs a predicate that distinguishes:

- **Meaningful sanitizer bound** (post-fix fixture's purpose):
  the sanitizer's bound target IS the sink's value-chain seed —
  this is exactly the ground-truth shape we need to preserve.
- **Noisy sibling guard** (#3079 over-emission driver): the
  sanitizer fires for a different chain than the sink uses;
  current emission keeps it as flavor that bloats the document
  count.

**Definition of done.**

1. Predicate distinguishes the two cases on at least one #3079
   document and on the existing post-fix fixtures.
2. `--compare --strict` on `imagesharp-3079-prefix` shows a
   meaningful drop in `D_a` from 51 toward `D_g=1`.
3. Existing post-fix fixtures (`imagesharp-3074-postfix`,
   future #3079-postfix) keep their sanitized-sink documents
   intact.
4. The redesign does not require fixture authors to invent
   alternate sinks (the original U1.c implementer's workaround
   that motivated the revert).

(Origin: spec revision history dated 2026-04-27 (de-scope, same day);
plan Task 5 marked DEFERRED.)

---
