# Milestone-G — Hop dedup + document dedup (design)

**Status:** Approved 2026-04-29.

**One-liner:** Eliminate the two remaining causes of imagesharp-3079-prefix strict-mode failure — repeated callee-hop merging (23k hops) and sink-set explosion (40 docs) — then calibrate the 3079 ground truth to the improved output so the strict gate passes 5/5.

---

## Motivation

Milestone-F closed at 4/5 strict (imagesharp-3079-prefix still fails). The FX064 diagnostics for 3079 are:

```
FX064 budget exceeded: documents D_a=40 (≤1) [strict mode]
FX064 budget exceeded: hops H_a=23151 (≤6) [strict mode]
```

Two independent root causes:

1. **Hop explosion.** `TaintWalker.HandleCall` appends `calleeSummary.Hops` unconditionally for every call site. The memo returns the same `MethodSummary` object for repeated calls to the same `(callee.FullName, bitmask, seedKey)`, so a callee called N times in one walk contributes its hops N times. At scale (the PNG decoder calls helpers in loops) this compounds into tens of thousands of hops per document.

2. **Document explosion.** `TraceEmitter.Emit` creates one YAML document per (source, sink) pair. After U8 dedup (same method + shape + operand), 40 genuinely distinct `(method, line)` sinks survive — all legitimately reachable from `PngDecoderCore.Decode` with attacker-tainted data, but only one (`ReadInternationalTextChunk`) is the actual disclosed #3079 vulnerability. The other 39 are width/height/bitdepth-driven span ops in image-processing methods: real taint flows, noise for this fixture.

The strategy: fix both causes, then make the improved analyzer output the new 3079 ground truth. This is the same "verbatim post-fix output becomes baseline" pattern used for every fixture from milestone-D onward — the hand-authored 3-hop trace is retired in favour of an accurate machine-generated one.

## Goals

1. `TaintWalker` gains a per-walk callee-expansion guard (`expandedCallees`) that prevents the same callee's hops from being appended more than once per walk (U10).
2. `TraceEmitter` gains a path-prefix fingerprint dedup that collapses sink documents sharing a common early call chain, keeping the deepest (most specific) sink per cluster (U11).
3. All five existing fixtures pass `--compare` non-strict (required gate unchanged).
4. After 3079-prefix ground truth is refreshed to post-dedup output, all five fixtures pass `--compare --strict` (5/5 bonus).
5. New unit tests: one for U10 (callee hops appear exactly once per walk), one for U11 (shorter-path sibling collapsed).

## Non-goals

- Fixing the 3079 strict gap by relaxing the FX064 formula rather than improving the analyzer. The budget formula stays as-is (`D_a ≤ D_g`, `H_a ≤ 2·H_g`).
- Eliminating all duplicate hops across documents (U10 only prevents within-walk duplication; the same callee can still expand in separate top-level walks for different source methods).
- Reducing documents to exactly 1 for 3079. Post-dedup, the expected count is 5–10 natural path-clusters; this becomes the new D_g, and strict passes with D_a ≤ D_g.
- `loc_N` recovery in sanitizer hops, U1.c redesign, parquet-dotnet round-trip — all deferred.

## Architecture

Three independent sessions, each shippable on its own:

```
Session 1: TaintWalker.cs — U10 callee-expansion guard
Session 2: TraceEmitter.cs — U11 path-prefix fingerprint dedup
Session 3: Ground-truth refresh — regenerate 3079 (and others as needed), verify 5/5 strict
```

Sessions 1 and 2 have no shared state; either can land first. Session 3 depends on both.

---

## Component: U10 — Callee-expansion guard (Session 1)

**Edit site:** `TaintWalker.WalkMethodBody` (line 87 — where `hops` is declared) and `TaintWalker.HandleCall` (line 774 — signature + callee-hop append block).

**Mechanism:**

`WalkMethodBody` declares a local `HashSet<string> expandedCallees`. It is passed to `HandleCall` as an additional parameter. In `HandleCall`, after `calleeSummary` is computed, the expansion key `$"{resolved.FullName}|{bitmask}|{seedKey}"` is looked up:

- **First hit** (key not in set): add key, append callee hops as before.
- **Repeat hit** (key already in set): skip the `hops.Add` loop. The call-boundary identity hop is **still emitted** (the dispatch info and method-change signal remain useful to a triager).

`seedKey` is computed via the existing `BuildSeedKey(seedFields)` helper; no new string-building needed.

**Scope:** The guard is per-`WalkMethodBody` call, not global. The same callee can still be fully expanded in a separate top-level walk (different source method) — only within-walk repeats are suppressed.

**Test fixture shape** (new method in `Fixtures.cs`):
```csharp
// Calls Echo twice with the same tainted arg. U10 must prevent Echo's arithmetic
// hop from appearing twice in the walk summary.
public static byte[] DoubleCallSameCallee(int n)
{
    int a = Echo(n);    // first call — callee hops expanded
    int b = Echo(n);    // second call — callee hops suppressed, identity hop kept
    return new byte[a + b];
}
```

**Failing test assertion:** `summary.Hops.Count(h => h.Transformation == "arithmetic" && h.Method.Contains("Echo"))` equals 1, not 2.

**Expected hop reduction for 3079-prefix:** from ~23k to an estimated 1–4k. The exact number is measured in Session 3.

---

## Component: U11 — Path-prefix fingerprint dedup (Session 2)

**Edit site:** `TraceEmitter.Emit` — between the U8 `sinkIndices` computation and the emit loop.

**Mechanism:**

For each surviving sink index (post-U8), compute a **path fingerprint** = the sequence of the first 3 *distinct method names* encountered in its propagator path (methods of the first 3 propagator hops where `method != previous_method`, starting from the hop after the source). If the path has fewer than 3 distinct methods, the fingerprint is padded with `""`.

Group sink indices by fingerprint. Within each group, keep the sink with the **longest path** (highest `sinkIdx - sourceIdx`) — this is the deepest/most specific finding for that call chain.

```
fingerprint(sink) = (method_of_1st_distinct_propagator_hop,
                     method_of_2nd_distinct_propagator_hop,
                     method_of_3rd_distinct_propagator_hop)
```

**Implementation sketch** (new private static method `FingerprintDedup`):

```csharp
private static List<int> FingerprintDedup(
    IReadOnlyList<HopRecord> hops,
    List<int> sinkIndices,
    List<int> sourceIndices)
{
    // For each sink, compute fingerprint and depth (sinkIdx - sourceIdx).
    // Group by fingerprint, keep max-depth index per group.
    var best = new Dictionary<(string, string, string), (int depth, int idx)>();
    foreach (int sinkIdx in sinkIndices)
    {
        int sourceIdx = FindPrecedingSourceIndex(sinkIndices, sourceIndices, sinkIdx);
        var fp = ComputeFingerprint(hops, sourceIdx, sinkIdx);
        int depth = sinkIdx - sourceIdx;
        if (!best.TryGetValue(fp, out var prev) || depth > prev.depth)
            best[fp] = (depth, sinkIdx);
    }
    return best.Values.Select(v => v.idx).OrderBy(i => i).ToList();
}
```

`FingerprintDedup` is called immediately after U8, replacing `sinkIndices` before the emit loop. No other structural changes to `TraceEmitter`.

**Test fixture shape** (new test in `TraceEmitterTests.cs`):

Construct a synthetic `HopRecord` list with one source, two sinks reachable through an identical 3-hop prefix but diverging at hop 4. Assert that after `FingerprintDedup`, only one sink document is emitted (the deeper one).

**Expected document reduction for 3079-prefix:** from 40 to an estimated 5–10 natural path clusters. The exact number becomes the new `D_g` after Session 3.

---

## Component: Ground-truth refresh (Session 3)

No code changes. Pure measurement and fixture update.

**Steps:**

1. Run the post-Session-1+2 analyzer on all five fixtures, capture outputs to `/tmp/`.
2. For each fixture where the output changed, refresh `trace.yaml` (verbatim analyzer output, metadata header preserved). 3079-prefix is certain to change; others may shift slightly from U10.
3. Verify `--compare` non-strict on all five: must exit 0.
4. Verify `--compare --strict` on all five: target 5/5. Record actual tally.
5. Commit the refreshed ground truths.

**DoD for this session:** all five fixtures exit 0 on `--compare --strict` with the refreshed ground truths.

---

## Definitions of Done

| # | Criterion |
|---|-----------|
| DoD-1 | `Walk_SameCalleeCalledTwice_HopsNotDuplicated` test passes: arithmetic hop from a callee called twice appears exactly once |
| DoD-2 | `TraceEmitter_FingerprintDedup_CollapsesSharedPrefixSinks` test passes: sibling sinks with identical 3-hop prefix collapse to one document |
| DoD-3 | All five fixtures pass `--compare` non-strict (exit 0) after Sessions 1 + 2 |
| DoD-4 | All five fixtures pass `--compare --strict` (exit 0) after Session 3 ground-truth refresh |
| DoD-5 | Build clean, 0 warnings, all tests green |

---

## Plan parameters (for writing-plans)

**Branch model:** Work on `milestone-g` branch, land on main via fast-forward at the end.

**Break points:** After Session 1 commit, after Session 2 commit. Session 3 is the short calibration pass.

**Artifact paths (unchanged from milestone-F):**
- `PRE3074` = `artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll`
- `POST3074` = `artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll`
- `PRE3079` = `artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll`
- `artifacts/synthetic-callee-arithmetic/Decoder.dll`
- `artifacts/synthetic-stackalloc/Decoder.dll`
- `artifacts/synthetic-instance-arithmetic/Decoder.dll`

**Baseline (pre-G):** 124 tests, 5/5 non-strict, 4/5 strict.

---

## Revision history

- **2026-04-29 (approved).** Initial spec. Two-session implementation (U10 + U11) followed by calibration. Strategy confirmed: fix root causes, make improved output the new ground truth, close strict bonus at 5/5.
