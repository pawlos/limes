# Milestone-J — `AppliedValueClamp` summary trust signal (design)

**Status:** Design 2026-05-06. Surgical follow-up to milestone-I task 14's reverted attempt at fixing the OTel `array_pool_rent` false-positives.

**One-liner:** Distinguish "callee returned untainted because a value-clamp actively bounded it" from "callee returned untainted incidentally" by adding an `AppliedValueClamp` flag to `MethodSummary`; use it to skip the `bitmask != 0` over-approximation in `HandleCall` only when the callee's clamp matcher actually fired. Eliminates 3 OTel `array_pool_rent` FPs (AWS, OTLP-HTTP, OTLP-gRPC) without regressing milestone-H 55m9.

---

## Motivation

Milestone-I task 14 attempted to replace the `bitmask != 0` over-approximation in `HandleCall` with `calleeSummary.ReturnsTainted`. That regressed `otelcontrib-55m9-prefix` and was reverted (commit `45632d7`). The problem: `ReturnsTainted=false` is ambiguous — it could mean "the callee actively sanitised the value" (AWS-`GetBufferLength`) or "the callee just doesn't track to a useful return and the over-approximation was load-bearing for downstream taint" (55m9-`BuildRequestContent`). Throw-shape sanitisers terminate execution but produce no value; only value-clamp sanitisers (milestone-I) actually bound a return value. So clamp-fire is the precise signal we need.

## Goals

1. `MethodSummary` gains a new required field `AppliedValueClamp : bool`. Set true iff `MatchValueClamps`'s untaint actually fired during the walk (a tainted slot was popped and replaced with an untainted one at a clamp join offset).
2. `WalkWithSeed` tracks the flag in a local `bool` next to the existing `reachedSink`; populates it on summary construction.
3. `TaintWalker.HandleCall` in-assembly branch changes its `callReturnIsTainted` calculation to skip the `bitmask != 0` over-approximation only when `AppliedValueClamp == true`.
4. Two unit tests covering the AppliedValueClamp summary semantics (positive and negative).
5. New fixture `fixtures/otelcontrib-aws-fp-fixed/` (rules.yaml + empty trace.yaml + README + materialize script) locking the AWS FP elimination in the regular `--compare` test suite.
6. Informal scan-validation: re-run analyzer against the cached `/tmp/otel-scan/Azure` and `/tmp/otel-core-scan/` OTLP binaries; confirm those `array_pool_rent` FPs are also empty; update `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md` and `docs/otelcore-scan-2026-04-29-addendum.md` accordingly.

## Non-goals

- OneCollector `http_content_read` FP — different root cause (`MatchHttpRead` unconditional sink); deferred.
- Per-arg taint-out tracking. The single-bit flag is enough for the OTel shape.
- Receiver-taint clause changes. Receiver-this-field propagation is load-bearing for 55m9 and stays untouched.
- External-call branch changes. `taint_from_external_returns` and the external over-approximation are independent of this change.

---

## Architecture

### Component 1 — `MethodSummary.AppliedValueClamp`

**File:** `tools/TaintAnalyzer/HopRecord.cs` (the `MethodSummary` record).

Add `public required bool AppliedValueClamp { get; init; }` next to the existing `ReachedSink`. All call sites that construct a `MethodSummary` must populate the new field (the walker's two return paths in `WalkWithSeed`).

### Component 2 — Walker tracking

**File:** `tools/TaintAnalyzer/TaintWalker.cs::WalkWithSeed`.

Add a local `bool appliedValueClamp = false;` next to the existing `bool reachedSink = false;`. In the existing clamp-untaint block (the `if (clampMatchByJoinOffset.TryGetValue(ins.Offset, out var clamp))` introduced in milestone-I task 11), inside the `if (top.Tainted)` branch — right after the pop and untainted push — set `appliedValueClamp = true;`. Populate `AppliedValueClamp = appliedValueClamp` on both summary-construction sites (the early-return path for body-less methods and the main return path).

The flag must be set **only** when an actual taint is sanitised, not when the clamp shape exists in IL but the linear walker's stack happens to be untainted at the join. Setting it based on shape alone would produce false positives on constant-folding clamps and walker stack-desync cases.

### Component 3 — `HandleCall` trust check

**File:** `tools/TaintAnalyzer/TaintWalker.cs::HandleCall`, in-assembly callee branch (around the existing `callReturnIsTainted` computation, ~ line 1000).

Before:
```csharp
bool callReturnIsTainted = !IsVoidReturn(callee)
    && (bitmask != 0
        || calleeSummary.ReturnsTainted
        || (hasThisOnStack && receiverSlot.Tainted));
```

After:
```csharp
bool callReturnIsTainted = !IsVoidReturn(callee)
    && (calleeSummary.ReturnsTainted
        || (hasThisOnStack && receiverSlot.Tainted)
        || (bitmask != 0 && !calleeSummary.AppliedValueClamp));
```

Receiver-taint clause unchanged. External-call branch (the other branch in `HandleCall`) unchanged.

### Component 4 — AWS fixture

**Files:**
- `fixtures/otelcontrib-aws-fp-fixed/rules.yaml` — copy from `/tmp/otel-scan/AWS/rules.yaml` (the version reconstructed in milestone-I task 14).
- `fixtures/otelcontrib-aws-fp-fixed/trace.yaml` — empty (0 bytes).
- `fixtures/otelcontrib-aws-fp-fixed/README.md` — short; points at `docs/otelcontrib-phase2-scan-2026-04-29.md` and the addendum for FP context; notes that pre-milestone-J this DLL produced `array_pool_rent` at `HttpClientHelpers.cs:170`.
- `scripts/materialize-otelcontrib-aws-fp.sh` — rebuilds `OpenTelemetry.Resources.AWS.dll` from the contrib repo at the same SHA used in milestone-I task 14 (or current main if that SHA is irrecoverable; document the choice in the README).

The fixture binary is built into `artifacts/<sha>/` per the existing convention (gitignored).

### Component 5 — Tests

**File:** `tools/TaintAnalyzer.Tests/MathClampTests.cs` (extend) or new `tools/TaintAnalyzer.Tests/AppliedValueClampTests.cs`.

- `WalkWithSeed_ClampFiresOnTaintedInput_SetsAppliedValueClamp` — `StreamLengthVsLimit` with seeded tainted `streamLength`; assert `summary.AppliedValueClamp == true`.
- `WalkWithSeed_NoClampShape_DoesNotSetAppliedValueClamp` — pick a fixture without a ternary diamond (e.g. `MathMin_TaintedAndConstant` or any non-clamp `SinkFixtures` method); assert `summary.AppliedValueClamp == false`.

---

## Acceptance gates

1. All existing tests + fixtures green (the milestone-H `otelcontrib-{55m9,vc24}-prefix` `--compare` non-strict gates are the canaries).
2. Two new unit tests pass.
3. New `otelcontrib-aws-fp-fixed` fixture passes `--compare` non-strict (analyzer output empty).
4. Informal scan rerun confirms Azure (already empty after milestone-I) stays empty; OTLP-HTTP and OTLP-gRPC `array_pool_rent` FPs go to empty. Addenda updated to reflect.
5. OneCollector remains documented as separate root cause; no change expected.

## Risks and mitigations

- **Risk:** `AppliedValueClamp` set by mistake on a clamp shape that the linear walker over-approximates (stack desync). *Mitigation:* the flag is set only inside the `if (top.Tainted)` arm — if the walker desynced, top probably isn't tainted, so the flag stays false (conservative, matches the milestone-I clamp-untaint conservatism).
- **Risk:** Some milestone-H fixture path actually does benefit from over-approximation flowing through a clamp-fired callee. *Mitigation:* gate 1 — full fixture suite re-run after the change. If any fixture regresses, the fix is incomplete and we revisit.

## Sequencing

Single session. ~30 lines of code + 1 fixture + 2 tests + addendum updates.
