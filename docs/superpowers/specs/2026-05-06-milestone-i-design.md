# Milestone-I — Async source resolution + loop-guard sanitizer (design)

**Status:** Design 2026-05-06. Triggered by CVE-2026-42348 (GHSA-w2jh-77fq-7gp8) in `OpenTelemetry.OpAmp.Client`, which our 2026-04-29 OTel scans missed because the analyzer cannot walk `async` source bodies.

**One-liner:** Close two analyzer gaps surfaced by the 2026-04-29 OpenTelemetry scans — (A) async source bodies are stubs that hand off to a compiler-generated state machine, so naming an `async` method as a source produces an empty walk; (B) the `length = stream.Length < limit ? (int)stream.Length : limit` clamp idiom in `Shared/HttpClientHelpers.GetBufferLength` is not recognised, producing five false-positive findings (3 in contrib: AWS, Azure, OneCollector; 2 in core: OTLP/HTTP, OTLP/gRPC) — then lock both fixes with a real-world OpAmp prefix/postfix fixture pair and rerun the OTel scans to confirm the false-positives are gone.

---

## Motivation

The 2026-04-29 OTel contrib + core scans (see `docs/otelcontrib-phase2-scan-2026-04-29.md`, `docs/otelcore-scan-2026-04-29.md`) produced 0 confirmed vulnerabilities and 5 false-positives (3 in contrib: AWS, Azure, OneCollector; 2 in core: OTLP/HTTP, OTLP/gRPC), all of the same shape: `array_pool_rent` (or `http_content_read` for OneCollector) inside `Shared/HttpClientHelpers.GetResponseBodyAsString`. The reports flagged the underlying analyzer limitation ("loop-guard sanitizer shapes not yet implemented — deferred to milestone-I").

On 2026-05-06 GHSA-w2jh-77fq-7gp8 / CVE-2026-42348 was published against `OpenTelemetry.OpAmp.Client`: an unbounded `ReadAsByteArrayAsync` on an HTTP response body in `PlainHttpTransport.SendAsync`. A regression run today (see workspace `/tmp/otel-opamp-regression/`) showed:

- Our scan would have missed it because `OpenTelemetry.OpAmp.Client` was not in the hand-picked Phase-2 contrib package list. (Coverage policy gap — deferred.)
- Even if it had been in the list, `MatchHttpRead` would not have fired against the user-facing async source method because the analyzer walked the stub body, not the compiler-generated `<SendAsync>d__7\`1::MoveNext`.
- When pointed manually at `MoveNext`, the analyzer fires correctly on `PlainHttpTransport.cs:51` and identifies the exact CVE shape. So the sink and taint-propagation logic are correct — the source-resolution layer is broken for `async` methods.

This milestone fixes both the source-resolution bug and the loop-guard sanitizer gap, then validates with a checked-in fixture pair built from the OpAmp pre-fix and post-fix commits.

## Goals

1. **`AsyncStateMachineResolver`** — new `tools/TaintAnalyzer/AsyncStateMachineResolver.cs` static helper. When a source method has `[AsyncStateMachineAttribute(typeof(<>d__N))]`, return the state machine type's `MoveNext`. When absent, return the source unchanged.
2. **Source-hop seed adjustment** — when a source has been async-redirected, taint state-machine `this`-fields whose names match the original method's parameter names (the captured arguments).
3. **`resolved_via: async_state_machine` trace marker** — `HopRecord` gains an optional field; `TraceEmitter` writes it on the source hop only when the resolver redirected; the trace's source-hop method name remains the user-facing async method.
4. **`MatchValueClamp` sanitizer (ternary-clamp diamond)** — new matcher in `tools/TaintAnalyzer/SanitizerShapes.cs` that recognises the `tainted < bounded ? tainted : bounded` IL diamond in both orientations and untaints the join slot.
5. **`Math.Min`/`Math.Max`/`Math.Clamp` recognizer in `TaintWalker.HandleCall`** — when a tainted argument meets a constant/bounded argument, the return slot is untainted with provenance `clamped(<tainted>, <bound>)`.
6. **OpAmp fixture pair** — `fixtures/otelcontrib-opamp-w2jh-{prefix,postfix}` containing only `rules.yaml` and `trace.yaml` (binaries materialized via `scripts/materialize-otelcontrib-opamp.sh`, gitignored under `artifacts/`).
7. **Scan-validation rerun** — re-run the 2026-04-29 OTel contrib + core scans against the new analyzer; confirm the 5 known `HttpClientHelpers` false-positives (3 contrib + 2 core) become empty findings; document as addenda to the existing scan reports.

## Non-goals

- Sync `ReadAsStream(CancellationToken)` overload in `MatchHttpRead` — net10+ only; covered by the existing scan reports as a known false-negative asymmetry. Deferred.
- Rules-file `& modreq(...)` space-validator fix for byref source signatures (`in T&` parameters) — deferred.
- Scan-coverage policy automation — i.e. switching from a hand-picked package list to "every `src/*` package referencing `System.Net.Http`" — deferred to a separate process doc.
- Cross-method clamp tracking beyond what the existing callee-summary mechanism provides. If `GetBufferLength` is summarised, the call-clamp recognizer applies at the summary's call site; if summarisation hits the depth limit, the existing `array_pool_rent` finding survives. We do not add new cross-method dataflow.
- Hard-coding any third-party helper FullName (e.g. `HttpClientHelpers.GetBufferLength`) into an allow-list. The fix must generalise via shape recognition.
- Verifying that the clamp constant is "safe-sized" in absolute terms. Bounded-by-constant is bounded enough for CWE-770; absolute size policy is the user's call.

---

## Architecture

### Component 1 — `AsyncStateMachineResolver`

**New file:** `tools/TaintAnalyzer/AsyncStateMachineResolver.cs` (~30 lines).

```csharp
public static class AsyncStateMachineResolver
{
    private const string AttributeFullName =
        "System.Runtime.CompilerServices.AsyncStateMachineAttribute";

    public sealed record Resolution(MethodDefinition Method, bool RedirectedFromAsync);

    public static Resolution Resolve(MethodDefinition source);
}
```

**Algorithm:**
1. Scan `source.CustomAttributes` for `AsyncStateMachineAttribute`. If absent, return `(source, false)`.
2. Read the attribute's first constructor argument (`TypeReference` to the state machine type).
3. Resolve the type. If unresolvable (rare; same module, should never fail in a well-formed assembly), throw `AssemblyContextException("async state machine type unresolvable for {source.FullName}")`.
4. Find `MoveNext` on the state machine type. There is exactly one. Throw if missing.
5. Return `(moveNext, true)`.

**Wiring in `Program.cs`** — between `FindMethod` (line 96–103) and `WalkWithSeed` (line 110):

```csharp
var resolution = AsyncStateMachineResolver.Resolve(source);
walker.TaintFromExternalReturns = entry.TaintFromExternalReturns ?? Array.Empty<string>();

int bitmask;
IReadOnlyCollection<string> seedFields;
if (resolution.RedirectedFromAsync)
{
    bitmask = 0;  // MoveNext has no parameters
    // Seed state-machine `this`-fields whose names match the original method's parameter names.
    seedFields = source.Parameters
        .Select(p => p.Name)
        .Where(name => resolution.Method.DeclaringType.Fields.Any(f => f.Name == name))
        .ToList();
}
else
{
    bitmask = (1 << source.Parameters.Count) - 1;
    seedFields = entry.SeedThisFields ?? Array.Empty<string>();
}
var summary = walker.WalkWithSeed(resolution.Method, bitmask, seedFields);
```

**Trace marker:** `HopRecord` gains `public string? ResolvedVia { get; init; }`. `TraceEmitter` writes `resolved_via: <value>` when set. `Program.cs`'s source-hop emission sets `ResolvedVia = "async_state_machine"` when `resolution.RedirectedFromAsync` is true. The source hop's `Method` field continues to use the user-facing name (`source.DeclaringType.FullName + "." + source.Name`) — only subsequent walker-emitted hops use the state-machine `MoveNext` name (already the case in the regression run).

**Tests** (`tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs`):
1. `Resolve_NonAsync_ReturnsSameMethod` — sync method with no attribute passes through unchanged.
2. `Resolve_AsyncMethod_RedirectsToMoveNext` — `[AsyncStateMachine(typeof(<X>d__N))]` returns the type's `MoveNext`.
3. `Resolve_AsyncGenericMethod_RedirectsToMoveNextOnGenericInstance` — generic `async Task M<T>(...)` resolves correctly.
4. End-to-end (`AsyncSourceWalkTests`): build a tiny synthetic async fixture method whose body calls `ReadAsByteArrayAsync` on a tainted `HttpClient.PostAsync` result. Assert that with the source rule naming the user-facing async method, the analyzer emits a `MatchHttpRead` sink hit and the trace contains `resolved_via: async_state_machine` on the source hop.

### Component 2 — Loop-guard sanitizer

**Where the changes land:**
- `tools/TaintAnalyzer/SanitizerShapes.cs` — new `MatchValueClamp` matcher.
- `tools/TaintAnalyzer/TaintWalker.cs` — `HandleCall` recognises `Math.Min`/`Math.Max`/`Math.Clamp` calls; main IL loop calls `MatchValueClamp` on conditional branches and untaints the join slot when matched.

**Shape 1 — ternary clamp.** C# emits `x < K ? x : K` as a branch diamond. Two orientations to match:

```il
; orientation A (brfalse → use K)
ldarg.X            ; tainted operand
ldc.i4 K           ; constant or bounded
clt
brfalse.s LBL_use_K
ldarg.X            ; small-side: use tainted
br.s LBL_join
LBL_use_K:
ldc.i4 K           ; large-side: use K
LBL_join:
```

Orientation B uses `bge`/`brtrue` and swaps the branch arms; semantically identical.

The matcher fires when **all** of the following hold at a `Cond_Branch` instruction:
1. Each arm contains a single straight-line load (`ldarg`/`ldfld`/`ldloc`/`ldc.*`) followed by a converging unconditional `br` to a common join.
2. One arm loads the same tainted slot that drove the comparison; the other loads a **bounded** value.
3. The conditional opcode is a less-than/greater-than/equality comparison between the tainted slot and the bounded operand.

When matched, the joined slot at the convergence point is **untainted** with provenance `clamped(<tainted-provenance>, <bound-provenance>)`.

**Shape 2 — call clamp.** In `TaintWalker.HandleCall`, when the callee is one of:
- `System.Math::Min(Int32, Int32)` / `(Int64, Int64)` / `(UInt32, UInt32)` / `(UInt64, UInt64)`
- `System.Math::Max(...)` (same overload set; symmetric)
- `System.Math::Clamp(Int32, Int32, Int32)` and other arithmetic overloads

…and at least one argument is bounded, the return slot is untainted with provenance `clamped(<tainted-args>, <bound-args>)`.

**"Bounded" definition.** A slot is bounded iff `Tainted == false` and its provenance originates from one of: a `ldc.*` constant, a method parameter that the source-rules YAML did not seed as tainted, or the result of a previous clamp. For implementation simplicity, **any non-tainted slot whose provenance is constant/parameter/field counts as bounded** — no separate `Bounded` flag is needed on `SymbolicStack.Slot`. The decision collapses to "compare two operands; if one is tainted and one is not, and the join keeps only the smaller, the result is bounded."

**Tests** (`tools/TaintAnalyzer.Tests/SanitizerShapeTests.cs` — extend existing file):
1. `TernaryClamp_OrientationA_LessThan_Untaints` — handcrafted IL `x < K ? x : K` → join is untainted.
2. `TernaryClamp_OrientationB_GreaterThanOrEqual_Untaints` — opposite branch direction, same shape.
3. `TernaryClamp_BothBranchesTainted_StaysTainted` — `x < y ? x : y` where both are tainted → no untaint.
4. `TernaryClamp_StreamLengthVsLimit_Untaints` — exact `(int)stream.Length < limit ? (int)stream.Length : limit` IL pattern (the canonical OTel `GetBufferLength` shape).
5. `MathMin_TwoConstants_NoOpButNoCrash` — `Math.Min(5, 10)` with both constant → return non-tainted.
6. `MathMin_TaintedAndConstant_Untaints` — return is untainted.
7. `MathMin_TwoTainted_StaysTainted` — return stays tainted.
8. `MathClamp_TaintedWithConstantBounds_Untaints` — return is untainted.

### Component 3 — OpAmp fixture pair

**Checked-in fixture contents** (mirrors `otelcontrib-55m9-{prefix,postfix}` exactly — no DLL/PDB):

```
fixtures/otelcontrib-opamp-w2jh-prefix/
    rules.yaml              source + sink rules
    trace.yaml              ground-truth analyzer output (sink fires)

fixtures/otelcontrib-opamp-w2jh-postfix/
    rules.yaml              same rules
    trace.yaml              ground-truth analyzer output (empty findings)
```

**Materialize script:** `scripts/materialize-otelcontrib-opamp.sh` — clones (or reuses a cached clone of) `opentelemetry-dotnet-contrib`, checks out both SHAs into `artifacts/<sha>/`, runs `dotnet build src/OpenTelemetry.OpAmp.Client/OpenTelemetry.OpAmp.Client.csproj -c Debug --framework net10.0 -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false`, and leaves `OpenTelemetry.OpAmp.Client.{dll,pdb}` at the path the test harness expects. Pre-fix SHA: `d6e87d8af403554107671e98e1913a3b2dfe141a`. Post-fix SHA: `bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a`.

**Rules YAML (identical for both fixtures):**

```yaml
vuln_id: otelcontrib-opamp-w2jh
source_methods:
  - signature: OpenTelemetry.OpAmp.Client.Internal.Transport.Http.PlainHttpTransport::SendAsync(T,System.Threading.CancellationToken)
    taint_from_external_returns:
      - HttpClient::Send
      - HttpClient::SendAsync
      - HttpClient::PostAsync
      - HttpClient::GetStringAsync
      - HttpClient::GetByteArrayAsync
```

The source signature names the **user-facing** async method. `AsyncStateMachineResolver` performs the redirect transparently.

**Prefix `trace.yaml`** — derived verbatim from running the post-milestone-I analyzer over the prefix DLL (the same "post-fix output becomes baseline" pattern used since milestone-D):
- Source `PlainHttpTransport.SendAsync` with `resolved_via: async_state_machine`.
- One `http_content_read` sink at `PlainHttpTransport.cs:51` (the `ReadAsByteArrayAsync` call).
- One `sanitizer_absence` between source and sink.
- Three propagator hops through state-machine fields.

**Postfix `trace.yaml`** — empty findings:
- Source still resolves (the async method exists in the post-fix code with a bounded body).
- No sink hit. The post-fix code uses `ReadAsStreamAsync` followed by `Stream.ReadAsync` into an `ArrayPool`-rented buffer sized by `TransportConstants.MaxMessageSize` (a constant, untainted by definition), so `array_pool_rent` does not fire. The test exercises the milestone-I sanitizer on a real-world clamp shape.

**Test wiring:** add the two fixtures to the existing `--compare` harness's data source, mirroring the milestone-H entries for `otelcontrib-{55m9,vc24}-{prefix,postfix}`.

**Per-fixture `README.md`:** short — pre/post-fix SHA, advisory link, build command pointer, expected analyzer behaviour.

---

## Acceptance gates

**Required (block the milestone):**

1. **All existing tests green.** Today's count is 195. New tests expected: ~10 (3 async-resolver + 8 sanitizer + 1 async-resolver end-to-end). Target: ~205+, all passing.
2. **All existing fixtures pass `--compare` non-strict.** No regressions in `imagesharp-307{4,9}-{prefix,postfix}`, `otelcontrib-{55m9,vc24}-{prefix,postfix}`, `parquet-dotnet-738`, synthetics. The two milestone-H OTel pre-fix fixtures are the false-negative regression canaries — the new sanitizer must NOT untaint their genuinely unbounded reads.
3. **New OpAmp pair passes `--compare` non-strict.** Both `otelcontrib-opamp-w2jh-prefix` (sink fires at line 51) and `-postfix` (empty findings).
4. **Scan-validation rerun.** Re-run the analyzer against the cached binaries from the original 2026-04-29 OTel scans (AWS, Azure, OneCollector, OTLP/HTTP, OTLP/gRPC — 5 cases). The `sanitizer_absence` findings inside `HttpClientHelpers.GetResponseBodyAsString` must all become **empty findings**. Document as addenda to `docs/otelcontrib-phase2-scan-2026-04-29.md` and `docs/otelcore-scan-2026-04-29.md` with explicit before/after counts.

**Bonus (not blocking):**

5. **`--compare --strict` passes for the OpAmp pair.** Same calibration pattern as milestone-G/H — analyzer output becomes ground truth, then strict diff stays empty.

## Risks and mitigations

- **False-negative regression on milestone-H fixtures.** The sanitizer change is the highest-risk piece because `otelcontrib-55m9-prefix` and `otelcontrib-vc24-prefix` *should* still fire — their pre-fix code was unbounded *without* a clamp. If the new sanitizer somehow over-untaints them, gate 2 fails. *Mitigation:* before touching the sanitizer, write a focused regression test that runs the full analyzer against `otelcontrib-55m9-prefix` and asserts the `MatchHttpRead` sink still fires. Establish the baseline assertion first.
- **Async resolver breaks non-async sources.** *Mitigation:* gate 2 covers it (every existing source is non-async; resolver must pass them through unchanged). The `Resolve_NonAsync_ReturnsSameMethod` unit test is the first line of defence.
- **Generic state machines (e.g. `<SendAsync>d__7\`1`).** Cecil's `TypeReference.Resolve()` returns the open generic; we just need its `MoveNext`. No special handling required, but covered by the `Resolve_AsyncGenericMethod_RedirectsToMoveNextOnGenericInstance` test.
- **Ternary-clamp orientation drift.** C# can emit the diamond two ways; the Roslyn version + optimisation level may shift the choice. *Mitigation:* both orientations have explicit unit tests; the canonical OTel shape (test 4) is the load-bearing one.

## Sequencing (3 sessions)

- **Session 1 — async resolver.** Implement `AsyncStateMachineResolver` + the three resolver unit tests + Program.cs wiring + `HopRecord.ResolvedVia` + TraceEmitter marker. Materialize the OpAmp pair (so we have artifacts for later sessions). Run all existing fixtures to confirm no regression. Skip writing OpAmp `trace.yaml` for now — the sanitizer isn't in yet.
- **Session 2 — sanitizer.** Implement `MatchValueClamp` + `Math.Min/Max/Clamp` recognizer + 8 sanitizer unit tests + the false-negative regression check on `otelcontrib-55m9-prefix` (gate 2 baseline). Confirm all milestone-H fixtures still fire correctly.
- **Session 3 — OpAmp pair + scan rerun.** Author OpAmp `trace.yaml` files from analyzer output. Run the scan-validation gate against all 5 cached OTel binaries. Write before/after addenda to the existing scan reports. Bonus: calibrate to `--strict`.
