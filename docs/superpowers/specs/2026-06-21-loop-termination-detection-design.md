# Loop-Termination Detection (CWE-835) — Design

**Date:** 2026-06-21
**Status:** Approved (design); pending implementation plan
**Milestone:** first non-taint detection class — `--scan-profile loop`

## Summary

Add a new detection class to Limes that finds **read loops with no completion check**
— the IL idiom behind CWE-835 (Loop with Unreachable Exit Condition / infinite loop).
The motivating bug is **CVE-2026-54772 / GHSA-p86g-xrr2-pf7c** in
`CoreWCF.NetFramingBase` (< 1.8.1 and 1.9.0): the framing-handshake middleware reads
from a `PipeReader` in a loop and never inspects `ReadResult.IsCompleted`, so a peer
that half-closes the connection pins a thread-pool worker at 100% CPU.

This is the first Limes detector that is **not** a source→sink taint analysis. It is a
structural, control-flow property checked per method. It reuses Limes infrastructure
(Cecil loading, async state-machine resolution, scan enumeration, sequence points) but
runs as a standalone pass parallel to `TaintWalker` — the taint engine is not touched.

## Spike result (already validated)

Using the project's own Mono.Cecil, scoped to the async `MoveNext` of the candidate
method:

| Version | Method (`MoveNext`) | `PipeReader.ReadAsync` | `ReadResult.get_IsCompleted` | Verdict |
|---|---|---|---|---|
| 1.9.0 (vuln) | `DuplexFramingMiddleware.OnConnectedAsync` | 1 | **0** | flag |
| 1.9.0 (vuln) | `SingletonFramingMiddleware.OnConnectedAsync` | 1 | **0** | flag |
| 1.9.1 (fix)  | `DuplexFramingMiddleware.OnConnectedAsync` | 1 | **1** | clear |
| 1.9.1 (fix)  | `SingletonFramingMiddleware.OnConnectedAsync` | 1 | **1** | clear |

Key finding: the signal **must be scoped to the async `MoveNext`**, not the
assembly/type — at whole-assembly scope `get_IsCompleted` appears 12× even in the
vulnerable 1.9.0 (other handshake phases legitimately check it). Limes already resolves
the state machine via `AsyncStateMachineResolver`, so the plumbing exists. The 1.9.1 fix
is exactly `get_IsCompleted` 0→1, and Cecil sees it directly.

## Scope

- **In scope:** Tier 1 (read present ∧ completion-signal absent) **and** Tier 2
  (require the read to sit on a loop back-edge, so non-looping single reads are not
  flagged). Read APIs: `PipeReader` (precise) and `Stream`/`Socket` (best-effort).
- **Out of scope (Tier 3):** proving the loop is actually non-terminating
  (progress provably gated on buffer content). This is undecidable in general and not
  needed — the detector reports the *dangerous idiom*, which is how CoreWCF and real
  pipe/socket CWE-835 bugs manifest. This limitation is stated in output and docs.

## Architecture

Approach A — standalone structural pass. New components, all in `tools/TaintAnalyzer/`:

| File | Responsibility |
|---|---|
| `LoopTerminationAnalyzer.cs` | Per-method orchestration: resolve async state machine, find loop spans, find read calls in spans, check completion-signal consumption, produce `LoopFinding`s. |
| `ReadLoopShapes.cs` | Extensible recognizer table (mirrors `SinkShapes`): `RecognizeRead(MethodReference)` and the per-kind completion-signal recognizer. |
| `LoopFinding.cs` | Finding record (method, loop-header location, read call site, read API, CWE, `resolved_via`). |
| `LoopFindingEmitter.cs` | Emits the new YAML finding schema. |
| `ScanProfile.cs` | Add `Loop` enum value. |

`TaintWalker`, `TraceEmitter`, and the taint/DoS/SQLi paths are untouched.

## Detection algorithm (per resolved method body)

The candidate is enumerated as the user-facing method (e.g. `OnConnectedAsync`). The
analyzer resolves its async state machine with `AsyncStateMachineResolver` and analyzes
the `MoveNext` body (the spike proved the loop's back-edge survives the await rewrite).
For non-async methods the body is analyzed directly.

1. **Back-edge / loop spans.** Scan instructions in offset order. Any branch
   (`Br*`, `Brtrue/false`, `Beq`…`Blt`, `Switch`) whose target instruction offset ≤ the
   branch's own offset is a back-edge defining a loop span `[targetOffset, branchOffset]`.
   Collect all spans; nested loops yield multiple spans, handled independently. An
   instruction "is in a loop" iff its offset falls within at least one span.

2. **Read call in a span.** For each `Call`/`Callvirt` whose offset is within a loop
   span, ask `ReadLoopShapes.RecognizeRead(methodRef)`:
   - `System.IO.Pipelines.PipeReader.ReadAsync` → kind `PipeReader`.
   - `System.IO.Stream.Read` / `Stream.ReadAsync`, `System.Net.Sockets.Socket.Receive` /
     `Socket.ReceiveAsync` → kind `StreamInt`.
   A loop span with no recognized read call is not a candidate (keeps false positives
   low: only read-bearing loops qualify).

3. **Completion-signal consumption in the same span.**
   - **PipeReader (precise):** is `ReadResult.get_IsCompleted` called anywhere within the
     span? Present → terminating, no finding. Absent → finding. (`ReadResult` is stored
     across the await; the getter appears post-resume but still inside the span, so a
     span-scoped search catches it — confirmed by the spike.)
   - **StreamInt (best-effort heuristic):** within the span, is the read's `int` result
     compared against `0` (a `ldc.i4.0`-keyed conditional branch — `Brfalse`/`Ble`/`Beq`
     /etc.) that can leave the span? Present → no finding; absent → finding. Precise
     int-result dataflow is heavier and not needed for CoreWCF; the heuristic's FP/FN
     bounds are documented (below).

4. **Emit** a `LoopFinding`: user-facing method signature, loop-header `file:line` and
   read-call `file:line` (via `MoveNext` sequence points when symbols exist, else empty),
   read API, `completion_signal: absent`, `cwe: 835`, and
   `resolved_via: async_state_machine` when the body came from a state machine.

### Heuristic precision notes

- **PipeReader path** is precise for presence/absence at span scope and is the validated
  CoreWCF path.
- **StreamInt path** may have false negatives (a completion check expressed without a
  literal `0` comparison, e.g. via a helper) and false positives (a zero-comparison that
  does not actually exit the loop). Documented; acceptable for a candidate-surfacing
  scanner. Tightening is a Tier-3 follow-up.

## Enumeration / candidate model

Refactor `EntryPointEnumerator` to expose its method-level reject filters
(`HardReject`, `ExclusionReject`, visibility) **without** the source-shape gate
(`MatchesParameterShape` / this-field / virtual-override). Under `ScanProfile.Loop`,
every non-compiler-generated method passing those filters is handed to
`LoopTerminationAnalyzer`, which decides whether a read loop exists.

**Visibility:** the Loop profile accepts a `public` method even on a non-public type
(mirroring the SQLi visibility relaxation from milestone-U), with reachable-from-public
for internal/protected members. Rationale: `DuplexFramingMiddleware` is an `internal`
class whose `public OnConnectedAsync` is invoked through a middleware delegate the call
graph cannot resolve when scanning the target assembly alone — the same situation that
forced the SQLi relaxation. The fixture validates this catches `OnConnectedAsync`.

## Output schema

A distinct YAML document (no `source`/`sink`/`path`). Example — CoreWCF 1.9.0 prefix:

```yaml
vuln_id: scan-CoreWCF.NetFramingBase
findings:
  - cwe: 835
    method: CoreWCF.Channels.Framing.DuplexFramingMiddleware.OnConnectedAsync
    resolved_via: async_state_machine
    loop:
      file: ""        # empty when the assembly ships no symbols
      line: 0
    read:
      api: pipe_reader_read_async
      file: ""
      line: 0
    completion_signal: absent
```

Findings are sorted deterministically (method signature, then read-call offset) so the
emitted document is stable and lockable. The postfix (patched) fixture emits a document
with an empty `findings` list.

## CLI

- New `--scan-profile loop` value, parsed into `ScanProfile.Loop`.
- Under `Loop`, `Program.cs` takes a new branch: enumerate candidates →
  `LoopTerminationAnalyzer` → `LoopFindingEmitter.Emit` to stdout or `--output`. The
  `TaintWalker`/`TraceEmitter` path is not entered.
- `--scan` required (existing guard); `--rules` remains mutually exclusive.
- `--progress` prints candidates-scanned / findings counts to stderr, mirroring the
  existing scan progress lines.

## Fixture

`scripts/materialize-corewcf-netframing.sh` (matches the `materialize-*` pattern)
downloads both NuGet packages and extracts the `netstandard2.0` DLLs into `artifacts/`
(gitignored). Two fixtures, prefix/postfix convention:

- `fixtures/corewcf-p86g-prefix` → 1.9.0 DLL; locked findings YAML lists
  `DuplexFramingMiddleware.OnConnectedAsync` and `SingletonFramingMiddleware.OnConnectedAsync`.
- `fixtures/corewcf-p86g-postfix` → 1.9.1 DLL; locked findings YAML has empty `findings`.

If the package DLLs carry embedded PDBs, findings include line numbers; otherwise they
are method-level — still deterministic and lockable.

## Testing (TDD)

Two layers, mirroring the SQLi milestone.

1. **Unit fixtures** in `tools/TaintAnalyzer.Tests.Fixtures` (handwritten C#), one small
   method per detector branch, tested against `LoopTerminationAnalyzer` with
   xUnit/Shouldly:
   - read loop, no completion check → **flag** (PipeReader and Stream/Socket variants)
   - read loop with `IsCompleted` / int-zero check → **clear**
   - single non-looping read ignoring completion → **clear** (proves Tier-2 back-edge gate)
   - loop with no read call → **clear** (not a candidate)
   - async/`MoveNext` variant → **flag** (proves state-machine resolution)
2. **End-to-end** over the CoreWCF DLLs: run `Program.Run` with
   `--scan --scan-profile loop`; assert prefix output equals the locked findings YAML and
   postfix is empty — the same locked-YAML comparison the SQLi e2e tests use.
   ValidateFixture's taint-trace vocabulary is untouched; the loop schema is validated by
   direct YAML comparison in the e2e tests.

## Exit criteria

- Full test suite green (current 375 + new tests).
- CoreWCF 1.9.0 flags both framing middlewares; 1.9.1 produces no findings.
- `--scan-profile loop` documented in CLI usage and README.

## Out of scope / follow-ups

- Tier 3: provable non-termination (progress-gated-on-buffer dataflow).
- Additional read APIs (`ChannelReader`, `TextReader`, etc.) via the `ReadLoopShapes` table.
- CLI-level fixture validation of the loop schema in `ValidateFixture` (only if needed
  later; e2e YAML comparison suffices for this milestone).
