# Milestone-T2: Marten SQLi prefix lock + DefaultInterpolatedStringHandler walker

**Date:** 2026-05-16
**Status:** Design approved; ready for implementation plan.
**Scope:** Real-world Marten 8.36 (GHSA-vmw2-qwm8-x84c) SQL-injection detection, plus the walker primitive needed to make it work.

## Problem

T1 (closed 2026-05-16) shipped `SinkKind.SqlInjection` + `SinkApi.SqlCommandText`
+ `SinkShapes.MatchCommandTextSetter` and locked a synthetic fixture
demonstrating the sink machinery on a `String.Concat`-shaped taint chain.

T1 did NOT detect the actual Marten advisory. Marten's vulnerable code in
`FullTextWhereFragment.Sql` uses `$"..."` string interpolation:

```csharp
$"to_tsvector('{_regConfig}'::regconfig, {_dataConfig}) @@ {_searchFunction}('{_regConfig}'::regconfig, ?)"
```

C# lowers `$"..."` to a sequence of calls on a `ref struct`
`System.Runtime.CompilerServices.DefaultInterpolatedStringHandler` value:
constructor → `AppendLiteral(string)` / `AppendFormatted<T>(T)` per segment →
`ToStringAndClear()` to materialize the result. The handler is held as a
local, addressed via `ldloca.s`, and each Append-call is a struct instance
method with an implicit byref `this` receiver.

The Limes walker currently does NOT propagate taint into the handler local:
`AppendFormatted`'s declared parameters don't include the byref `this`, so
the existing `TaintBufferLikeArgsFromCall` mechanism (which only inspects
`callee.Parameters`) sees no byref-typed param and returns early. Taint
flowing into `AppendFormatted` stays on the stack slot but doesn't reach
the handler local. `ToStringAndClear` then reads from an untainted handler
and returns an untainted string. The downstream `CommandText` setter
matcher never sees a tainted value.

Milestone-T2 closes this gap with the minimum walker addition needed
(a targeted recognizer for `DefaultInterpolatedStringHandler.AppendFormatted`)
plus the Marten 8.36 fixture lock that proves end-to-end detection of the
real-world advisory.

## Goals & non-goals

**In scope (T2 — two phases, one milestone):**

Phase 1 (walker primitive + synthetic anchor):
- New `SinkShapes.TryHandleInterpolatedStringAppend(Instruction, SymbolicStack, TaintState)` returning bool.
- Wire-up in `TaintWalker.HandleCall` before default call dispatch.
- New synthetic fixture `fixtures/sqli-interpolated-prefix/` with C# `$"..."` flowing to `IDbCommand.CommandText`.
- 4 unit tests for the recognizer.
- 1 fixture-runner test for the synthetic.

Phase 2 (Marten real-world lock):
- `scripts/materialize-marten-8.36.sh` — downloads Marten 8.36 from NuGet, extracts to `artifacts/marten-8.36/`.
- `fixtures/marten-vmw2-prefix/rules.yaml` — source method on `Marten.IQuerySession::SearchAsync<T>(...)`.
- `fixtures/marten-vmw2-prefix/trace.yaml` — locked trace from a real analyzer run.
- 1 fixture-runner test for Marten (skip-if-missing pattern).

**Out of scope (deferred to T3 — Marten postfix lock):**
- Regex-guard throw-shape sanitizer extension (`if (!Regex.IsMatch(x, pat)) throw`).
- `scripts/materialize-marten-8.37.sh`.
- `fixtures/marten-vmw2-postfix/` — locked clean trace.

**Out of scope (cheap follow-ups, not this milestone):**
- The other 4 vulnerable `IQuerySession.*Async` methods. Once Phase 2 lands,
  adding them is mechanical (more `source_methods:` entries, re-lock).
- LINQ-extension shape `Where(x => x.Search(term, regConfig))`. Routes
  through delegate / expression-tree IL with different walker semantics.

**Out of scope indefinitely:**
- Auto-enumeration of SQLi entry points via `--scan` (string-typed public params).
- Other SQL sinks: `Execute*` family, `ExecuteSqlRaw`, Dapper extensions.
- Other CWE-89-adjacent classes: command/path/LDAP injection.
- `stelem.ref` walker gap (long-form `+` chains → `String.Concat(string[])`);
  separate watch item, lower leverage than interpolation modeling.

## Architecture

Five edits + four new files across two phases.

### Phase 1

| File | Change |
|---|---|
| `tools/TaintAnalyzer/SinkShapes.cs` | New static method `TryHandleInterpolatedStringAppend`. |
| `tools/TaintAnalyzer/TaintWalker.cs` | One new call in `HandleCall` before default dispatch; early-return if the recognizer handled the call. |
| `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` | New `InterpolatedStringFixtures` static class with `$"..."`-using methods. |
| `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` | 4 new tests for the recognizer. |
| (new) `fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.cs` + `.csproj` | C# program: `$"..."` flowing to `DbCommand.CommandText`. |
| (new) `fixtures/sqli-interpolated-prefix/rules.yaml` | Source method declaration. |
| (new) `fixtures/sqli-interpolated-prefix/trace.yaml` | Locked trace. |
| (new) `scripts/build-sqli-interpolated.sh` | Build script mirroring `build-sqli-synthetic.sh`. |
| (new) `tools/TaintAnalyzer.Tests/SqliInterpolatedFixtureTests.cs` | Fixture-runner test. |

### Phase 2

| File | Change |
|---|---|
| (new) `scripts/materialize-marten-8.36.sh` | Downloads + extracts Marten.dll from NuGet. |
| (new) `fixtures/marten-vmw2-prefix/rules.yaml` | Source: `Marten.IQuerySession::SearchAsync<T>(...)`. |
| (new) `fixtures/marten-vmw2-prefix/trace.yaml` | Locked trace from real run. |
| (new) `tools/TaintAnalyzer.Tests/MartenVmw2FixtureTests.cs` | Fixture-runner test, skip-if-missing. |

No changes to `EntryPointEnumerator`, `ReverseCallGraph`, `SanitizerShapes`,
`HopRecord`, or CLI flags. T1's existing `MatchCommandTextSetter` matcher is
the SQL-injection sink consumer; T2 just feeds it taint via the new walker
primitive.

## Walker recognizer contract

`SinkShapes.TryHandleInterpolatedStringAppend(Instruction, SymbolicStack, TaintState)`
returns `bool`. The method has these match conditions (all required to return
true):

1. `instruction.OpCode == OpCodes.Call` (struct instance method; not callvirt).
2. `instruction.Operand` is a `MethodReference` whose `DeclaringType.FullName
   == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler"`.
3. The method name is `"AppendFormatted"`. (Match by name only; the BCL has
   8 overloads with various extra args — alignment / format string. Any of
   them with a tainted value arg counts.)
4. The top-of-stack slot (`stack.Peek(0)`) is tainted.

On match, walk backward from the call to find the receiver's pusher. The
receiver was pushed first (lowest stack position); for `AppendFormatted<T>(T)`
the IL is canonically `ldloca.s V_n` followed by `ldarg.k`. Walk back past
`Code.Nop` instructions; the next non-nop is expected to be the value-arg
pusher (`ldarg.k`, `ldloc`, etc.). Walk back one more step (past the
value-arg pusher) to find the receiver pusher. Expect `ldloca` or `ldloca.s`
with a `VariableDefinition` operand.

If the receiver pusher is `ldloca`/`ldloca.s`:
- Read the `VariableDefinition.Index`.
- Set `state.Locals[index] = StackSlot.TaintedWith($"InterpolatedString({prov})")`
  where `prov` is the value slot's provenance.
- Return true (the recognizer handled this call; HandleCall skips default dispatch).

If the receiver pusher is something else (field address, address-of-arg,
chained struct manipulation):
- Return false. Let default HandleCall dispatch fire. The chain may still
  work via other walker mechanisms, or it may surface as a Phase 2 gap to
  document.

**AppendLiteral and ToStringAndClear are NOT recognized here.** AppendLiteral's
value arg is a constant literal; never tainted; no propagation needed.
ToStringAndClear takes no explicit args and returns a string; its receiver
(loaded via `ldloca.s` immediately before the call) is a byref to the
handler local. The existing `HandleCall` over-approximation already treats
the receiver as `argSlots[0]` for `HasThis` methods and includes it in the
bitmask. If the handler local was tainted by a prior AppendFormatted call,
the receiver slot at ToStringAndClear's site will read as tainted, the
bitmask is non-zero, and the over-approximation propagates taint to the
return value. No new code needed for ToStringAndClear.

**Wire-up in `TaintWalker.HandleCall`:** add an early branch:

```csharp
if (SinkShapes.TryHandleInterpolatedStringAppend(ins, state.Stack, state))
{
    // Pop the value arg and receiver from the stack (the recognizer
    // mutates state.Locals but doesn't pop the stack — HandleCall's
    // standard arg-pop logic still needs to run).
    // The recognizer handled the side-effect; skip the rest of
    // HandleCall (over-approximation, propagator hop emission, etc.)
    // and return early.
}
```

Exact integration point and stack-popping behavior to be finalized in the
implementation plan after reviewing the current `HandleCall` structure.

## Phase 1 synthetic fixture

`fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.cs`:

```csharp
using System.Data.Common;

namespace InterpolatedSqliPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    public void Search(string regConfig)
    {
        _cmd.CommandText = $"to_tsvector('{regConfig}'::regconfig, body)";
        _cmd.ExecuteNonQuery();
    }
}
```

Single tainted parameter. C# lowers the `$"..."` to:

```
ldloca.s V_0
ldc.i4.s <literalLen>
ldc.i4.1
call DefaultInterpolatedStringHandler::.ctor(int, int)

ldloca.s V_0; ldstr "to_tsvector('"; call AppendLiteral(string)
ldloca.s V_0; ldarg.1;               call AppendFormatted(string)   <-- TAINT POINT
ldloca.s V_0; ldstr "'::regconfig, body)"; call AppendLiteral(string)

ldloca.s V_0
call ToStringAndClear()    <-- return is tainted via over-approximation
```

`rules.yaml`:

```yaml
vuln_id: sqli-interpolated-prefix
source_methods:
  - InterpolatedSqliPoc.SearchService::Search(System.String)
```

`build-sqli-interpolated.sh`: mirrors `scripts/build-sqli-synthetic.sh`.
Outputs to `artifacts/sqli-interpolated-prefix/InterpolatedSqliDemo.dll`.

`trace.yaml`: locked from the analyzer run. Expected sink hop:
- `kind: sql_injection`
- `api: sql_command_text`
- `tainted_value_in: InterpolatedString(regConfig)` or similar provenance string

## Phase 2 Marten materialization

`scripts/materialize-marten-8.36.sh`:

1. `REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`
2. `MARTEN_VERSION=8.36.0`; `OUT_DIR="$REPO_ROOT/artifacts/marten-8.36"`.
3. Create a scratch project in `$(mktemp -d)` with a minimal `.csproj`:
   `<TargetFramework>net9.0</TargetFramework>` + `<PackageReference Include="Marten" Version="$MARTEN_VERSION" />`.
4. `dotnet restore` in the scratch dir.
5. Locate `~/.nuget/packages/marten/$MARTEN_VERSION/lib/net9.0/Marten.dll` and `Marten.pdb` (if present).
6. `mkdir -p "$OUT_DIR"`; copy DLL (and PDB if present) into `$OUT_DIR`.
7. If no PDB: create `$OUT_DIR/.nopdb-marker`; the fixture's run script reads this marker to add `--no-symbols`.
8. `sha256sum "$OUT_DIR/Marten.dll"` for log.
9. Clean up scratch dir.

**TFM selection:** prefer `net9.0`. If the package doesn't ship it (verify via
`unzip -l ~/.nuget/packages/marten/$MARTEN_VERSION/marten.$MARTEN_VERSION.nupkg | grep '\.dll$'` at script-write time), fall back to `net8.0`.

**Transitive packages are NOT materialized.** Only `Marten.dll` is needed.
Npgsql, Microsoft.Extensions.*, etc. are intentionally not loaded — Limes
sees them as unresolvable external types. The T1
`MatchesDbProviderHeuristic` fallback fires on `Npgsql.NpgsqlCommand`
because the namespace starts with `Npgsql` and the type name ends with
`Command`.

**Idempotency:** re-running the script produces byte-identical
`Marten.dll` (NuGet packages are immutable at version). Safe to invoke
repeatedly.

**`.gitignore`:** `artifacts/` should already be ignored (other
materialize-* scripts produce git-ignored output). Confirm at script-write
time; add to `.gitignore` if not.

## Phase 2 Marten rules + trace lock

`fixtures/marten-vmw2-prefix/rules.yaml`:

```yaml
vuln_id: marten-vmw2-prefix
source_methods:
  - Marten.IQuerySession::SearchAsync<T>(System.String,System.String,System.Threading.CancellationToken)
```

**Signature caveat:** the exact short-signature form used by Cecil for
generic methods on interfaces will be confirmed at fixture-write time
by running `--scan --emit-rules` or inspecting IL. The form above is a
best guess; if the actual form differs (e.g., requires ``1` arity
encoding, different generic syntax), the implementation plan updates
this rules.yaml entry to match.

**Trace lock expectations** (best-guess, refined at lock time):
- `source`: `Marten.IQuerySession.SearchAsync` at the relevant source line.
- `path`: propagator hops through `new FullTextWhereFragment(regConfig, ...)` →
  `stfld _regConfig` → ... → `FullTextWhereFragment.get_Sql()` →
  `DefaultInterpolatedStringHandler.AppendFormatted` (TaintInterpolated hop
  emitted by the new recognizer) → `ToStringAndClear` → caller → eventually
  `set_CommandText`.
- `sink`: `Npgsql.NpgsqlCommand.set_CommandText` (matched via T1's namespace
  fallback heuristic since Npgsql.dll isn't loaded).
- `sanitizer_absence`: should fire because the path has propagator hops
  and Marten 8.36 has no validation guard. Existing
  `TraceEmitter.SynthesizeSanitizerAbsence` covers this.

**Known unknowns at design time:**
1. Whether the walker traces from `SearchAsync` through Marten's internal
   call graph all the way to a `set_CommandText` site. The chain crosses
   multiple Marten types and may involve async state machines (which the
   existing `AsyncStateMachineResolver` handles).
2. Whether field-taint cross-method seeding works for `_regConfig`
   without `--include-this-field`. The flag is opt-in; if needed, add
   it to the fixture's run command.
3. Whether the `Sql` property getter materializes its own
   `DefaultInterpolatedStringHandler` local in a way the recognizer's
   `ldloca.s` walk-back can match. If Marten uses an unusual pattern
   (e.g., the handler is a field, or constructed via factory), the
   recognizer falls back to no-op and the chain doesn't lock.

**If the lock doesn't fire on first try:**
1. Use `--progress` to identify where in the call graph taint is lost.
2. If walker gap is < ~80 LOC to fix: extend the recognizer or related
   mechanism, document the gap in `analyzer_gap_backlog.md`, re-lock.
3. If the fix is larger or architectural: stop Phase 2 and propose
   T2.1 (the fix) + T2.2 (Marten lock) as a split.

## TraceEmitter / sanitizer absence

No new TraceEmitter code. The existing
`TraceEmitter.SynthesizeSanitizerAbsence` already fires when
`pathHops.Count > 0` and no `HopRole.Sanitizer` hop appears on the path.
For Marten 8.36 (no validation), the path will contain propagator hops
and no sanitizer, so absence synthesizes automatically.

T1's synthetic trace showed `sanitizer_absence: []` because that fixture's
path was empty (the over-approximation collapsed Concat into the sink's
provenance). T2's interpolated path is longer (multiple AppendFormatted
calls + Sql property getter + cross-method propagation) so the path
should contain at least one propagator hop. If Phase 1's synthetic
trace also shows `sanitizer_absence: []`, that's acceptable — the
synthetic is shorter than Marten's chain.

## Testing

**Phase 1 unit tests** (in `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`,
appended to the existing `SinkShapesTests` class):

1. `TryHandleInterpolatedStringAppend_TaintedValue_TaintsHandlerLocal` —
   call AppendFormatted with tainted top-of-stack value; assert
   `state.Locals[receiverLocalIdx]` is tainted afterward; method returns
   true.
2. `TryHandleInterpolatedStringAppend_UntaintedValue_NoStateChange` —
   call AppendFormatted with untainted value; assert state unchanged;
   method returns false.
3. `TryHandleInterpolatedStringAppend_AppendLiteral_ReturnsFalse` —
   guard: call AppendLiteral (literal arg, not AppendFormatted); method
   returns false even if anything happens to be tainted.
4. `TryHandleInterpolatedStringAppend_NonHandlerType_ReturnsFalse` —
   guard: call AppendFormatted on a fake type (synthesize a fixture
   class with an `AppendFormatted` method); method returns false.

New fixtures in `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:
`InterpolatedStringFixtures` static class with methods exposing the
required IL shapes (one `$"..."` method, one `AppendLiteral` method,
one fake-type method).

**Phase 1 fixture-runner test:**
5. `SqliInterpolatedFixtureTests.SqliInterpolatedPrefix_TraceContainsSqlInjectionSink`
   — clones `SqliSyntheticFixtureTests` pattern; asserts
   `kind: sql_injection` and `api: sql_command_text` appear in
   `fixtures/sqli-interpolated-prefix/trace.yaml`.

**Phase 2 fixture-runner test:**
6. `MartenVmw2FixtureTests.MartenVmw2Prefix_TraceContainsSqlInjectionSink`
   — skip-if-missing pattern (artifact dir not materialized → return
   silently). Asserts trace contains expected source + sink markers.

**Anchor regression discipline** (no new test code; merge-time check):
- All anchors in `analyzer_gap_backlog.md` + new `sqli-synthetic-prefix`
  (T1) stay green. The new recognizer fires only on
  `DefaultInterpolatedStringHandler::AppendFormatted` — not present in
  any existing fixture's call graph. Expected delta: zero new findings
  on prior anchors.

**Test count after T2:**
- Phase 1: 277 → 282 (4 unit + 1 fixture-runner = +5)
- Phase 2: 282 → 283 (+1 fixture-runner)
- ValidateFixture.Tests: 63 (unchanged)
- **Total: ~346.**

## Anchor set after T2

What NOT to break (in order of priority):
1. All existing anchors from `analyzer_gap_backlog.md`.
2. `fixtures/sqli-synthetic-prefix/` (T1).
3. (Phase 1) `fixtures/sqli-interpolated-prefix/`.
4. (Phase 2) `fixtures/marten-vmw2-prefix/`.

## Open questions resolved at implementation time

These are deferred from design to plan/implementation:
- Exact integration point in `TaintWalker.HandleCall` for the recognizer
  early-branch (before or after `argSlots` are popped? before or after
  bitmask is computed?).
- Whether AppendFormatted's various overloads
  (`AppendFormatted<T>(T)`, `AppendFormatted<T>(T, int)`,
  `AppendFormatted<T>(T, string)`, `AppendFormatted<T>(T, int, string)`)
  all use the same stack layout (value at Peek(0), receiver at Peek(N) for
  some N) — likely yes but verify with the probe approach.
- Marten's exact source-method signature in rules.yaml form.
- Whether `--include-this-field` is required for Marten's
  `_regConfig`-via-constructor pattern.
