# Milestone-T1: SQLi sink — CommandText setter

**Date:** 2026-05-15
**Status:** Design approved; ready for implementation plan.
**Scope:** First non-DoS sink class in Limes. T1 is the synthetic-fixture proof; Marten (T2/T3) lands separately.

## Problem

Limes today is scoped to HTTP-read + allocation DoS (CWE-770 / CWE-789). The
GHSA-vmw2-qwm8-x84c advisory in Marten ≤ 8.36 is a textbook SQL injection
(CWE-89): a `string regConfig` parameter flows from five public `IQuerySession`
APIs into `$"to_tsvector('{_regConfig}'::regconfig, …)"` inside
`FullTextWhereFragment.Sql`, then into the database command stream without
parameterization.

Architecturally the bug fits Limes's existing call-graph + walker model — it
is a source-to-sink taint flow with a parameter source and a string-typed
sink. What's missing is the **sink class** itself: there is no `SinkKind` for
SQL execution today, no matcher for SQL-execution-bearing IL instructions,
and no fixture under `fixtures/` exercising that flow.

Milestone-T1 adds the minimum sink-side machinery to detect a tainted string
flowing into an ADO.NET `IDbCommand.CommandText` setter, locked by a
synthetic prefix fixture. Marten itself is deferred to T2 (which needs
`DefaultInterpolatedStringHandler` modeling) and T3 (which needs a
regex-guard sanitizer for the postfix).

## Goals & non-goals

**In scope (T1):**
- New `SinkKind.SqlInjection`, new `SinkApi.SqlCommandText`.
- New `SinkShapes.MatchCommandTextSetter` matcher.
- Wire the matcher into `TaintWalker`'s per-instruction sink sweep.
- Wire string serialization into `TraceEmitter`.
- New synthetic PoC project under `samples/sqli-synthetic-poc/`.
- New prefix fixture under `fixtures/sqli-synthetic-prefix/` with `rules.yaml`,
  `run`, and `rules.yaml.expected` lock.
- Unit tests for the matcher (6) + fixture-runner test (1).

**Out of scope (deferred to T2 — Marten prefix lock):**
- `DefaultInterpolatedStringHandler` byref-struct modeling.
  Marten's `Sql` property uses `$"..."` lowering which goes through
  `AppendLiteral` / `AppendFormatted<T>(T)` / `ToStringAndClear()` on a
  `ref DefaultInterpolatedStringHandler`. The walker today has no model
  for this. T1's synthetic uses `string.Concat`-shaped lowering, which
  works via the existing tainted-arg-over-approximation.
- Real Marten 8.36 / 8.37 assemblies under `artifacts/`.
- `fixtures/marten-vmw2-prefix/` lock.

**Out of scope (deferred to T3 — Marten postfix lock):**
- Regex-guard throw-shape sanitizer (PR #4343 is
  `if (!Regex.IsMatch(x, "^[a-zA-Z_]…$")) throw new ArgumentException`).
  Extending `MethodSummary.AppliedThrowShapeSanitiser` to recognize this
  shape needs care to avoid regressing the NBMP / OTel anchors that
  depend on the current arithmetic-comparison shape.
- `fixtures/marten-vmw2-postfix/` lock.

**Out of scope indefinitely (watch items):**
- Auto-enumeration of SQLi entry points via `--scan`. Parameter-shape
  heuristic is byte-source-typed; surfacing `string`-typed public-API
  methods broadens the surface significantly.
- Other SQL execution sinks: `Execute*` family, ORM raw-SQL methods
  (`DbContext.Database.ExecuteSqlRaw`, Dapper extensions). Add when a
  real fixture demands them.
- Adjacent CWE classes: command injection, path injection, LDAP injection.

## Architecture

Six edits in `tools/TaintAnalyzer/`:

| File | Change |
|---|---|
| `HopRecord.cs` | `SinkKind` += `SqlInjection`. `SinkApi` += `SqlCommandText`. |
| `SinkShapes.cs` | New static method `MatchCommandTextSetter(Instruction, SymbolicStack)`. |
| `TaintWalker.cs` | One added call in the per-instruction sink sweep, mirroring `MatchNewArr` / `MatchArrayPoolRent`. |
| `TraceEmitter.cs` | `SinkKindToString` += `"sql_injection"`. `SinkApiToString` += `"sql_command_text"`. No dedup logic change. |
| (new) `samples/sqli-synthetic-poc/` | Console project + class with the source method. |
| (new) `fixtures/sqli-synthetic-prefix/` | `rules.yaml`, `run`, `rules.yaml.expected`. |

No changes to `EntryPointEnumerator`, `ReverseCallGraph`, `SanitizerShapes`,
`RulesDocument`, `RulesYamlEmitter`, `VirtualOverrideIndex`, or CLI flags.

## Sink matcher contract

`SinkShapes.MatchCommandTextSetter(Instruction, SymbolicStack)` returns a
`SinkMatch?`. All of the following must hold to match:

1. `instruction.OpCode` is `OpCodes.Call` or `OpCodes.Callvirt`.
2. `instruction.Operand` is a `MethodReference` with `Name == "set_CommandText"`.
3. The method has exactly one parameter of type `System.String`.
4. The declaring type is `System.Data.IDbCommand` *or* implements
   `System.Data.IDbCommand` (Cecil walk: `TypeDefinition.Interfaces`
   recursively + base-chain).
   On resolve failure, fall back to a namespace-prefix heuristic: accept if
   the declaring-type's `FullName` ends in `Command` AND its namespace
   starts with one of:
   - `System.Data.`
   - `Npgsql`
   - `MySql`
   - `Microsoft.Data.`
   - `Microsoft.EntityFrameworkCore.`
5. The top-of-stack slot (`stack.Peek(0)`) is tainted.

Stack layout at `set_CommandText`: `[receiver, value]` with `value` at
`Peek(0)` and `receiver` at `Peek(1)`. The match consults `Peek(0)` only.

On match, return:
```csharp
new SinkMatch
{
    Kind = SinkKind.SqlInjection,
    Api = SinkApi.SqlCommandText,
    SizeProvenance = peekedSlot.Provenance,
}
```

The `SizeProvenance` field name is reused unchanged to avoid a `HopRecord`
schema change — it carries the provenance string of the sink-feeding slot,
which for SQLi is a string-flow rather than a size.

The interface-implementation walk follows the precedent in
`VirtualOverrideIndex` (interface-table traversal). The traversal logic may
be inlined in the matcher or extracted as a helper next to the existing
override-resolution code — implementation choice; both are acceptable.

The fallback namespace heuristic is the only fuzzy part of the contract.
It exists because Marten and similar libraries don't directly reference
their DB-provider assembly in IL — when scanning Marten alone, Cecil can't
resolve `Npgsql.NpgsqlCommand` and the interface check fails. For T1's
synthetic fixture the receiver is `System.Data.Common.DbCommand` (BCL),
which resolves cleanly; the fallback won't trigger. The fallback exists
to keep T2 feasible.

## Synthetic fixture

`samples/sqli-synthetic-poc/SqliDemo.cs`:

```csharp
using System.Data.Common;

namespace SqliSyntheticPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    public void Search(string regConfig, string term)
    {
        var sql = "SELECT * FROM docs WHERE to_tsvector('"
                  + regConfig
                  + "'::regconfig, body) @@ to_tsquery('"
                  + term
                  + "')";
        _cmd.CommandText = sql;
        _cmd.ExecuteNonQuery();
    }
}
```

Why this shape:
- `DbCommand` is `System.Data.Common.DbCommand` (BCL) which implements
  `IDbCommand` — declaring-type check resolves cleanly without needing a
  DB-provider assembly.
- Two `string`-concatenable fragments verify taint propagates through both
  arg positions of the lowered `String.Concat` call.
- A second tainted parameter `term` makes the matcher's provenance
  deterministic-but-singular under dedup (one finding).
- `ExecuteNonQuery` is present but is NOT a sink — confirms the sink is
  the setter, not the executor.

`fixtures/sqli-synthetic-prefix/rules.yaml`:

```yaml
vuln_id: sqli-synthetic-prefix
source_methods:
  - SqliSyntheticPoc.SearchService::Search(System.String,System.String)
```

`fixtures/sqli-synthetic-prefix/run`: invokes the analyzer with the rules
file against the compiled `SqliSyntheticPoc.dll` under
`artifacts/sqli-synthetic-poc/`, `--compare` against the expected lock.

`fixtures/sqli-synthetic-prefix/rules.yaml.expected`: locked output with
one finding, `sink_kind: sql_injection`, `sink_api: sql_command_text`,
provenance pointing to `regConfig` or `term` (whichever the walker selects
deterministically — established once at lock time and held).

## TraceEmitter / dedup wiring

Three mechanical edits in `TraceEmitter.cs`:

1. `SinkKindToString` switch: `SinkKind.SqlInjection => "sql_injection"`.
2. `SinkApiToString` switch: `SinkApi.SqlCommandText => "sql_command_text"`.
3. `FingerprintDedup` group key — no change. Per `TraceEmitter.cs:459`
   the key is `(string, string, string, SinkKind?)`; the new `SinkKind`
   value is distinguished automatically from `Allocation` / `SpanAccess`
   groups. This is the milestone-K fix; we inherit it.

`seenSinkKeys` at `TraceEmitter.cs:62` is also already keyed on `SinkKind`
and needs no change.

## Testing

**Unit tests** in `tools/TaintAnalyzer.Tests/`:

1. `MatchCommandTextSetter_DirectIDbCommand_Tainted_Matches` — calling
   `set_CommandText` directly on `IDbCommand` with tainted top-of-stack
   returns a `SinkMatch`.
2. `MatchCommandTextSetter_DbCommandSubtype_Tainted_Matches` — same via
   a class implementing `IDbCommand` through `DbCommand`.
3. `MatchCommandTextSetter_Untainted_ReturnsNull` — untainted value
   rejected.
4. `MatchCommandTextSetter_NonDbType_ReturnsNull` — guard: an unrelated
   type with a `set_CommandText` member (synthesized in
   `Fixtures.SinkShapes.cs`) does not match.
5. `MatchCommandTextSetter_ResolveFailure_FallbackHeuristic_Matches` —
   synth a `MethodReference` whose declaring type can't be resolved but
   namespace starts with `Npgsql` and type name ends in `Command`;
   fallback fires.
6. `MatchCommandTextSetter_ResolveFailure_NoFallback_ReturnsNull` — same
   shape but namespace `Acme.Logging`, type name `LogCommand`; fallback
   does NOT fire.

**Fixture test** in `tools/ValidateFixture.Tests/`:

7. `SqliSyntheticPrefix_LockMatches` — runs the prefix fixture's `run`
   script via the existing fixture-runner harness, `--compare` against
   `rules.yaml.expected`, asserts zero diff.

**Anchor regression check** (no new test code, just discipline at merge):

8. All existing fixtures still green. The matcher only fires on
   `set_CommandText`-shaped instructions, which do not appear in any
   current fixture's call graph, so this should be no-op. If any anchor
   regresses, debug before merge.

**Test count after T1:** 270 → ~276 TaintAnalyzer.Tests; 63 → 64
ValidateFixture.Tests. Total ~340.

## Anchor set after T1

What NOT to break:

- All anchors listed in `analyzer_gap_backlog.md` (imagesharp-307{4,9},
  otelcontrib-{55m9,vc24,opamp-w2jh}, otelcontrib-aws-fp-fixed,
  nbmp-2cwq-pwfr-wcw3-postfix, all synthetic + parquet fixtures,
  scan-protobuf-net, scan-nbmp-1.1.25, full unit-test suite).
- Plus the new `sqli-synthetic-prefix` fixture.
