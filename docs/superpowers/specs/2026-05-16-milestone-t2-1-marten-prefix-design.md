# Milestone-T2.1: Marten SQLi prefix lock via ICommandBuilder sink + seed_this_fields

**Date:** 2026-05-16
**Status:** Design approved; ready for implementation plan.
**Scope:** Lock a real Marten 8.36 SQLi trace by sourcing `FullTextWhereFragment.Apply` with seeded this-fields and adding a new `Weasel.Postgresql.ICommandBuilder::AppendWithParameters` sink. Pragmatic shortcut around LINQ expression-tree analysis.

## Problem

T2 Phase 1 (closed 2026-05-16) shipped `SinkShapes.TryHandleInterpolatedStringAppend` — a walker primitive that propagates taint through `DefaultInterpolatedStringHandler.AppendFormatted` calls. The synthetic fixture `sqli-interpolated-prefix` proves the primitive works end-to-end against `$"..."` interpolations flowing into `IDbCommand.CommandText`.

T2 Phase 1 did NOT lock the real Marten 8.36 advisory (GHSA-vmw2-qwm8-x84c) because two gaps surfaced:

1. **LINQ expression-tree gap.** Marten's `QuerySession.SearchAsync(searchTerm, regConfig, token)` doesn't directly emit the interpolation chain. It captures `regConfig` into a closure (`<>c__DisplayClass*`), constructs an `Expression.Lambda(Expression.Call(LinqExtensions.Search, Expression.Field(closure, "regConfig"), …))`, and calls `Queryable.Where(query, lambda).ToListAsync(token)`. Marten's IQueryProvider parses the expression tree at execution time, eventually constructing `FullTextWhereFragment` deep inside its LINQ visitor pipeline. The walker would need expression-tree + closure-capture + visitor analysis to chase this chain — an order of magnitude larger than the interpolation primitive.

2. **Sink-shape gap.** When `FullTextWhereFragment.Apply(Weasel.Postgresql.ICommandBuilder builder)` finally emits the SQL, it calls `builder.AppendWithParameters(this.get_Sql())` — NOT `cmd.CommandText = sql`. T1's `MatchCommandTextSetter` doesn't fire on this shape. The actual sink site uses a query-builder abstraction whose interface is in `Weasel.Postgresql.dll` (not loaded when scanning Marten alone).

Milestone-T2.1 closes the second gap (sink shape) and bypasses the first (LINQ analysis) via a pragmatic shortcut: source `FullTextWhereFragment.Apply` directly with `seed_this_fields`, asserting that the public-API-to-Apply reachability is real (confirmed by the published CVE) without requiring the analyzer to prove it.

## Goals & non-goals

**In scope (T2.1 — two phases, one milestone):**

Phase 1 (sink primitive + synthetic anchor):
- New `SinkApi.SqlCommandBuilderAppend` enum value.
- New `SinkShapes.MatchCommandBuilderAppend` matcher.
- Wire-up in `TaintWalker.HandleSinkMatch` (one-line `??`-append).
- TraceEmitter string mapping for `sql_command_builder_append`.
- New synthetic fixture `fixtures/sqli-command-builder-prefix/`: `_regConfig` field tainted via `seed_this_fields`, flows through `$"..."` in a `Sql` getter, returns to `Apply`, lands in `AppendWithParameters` on a locally-declared `Weasel.Postgresql.ICommandBuilder` interface.
- 5 unit tests for the recognizer + 1 fixture-runner test.

Phase 2 (Marten real-world lock):
- `fixtures/marten-vmw2-prefix/rules.yaml` sourcing `FullTextWhereFragment::Apply` with `seed_this_fields: [_regConfig, _dataConfig, _searchTerm]`.
- `fixtures/marten-vmw2-prefix/trace.yaml` locked from a real analyzer run against `artifacts/marten-8.36/Marten.dll`.
- 1 fixture-runner test with the skip-if-missing pattern.

**Out of scope (deferred):**
- LINQ expression-tree analysis. The public-API-to-`FullTextWhereFragment`-ctor chain stays unsourceable; trace narrative documents this honestly.
- Other 4 vulnerable `IQuerySession.*Async` methods. They all funnel through the same `FullTextWhereFragment.Apply`; T2.1's single source entry covers them implicitly. Verify at lock time.
- Marten 8.37 postfix lock (T3) — regex-guard sanitizer extension.
- Generalizing the matcher to `Append`, `AppendLine`, or other `Append*` methods on Weasel.Postgresql / similar namespaces.
- Dapper, EF Core raw-SQL, or other ORMs' command-builder abstractions.

**Out of scope indefinitely:**
- Auto-enumeration of SQLi entry points via `--scan` (string-typed public params).
- `stelem.ref` walker gap (long-form `+` chains).
- Other CWE-89-adjacent classes: command/path/LDAP injection.

## Architecture

Six edits + four new files across two phases.

### Phase 1

| File | Change |
|---|---|
| `tools/TaintAnalyzer/HopRecord.cs` | `SinkApi` += `SqlCommandBuilderAppend`. |
| `tools/TaintAnalyzer/SinkShapes.cs` | New static method `MatchCommandBuilderAppend`. |
| `tools/TaintAnalyzer/TaintWalker.cs` | One added call in `HandleSinkMatch` chain, mirroring `MatchCommandTextSetter`. |
| `tools/TaintAnalyzer/TraceEmitter.cs` | `SinkApiToString` += `"sql_command_builder_append"`. |
| `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` | New `CommandBuilderFixtures` + a local `Weasel.Postgresql.IFakeCommandBuilder` interface for unit tests. |
| `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` | 5 new unit tests for `MatchCommandBuilderAppend`. |
| (new) `fixtures/sqli-command-builder-prefix/source/CommandBuilderSqliDemo.cs` + `.csproj` | Synthetic source with a locally-declared `Weasel.Postgresql.ICommandBuilder` interface, a tainted-field-bearing class, and an `Apply` method. |
| (new) `fixtures/sqli-command-builder-prefix/rules.yaml` | Sources `Apply` with `seed_this_fields: [_regConfig]`. |
| (new) `fixtures/sqli-command-builder-prefix/trace.yaml` | Locked trace. |
| (new) `scripts/build-sqli-command-builder.sh` | Build script. |
| (new) `tools/TaintAnalyzer.Tests/SqliCommandBuilderFixtureTests.cs` | Fixture-runner test. |

### Phase 2

| File | Change |
|---|---|
| (new) `fixtures/marten-vmw2-prefix/rules.yaml` | Source `FullTextWhereFragment::Apply` with `seed_this_fields`. |
| (new) `fixtures/marten-vmw2-prefix/trace.yaml` | Locked trace from real Marten run. |
| (new) `tools/TaintAnalyzer.Tests/MartenVmw2FixtureTests.cs` | Fixture-runner test, skip-if-missing. |

No changes to `EntryPointEnumerator`, `ReverseCallGraph`, `SanitizerShapes`, `RulesDocument` (existing `seed_this_fields` support is sufficient), or CLI flags. T2 Phase 1's `TryHandleInterpolatedStringAppend` is the taint-propagation primitive; T2.1 just adds the matching sink.

## Sink matcher contract

`SinkShapes.MatchCommandBuilderAppend(Instruction, SymbolicStack)` returns `SinkMatch?`. All of the following must hold to match:

1. `instruction.OpCode` is `OpCodes.Call` or `OpCodes.Callvirt`.
2. `instruction.Operand` is a `MethodReference` with `Name == "AppendWithParameters"`.
3. The method's first parameter type is `System.String` (the SQL text). Subsequent parameters are not constrained.
4. The first arg slot on the stack is tainted. Stack layout at the call: `[receiver, arg0, arg1, …, argN-1]` with `argN-1` at `Peek(0)`. Compute `peekOffset = paramCount - 1` to inspect arg0 (the first parameter; the SQL string).
5. The declaring type is `Weasel.Postgresql.ICommandBuilder` *or* implements it. Cecil walk: `TypeDefinition.Interfaces` recursively + base-chain (reuse the helper pattern from T1's `ImplementsIDbCommand`, generalized as `ImplementsInterface(td, targetFullName)`).
6. **Resolve-failure fallback**: on `MethodReference.DeclaringType.Resolve() == null`, accept declaring types whose `Namespace` starts with `Weasel.Postgresql` AND whose `Name` contains `Command` (substring; e.g. `CommandBuilder`, `PostgresqlCommandBuilder`).

On match, return:
```csharp
new SinkMatch
{
    Kind = SinkKind.SqlInjection,
    Api = SinkApi.SqlCommandBuilderAppend,
    SizeProvenance = firstArgSlot.Provenance,
}
```

This matcher is **read-only on state**: it inspects the symbolic stack and returns a SinkMatch if it fires. Unlike T2 Phase 1's `TryHandleInterpolatedStringAppend` (which mutates `state.Locals`), this matcher follows the same pattern as `MatchNewArr` / `MatchCommandTextSetter`.

**Why `AppendWithParameters` specifically:** Marten 8.36's `FullTextWhereFragment.Apply` literally calls this method on `ICommandBuilder` with the tainted SQL as the first arg. Other `Append*` methods on ICommandBuilder may exist but are out of scope.

**Why `Name` contains `Command` (vs T1's `EndsWith("Command")`):** the legitimate hits are `*CommandBuilder` types, not `*Command`. T1's looser end-with check would miss `CommandBuilder`.

## Phase 1 synthetic fixture

`fixtures/sqli-command-builder-prefix/source/CommandBuilderSqliDemo.cs`:

```csharp
namespace Weasel.Postgresql;
public interface ICommandBuilder
{
    void AppendWithParameters(string sql);
}

namespace CommandBuilderSqliPoc;

public sealed class SearchFragment
{
    private readonly string _regConfig;
    public SearchFragment(string regConfig) => _regConfig = regConfig;

    private string Sql => $"a{_regConfig}b{_regConfig}c";

    public void Apply(Weasel.Postgresql.ICommandBuilder builder)
    {
        builder.AppendWithParameters(this.Sql);
    }
}
```

Why this shape:
- Declares `Weasel.Postgresql.ICommandBuilder` LOCALLY so the synthetic's IL has the matching namespace shape — the matcher's namespace-prefix fallback path is exercised exactly like it will be when scanning Marten alone (Weasel.Postgresql.dll not loaded).
- Single instance field `_regConfig` (vs Marten's three) keeps IL minimal; multi-field validation lives in Phase 2.
- 5-part `$"..."` interpolation forces handler emission (T2 Phase 1 lesson).
- `Apply` takes `ICommandBuilder` by interface — exercises the matcher's interface-walk + fallback path.

`fixtures/sqli-command-builder-prefix/rules.yaml`:

```yaml
vuln_id: sqli-command-builder-prefix
source_methods:
  - signature: CommandBuilderSqliPoc.SearchFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _regConfig
```

`fixtures/sqli-command-builder-prefix/trace.yaml`: locked from analyzer run. Expected sink:
- `kind: sql_injection`
- `api: sql_command_builder_append`
- `tainted_value_in: InterpolatedString(_regConfig).ToStringAndClear` (provenance via T2 Phase 1 primitive + over-approximation chain)

`scripts/build-sqli-command-builder.sh`: mirrors `scripts/build-sqli-interpolated.sh`.

## Phase 2 Marten lock

`fixtures/marten-vmw2-prefix/rules.yaml`:

```yaml
vuln_id: marten-vmw2-prefix
source_methods:
  - signature: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _regConfig
      - _dataConfig
      - _searchTerm
```

The signature was confirmed from Marten 8.36 IL inspection at design time. The exact form may need minor adjustments at fixture-write time (e.g., if Cecil renders the interface parameter type slightly differently for generic-method-on-interface cases — verify with a quick run).

**Trace lock expectations:**
- `source`: `Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment.Apply`, with seeded fields as the implicit tainted state.
- `path`: hops through:
  - `call this.get_Sql()` (cross-method seed propagates `_regConfig`, `_dataConfig` into get_Sql's walk)
  - Multiple `AppendFormatted` calls inside get_Sql (T2 Phase 1 recognizer fires on each, taints the handler local)
  - `ToStringAndClear()` returns tainted string via byref-receiver over-approximation
  - Return to Apply
  - `callvirt ICommandBuilder::AppendWithParameters(taintedSql, …)` — sink hop
- `sink`: `Weasel.Postgresql.ICommandBuilder::AppendWithParameters` (matched via namespace-prefix fallback since Weasel.Postgresql.dll isn't loaded).
- `sanitizer_absence`: should fire because path has propagator hops and no sanitizer (Marten 8.36 has none; that's the bug).

**Trace description block** documents the LINQ-bypass clearly:

```yaml
description: >
  Real-world advisory fixture for GHSA-vmw2-qwm8-x84c (Marten ≤ 8.36 SQL
  injection via FullTextWhereFragment.Sql interpolating user-controlled
  regConfig). Source is FullTextWhereFragment.Apply with seeded this-fields,
  NOT the public IQuerySession.SearchAsync — that public-API chain goes
  through a LINQ expression tree (closure capture + Queryable.Where +
  IQueryProvider visitor parsing) which the analyzer does not currently model
  end-to-end. The CVE confirms that regConfig DOES reach this fragment from
  public API; this fixture proves the analyzer detects the SQL injection
  given that reachability assumption. Walker primitive used: T2 Phase 1's
  TryHandleInterpolatedStringAppend on the $"..." in get_Sql. Sink matcher:
  T2.1's MatchCommandBuilderAppend on AppendWithParameters. Locked at
  milestone-T2.1; do not regenerate without re-locking.
```

**Known unknowns at design time:**
1. Whether `seed_this_fields` propagates correctly through `call this.get_Sql()` for THIS specific shape (Apply is an instance method on a concrete class; the cross-method seed mechanism is well-tested but might surface a corner case).
2. Whether the 5 `IQuerySession.*Async` APIs all funnel through this same Apply method or whether some use a different fragment type. Verify by inspecting Marten IL once Phase 2 runs; document in trace description.
3. The exact rules.yaml syntax form for `seed_this_fields` (inline object vs flat-string array). Will be confirmed by reading `RulesDocument.cs` at task-write time.

**Phase 2 triage protocol (if first lock fails):**
1. Use IL inspection to confirm Apply's exact call sequence (does it really call `this.get_Sql()`? does it call `AppendWithParameters` directly or through a delegate?).
2. If a walker quirk surfaces (generic method dispatch, async state machine wrapping Apply, etc.): document the gap, evaluate whether < 80 LOC fixes it; if yes, fix and re-lock; if no, stop and propose T2.1.1.
3. If `seed_this_fields` doesn't propagate as expected: investigate `ComputeCrossMethodSeed` in TaintWalker; this is well-tested existing code so a failure here would be an obscure shape issue. Same go/no-go discipline.

## TraceEmitter wiring

Two-line addition to `TraceEmitter.SinkApiToString`:

```csharp
SinkApi.SqlCommandBuilderAppend => "sql_command_builder_append",
```

`FingerprintDedup` group key already includes `SinkKind`; no change needed. `seenSinkKeys` likewise unchanged.

## Testing

**Phase 1 unit tests** (in `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`):

1. `MatchCommandBuilderAppend_DirectICommandBuilder_Tainted_Matches` — call directly on `Weasel.Postgresql.ICommandBuilder` (local fixture interface). Assert `Kind == SqlInjection`, `Api == SqlCommandBuilderAppend`, provenance correct.
2. `MatchCommandBuilderAppend_Untainted_ReturnsNull` — untainted first arg rejected.
3. `MatchCommandBuilderAppend_WrongName_ReturnsNull` — method named `Append` on the same interface; must not fire.
4. `MatchCommandBuilderAppend_ResolveFailure_FallbackHeuristic_Matches` — synthesize an unresolvable `MethodReference` in `Weasel.Postgresql.CommandBuilder`; fallback fires.
5. `MatchCommandBuilderAppend_ResolveFailure_NoFallback_ReturnsNull` — synthesize unresolvable `Acme.QueryBuilder.SomeCommandBuilder.AppendWithParameters`; fallback rejects.

New fixtures in `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:
- `CommandBuilderFixtures` with two methods (one calling `AppendWithParameters`, one calling `Append`).
- A local `IFakeCommandBuilder` interface declared inside a `Weasel.Postgresql` (or similar) namespace.

**Phase 1 fixture-runner test:**

6. `SqliCommandBuilderFixtureTests.SqliCommandBuilderPrefix_TraceContainsCommandBuilderSink` — mirrors `SqliInterpolatedFixtureTests`. Skip-if-missing pattern. Asserts trace markers.

**Phase 2 Marten fixture-runner test:**

7. `MartenVmw2FixtureTests.MartenVmw2Prefix_TraceContainsCommandBuilderSink` — skip-if `artifacts/marten-8.36/Marten.dll` missing. Asserts `kind: sql_injection`, `api: sql_command_builder_append`, `Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment` in trace.

**Anchor regression discipline:**

8. All anchors stay green:
   - All from `analyzer_gap_backlog.md`.
   - T1's `sqli-synthetic-prefix`.
   - T2 Phase 1's `sqli-interpolated-prefix`.
   The new matcher fires only on `AppendWithParameters`-named methods on `Weasel.Postgresql`-namespaced types — not in any current anchor.

**Test count after T2.1:**
- Phase 1: 282 → 288 (5 unit + 1 fixture-runner = +6).
- Phase 2: 288 → 289 (+1 Marten fixture-runner).
- ValidateFixture.Tests: 63 (unchanged).
- **Total: ~352.**

## Anchor set after T2.1

What NOT to break (priority order):
1. All anchors in `analyzer_gap_backlog.md`.
2. `fixtures/sqli-synthetic-prefix/` (T1).
3. `fixtures/sqli-interpolated-prefix/` (T2 Phase 1).
4. (Phase 1) `fixtures/sqli-command-builder-prefix/`.
5. (Phase 2) `fixtures/marten-vmw2-prefix/`.

## Open questions resolved at implementation time

- Exact rules.yaml syntax form for `seed_this_fields` (inline object vs flat-string array vs another shape supported by `RulesDocument.cs`).
- Whether IL inspection of Marten reveals overload-set or generic-method quirks on `AppendWithParameters` that need the matcher tightened.
- Whether the 5 IQuerySession.*Async APIs all funnel through the same Apply (likely yes; verify at lock time).
- Whether `seed_this_fields` propagation through `call this.get_Sql()` works without `--include-this-field` (it should — `--include-this-field` is for scan-mode enumeration; `seed_this_fields` is the per-source rules-mode mechanism).
