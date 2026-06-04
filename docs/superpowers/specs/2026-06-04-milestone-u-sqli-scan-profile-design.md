# Milestone-U: SQLi auto-enumeration via `--scan` (sqli scan profile)

**Date:** 2026-06-04
**Status:** Approved design, pending implementation plan
**Predecessors:** Milestones Q–S (cold-scan entry-point enumeration), Milestone-T (CWE-89 SQLi sink + sanitizer machinery)

## Goal

Let `--scan` discover SQL-injection (CWE-89) entry points **cold** — with no hand-written
source method in `rules.yaml` — by pointing the already-proven cold-scan enumeration
machinery at the SQLi sink class shipped in milestone-T. This converges the two strategic
threads of the project: automatic entry-point enumeration (the north star) and sink-class
breadth (DoS → SQLi).

## Headline success criterion (anchor)

`--scan --scan-profile sqli` over the **already-materialized Marten 8.36** artifact
(`GHSA-vmw2-qwm8-x84c`, vulnerable) rediscovers the
`FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)` SQLi path **cold**, i.e.
without the hand-written source entry used by the `marten-vmw2-prefix` fixture.

The `marten-vmw2-prefix` fixture sources that method by hand as:

```yaml
source_methods:
  - signature: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _regConfig
      - _dataConfig
      - _searchTerm
```

`Apply` takes **no string parameter** — the tainted strings arrive as `this`-fields stored
from constructor arguments. Cold rediscovery therefore *requires* a string **this-field**
source path. `FullTextWhereFragment` does not match the existing decoder type-name patterns
(`*Reader`/`*Decoder`/`*Deserializer`/`*Parser`), so the SQLi profile cannot reuse those
patterns; it gates candidates by **sink reachability** instead (see below).

## Key facts grounding the design (verified against code 2026-06-04)

- `--scan` already does **both** enumeration *and* walking in one run: it enumerates
  candidate sources via `EntryPointEnumerator.Enumerate` (`Program.cs:191`), then feeds each
  into `TaintWalker.WalkWithSeed` (`Program.cs:265`) and reports only sink-reaching findings.
- `--emit-rules` is **terminal**: it writes the candidate `rules.yaml` *without* walking.
  This is the artifact locked by `scan-protobuf-net/rules.yaml.expected`. Consequently an
  ungated string scan would emit thousands of useless candidates — gating is mandatory, not
  optional.
- The enumerator's source shape is byte-source-only today
  (`EnumeratorConfig.ByteSourceTypes` = Stream/BinaryReader/byte[]/spans/memory).
- The SQL sink machinery already exists from milestone-T: `SinkKind.SqlInjection`,
  `SinkApi.{SqlCommandText, SqlCommandBuilderAppend}`, `SinkShapes.MatchCommandTextSetter`,
  `SinkShapes.MatchCommandBuilderAppend` (the latter already has a Weasel/Npgsql
  **namespace-prefix fallback** for unresolved cross-assembly references).
- `ReverseCallGraph` exposes `IsReachableFromPublic` and builds `call`/`callvirt`/`newobj`
  edges, expanding `callvirt` via milestone-R `VirtualOverrideIndex`.

## Approach decisions (from brainstorming)

1. **Anchor:** single Marten cold-rediscovery fixture (no separate synthetic success
   criterion; synthetic *unit* fixtures still back the new mechanics).
2. **Architecture:** **scan profiles** (`--scan-profile dos|sqli`, default `dos`) rather than
   additive config knobs — clean separation of source-type set + active sink kinds + gating,
   no DoS/SQLi cross-noise, extensible to future CWE classes.
3. **Source paths:** **both** the string this-field path (required for the anchor) *and* the
   string parameter-shape path (the general "string-typed public params" win).
4. **Gating:** **sink-reachability** (Approach B) — gate string candidates to methods/types
   that transitively reach a SQL-sink API. Precise, general, produces a meaningful
   `--emit-rules` artifact, and aligns with the north star (no hand-curated name lists).

## Architecture & components

A new `ScanProfile` concept. Default `dos` reproduces today's behavior byte-for-byte; new
`sqli`. A profile bundles three things currently hardcoded to byte-DoS semantics:

| | `dos` (default, unchanged) | `sqli` (new) |
|---|---|---|
| Source types | Stream/BinaryReader/byte[]/spans/memory | `System.String` |
| Active sink kinds | Allocation, SpanAccess, Http | SqlInjection only |
| Candidate gate | shape + visibility | + reaches-SQL-sink |
| This-field path | opt-in (`--include-this-field`) | on by default |

Isolated touch points:

- **`EntryPointEnumerator`** — uses the profile's source-type set + applies the
  sink-reachability gate for `sqli`. The existing `MatchesParameterShape` and this-field
  machinery are reused unchanged; only the source-type set and the gate vary. The byte
  this-field path's `DecoderTypeNamePatterns` gate is **not** used by `sqli` (the gate is
  sink-reachability instead).
- **Sink reporting (walker / `Program`)** — filters findings to the profile's active
  `SinkKind`s, so a string scan does not surface incidental allocation hits and vice versa.
- **`dos` path is byte-for-byte unchanged** — `scan-protobuf-net` and `scan-nbmp`
  `--emit-rules` locks are the regression proof.

## The sink-reachability pass (new core — Approach B)

New component (working name `SqlSinkReachability`) computing "which methods can transitively
reach a SQL sink," in two steps:

1. **Direct sink-callers** — methods whose body contains a `call`/`callvirt` to a SQL-sink
   API. The signature-level recognition (`IDbCommand.set_CommandText`,
   `ICommandBuilder.Append`, including the namespace-prefix fallback for unresolved
   Weasel/Npgsql references) is **extracted into one shared predicate used by BOTH this pass
   and `SinkShapes`**, so the static gate and the runtime walker cannot drift. This shared
   extraction is an explicit deliverable of the milestone.
2. **Transitive closure** — BFS over the call-graph edges (reusing `ReverseCallGraph`'s edge
   construction and milestone-R `VirtualOverrides` for `callvirt` hops) to mark every method
   that reaches a direct sink-caller.

The enumerator gates `sqli` candidates on membership in this set. On Marten this collapses
the candidate set from "every string-taking method" to the handful of SQL-building methods —
`FullTextWhereFragment::Apply` among them.

### Robustness

- Cecil resolution failures are tolerated (the existing pattern: treat unresolved as a miss
  and stop walking the base chain). The namespace-prefix fallback handles unresolved Weasel
  (`ICommandBuilder`) and Npgsql references at the sink-signature level.
- The shared sink-signature predicate is the single source of truth; a divergence between
  gate and walker is prevented structurally, not by duplicated logic.

## CLI & config

- New flag **`--scan-profile dos|sqli`** (default `dos`); guarded to require `--scan`
  (same pattern as existing `--include-*` / `--enumerator-config` guards). Unknown profile
  value → error exit.
- `sqli` implies the string this-field path (no separate flag needed).
- `EnumeratorConfig` keeps user-override knobs (exclude namespace/type/method patterns still
  apply). The profile supplies the source-type defaults. `--emit-rules` stays terminal and
  now emits the SQLi candidate set under the `sqli` profile.

## Data flow

```
target.dll
  → AssemblyContext (Cecil) + VirtualOverrides + ReverseCallGraph
  → [profile == sqli] SqlSinkReachability:
        directCallers = methods whose body calls a SQL-sink API (shared predicate w/ SinkShapes)
        reachesSink   = BFS closure over call edges back from directCallers
  → EntryPointEnumerator.Enumerate(profile):
        for each method surviving Hard/Visibility/Exclusion rejects:
          [sqli] gate: reachesSink(method)? else skip
          string parameter-shape  → emit source
          string this-field shape → emit source + seed_this_fields = [string fields]
  → [--emit-rules]  write rules.yaml (TERMINAL)
     else            walker.WalkWithSeed per source, findings filtered to profile sink kinds
```

## Testing

**Anchor fixture** `fixtures/scan-marten-vmw2/` over the materialized Marten 8.36 artifact,
two locked assertions:

1. `--scan --scan-profile sqli --emit-rules` output **contains**
   `FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)` with `seed_this_fields`
   ⊇ `{_regConfig, _dataConfig, _searchTerm}`.
2. End-to-end scan produces a `sql_injection / sql_command_builder_append` finding on that
   path.

**Unit tests** (synthetic fixtures in `TaintAnalyzer.Tests.Fixtures`):

- Sink-reachability: direct caller / transitive caller / unreachable / cross-assembly
  unresolved (namespace-prefix fallback fires).
- String parameter-shape path emits a source.
- String this-field path emits a source with correct `seed_this_fields` selection
  (string fields only).
- Profile sink-kind filtering (a `sqli` scan does not report allocation findings; a `dos`
  scan does not report SQL findings).
- `dos`-profile-unchanged guard.
- CLI flag validation (`--scan-profile` requires `--scan`; unknown value rejected).

## What NOT to break (anchors)

- All 6 SQLi fixtures: `sqli-{synthetic,interpolated,command-builder,regex-guard}-prefix`,
  `marten-vmw2-{prefix,postfix}`.
- All DoS anchors: `imagesharp-307{4,9}-{prefix,postfix}`,
  `otelcontrib-{55m9,vc24,opamp-w2jh}-{prefix,postfix}`, `otelcontrib-aws-fp-fixed`,
  synthetic + parquet fixtures, `nbmp-2cwq-pwfr-wcw3-postfix`.
- **Both** `scan-protobuf-net` and `scan-nbmp-1.1.25` `--emit-rules` locks (proving the
  `dos` profile is byte-for-byte unchanged).
- Full unit suite (currently 362: 299 TaintAnalyzer.Tests + 63 ValidateFixture.Tests).
  Run with `-- xunit.parallelizeTestCollections=false` per the known parallel-flakiness note.

## Out of scope (deferred)

- LINQ expression-tree / `IQueryProvider` visitor analysis to source the public
  `IQuerySession.SearchAsync` family directly (separate analyzer-capability frontier).
- Additional SQL sinks (`ExecuteSqlRaw`, `Execute*` family, Dapper).
- Other injection classes (command / path / LDAP).
- Optional type-name narrowing knob on top of sink-reachability (the "B + A hybrid" option;
  can be added later if a real assembly proves too noisy).
```
