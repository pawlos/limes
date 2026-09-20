# Milestone-Escape: Marten GHSA-rfx3 via raw `Append(string)` sink + quote-escape sanitizer

**Date:** 2026-09-19
**Status:** Design approved; ready for implementation plan.
**Scope:** Detect Marten GHSA-rfx3-98h7-v3xp (CVE-2026-75513) on the vulnerable build and prove it is clean on the patched build. Three pieces: a raw `ICommandBuilder.Append(string)` SQL sink under its own api label, recognition of the Weasel 9.x `Weasel.Core` namespace, and Limes' first **value-transforming** sanitizer, which recognizes quote-doubling `String.Replace("'", "''")`.

## Problem

GHSA-rfx3-98h7-v3xp: SQL injection in Marten's LINQ provider through unescaped string literals. CVSS 9.1, affected `>= 7.0.0, <= 9.12.0`, first patched **9.13.0** (fix PR JasperFx/marten#4911). There is no 8.x backport: an IL dump of 8.37.4 is identical to 8.37.0, and NuGet flags both with NU1904.

Primary vector: `Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter::Apply(Weasel.Postgresql.ICommandBuilder)`. `_keyText` is the LINQ dictionary-indexer / `ContainsKey` key, set in the ctor from `ISerializer.ToCleanJson(ConstantExpression.Value)`, and `Apply` appends it raw inside a single-quoted literal:

```
IL_0000: ldarg.1; ldstr "d.data #> '{"        ; callvirt ICommandBuilder::Append(string)
         ... foreach JsonPathSegments(_member) → Append(seg); Append(", ") ...   (try/finally)
IL_004b: ldarg.1; ldarg.0; ldfld _keyText     ; callvirt ICommandBuilder::Append(string)   ← injection
IL_0057: ldarg.1; ldstr "}' is not null"       ; callvirt ICommandBuilder::Append(string)
```

Marten 9.13.0 changes exactly one thing in this method. It inserts `ldstr "'"; ldstr "''"; callvirt String::Replace(string,string)` between the `ldfld _keyText` and the `Append`. The call sites also now target `Weasel.Core.ICommandBuilder`.

### Why Limes misses it today (root-caused 2026-09-19)

- **Enumeration works.** `--scan --scan-profile sqli` over Marten 8.37.0 already emits `DictionaryContainsKeyFilter::Apply` with `seed_this_fields: [_keyText, <ParameterName>k__BackingField]`.
- **The walker works.** A debug trace of the linear walk shows `depth=2, top=T:_keyText` at `IL_0052`, the `Append` call, including across the enumerator try/finally region.
- **The sink recognizer rejects it.** `SinkShapes.IsCommandBuilderAppendCall` gates on `mr.Name != "AppendWithParameters"`. GHSA-vmw2's `FullTextWhereFragment` used `AppendWithParameters`, while rfx3 uses plain `Append(string)`. The raw overload is the *more* dangerous one because nothing gets parameter-bound. T2.1 locked this exclusion on purpose (`SinkShapesTests.MatchCommandBuilderAppend_WrongName_ReturnsNull`), and rfx3 shows that choice was wrong.

Confirmed empirically: accepting `Append` (one-line change, since reverted) flips `reachedSink` to `True` and makes the cold scan report the method. Cost: the cold sqli scan of 8.37 goes from 19 to 66 trace documents. Marten 8.37 has 538 `ICommandBuilder::Append(string)` call sites against 10 `AppendWithParameters`.

### Why the postfix needs a new sanitizer class

External BCL calls over-approximate: a tainted receiver gives a tainted return. So once `Weasel.Core` is recognized, `_keyText.Replace("'", "''")` stays tainted and 9.13 would report a false positive. Every existing sanitizer shape (`MatchCompareAndThrow`, `MatchCompareAndReturnEarly`, `MatchRegexIsMatchAndThrow`, `MatchValueClamps`) models a **bound plus a failure mode**. Escaping has neither: it rewrites the value and control flow continues.

Without the namespace fix, 9.13 comes out "clean" for the wrong reason: the `Weasel.Postgresql` namespace heuristic doesn't match `Weasel.Core`.

## Goals & non-goals

**In scope:**
- `SinkApi.SqlCommandBuilderAppendRaw` → `sql_command_builder_append_raw`, on by default.
- `Weasel.Core.ICommandBuilder` recognition, and a heuristic widened from `Weasel.Postgresql` to `Weasel.`.
- `SanitizerShapes.MatchSqlQuoteEscapes`, plus walker untainting and a transformation-based sanitizer hop.
- ValidateFixture: FX023 exemption for value-transforming sanitizers, and closing the pre-existing SQLi vocabulary gap.
- Synthetic anchors `sqli-raw-append-prefix` and `sqli-quote-escape-postfix`.
- Real-world anchors `marten-rfx3-prefix` (8.37.0) and `marten-rfx3-postfix` (9.13.0).
- Cold-scan lock on both Marten versions.
- A README row.

**Out of scope (backlog):**
- The advisory's other vectors: Select-projection string constants, tenant IDs in projection teardown, partition DDL, per-tenant partition-pruning literals. Tenant and partition DDL probably need different sources and sinks.
- A table-driven escape registry (Npgsql/Weasel quoting helpers, `QuoteIdentifier`, …).
- `Replace` overloads with `StringComparison`/culture, and escape arguments routed through locals or fields.
- Verifying literal context (see Limitations).
- FP reduction for the extra raw-append documents (interpolation-vs-parameter discrimination, the milestone-U follow-up seed, still reserved as "milestone-V").
- `Append(char)`.

## Design

### 1. Sink side (`SinkShapes`, `HopRecord`, `TraceEmitter`)

- `HopRecord.cs`: add `SqlCommandBuilderAppendRaw` to `SinkApi`. `TraceEmitter` maps it to `sql_command_builder_append_raw`.
- Split `IsCommandBuilderAppendCall` into two predicates that share a declaring-type check (resolve → `ImplementsCommandBuilder`, or fall back to `MatchesCommandBuilderHeuristic` on resolution failure):
  - `IsCommandBuilderParameterizedAppend(mr)`: `Name == "AppendWithParameters"`, `Parameters.Count >= 1`, `Parameters[0]` is `System.String`. Unchanged behaviour.
  - `IsCommandBuilderRawAppend(mr)`: `Name == "Append"`, `Parameters.Count == 1`, `Parameters[0]` is `System.String`.
- `MatchCommandBuilderAppend` returns `Api = SqlCommandBuilderAppendRaw` for raw and `SqlCommandBuilderAppend` for parameterized. Stack logic is unchanged (SQL arg at `Peek(paramCount - 1)`, requires `Depth >= paramCount + 1`).
- `IsSqlSinkCall` covers both predicates. `SqlSinkReachability` and the runtime walker share that predicate, so the static gate and the walk stay consistent (a milestone-U invariant).
- `ImplementsCommandBuilder` also accepts `Weasel.Core.ICommandBuilder`.
- `MatchesCommandBuilderHeuristic` widens its namespace test from `StartsWith("Weasel.Postgresql")` to `StartsWith("Weasel.")`. The type name must still contain `Command`.

**Invariant:** every existing fixture trace stays byte-identical. I grepped for this at design time: no synthetic fixture, anchor or enum fixture calls `Append(string)` with a tainted value. The only `Append` use is `CommandBuilderFixtures.DoAppend`, which is referenced solely by the unit test inverted below.

### 2. Escape sanitizer (`SanitizerShapes`, `TaintWalker`)

**Pattern.** `SanitizerShapes.MatchSqlQuoteEscapes(MethodDefinition) → IEnumerable<QuoteEscapeMatch>`, where `QuoteEscapeMatch { int CallIlOffset }`. This is a pure IL pattern that needs no walker. A call site matches when:
- the instruction is `call` or `callvirt` to `System.String::Replace(System.String, System.String)`;
- the instruction pushing argument 2 (skipping `nop`s) is `ldstr "''"`, and the one before it (skipping `nop`s) is `ldstr "'"`.

Not matched: `Replace(char, char)` (it can't double a quote), the `StringComparison` and culture overloads, and arguments loaded from locals or fields. Release builds, including Marten 9.13, emit the literals inline.

**Walker.** In `WalkMethodBody`, precompute `quoteEscapeOffsets` (a `HashSet<int>`) next to `clampMatchByJoinOffset`. In the main loop, **after** `StepInstruction`, if `ins.Offset` is in the set and `state.Stack.Depth > 0 && state.Stack.Peek().Tainted`:
- pop the slot and push `new StackSlot(false, $"sql_quote_escaped({prov})")`;
- emit a hop: `Role = Sanitizer`, `Transformation = "sql_quote_escape"`, `TaintedValueIn = prov`, `TaintedValueOut = sql_quote_escaped(prov)`, `EstablishesBound = null`, `OnFailure = null`, direct dispatch on the declaring type.

The check runs post-step because `StepInstruction` handles the external `Replace` call and pushes the over-approximated tainted return. We then replace that result. This is the same "adjust the stack at a precomputed offset" approach as ternary clamps. If the input was untainted, no hop is emitted.

### 3. Trace contract (`TraceEmitter`, ValidateFixture)

The escape hop's shape in `trace.yaml`:

```yaml
- hop: 1
  method: Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter.Apply
  role: sanitizer
  tainted_value_in: _keyText
  transformation: sql_quote_escape
  tainted_value_out: sql_quote_escaped(_keyText)
  dispatch: { kind: direct, static_type: ..., resolved_targets: [], closure_boundary: false }
```

No `establishes_bound` and no `on_failure`.

- **TraceEmitter.** The source+sanitizer-only document path added in T3 already triggers on any sanitizer hop (`rawSinkIndices.Count == 0 && rawSanitizerCount == 0` early return), so the postfix emits source, field_load and sanitizer with no sink. `SanitizerBoundMatchesSink` reads `EstablishesBound?.Target` and returns `true` when it is empty, which would let an escape hop suppress `sanitizer_absence` for an unrelated value in the same method. For bound-less hops it falls back to matching on the hop's `tainted_value_in`, so an escape suppresses absence only for its own chain.
- **ValidateFixture.**
  - `FixtureValidator` FX023 skips the `establishes_bound`/`on_failure` requirement for sanitizer nodes whose `transformation` is in a new `Vocabularies.ValueTransformingSanitizers = { "sql_quote_escape" }`.
  - `sql_quote_escape` is added to `Transformations`.
  - The pre-existing SQLi gap (no SQLi fixture is currently validated) is closed at the same time: `sql_injection` goes into `SinkKinds`; `sql_command_text`, `sql_command_builder_append` and `sql_command_builder_append_raw` go into `SinkApis`; `regex_match` goes into `Relations`.
  - One new `ValidateFixture.Tests` TestData case covers a bound-less `sql_quote_escape` sanitizer node (valid), with a negative control (a bound-less `identity` sanitizer still fails FX023).

## Fixtures and tests

**Lock inversion (deliberate).** `SinkShapesTests.MatchCommandBuilderAppend_WrongName_ReturnsNull` becomes `MatchCommandBuilderAppend_RawAppend_MatchesRawApi`: a tainted `IFakeCommandBuilder.Append(string)` now matches with `Api == SqlCommandBuilderAppendRaw`. `IFakeCommandBuilder` already declares `Append(string)`, so no change is needed in the fixture library.

**Unit tests (TDD, red first):**
- `SinkShapes`:
  - raw vs parameterized api selection;
  - `Append(char)` rejected (new fixture method);
  - `Weasel.Core` heuristic fallback (a synthesized unresolvable `Weasel.Core.XCommandBuilder::Append(string)` matches);
  - a non-Weasel namespace is still rejected.
- `SanitizerShapes.MatchSqlQuoteEscapes`:
  - positive: `s.Replace("'", "''")`;
  - negatives: `Replace("\"", "\"\"")`, `Replace("'", "")`, `Replace('\'', '"')` (char overload), and literals loaded from locals.

  These need new fixture methods in `TaintAnalyzer.Tests.Fixtures`. The existing Debug build is fine: Roslyn emits string-literal arguments as inline `ldstr` in Debug too, and only statement-boundary `nop`s differ. For the "literals loaded from locals" negative, use non-`const` locals so the compiler doesn't fold them.
- Walker:
  - tainted `this`-field → Replace → `Append`: `ReachedSink == false`, exactly one hop with `transformation: sql_quote_escape`;
  - untainted Replace: no sanitizer hop;
  - tainted field → `Append` without Replace: sink with the raw api.
- ValidateFixture: the two TestData cases above.

**Phase 1: synthetic anchors.** Build scripts mirror `scripts/build-sqli-command-builder.sh`. Each fixture ships a local fake `Weasel.Postgresql` builder interface declaring `Append(string)`.
- `fixtures/sqli-raw-append-prefix/`: a fragment class with a `_key` field. `Apply(builder)` does `Append("d.data #> '{")`, `Append(_key)`, `Append("}' is not null")`. Rules seed `_key`. Expected trace: `sql_injection` / `sql_command_builder_append_raw`.
- `fixtures/sqli-quote-escape-postfix/`: identical except `Append(_key.Replace("'", "''"))`. Expected trace: source, field_load and a `sql_quote_escape` sanitizer, no sink, `sanitizer_absence: []`.

**Phase 2: real-world anchors.**
- `scripts/materialize-marten-9.13.sh` mirrors `materialize-marten-8.37.sh` (`MARTEN_VERSION=9.13.0`, out `artifacts/marten-9.13`, TFM net9.0 with net8.0 fallback). The 8.37 artifact comes from the existing script.
- `fixtures/marten-rfx3-prefix/` uses **Marten 8.37.0**. This is intentional: 8.37.0 is the GHSA-vmw2-patched build, so the pair shows "fixed for one advisory, still vulnerable to the next." `rules.yaml` sources `Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter::Apply(Weasel.Postgresql.ICommandBuilder)` with `seed_this_fields: [_keyText]`. `trace.yaml` is locked from a real run, with sink `sql_command_builder_append_raw`.
- `fixtures/marten-rfx3-postfix/` uses **Marten 9.13.0**, with the same rules (the `Apply` signature still takes `Weasel.Postgresql.ICommandBuilder` in 9.13). `trace.yaml` holds source, field_load and a `sql_quote_escape` sanitizer, with no sink.
- `MartenRfx3FixtureTests` (prefix and postfix) returns early when the artifact isn't materialized (existing convention, `--no-symbols` when `.nopdb-marker` is present).

**Cold-scan lock.** `ScanMartenRfx3FixtureTests`:
- `--scan --scan-profile sqli` on 8.37.0: the trace contains a document whose source is `DictionaryContainsKeyFilter.Apply` with `api: sql_command_builder_append_raw`.
- The same scan on 9.13.0: no document whose source is `DictionaryContainsKeyFilter.Apply` carries a `sink:`.

The assertions cover only this method. The other raw-append documents (19 → 66 on 8.37) are known over-approximation and are recorded here, not locked.

## Success criteria

1. All existing fixtures are byte-identical, including the six SQLi anchors (`sqli-synthetic-prefix`, `sqli-interpolated-prefix`, `sqli-command-builder-prefix`, `marten-vmw2-prefix`, `sqli-regex-guard-prefix`, `marten-vmw2-postfix`). The one intended exception is the inverted unit test.
2. The full suite is green in serial mode (`-- xunit.parallelizeTestCollections=false`, per the known YamlDotNet parallel flake).
3. `diff -u fixtures/marten-rfx3-prefix/trace.yaml fixtures/marten-rfx3-postfix/trace.yaml` shows the `sql_command_builder_append_raw` sink replaced by a `sql_quote_escape` sanitizer hop.
4. The cold scan finds rfx3 on 8.37.0 and does not flag the method on 9.13.0.
5. The README vulnerability table gains a row: Marten `DictionaryContainsKeyFilter` SQL injection (GHSA-rfx3-98h7-v3xp), CWE-89. The sink list gains `sql_command_builder_append_raw`, and the sanitizer description mentions quote-escape recognition.

## Limitations (documented, not fixed)

- **Literal context is not verified.** Quote-doubling is only a valid escape inside a single-quoted literal. A quote-escaped value appended into an identifier, numeric, or `E'...'` (backslash-escape) position is still injectable, and Limes will call it clean. This is a known false negative.
- **Pattern is shape-specific.** Escaping done by a helper method, a registry API, or with literals routed through locals is not recognized. It will show up as a false positive.
- **More noise from the raw sink.** Under the sqli profile's "any string field is tainted" over-approximation, many benign `Apply(ICommandBuilder)` fragments that append developer-controlled strings now report. The distinct `_raw` api label keeps them triageable, and reducing them belongs to the interpolation-vs-parameter follow-up.
