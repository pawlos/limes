# Milestone-T3: Marten SQLi postfix lock via Regex.IsMatch sanitizer recognizer

**Date:** 2026-05-16
**Status:** Design approved; ready for implementation plan.
**Scope:** Lock Marten 8.37's fix of GHSA-vmw2-qwm8-x84c by adding a `Regex.IsMatch + throw` sanitizer recognizer and extending TraceEmitter to emit traces when sanitizer hops exist without a sink. Sources the constructor (parameter-bitmask seeding) since the guard is in `FullTextWhereFragment::.ctor`, not `Apply`.

## Problem

T2.1 (closed 2026-05-16) locked the prefix trace against Marten 8.36 — the analyzer detects `FullTextWhereFragment.Apply` flowing tainted `_regConfig` through `$"..."` interpolation into `ICommandBuilder::AppendWithParameters`. Sink: `sql_injection / sql_command_builder_append`.

T3 closes the parallel postfix lock against Marten 8.37, which adds a regex guard inside the `FullTextWhereFragment` constructor:

```csharp
private static readonly Regex _regConfigPattern = new(
    @"^[a-zA-Z_][a-zA-Z0-9_]{0,62}(\.[a-zA-Z_][a-zA-Z0-9_]{0,62})?$",
    RegexOptions.Compiled | RegexOptions.CultureInvariant);

private static void ValidateRegConfig(string regConfig)
{
    if (regConfig is null) throw new ArgumentNullException(nameof(regConfig));
    if (!_regConfigPattern.IsMatch(regConfig))
        throw new ArgumentException($"Invalid PostgreSQL text-search configuration name '{regConfig}'. …", nameof(regConfig));
}
```

`ValidateRegConfig(regConfig)` is called from the ctor before the `stfld _regConfig` assignment. Existing `SanitizerShapes` matchers recognize only numeric `compare → branch → throw` shapes (`Clt`/`Cgt`/`Ceq` etc.); a method call returning `bool` doesn't fit. Without a new recognizer, the analyzer would still report SQLi against 8.37, missing the fact that the fix is in place.

Two architectural gaps surface:

1. **No recognizer for method-call guards.** Need a new matcher `MatchRegexIsMatchAndThrow` that fires on `<load tainted>; call/callvirt Regex::IsMatch; brfalse/brtrue → throw` and produces a SanitizerMatch with `EstablishesBound.Relation = "regex_match"`.

2. **TraceEmitter discards sanitizer-only walks.** Currently emits empty string when no sink hop exists. The Marten 8.37 lock sources the ctor (where the regex guard lives); the ctor walk hits the sanitizer but never reaches a sink (the sink is in `Apply`, called later in a different method). Need to emit a trace when source + sanitizer exist without sink.

T3 closes both gaps with a targeted (non-refactoring) addition, mirroring T2.1's pragmatic shortcut style.

## Goals & non-goals

**In scope (T3 — two phases, one milestone):**

Phase 1 (sanitizer primitive + synthetic anchor):
- New `SanitizerShapes.MatchRegexIsMatchAndThrow(MethodDefinition)` returning `IEnumerable<SanitizerMatch>`.
- Best-effort pattern extraction from `static-readonly Regex` fields and from inline-`ldstr` static-call overloads.
- TraceEmitter change: emit when at least one Source hop AND at least one (Sink hop OR Sanitizer hop) exist.
- New synthetic anchor `fixtures/sqli-regex-guard-prefix/`: T2.1's `sqli-command-builder-prefix` shape PLUS an inline regex guard in `Apply` before the sink. Trace: source + sanitizer + sink, no `sanitizer_absence`.
- 6 unit tests for the recognizer + 2 emitter tests + 1 fixture-runner test.

Phase 2 (Marten 8.37 real-world lock):
- New `scripts/materialize-marten-8.37.sh` mirroring the 8.36 script.
- `fixtures/marten-vmw2-postfix/rules.yaml` sources `Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::.ctor(<ctor-signature>)` with parameter-bitmask seeding.
- `fixtures/marten-vmw2-postfix/trace.yaml` locked from a real analyzer run; trace contains source + sanitizer hop, no sink.
- 1 fixture-runner test with skip-if-missing pattern.

**Out of scope (deferred):**
- Other validator-method recognizers (Uri.IsWellFormedUriString, Char.IsLetterOrDigit, etc.) — extend when a real advisory requires them.
- Generic "any bool-method-call → brfalse/brtrue → throw" pattern — over-sanitizes; would need an allowlist that we don't have entries for yet.
- Cross-method sanitization propagation (ctor sanitizes a field → field reads in other methods are clean). Marten 8.37 sources the ctor directly so this isn't needed for the lock; future advisories may want it.
- Refactoring SanitizerShapes into a first-class `SanitizerKind` enum. The existing flat structure can carry one more matcher; refactor when the file grows or a 4th matcher arrives.
- ReturnEarly variant of the regex matcher (`if (!Regex.IsMatch(x)) return;`). Marten uses throw; ship the throw variant.
- SinkShapes / TaintWalker changes — T2.1's machinery covers the prefix; T3 is purely sanitizer-side.

**Out of scope indefinitely:**
- LINQ expression-tree analysis (still deferred from T2.1).
- Auto-enumeration of SQLi entry points via `--scan`.
- Other SQL sinks: Execute* family, Dapper, EF Core raw-SQL.

## Architecture

Six edits + four new files across two phases.

### Phase 1

| File | Change |
|---|---|
| `tools/TaintAnalyzer/SanitizerShapes.cs` | New `MatchRegexIsMatchAndThrow(method)` matcher + pattern-extraction helper `TryExtractRegexPattern`. Update `MatchAll` to concat new matcher's results. |
| `tools/TaintAnalyzer/TraceEmitter.cs` | Replace the no-sink early-return with "no sink AND no sanitizer". Guard sink/sanitizer_absence emission blocks with sink-count check. |
| `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` | 6 new unit tests for `MatchRegexIsMatchAndThrow`. |
| `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` (or co-located file if it exists) | 2 new emitter tests. |
| `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` | New `RegexGuardFixtures` class with method shapes the unit tests load via Cecil (instance Regex field, static IsMatch overload, brtrue-direction variant, no-throw variant, dynamic-pattern variant, non-Regex-bool-call variant). |
| (new) `fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.cs` + `.csproj` | Synthetic source with locally-declared `Weasel.Postgresql.ICommandBuilder`, a `_regConfig` field, an inline `_pattern.IsMatch` guard in `Apply`, and a sink-reaching `AppendWithParameters` call. |
| (new) `fixtures/sqli-regex-guard-prefix/rules.yaml` | Sources `Apply` with `seed_this_fields: [_regConfig]`. |
| (new) `fixtures/sqli-regex-guard-prefix/trace.yaml` | Locked trace: source + sanitizer + sink. |
| (new) `scripts/build-sqli-regex-guard.sh` | Build script. |
| (new) `tools/TaintAnalyzer.Tests/SqliRegexGuardFixtureTests.cs` | Fixture-runner test. |

### Phase 2

| File | Change |
|---|---|
| (new) `scripts/materialize-marten-8.37.sh` | Mirrors 8.36 materializer; pulls Marten 8.37.0 from NuGet into `artifacts/marten-8.37/`. |
| (new) `fixtures/marten-vmw2-postfix/rules.yaml` | Sources `FullTextWhereFragment::.ctor(<exact-signature>)` with no explicit seeding (default `(1 << paramCount) - 1` bitmask taints every string parameter). |
| (new) `fixtures/marten-vmw2-postfix/trace.yaml` | Locked trace from real Marten 8.37 run. |
| (new) `tools/TaintAnalyzer.Tests/MartenVmw2PostfixFixtureTests.cs` | Fixture-runner test with skip-if-missing. |

No changes to `SinkShapes`, `TaintWalker`, `EntryPointEnumerator`, `RulesDocument`, `ReverseCallGraph`, or CLI flags.

## Sanitizer matcher contract

`SanitizerShapes.MatchRegexIsMatchAndThrow(MethodDefinition)` returns `IEnumerable<SanitizerMatch>`. The walk iterates `method.Body.Instructions` looking for conditional-branch opcodes (`Brfalse`, `Brtrue`, `Brfalse_S`, `Brtrue_S`). For each:

1. The previous non-nop instruction must be `Call` or `Callvirt` with operand a `MethodReference` whose `DeclaringType.FullName == "System.Text.RegularExpressions.Regex"` and `Name == "IsMatch"`. Both overloads accepted:
   - Instance: `bool IsMatch(string input)` — `HasThis == true`, 1 parameter.
   - Static: `bool IsMatch(string input, string pattern)` — `HasThis == false`, 2 parameters.
2. The conditional branch's source (the call-result on the stack) must come directly from the IsMatch call. Use net stack-balance walk-back (reuse the `ComputeStackPushes/Pops` helper from T2.1's `SinkShapes` — extract to a shared helper file if cleaner; otherwise duplicate locally — implementer's call at writing time).
3. Determine the tainted-arg index:
   - Instance form: `argSlots[0]` (the only param is the input string).
   - Static form: `argSlots[0]` (input is first, pattern is second).
4. Use existing `DetectBranchSides(conditionalBranch, method)` to determine throw direction. Existing `ClassifyArm` confirms the unsafe arm reaches a throw (or throw-helper call).
5. Extract the pattern via `TryExtractRegexPattern(call, method)`:
   - Static form: walk back from the call across its arg-pushers; if arg1 was pushed by `ldstr "..."`, use that string literal.
   - Instance form: the receiver was pushed by `ldsfld <field>` (static-readonly Regex). Resolve the FieldReference (try/catch AssemblyResolutionException → null fallback). Walk the declaring type's `.cctor` looking for `<patternPushers>; newobj Regex::.ctor(...); stsfld <thatField>`. The patternPushers immediately before `newobj` end with `ldstr "..."` for the first arg.
   - Instance form with `ldfld <field>` (non-static): walk all instance ctors of the declaring type for matching `<patternPushers>; newobj Regex::.ctor(...); stfld <thatField>` chains. Take the first.
   - Any failure → return `null`. Match still fires.
6. Emit `SanitizerMatch`:
   ```csharp
   new SanitizerMatch
   {
       EstablishesBound = new EstablishesBound
       {
           Target = <tainted-arg-name-via-existing-OperandName-helper>,
           Relation = "regex_match",
           UpperBound = <extracted-pattern-or-null>,
           LowerBound = null,
           VacuousUpperBound = false,
       },
       OnFailure = new OnFailure
       {
           Kind = FailureKind.Throw,
           Exception = <throw-helper-resolved-exception-type-or-null>,
       },
       ComparisonIlOffset = callInstruction.Offset,
   }
   ```

Match is **NOT** emitted when:
- Unsafe arm doesn't reach a throw (handled by `ClassifyArm` returning failure).
- IsMatch's declaring type is unresolvable (we still match: namespace + name comparison work on `TypeReference` without resolving — Regex is in `System.Text.RegularExpressions` so this is always reliable).
- The conditional branch is preceded by something other than a Regex::IsMatch call.

**Why `Relation = "regex_match"` carries the pattern in `UpperBound`:** the existing schema's `UpperBound` is a free-form string. Reusing it (with the `Relation` discriminant signaling "this isn't a numeric upper bound") avoids a schema or emitter change. A consumer that cares can branch on `relation == "regex_match"` and read `upper_bound` as the pattern string.

**Concurrency note:** the matcher is read-only on method.Body; safe to call once per method. `MatchAll` already runs in the walker's per-method preamble and is not on the hot path.

## TraceEmitter change

**Current behavior (TraceEmitter.cs:43-48):**

```csharp
if (rawSinkIndices.Count == 0)
{
    return "";
}
```

**New behavior:**

```csharp
int rawSanitizerCount = hops.Count(h => h.Role == HopRole.Sanitizer);
if (rawSinkIndices.Count == 0 && rawSanitizerCount == 0)
{
    return "";
}
```

Then below in the per-source emit loop, guard the `sink:` block and `sanitizer_absence:` block with sink-count checks. The path/sanitizer hops emit unchanged. The `source:` block emits unchanged.

The resulting Marten-postfix trace shape:

```yaml
vuln_id: marten-vmw2-postfix
fix_commit: …
fix_pr: https://github.com/JasperFx/marten/pull/4343
description: |
  …
source:
  method: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment..ctor
  …
path:
  - hop: 0
    method: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment..ctor
    role: sanitizer
    tainted_value_in: regConfig
    transformation: identity
    tainted_value_out: regConfig
    establishes_bound:
      target: regConfig
      relation: regex_match
      upper_bound: '^[a-zA-Z_][a-zA-Z0-9_]{0,62}(\.[a-zA-Z_][a-zA-Z0-9_]{0,62})?$'
    on_failure:
      kind: throw
      exception: System.ArgumentException
sanitizer_absence: []
```

(No `sink:` block.) The Phase 1 synthetic anchor produces the standard `source + path(sanitizer) + sink + sanitizer_absence: []` shape because Apply DOES reach a sink after the guard.

**Schema check:** `tools/ValidateFixture/FixtureDocument.cs:11-12` already declares `PathNode? Sink` (nullable). Trace without `sink:` is schema-valid; no ValidateFixture change needed.

## Phase 1 synthetic fixture

`fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.cs`:

```csharp
namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void AppendWithParameters(string sql);
    }
}

namespace RegexGuardSqliPoc
{
    public sealed class GuardedSearchFragment
    {
        private static readonly System.Text.RegularExpressions.Regex _pattern =
            new(@"^[a-zA-Z_][a-zA-Z0-9_]*$",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        private readonly string _regConfig;
        public GuardedSearchFragment(string regConfig) => _regConfig = regConfig;

        private string Sql => $"a{_regConfig}b{_regConfig}c";

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            if (!_pattern.IsMatch(_regConfig))
                throw new System.ArgumentException("invalid regConfig", nameof(_regConfig));
            builder.AppendWithParameters(this.Sql);
        }
    }
}
```

`fixtures/sqli-regex-guard-prefix/rules.yaml`:

```yaml
vuln_id: sqli-regex-guard-prefix
source_methods:
  - signature: RegexGuardSqliPoc.GuardedSearchFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _regConfig
```

`fixtures/sqli-regex-guard-prefix/trace.yaml`: locked from analyzer run. Expected:
- Source: GuardedSearchFragment.Apply (seeded `_regConfig`).
- Path: sanitizer hop (`relation: regex_match`, `upper_bound: '^[a-zA-Z_][a-zA-Z0-9_]*$'`, `on_failure.kind: throw`, `exception: System.ArgumentException`).
- Path: propagator hops for the get_Sql call and field_load (mirroring T2.1's `sqli-command-builder-prefix`).
- Sink: `sql_injection / sql_command_builder_append`.
- `sanitizer_absence: []` (the matcher's throw-shape suppresses absence emission via the existing `appliedThrowShapeSanitiser` mechanism).

## Phase 2 Marten 8.37 lock

`scripts/materialize-marten-8.37.sh` (mirror of 8.36 script):

```bash
#!/usr/bin/env bash
set -euo pipefail
# Materialize Marten 8.37.0 from NuGet into artifacts/marten-8.37/.
# … (same shape as scripts/materialize-marten-8.36.sh, swap version) …
```

`fixtures/marten-vmw2-postfix/rules.yaml`:

```yaml
vuln_id: marten-vmw2-postfix
source_methods:
  - signature: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::.ctor(<TBD-by-IL-inspection>)
```

The ctor signature must be confirmed against Marten 8.37 IL. The fix PR adds `ValidateRegConfig(regConfig)` as a private helper called from the ctor; the call site itself is the matcher target. If the helper is inlined into the ctor at the JIT level it doesn't matter (Cecil reads pre-JIT IL); if the helper is a separate `private static` method, the matcher fires inside that helper, and the walker's cross-method walk surfaces the sanitizer hop in the trace.

**Known unknowns at design time:**

1. **Exact ctor signature.** Marten 8.37 may have added/changed ctor parameters; the rules.yaml signature needs IL inspection to confirm. The implementer must verify via Cecil during plan execution.
2. **Helper vs inlined guard.** If `ValidateRegConfig` is a separate method, the walker's cross-method walk into it must propagate the tainted regConfig as an argument. This should "just work" — the existing call-graph walk seeds the callee's bitmask from tainted argSlots, and the matcher fires inside the callee method. But verify at lock time.
3. **Multiple guards.** The PR also adds `ArgumentNullException.ThrowIfNull(regConfig)`. That's a separate matcher concern (null-check throw-shape) and is OUT OF SCOPE for T3 — we don't recognize it. Only the IsMatch guard needs to be detected; the null-check is upstream and doesn't affect the regex-match sanitizer hop. If `ThrowIfNull` makes the walker think `regConfig` is sanitized somehow, that's a triage finding; document and proceed.

**Trace lock expectations:**

```yaml
vuln_id: marten-vmw2-postfix
fix_commit: <Marten 8.37 release commit SHA>
fix_pr: https://github.com/JasperFx/marten/pull/4343
description: >
  Real-world advisory fix lock for GHSA-vmw2-qwm8-x84c. Marten 8.37 adds a
  Regex.IsMatch guard in FullTextWhereFragment's constructor that rejects
  regConfig values not matching the PostgreSQL identifier pattern. Source is
  FullTextWhereFragment::.ctor with parameter-bitmask seeding. T3's
  MatchRegexIsMatchAndThrow recognizer fires inside the ctor (or its inlined
  helper); trace contains source + sanitizer hop, no sink — the standard
  TraceEmitter "patched" shape. Compare against fixtures/marten-vmw2-prefix
  (T2.1 lock against 8.36) to see Limes distinguishing vulnerable from
  patched on the same advisory.
source:
  method: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment..ctor
  …
path:
  - hop: 0
    role: sanitizer
    tainted_value_in: regConfig
    establishes_bound:
      target: regConfig
      relation: regex_match
      upper_bound: '^[a-zA-Z_][a-zA-Z0-9_]{0,62}(\.[a-zA-Z_][a-zA-Z0-9_]{0,62})?$'
    on_failure:
      kind: throw
      exception: System.ArgumentException
sanitizer_absence: []
```

**Phase 2 triage protocol** (if first lock attempt fails):

1. If the recognizer doesn't fire on Marten IL: IL-inspect to confirm `Regex.IsMatch` is actually called (vs a generated wrapper, an inlined comparison, or a switch table). Walker may need a narrow shape adjustment (< 30 LOC).
2. If pattern extraction returns null against Marten's static field: this is acceptable (sanitizer hop still emits). Document in trace description.
3. If `ThrowIfNull(regConfig)` surfaces as an unintended sanitizer: it shouldn't — the existing null-check recognition lives in `MatchCompareAndThrow` and requires a `ldnull; ceq` shape that `ThrowIfNull` may not emit. Triage if needed.
4. If `ValidateRegConfig` is a separate method and the cross-method walk doesn't surface the inner sanitizer: walker quirk; small fix likely. Escalate if > 80 LOC.

## TraceEmitter wiring

Single change point: TraceEmitter.cs:43-48 + the per-source emit body's guards. No new fields on FixtureDocument. No new schema entries.

## Testing

**Phase 1 unit tests** (in `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`):

1. `MatchRegexIsMatchAndThrow_InstanceRegexOnStaticField_Matches` — fixture: method calling `_pattern.IsMatch(arg)` with `brfalse → throw`. Asserts EstablishesBound shape and OnFailure shape.
2. `MatchRegexIsMatchAndThrow_StaticOverload_Matches` — fixture: `Regex.IsMatch(arg, "pattern")` (static). Pattern extracted from inline `ldstr`.
3. `MatchRegexIsMatchAndThrow_BranchInverted_Matches` — `brtrue → throw`. Throw-side classification independent of branch direction.
4. `MatchRegexIsMatchAndThrow_NoThrowOnUnsafePath_ReturnsEmpty` — `if (!IsMatch) return;` shape. Recognizer must not fire (ReturnEarly variant out of scope).
5. `MatchRegexIsMatchAndThrow_PatternUnresolvable_ReturnsMatchWithNullPattern` — dynamically-constructed Regex. Match fires with `UpperBound = null`.
6. `MatchRegexIsMatchAndThrow_NonRegexBoolCall_ReturnsEmpty` — `if (!s.StartsWith("x")) throw`. Recognizer must require `DeclaringType == System.Text.RegularExpressions.Regex`.

**Phase 1 emitter tests** (new file `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` if none exists; otherwise append):

7. `Emit_SourceAndSanitizerNoSink_EmitsTrace` — hops list: 1 source + 1 sanitizer. Output non-empty; contains `role: sanitizer` and `source:`; does NOT contain `sink:`.
8. `Emit_SourceOnly_EmitsEmpty` — hops list: 1 source only. Output empty.

New fixtures in `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:
- `RegexGuardFixtures` with methods matching each unit-test shape (instance, static, brtrue, no-throw, dynamic, non-Regex). The fixture methods don't need to be reachable from the assembly entry point — they exist solely as Cecil-loadable IL templates.

**Phase 1 fixture-runner test** (new file `tools/TaintAnalyzer.Tests/SqliRegexGuardFixtureTests.cs`):

9. `SqliRegexGuardPrefix_TraceContainsSanitizerAndSink` — runs analyzer over the synthetic artifact. Asserts trace contains `relation: regex_match`, contains `api: sql_command_builder_append`, contains `kind: sql_injection`, AND does NOT contain a non-empty `sanitizer_absence:` (the regex sanitizer suppresses absence emission).

**Phase 2 Marten fixture-runner test** (new file `tools/TaintAnalyzer.Tests/MartenVmw2PostfixFixtureTests.cs`):

10. `MartenVmw2Postfix_TraceContainsSanitizerNoSink` — skip-if `artifacts/marten-8.37/Marten.dll` missing. Asserts trace contains `relation: regex_match`, contains a portion of the expected pattern (`[a-zA-Z_]`), does NOT contain `kind: sql_injection`, does NOT contain `sink:`, AND does NOT contain a non-empty `sanitizer_absence:`.

**Anchor regression discipline:**

11. All prior anchors stay green:
   - All from `analyzer_gap_backlog.md`.
   - T1's `sqli-synthetic-prefix`.
   - T2 Phase 1's `sqli-interpolated-prefix`.
   - T2.1 Phase 1's `sqli-command-builder-prefix`.
   - T2.1 Phase 2's `marten-vmw2-prefix`.
   The new recognizer fires only on `Regex::IsMatch` IL — not present in any prior anchor's IL. The new emitter behavior only changes outputs when source + sanitizer exist without sink, which no prior fixture exercises.

**Test count after T3:**
- Phase 1: 289 → 298 TaintAnalyzer.Tests (+6 unit + 2 emitter + 1 fixture-runner = +9).
- Phase 2: 298 → 299 TaintAnalyzer.Tests (+1 Marten fixture-runner).
- ValidateFixture.Tests: 63 (unchanged).
- **Total: ~362.**

## Anchor set after T3

What NOT to break (priority order):
1. All anchors in `analyzer_gap_backlog.md`.
2. `fixtures/sqli-synthetic-prefix/` (T1).
3. `fixtures/sqli-interpolated-prefix/` (T2 Phase 1).
4. `fixtures/sqli-command-builder-prefix/` (T2.1 Phase 1).
5. `fixtures/marten-vmw2-prefix/` (T2.1 Phase 2).
6. (Phase 1) `fixtures/sqli-regex-guard-prefix/`.
7. (Phase 2) `fixtures/marten-vmw2-postfix/`.

## Open questions resolved at implementation time

- Exact ctor signature of `FullTextWhereFragment` in Marten 8.37 (parameter list may have changed between 8.36 and 8.37). Confirm via Cecil IL inspection.
- Whether the regex guard is inlined into the ctor body or kept as `private static ValidateRegConfig` helper. Either way the recognizer should fire; if the helper case requires a walker quirk fix, document and patch.
- Whether `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` exists already or needs to be created (no `grep` hit at design time suggests it doesn't, but verify at plan-execution start).
- Whether to extract the `ComputeStackPushes/Pops` helper from `SinkShapes` into a shared internal class. Implementer's call — duplicate locally if it stays under ~20 LOC.

## Why this approach

- **Targeted matcher, not a refactor.** The existing `SanitizerShapes` has three matchers (`MatchCompareAndThrow`, `MatchCompareAndReturnEarly`, `MatchValueClamps`); adding a fourth is mechanical. Refactoring into a SanitizerKind enum is a separate (and currently unjustified) project.
- **Sources the ctor, not Apply.** Mirrors T2.1's pragmatic shortcut style (don't model what the analyzer can't model — here, cross-method ctor-to-Apply propagation of sanitized fields). The fix is in the ctor; we walk the ctor.
- **Sanitizer-only trace.** Empty trace as "patched" signal is too fragile (could mean failed walk). A trace that explicitly shows the sanitizer hop is machine-checkable and human-readable.
- **No `result:` marker.** The presence/absence of a `sink:` block is already a clear discriminant. Adding a top-level marker is overkill for a binary signal.
- **Two anchors.** Phase 1 synthetic tests the recognizer in the full source+sanitizer+sink shape (existing semantics). Phase 2 Marten tests the recognizer + new emitter behavior together. Without both, regressions in one direction would be invisible.

## Anti-goals

- Don't introduce a new top-level `result:` field on the trace YAML.
- Don't change the schema's required fields.
- Don't refactor `SanitizerShapes` into a kind-enum architecture.
- Don't add cross-method sanitization propagation (this-field-sanitized-in-ctor flowing to other methods).
- Don't expand the recognizer beyond `Regex::IsMatch` (no Uri.IsWellFormedUriString, no Char.IsLetterOrDigit) without a real advisory needing it.
