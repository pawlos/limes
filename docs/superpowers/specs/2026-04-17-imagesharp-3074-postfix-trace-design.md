# Milestone B — Post-fix trace of ImageSharp #3074

**Status:** Implemented 2026-04-17. Schema extended (`establishes_bound`, `on_failure`, `Relations`, `FailureKinds`); FX013/FX014/FX023 added. Post-fix fixture committed under `fixtures/imagesharp-3074-postfix/`; pre-fix fixture renamed to `fixtures/imagesharp-3074-prefix/`. See revision history.
**Predecessor:** Milestone 1 (`2026-04-16-imagesharp-3074-trace-design.md`).
**Successor:** Milestone A — second-bug fixture from the user's disclosure list (#3067/#3071/#3078/#3079/#3082), TBD.

## Context

Milestone 1 produced the *pre-fix* trace of ImageSharp issue #3074: source (`BmpDecoderCore.Decode`), five propagator hops, sink (`new byte[colorMapSizeBytes]`), and a `sanitizer_absence` record citing exactly the check the fix added at post-fix lines 1551–1555. The fixture validator (`tools/ValidateFixture`, 17 xUnit tests) enforces the v0 schema.

M1 left four open schema questions (recorded in its `trace.md`):
- **O1** — no `taint_value_state` / `bounded_by` field; untested because no sanitizer exists pre-fix.
- **O2** — aggregate-to-scalar modelled via `field_load`; natural, but the two-hops-at-line-1551 split was slightly clunky.
- **O3** — `async_continuation` dispatch kind defined but unexercised (BMP is synchronous).
- **O4** — `Nullable<T>.Value` access: should it be its own transformation distinct from `field_load`?

This milestone closes **O1** by tracing the *post-fix* state of the same bug. Same decoder, same call graph, one additional hop: the `if (Offset > stream.Length) throw …` check now sits between the field-load and the arithmetic. The sanitizer's effect on the tainted value's known-state (it becomes `bounded_by stream.Length`) is recorded at the sanitizer node only — downstream hops do not carry inherited state (option (ii) in the brainstorm; the analyzer will eventually fold forward itself).

O2, O3, O4 remain deferred to milestone A, where a different bug will exercise them.

## Goals

1. Produce `fixtures/imagesharp-3074-postfix/` as the corollary fixture to M1: a machine-checkable `trace.yaml`, a narrative `trace.md`, and a SHA-pinned post-fix snippet.
2. Extend the v0 schema *additively* to v0.1 — new fields optional on non-sanitizer nodes — so M1's fixture validates without change.
3. Extend the validator with FX013/FX014/FX023 to enforce the new fields on sanitizer nodes.
4. Establish the "fixed program" test oracle: the post-fix trace is what the eventual analyzer should emit when run on fixed code.

## Non-goals

- No analyzer code.
- No tech-choice decision (Roslyn vs. Cecil vs. ILLink).
- No resolution of O2, O3, O4 — they are out of scope for this fixture.
- No refactor of the M1 validator tech-debt (unified `Require<T>`/`RequireField<T>`, unused `using YamlDotNet.Serialization.NamingConventions`, etc.) — still deferred.
- No modifications to the shared ImageSharp clone at `/mnt/c/work/dotnet-fuzzing/external/ImageSharp`.

## Directory restructure

Rename `fixtures/imagesharp-3074/` → `fixtures/imagesharp-3074-prefix/`. Create `fixtures/imagesharp-3074-postfix/` as its sibling. Each directory is a **self-contained fixture** with its own `trace.yaml`, `trace.md`, `snippets/` subdirectory, and `fix-files.txt`. `fix-files.txt` (one line: `src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs`) is duplicated rather than shared; at one line each, the duplication cost is trivial and the self-containment property is worth preserving.

The snippets subdirectory is named `snippets/` (not `prefix-snippets/` or `postfix-snippets/`) — the parent directory's name already tells you pre-or-post, and doubling it up is noise. So M1's `prefix-snippets/` is also renamed to `snippets/` as part of this commit.

The rename is a single `git mv` commit. It changes no file contents (all `file:` references in M1's `trace.yaml` point to the snippets directory, which is passed via `--snippets-dir` at validator invocation time — nothing in the YAML bakes in the parent directory name).

## Post-fix snippet extraction

Pin the post-fix content to the fix merge commit, not to HEAD:

```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp
git show 461c021608802370374afabd5d3c2720b3e46f04:src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs \
  > fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
```

Rationale: HEAD has drifted from the fix merge through unrelated PRs (#3082, #3084, etc.). Pinning to the merge commit locks the fixture to the exact content the fix introduced. Shallow-clone-safe — the tree and blob objects for `461c021…` are present in the local object store even though its parents are not.

Provenance sidecar (`<snippet>.meta.json`):

```json
{
  "source_path": "src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs",
  "recovered_against_sha": "461c021608802370374afabd5d3c2720b3e46f04",
  "recovery_method": "git-show-at-fix-merge",
  "sha256": "<computed at implementation time>"
}
```

## Schema v0.1 additions

Additive; v0 fixtures remain valid.

### New optional POCOs in `FixtureDocument.cs`

```csharp
public sealed class EstablishesBound
{
    [YamlMember(Alias = "target")]      public string? Target      { get; init; }
    [YamlMember(Alias = "relation")]    public string? Relation    { get; init; }
    [YamlMember(Alias = "upper_bound")] public string? UpperBound  { get; init; }
    [YamlMember(Alias = "lower_bound")] public string? LowerBound  { get; init; }  // reserved, not required in v0.1
}

public sealed class OnFailure
{
    [YamlMember(Alias = "kind")]      public string? Kind      { get; init; }
    [YamlMember(Alias = "exception")] public string? Exception { get; init; }  // populated when kind == "throw"
}
```

Extend `PathNode`:

```csharp
[YamlMember(Alias = "establishes_bound")] public EstablishesBound? EstablishesBound { get; init; }
[YamlMember(Alias = "on_failure")]        public OnFailure?        OnFailure        { get; init; }
```

### New closed vocabularies in `Vocabularies.cs`

```csharp
public static readonly FrozenSet<string> Relations = ... {
    "<", "<=", "==", "!=", ">=", ">",
};

public static readonly FrozenSet<string> FailureKinds = ... {
    "throw", "return_early", "clamp", "skip",
};
```

### New diagnostic codes in the validator

- **FX013** — `path[i].establishes_bound.relation` must be in `Relations`. Applies only when the field is present; no error if the whole `establishes_bound` object is absent (the node may not be a sanitizer).
- **FX014** — `path[i].on_failure.kind` must be in `FailureKinds`. Applies only when the field is present.
- **FX023** — sanitizer nodes (i.e., `path[i].role == "sanitizer"`) must have:
  - `establishes_bound.target` (non-empty string)
  - `establishes_bound.relation` (valid vocab)
  - `establishes_bound.upper_bound` (non-empty string)
  - `on_failure.kind` (valid vocab)
  - `on_failure.exception` required only when `on_failure.kind == "throw"`.

  Diagnostic message: `"sanitizer node path[i] missing required field: <field>"`.

### Validator-test plan

- FX013 test: path node with `role: sanitizer` and `establishes_bound.relation: "~~"` → expect FX013.
- FX014 test: path node with `role: sanitizer` and `on_failure.kind: "pray"` → expect FX014.
- FX023 tests (one per required field): sanitizer node missing `establishes_bound.upper_bound`, sanitizer node with `on_failure.kind == "throw"` but no `exception`, etc.
- Negative/regression: existing M1 `minimal_valid.yaml` (role `propagator` throughout) still validates clean with no FX013/FX014/FX023.

Total new tests: ~6–8. Existing 17 must stay green.

## Post-fix trace shape

Six path hops (M1 had five). Line numbers for hops 4 and 5 and the sink need verification at implementation time — the fix inserted 6 lines (5-line `if` block + 1 blank line) immediately before the arithmetic, so hops and sink shift down by 6 from their pre-fix positions.

| Hop | Method | Pre-fix line | Post-fix line (expected) | Role | Transformation | Notes |
|-----|--------|--------------|--------------------------|------|----------------|-------|
| 0 | `Decode` | 133 | 133 | propagator | identity | direct call to ReadImageHeaders |
| 1 | `ReadImageHeaders` | 1523 | 1523 | propagator | identity | direct call to ReadFileHeader |
| 2 | `ReadFileHeader` | 1480 | 1480 | propagator | read_stream | virtual (sealed) dispatch on BufferedReadStream.Read |
| 3 | `ReadImageHeaders` | 1551 | ~1551 | propagator | field_load | Nullable<T>.Value.Offset field load |
| **4** | **`ReadImageHeaders`** | **n/a** | **~1551–1555** | **sanitizer** | **identity** | **`if (Offset > stream.Length) throw …`; `establishes_bound: Offset <= stream.Length`; `on_failure: throw InvalidImageContentException`** |
| 5 | `ReadImageHeaders` | 1551 | ~1557 | propagator | arithmetic | `colorMapSizeBytes = Offset - BmpFileHeader.Size - infoHeader.HeaderSize` |
| Sink | `ReadImageHeaders` | 1600 | ~1606 | sink | (on node) | `new byte[colorMapSizeBytes]` |

Dispatch for the sanitizer hop: `direct` (the `throw BmpThrowHelper.ThrowInvalidImageContentException(...)` is a static method call). Classifiers for all other hops unchanged from M1.

`sanitizer_absence: []` — the sanitizer is present, so this array is empty (the v0 schema still requires the key to exist per FX008).

## Narrative (`trace.md`) outline

Mirrors M1's structure with the following deltas:

1. **Summary** — same bug, fix added; the check prevents the OOM.
2. **BMP header reference** — unchanged.
3. **Hop-by-hop walkthrough** — six subsections instead of five; hop 4 gets its own treatment explaining `establishes_bound` / `on_failure` as the O1 resolution.
4. **Sanitizer presence** (replaces M1's "Sanitizer absence") — side-by-side of the check with the sink, showing why the bounded `Offset` makes `colorMapSizeBytes` implicitly bounded (once the analyzer folds forward the inherited bound through the arithmetic).
5. **Open schema questions — resolution status** — O1 marked **Resolved**, with a cross-reference to the field shapes that closed it. O2/O3/O4 still open; note which will be exercised by milestone A.

## Done criteria

1. `fixtures/imagesharp-3074-prefix/trace.yaml` validates `OK` (no regression after rename).
2. `fixtures/imagesharp-3074-postfix/trace.yaml` validates `OK` (all FX-codes silent, new FX013/FX014/FX023 satisfied).
3. `dotnet test` — existing 17 tests plus 6–8 new tests, all green, 0 warnings on `--no-incremental` build.
4. Every `path[*].file:line` in both fixtures resolves against its respective snippets directory.
5. Post-fix `trace.md` readable end-to-end without prior knowledge of the bug.
6. One-line edit to pre-fix `trace.md` recording O1 as "resolved in milestone B"; equivalent text in post-fix `trace.md`.
7. Shared ImageSharp clone untouched.

## Open schema questions after milestone B

- **O1** — **Resolved** by `establishes_bound` + `on_failure` fields.
- **O2** — **Still open**; `field_load` followed by `arithmetic` on the same line remains clunky. Milestone A may or may not pressure-test it further.
- **O3** — **Still open**; no async decoder touched yet.
- **O4** — **Still open**; `Nullable<T>.Value` access still modelled as `field_load`. A future milestone may promote it to its own transformation kind.

## Execution plan outline

(Full plan authored in the writing-plans step.)

1. Rename M1 fixture directory and update any references.
2. Extend schema: add `EstablishesBound`, `OnFailure` POCOs; extend `PathNode`; add `Relations`, `FailureKinds` vocabs.
3. TDD: FX013 (invalid relation), FX014 (invalid failure kind), FX023 (sanitizer completeness — one test per required sub-field).
4. Extract post-fix snippet against fix merge commit; write `.meta.json`.
5. Author post-fix `trace.yaml`: hops 0–3 identical to pre-fix; new hop 4 (sanitizer) with `establishes_bound` and `on_failure`; hop 5 arithmetic at post-fix line; sink.
6. Validate. Iterate on line numbers if FX041 fires.
7. Write post-fix `trace.md`; add one-line O1-resolved note to pre-fix `trace.md`.
8. Final cross-check: both fixtures `OK`, all tests green, build clean.

## Revision history

- **2026-04-17** — Initial spec; approved pending post-write review.
- **2026-04-17** — Implemented. Schema evolved v0 → v0.1 (`establishes_bound`, `on_failure`, `Relations`, `FailureKinds`). FX013/FX014/FX023 added to validator. Post-fix fixture committed at commit `e05859b` (trace.yaml) / `d9c7e0b` (trace.md) / `e03cc4d` (snippet) / `4765b6c` (fix-files). Open question O1 closed in this milestone — annotated on the pre-fix trace.md in commit `e021581`. The post-fix fixture is the milestone-C analyzer's primary post-fix regression target (commit `648ba08`).
