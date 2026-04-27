# ImageSharp #3079 Pre/Post Trace — Implementation Plan

**Status:** Implemented 2026-04-18. See revision history at end.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce pre-fix and post-fix ground-truth traces of ImageSharp #3079 (PNG `ReadInternationalTextChunk` insufficient-data reads), extend the validator to v0.2 (closed `SinkKinds` / `SinkApis` vocabs, FX015/FX024 diagnostics, refined FX023 accepting lower bounds), and keep v0.1 fixtures valid without modification.

**Architecture:** Additive schema evolution (v0.1 → v0.2). Two new closed vocabularies + one new optional `PathNode` property (`AccessExpression`). Two new diagnostics (FX015, FX024) plus an FX023 refinement that accepts either `UpperBound` or `LowerBound`. Fixture pair at `fixtures/imagesharp-3079-{prefix,postfix}/` pinned to `89face0b8` (fix merge) and `89face0b8^1` (main-parent pre-fix). Post-fix trace has six-ish propagator hops plus TWO sanitizer hops (one `<=` with upper bound, one `>=` with lower bound, both `on_failure: return_early`) leading to a `sink.kind: span_access`, `sink.api: span_slice` sink.

**Tech Stack:** .NET 10, YamlDotNet 15.1.6, xUnit, Shouldly. No new dependencies.

**Spec reference:** `docs/superpowers/specs/2026-04-17-imagesharp-3079-trace-design.md` (commit `2a24515`).

---

## File Structure

**Validator (Tasks 1–5):**
- Modify: `tools/ValidateFixture/FixtureDocument.cs` — add `AccessExpression` property on `PathNode`.
- Modify: `tools/ValidateFixture/Vocabularies.cs` — add `SinkKinds` and `SinkApis` frozen sets.
- Modify: `tools/ValidateFixture/FixtureValidator.cs` — add FX015 + FX024 checks on top-level sink; refine FX023 to accept `UpperBound` OR `LowerBound`.
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` — add tests; migrate one row of the existing FX023 theory.

**Pre-fix fixture (Tasks 6–8, 10):**
- Create: `fixtures/imagesharp-3079-prefix/fix-files.txt`
- Create: `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`
- Create: `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`
- Create: `fixtures/imagesharp-3079-prefix/trace.yaml`
- Create: `fixtures/imagesharp-3079-prefix/trace.md`

**Post-fix fixture (Tasks 6, 8, 7, 9):**
- Create: `fixtures/imagesharp-3079-postfix/fix-files.txt`
- Create: `fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`
- Create: `fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`
- Create: `fixtures/imagesharp-3079-postfix/trace.yaml`
- Create: `fixtures/imagesharp-3079-postfix/trace.md`

**Existing-fixture annotations (Task 11):**
- Modify: `fixtures/imagesharp-3074-prefix/trace.md` — add O5 cross-reference.
- Modify: `fixtures/imagesharp-3074-postfix/trace.md` — add O5 cross-reference.

---

## Task 1: Schema — `AccessExpression` on `PathNode`

Add a single new property. Structural change; no new tests (the new property is used in later fixture work).

**Files:**
- Modify: `tools/ValidateFixture/FixtureDocument.cs`

- [ ] **Step 1.1: Add the property**

Open `tools/ValidateFixture/FixtureDocument.cs`. In the `PathNode` class, in the block of fields marked "Fields used only on the top-level `source` / `sink` shapes.", add `AccessExpression` next to `SizeExpression`:

```csharp
    [YamlMember(Alias = "access_expression")] public string? AccessExpression { get; init; }
```

- [ ] **Step 1.2: Build**

Run: `dotnet build`
Expected: 0 errors, 0 warnings.

- [ ] **Step 1.3: Tests still green**

Run: `dotnet test`
Expected: 25 passing, 0 failing.

- [ ] **Step 1.4: Commit**

```bash
git add tools/ValidateFixture/FixtureDocument.cs
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "validator: add AccessExpression property on PathNode (schema v0.2)"
```

---

## Task 2: Vocabularies — `SinkKinds`, `SinkApis`

**Files:**
- Modify: `tools/ValidateFixture/Vocabularies.cs`

- [ ] **Step 2.1: Extend Vocabularies.cs**

After the existing `FailureKinds` field, add:

```csharp
    public static readonly FrozenSet<string> SinkKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "allocation", "span_access",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
    }.ToFrozenSet(StringComparer.Ordinal);
```

- [ ] **Step 2.2: Build**

Run: `dotnet build`
Expected: 0 errors, 0 warnings.

- [ ] **Step 2.3: Tests still green**

Run: `dotnet test`
Expected: 25 passing.

- [ ] **Step 2.4: Commit**

```bash
git add tools/ValidateFixture/Vocabularies.cs
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "validator: add SinkKinds and SinkApis vocabularies (schema v0.2)"
```

---

## Task 3: FX015 — closed-vocab `sink.kind` / `sink.api`

TDD for vocabulary enforcement on the top-level `sink` object.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 3.1: Write failing tests**

Append to `FixtureValidatorTests.cs`:

```csharp
    [Fact]
    public void Sink_InvalidKind_ReportsFX015()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: banana, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX015" && d.Message.Contains("sink.kind") && d.Message.Contains("banana"));
    }

    [Fact]
    public void Sink_InvalidApi_ReportsFX015()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: teleport, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX015" && d.Message.Contains("sink.api") && d.Message.Contains("teleport"));
    }
```

- [ ] **Step 3.2: Run — expect 2 failing**

Run: `dotnet test`
Expected: 2 failures, 25 still passing.

- [ ] **Step 3.3: Add FX015 checks in the validator**

Open `tools/ValidateFixture/FixtureValidator.cs`. In `Validate`, find the top-level Require calls (`Require(doc.VulnId, ...)` etc.) around the `Require(doc.Sink, "FX006", "sink", diagnostics)` call. After ALL the `Require(...)` calls for the top-level fields, before the path-iteration loop, add:

```csharp
        if (doc.Sink is { } sinkForVocab)
        {
            CheckVocab(sinkForVocab.Kind, Vocabularies.SinkKinds, "FX015", "sink.kind", diagnostics);
            CheckVocab(sinkForVocab.Api,  Vocabularies.SinkApis,  "FX015", "sink.api",  diagnostics);
        }
```

`CheckVocab` already exists as a static local function inside `Validate` (from milestone 1 work). Reuse it.

- [ ] **Step 3.4: Run — green**

Run: `dotnet test`
Expected: 27 passing, 0 failing.

- [ ] **Step 3.5: Commit**

```bash
git add tools/
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "validator: FX015 — sink.kind and sink.api must be in their vocabs"
```

---

## Task 4: FX024 — sink kind/api/expression coupling

The sink's `kind` determines which `api` values are valid AND which expression field is required. Allocation sinks need `size_expression`; span-access sinks need `access_expression`.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 4.1: Write failing tests**

Append to `FixtureValidatorTests.cs`:

```csharp
    [Fact]
    public void Sink_AllocationWithoutSizeExpression_ReportsFX024()
    {
        // Omit size_expression from an allocation sink.
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX024" && d.Message.Contains("size_expression"));
    }

    [Fact]
    public void Sink_AllocationWithSpanApi_ReportsFX024()
    {
        // kind=allocation but api=span_index is a mismatch.
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: span_index, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX024" && d.Message.Contains("allocation") && d.Message.Contains("span_index"));
    }

    [Fact]
    public void Sink_SpanAccessWithoutAccessExpression_ReportsFX024()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: span_access, api: span_slice, file: f, line: 2, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX024" && d.Message.Contains("access_expression"));
    }

    [Fact]
    public void Sink_SpanAccessWithAllocationApi_ReportsFX024()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: span_access, api: new_array, file: f, line: 2, access_expression: "data[i]", method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX024" && d.Message.Contains("span_access") && d.Message.Contains("new_array"));
    }

    [Fact]
    public void Sink_ValidAllocation_NoFX024()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: "n", method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldNotContain(d => d.Code == "FX024");
    }

    [Fact]
    public void Sink_ValidSpanAccess_NoFX024()
    {
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: span_access, api: span_slice, file: f, line: 2, access_expression: "data.Slice(a, b)", method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path: []
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldNotContain(d => d.Code == "FX024");
    }
```

- [ ] **Step 4.2: Run — expect 4 failing**

Run: `dotnet test`
Expected: 4 new failing (the 4 `Should Contain FX024` tests), 2 trivially passing (the `ShouldNotContain` pair), plus the existing 27 still passing. Total 29 tests, 4 failing.

- [ ] **Step 4.3: Add FX024 block in the validator**

In `FixtureValidator.cs`, immediately after the FX015 block from Task 3, append:

```csharp
        if (doc.Sink is { } sinkForCoupling && sinkForCoupling.Kind is { } sinkKind
            && Vocabularies.SinkKinds.Contains(sinkKind))
        {
            // Only run FX024 when kind is in the closed vocab — otherwise FX015 already reports.
            if (string.Equals(sinkKind, "allocation", StringComparison.Ordinal))
            {
                if (sinkForCoupling.Api is { } api && Vocabularies.SinkApis.Contains(api))
                {
                    if (api is not ("new_array" or "array_pool_rent" or "alloc_hglobal" or "memory_pool_rent" or "stackalloc"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'allocation' is not compatible with sink.api '{api}' (expected one of new_array, array_pool_rent, alloc_hglobal, memory_pool_rent, stackalloc)"));
                    }
                }
                if (string.IsNullOrWhiteSpace(sinkForCoupling.SizeExpression))
                {
                    diagnostics.Add(new Diagnostic("FX024",
                        "sink.kind 'allocation' requires sink.size_expression to be populated"));
                }
            }
            else if (string.Equals(sinkKind, "span_access", StringComparison.Ordinal))
            {
                if (sinkForCoupling.Api is { } api && Vocabularies.SinkApis.Contains(api))
                {
                    if (api is not ("span_index" or "span_slice"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'span_access' is not compatible with sink.api '{api}' (expected span_index or span_slice)"));
                    }
                }
                if (string.IsNullOrWhiteSpace(sinkForCoupling.AccessExpression))
                {
                    diagnostics.Add(new Diagnostic("FX024",
                        "sink.kind 'span_access' requires sink.access_expression to be populated"));
                }
            }
        }
```

The outer guard `Vocabularies.SinkKinds.Contains(sinkKind)` prevents double-reporting alongside FX015.

- [ ] **Step 4.4: Run — green**

Run: `dotnet test`
Expected: 33 passing, 0 failing.

- [ ] **Step 4.5: Commit**

```bash
git add tools/
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "validator: FX024 — sink kind/api/expression coupling for allocation and span_access"
```

---

## Task 5: FX023 refinement — accept `UpperBound` OR `LowerBound`

The current FX023 theory asserts "missing upper_bound alone produces FX023". Under v0.2, a sanitizer may instead set `lower_bound` (for `>=`/`>` relations). Relax the validator; update the test surface.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 5.1: Update the existing FX023 theory**

In `FixtureValidatorTests.cs`, find the `SanitizerNode_MissingRequiredField_ReportsFX023` theory (from milestone B). It currently has four `[InlineData]` rows including `[InlineData("upper_bound", "establishes_bound.upper_bound")]`. REMOVE that row. The remaining three rows (`target`, `relation`, `kind`) stay unchanged.

- [ ] **Step 5.2: Add a new "missing both bounds" test**

Append to `FixtureValidatorTests.cs`:

```csharp
    [Fact]
    public void SanitizerNode_MissingBothBounds_ReportsFX023()
    {
        // upper_bound AND lower_bound both absent — FX023.
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path:
              - hop: 0
                method: M
                file: f
                line: 1
                role: sanitizer
                tainted_value_in: x
                transformation: identity
                tainted_value_out: x
                dispatch: { kind: direct }
                establishes_bound: { target: x, relation: "<=" }
                on_failure: { kind: throw, exception: E }
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX023" && d.Message.Contains("establishes_bound") && (d.Message.Contains("upper_bound") || d.Message.Contains("lower_bound")));
    }

    [Fact]
    public void SanitizerNode_LowerBoundOnly_NoFX023()
    {
        // Sanitizer with only lower_bound set — FX023 must NOT fire.
        var yaml = """
            vuln_id: t
            fix_commit: 0
            fix_pr: u
            description: d
            source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
            sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
            path:
              - hop: 0
                method: M
                file: f
                line: 1
                role: sanitizer
                tainted_value_in: x
                transformation: identity
                tainted_value_out: x
                dispatch: { kind: direct }
                establishes_bound: { target: x, relation: ">=", lower_bound: "0" }
                on_failure: { kind: return_early }
            sanitizer_absence: []
            """;
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
        diagnostics.ShouldNotContain(d => d.Code == "FX023");
    }
```

- [ ] **Step 5.3: Run — expect 2 new failing**

Run: `dotnet test`
Expected: 2 new failing. One row removed from the theory (3 rows remain, all passing). Two new facts:
  - `MissingBothBounds` — fails because the existing validator requires `UpperBound` specifically; with both missing, the existing FX023 fires with a message about `upper_bound` but the test accepts either wording, so this may actually pass. If it passes, great — the assertion is loose enough. If it fails because of a message-text mismatch, the test's substring assertion catches it.
  - `LowerBoundOnly` — fails because the existing validator requires `UpperBound`; with `LowerBound` set but `UpperBound` not set, FX023 fires — but this test asserts FX023 must NOT fire. So this fails.

Depending on existing message wording, expect 1 or 2 new failures.

- [ ] **Step 5.4: Refine the FX023 block in the validator**

In `FixtureValidator.cs`, find the existing FX023 block inside the path-iteration loop (from milestone B). It currently contains:

```csharp
                    else
                    {
                        RequireField(node.EstablishesBound.Target,     "FX023", $"path[{i}].establishes_bound.target",      diagnostics);
                        RequireField(node.EstablishesBound.Relation,   "FX023", $"path[{i}].establishes_bound.relation",    diagnostics);
                        RequireField(node.EstablishesBound.UpperBound, "FX023", $"path[{i}].establishes_bound.upper_bound", diagnostics);
                    }
```

Replace with:

```csharp
                    else
                    {
                        RequireField(node.EstablishesBound.Target,   "FX023", $"path[{i}].establishes_bound.target",   diagnostics);
                        RequireField(node.EstablishesBound.Relation, "FX023", $"path[{i}].establishes_bound.relation", diagnostics);
                        bool hasUpper = !string.IsNullOrWhiteSpace(node.EstablishesBound.UpperBound);
                        bool hasLower = !string.IsNullOrWhiteSpace(node.EstablishesBound.LowerBound);
                        if (!hasUpper && !hasLower)
                        {
                            diagnostics.Add(new Diagnostic("FX023",
                                $"sanitizer node path[{i}].establishes_bound requires at least one of upper_bound or lower_bound"));
                        }
                    }
```

- [ ] **Step 5.5: Run — green**

Run: `dotnet test`
Expected: 35 passing, 0 failing (33 after Task 4 + 2 new).

- [ ] **Step 5.6: Commit**

```bash
git add tools/
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "validator: refine FX023 — sanitizer accepts upper_bound OR lower_bound"
```

---

## Task 6: Extract pre-fix and post-fix snippets

Two `git show` extractions plus their `.meta.json` sidecars. One commit.

**Files:**
- Create: `fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`
- Create: `fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`
- Create: `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`
- Create: `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`

- [ ] **Step 6.1: Verify the pre-fix parent is accessible in the shallow clone**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git cat-file -p 89face0b8 | head -5
```

Expected output includes two `parent <sha>` lines. Note both SHAs. Then check accessibility of each:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  for p in <parent1> <parent2>; do echo -n "$p: "; git cat-file -t $p 2>&1 || echo not-found; done
```

At least one parent must be accessible. The main-side parent (the one that contains #3074's fix merge `461c021` in its history — use `git merge-base --is-ancestor 461c021608802370374afabd5d3c2720b3e46f04 <parent>` to test) is the one we want for pre-fix.

Set `PREFIX_SHA=<that parent>` for use below.

If neither parent is accessible, FALLBACK: extract the post-fix snippet, then reverse-apply the fix diff to produce a pre-fix snippet. Report BLOCKED and the controller will adjust the plan.

- [ ] **Step 6.2: Create both snippet directories**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
mkdir -p fixtures/imagesharp-3079-postfix/snippets fixtures/imagesharp-3079-prefix/snippets
```

- [ ] **Step 6.3: Extract post-fix content (pinned to fix merge commit)**

```bash
(cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show 89face0b8:src/ImageSharp/Formats/Png/PngDecoderCore.cs) \
  > fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
wc -l fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Expected: several thousand lines (PngDecoderCore.cs is large).

- [ ] **Step 6.4: Verify the fix's NEW checks ARE present in the post-fix snippet**

```bash
grep -n 'Not enough data for keyword + null + compression method' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
grep -n 'Not enough data for keyword + null + flag + method + language' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
grep -n 'translatedKeywordLength < 0' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Expected: each returns a line number. If any returns nothing, stop — the SHA is wrong or the fix's content is not what we think it is.

- [ ] **Step 6.5: Extract pre-fix content**

Using `PREFIX_SHA` from step 6.1:
```bash
(cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show <PREFIX_SHA>:src/ImageSharp/Formats/Png/PngDecoderCore.cs) \
  > fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
wc -l fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Expected: slightly fewer lines than post-fix (the fix adds ~15 lines total across its three additions).

- [ ] **Step 6.6: Verify the fix's NEW checks ARE ABSENT in the pre-fix snippet**

```bash
grep -n 'Not enough data for keyword' \
  fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Expected: no matches (exit code 1).

- [ ] **Step 6.7: Compute sha256 and write meta sidecars**

```bash
sha256sum fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
sha256sum fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Note both hex strings.

Create `fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`:

```json
{
  "source_path": "src/ImageSharp/Formats/Png/PngDecoderCore.cs",
  "recovered_against_sha": "89face0b8...",
  "recovery_method": "git-show-at-fix-merge",
  "sha256": "<post-fix hex from sha256sum>"
}
```

(Substitute the full 40-char SHA and the actual sha256 hex. The `89face0b8...` is a short form — use the full 40-char form `89face0b8...`. If you need the full form, run `git rev-parse 89face0b8` in the shared clone.)

Create `fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs.meta.json`:

```json
{
  "source_path": "src/ImageSharp/Formats/Png/PngDecoderCore.cs",
  "recovered_against_sha": "<PREFIX_SHA — full 40-char form>",
  "recovery_method": "git-show-at-pre-merge-parent",
  "sha256": "<pre-fix hex from sha256sum>"
}
```

- [ ] **Step 6.8: Confirm shared clone is clean**

```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && git status
```
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 6.9: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add fixtures/imagesharp-3079-postfix/ fixtures/imagesharp-3079-prefix/
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: pre- and post-fix PngDecoderCore.cs snippets for #3079"
```

---

## Task 7: `fix-files.txt` for both #3079 directories

One line each. One commit.

**Files:**
- Create: `fixtures/imagesharp-3079-prefix/fix-files.txt`
- Create: `fixtures/imagesharp-3079-postfix/fix-files.txt`

- [ ] **Step 7.1: Write both**

Contents of both files (identical):
```
src/ImageSharp/Formats/Png/PngDecoderCore.cs
```

(One line, trailing newline.)

- [ ] **Step 7.2: Commit**

```bash
git add fixtures/imagesharp-3079-prefix/fix-files.txt fixtures/imagesharp-3079-postfix/fix-files.txt
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: #3079 fix-files.txt for pre and post fixtures (one file each)"
```

---

## Task 8: Author post-fix `trace.yaml`

Walk the call chain from `PngDecoderCore.Decode` to `ReadInternationalTextChunk`. Record hops. Validate.

**Files:**
- Create: `fixtures/imagesharp-3079-postfix/trace.yaml`

- [ ] **Step 8.1: Locate source — `PngDecoderCore.Decode<TPixel>` signature line**

```bash
grep -n 'protected override Image<TPixel> Decode<TPixel>' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Note the line. If there are multiple Decode overloads, pick the one taking a `BufferedReadStream` + `CancellationToken` (the primary entry point).

- [ ] **Step 8.2: Locate `ReadInternationalTextChunk`**

Definition line:
```bash
grep -n 'private.*ReadInternationalTextChunk\|void ReadInternationalTextChunk' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Call site(s) — look for where this method is invoked:
```bash
grep -n 'ReadInternationalTextChunk(' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Typical PNG decoder structure: a chunk-dispatch switch that maps `PngChunkType.InternationalText` to a call of `ReadInternationalTextChunk(metadata, data)`. Note the call-site line.

- [ ] **Step 8.3: Follow callers back to Decode**

The method containing the `ReadInternationalTextChunk(...)` call site (from 8.2) is the PNG chunk dispatcher — usually `Decode` itself, or a helper called by Decode (e.g., `Parse`, `ReadChunks`). Determine the chain: `Decode` → [optional intermediate(s)] → [chunk dispatcher] → `ReadInternationalTextChunk`.

Record the chain. It will be **2–4 hops** (confirmed by the spec).

- [ ] **Step 8.4: Locate sanitizer 1 line**

```bash
grep -n 'Not enough data for keyword + null + flag + method + language' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

The `return;` preceding that comment is sanitizer 1. Note the line number of the `if` statement above the comment.

- [ ] **Step 8.5: Locate sanitizer 2 line**

```bash
grep -n 'translatedKeywordLength < 0' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

That's the `if` statement of sanitizer 2. Note the line.

- [ ] **Step 8.6: Locate the sink — `data.Slice(...)` for translated keyword**

```bash
grep -n 'data.Slice(translatedKeywordStartIdx, translatedKeywordLength)' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Note the line.

- [ ] **Step 8.7: Locate zeroIndexKeyword computation**

```bash
grep -n 'zeroIndexKeyword = data.IndexOf' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Note the line — this is the hop where `zeroIndexKeyword` is computed from `data`.

- [ ] **Step 8.8: Locate translatedKeywordLength computation**

```bash
grep -n 'translatedKeywordLength = data\[translatedKeywordStartIdx' \
  fixtures/imagesharp-3079-postfix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs
```

Note the line.

- [ ] **Step 8.9: Write post-fix `trace.yaml`**

Substitute every `<...>` placeholder with the verified line number / name. The chunk-dispatch chain between hop 0 (Decode entry) and the entry into `ReadInternationalTextChunk` can be 1–3 intermediate hops — add or remove propagator entries as matches the actual code.

```yaml
vuln_id: imagesharp-3079-postfix
fix_commit: <full 40-char SHA of 89face0b8...>
fix_pr: https://github.com/SixLabors/ImageSharp/pull/3081
description: PNG iTXt chunk decoder after the fix — attacker-crafted truncated
             iTXt chunks now return_early on insufficient data, guarding against
             IndexOutOfRangeException on span slice.

source:
  kind: decoder_entry
  method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.Decode
  file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
  line: <Decode<TPixel> signature line>
  role: source
  tainted_value_in: stream
  transformation: read_stream
  tainted_value_out: stream
  tainted_inputs:
    - name: data
      origin: chunk_body:iTXt

sink:
  kind: span_access
  api: span_slice
  method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
  file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
  line: <data.Slice line from 8.6>
  role: sink
  tainted_value_in: translatedKeywordLength
  transformation: array_index
  tainted_value_out: translatedKeyword
  access_expression: "data.Slice(translatedKeywordStartIdx, translatedKeywordLength)"

path:
  # Hop 0: Decode forwards stream into chunk dispatch. Line is inside Decode
  # where the dispatch call is made. Replace the 'method' / 'line' below.
  - hop: 0
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.Decode
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <line inside Decode where the chunk-dispatch helper is called>
    role: propagator
    tainted_value_in: stream
    transformation: identity
    tainted_value_out: stream
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Png.PngDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: Decode forwards stream to the PNG chunk-dispatch helper.

  # Optional intermediate propagator hops if Decode → helper → ReadInternationalTextChunk
  # is more than two hops. Delete this placeholder if the chain is direct.
  # - hop: 1
  #   method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.<chunk-dispatch method>
  #   line: <call-site of ReadInternationalTextChunk in the dispatcher>
  #   role: propagator
  #   ...

  # Hop N: ReadInternationalTextChunk reads data.IndexOf((byte)0) into zeroIndexKeyword.
  - hop: <N>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <line from 8.7 where zeroIndexKeyword is assigned>
    role: propagator
    tainted_value_in: data
    transformation: field_load
    tainted_value_out: zeroIndexKeyword
    dispatch:
      kind: direct
      static_type: System.ReadOnlySpan<byte>
      resolved_targets: []
      closure_boundary: false
    note: >
      zeroIndexKeyword = data.IndexOf((byte)0). Locates the null terminator
      ending the English keyword within the iTXt chunk body.

  # Hop N+1: Sanitizer 1 — the first new check added by the fix.
  - hop: <N+1>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <line from 8.4 — the 'if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length)'>
    role: sanitizer
    tainted_value_in: zeroIndexKeyword
    transformation: identity
    tainted_value_out: zeroIndexKeyword
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Png.PngDecoderCore
      resolved_targets: []
      closure_boundary: false
    establishes_bound:
      target: zeroIndexKeyword
      relation: "<="
      upper_bound: "data.Length - 4"
    on_failure:
      kind: return_early
    note: >
      The fix's first new check. The prior existing range-check already forces
      zeroIndexKeyword >= MinTextKeywordLength > 0, so the disjunct
      'zeroIndexKeyword < 0' is dead; the meaningful new contribution is
      'zeroIndexKeyword + 4 <= data.Length'. Full check text preserved here
      per open question O5. On failure, the method returns (silently skipping
      the malformed chunk), making the remainder of this trace unreachable.

  # Hop N+2: Propagator reading translatedKeywordLength.
  - hop: <N+2>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <line from 8.8>
    role: propagator
    tainted_value_in: data
    transformation: field_load
    tainted_value_out: translatedKeywordLength
    dispatch:
      kind: direct
      static_type: System.ReadOnlySpan<byte>
      resolved_targets: []
      closure_boundary: false
    note: >
      translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0).
      IndexOf returns -1 if the byte is not found, so translatedKeywordLength
      may be negative — that's the invariant sanitizer 2 checks.

  # Hop N+3: Sanitizer 2 — the second new check.
  - hop: <N+3>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <line from 8.5 — the 'if (translatedKeywordLength < 0)'>
    role: sanitizer
    tainted_value_in: translatedKeywordLength
    transformation: identity
    tainted_value_out: translatedKeywordLength
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Png.PngDecoderCore
      resolved_targets: []
      closure_boundary: false
    establishes_bound:
      target: translatedKeywordLength
      relation: ">="
      lower_bound: "0"
    on_failure:
      kind: return_early
    note: >
      The fix's second new check. Establishes translatedKeywordLength >= 0,
      guaranteeing the subsequent data.Slice(startIdx, length) receives a
      non-negative count. On failure, the method returns.

sanitizer_absence: []
```

- [ ] **Step 8.10: Run the validator**

```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3079-postfix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3079-postfix/snippets
```

Expected: `OK: fixtures/imagesharp-3079-postfix/trace.yaml`, exit 0.

Iterate if FX041 (line out of range) or FX024 (sink coupling) fires — cross-check grep results and fix.

- [ ] **Step 8.11: Regression-check all prior fixtures**

```bash
for d in imagesharp-3074-prefix imagesharp-3074-postfix; do
  dotnet run --project tools/ValidateFixture -- \
    fixtures/$d/trace.yaml --snippets-dir fixtures/$d/snippets
done
```

Expected: both `OK: ...`, exit 0.

- [ ] **Step 8.12: Commit**

```bash
git add fixtures/imagesharp-3079-postfix/trace.yaml
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: #3079 post-fix trace.yaml — 2 sanitizer hops (return_early) + span_slice sink"
```

---

## Task 9: Author pre-fix `trace.yaml`

Same structure as post-fix but with NO sanitizer hops and TWO `sanitizer_absence` entries. Line numbers come from the **pre-fix** snippet — they may differ from post-fix since the fix inserts ~15 lines across three locations.

**Files:**
- Create: `fixtures/imagesharp-3079-prefix/trace.yaml`

- [ ] **Step 9.1: Re-run the greps against the pre-fix snippet**

Same greps as Task 8 (8.1, 8.2, 8.6, 8.7, 8.8) but against:
`fixtures/imagesharp-3079-prefix/snippets/src__ImageSharp__Formats__Png__PngDecoderCore.cs`

Sanitizer 1 and 2 DO NOT exist in pre-fix — skip 8.4 and 8.5. Note the lines where they SHOULD have been (right before the first guarded access, and right before the `data.Slice(...)` sink respectively).

- [ ] **Step 9.2: Write pre-fix `trace.yaml`**

Use pre-fix line numbers everywhere. `path[]` has the same propagator hops as post-fix but NO sanitizer nodes:

```yaml
vuln_id: imagesharp-3079-prefix
fix_commit: <full 40-char SHA of 89face0b8>
fix_pr: https://github.com/SixLabors/ImageSharp/pull/3081
description: PNG iTXt chunk decoder before the fix — attacker-crafted truncated
             iTXt chunks reach data.Slice(startIdx, length) with an
             attacker-controlled length (potentially -1 from IndexOf not finding
             the null terminator), causing ArgumentOutOfRangeException.

source:
  kind: decoder_entry
  method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.Decode
  file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
  line: <pre-fix Decode signature line>
  role: source
  tainted_value_in: stream
  transformation: read_stream
  tainted_value_out: stream
  tainted_inputs:
    - name: data
      origin: chunk_body:iTXt

sink:
  kind: span_access
  api: span_slice
  method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
  file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
  line: <pre-fix data.Slice line>
  role: sink
  tainted_value_in: translatedKeywordLength
  transformation: array_index
  tainted_value_out: translatedKeyword
  access_expression: "data.Slice(translatedKeywordStartIdx, translatedKeywordLength)"

path:
  # Same propagator hops as post-fix trace, without sanitizers.
  - hop: 0
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.Decode
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <pre-fix dispatch call line>
    role: propagator
    tainted_value_in: stream
    transformation: identity
    tainted_value_out: stream
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Png.PngDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: Decode forwards stream to the PNG chunk-dispatch helper.

  # (Add intermediate hop(s) matching post-fix if any.)

  - hop: <N>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <pre-fix zeroIndexKeyword line>
    role: propagator
    tainted_value_in: data
    transformation: field_load
    tainted_value_out: zeroIndexKeyword
    dispatch:
      kind: direct
      static_type: System.ReadOnlySpan<byte>
      resolved_targets: []
      closure_boundary: false
    note: zeroIndexKeyword = data.IndexOf((byte)0).

  - hop: <N+1>
    method: SixLabors.ImageSharp.Formats.Png.PngDecoderCore.ReadInternationalTextChunk
    file: src__ImageSharp__Formats__Png__PngDecoderCore.cs
    line: <pre-fix translatedKeywordLength line>
    role: propagator
    tainted_value_in: data
    transformation: field_load
    tainted_value_out: translatedKeywordLength
    dispatch:
      kind: direct
      static_type: System.ReadOnlySpan<byte>
      resolved_targets: []
      closure_boundary: false
    note: >
      translatedKeywordLength = data[translatedKeywordStartIdx..].IndexOf((byte)0).
      Unchecked — can be -1 if no null terminator is present.

sanitizer_absence:
  - location: src__ImageSharp__Formats__Png__PngDecoderCore.cs:<line where sanitizer 1 SHOULD have been>
    expected_check: >
      Before data[zeroIndexKeyword + 1] / data[zeroIndexKeyword + 2] / ... accesses,
      verify zeroIndexKeyword + 4 <= data.Length. Fix adds
      `if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length) return;`.
    tainted_value: zeroIndexKeyword
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: <full 40-char SHA of 89face0b8>
      added_lines: src/ImageSharp/Formats/Png/PngDecoderCore.cs:<post-fix start>-<post-fix end>

  - location: src__ImageSharp__Formats__Png__PngDecoderCore.cs:<line where sanitizer 2 SHOULD have been>
    expected_check: >
      Before data.Slice(translatedKeywordStartIdx, translatedKeywordLength),
      verify translatedKeywordLength >= 0. Fix adds
      `if (translatedKeywordLength < 0) return;`.
    tainted_value: translatedKeywordLength
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: <full 40-char SHA of 89face0b8>
      added_lines: src/ImageSharp/Formats/Png/PngDecoderCore.cs:<post-fix start>-<post-fix end>
```

- [ ] **Step 9.3: Run the validator**

```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3079-prefix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3079-prefix/snippets
```

Expected: `OK: fixtures/imagesharp-3079-prefix/trace.yaml`, exit 0.

- [ ] **Step 9.4: All prior fixtures still green**

```bash
for d in imagesharp-3074-prefix imagesharp-3074-postfix imagesharp-3079-postfix; do
  dotnet run --project tools/ValidateFixture -- \
    fixtures/$d/trace.yaml --snippets-dir fixtures/$d/snippets
done
```

Expected: all three `OK: ...`.

- [ ] **Step 9.5: Commit**

```bash
git add fixtures/imagesharp-3079-prefix/trace.yaml
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: #3079 pre-fix trace.yaml — 2 sanitizer_absence entries, same span_slice sink"
```

---

## Task 10: Author post-fix `trace.md`

Narrative companion for the post-fix fixture. Mirrors #3074's `trace.md` structure with PNG-specific deltas.

**Files:**
- Create: `fixtures/imagesharp-3079-postfix/trace.md`

- [ ] **Step 10.1: Read inputs**

Read these files:
- `fixtures/imagesharp-3079-postfix/trace.yaml` — source of truth.
- `fixtures/imagesharp-3079-postfix/snippets/.../PngDecoderCore.cs` — quote verbatim from it.
- `fixtures/imagesharp-3074-postfix/trace.md` — structural model (same section set).

- [ ] **Step 10.2: Write `trace.md` with the following five sections**

**Section 1 — Summary**

One paragraph: what the bug is (attacker-crafted iTXt chunk with truncated data causes out-of-range span access); what the fix adds (two `if (...) return;` early-return guards in `ReadInternationalTextChunk`); why this matters (the fix closes an unhandled-exception DoS surface, not a memory-corruption bug).

**Section 2 — PNG chunk reference**

Replaces #3074's BMP header reference. Briefly cover:
- PNG 8-byte signature.
- Chunk framing: length (4) / type (4) / data (length bytes) / CRC (4).
- iTXt chunk body layout per the PNG spec: keyword (variable) / null / compression flag (1) / compression method (1) / language tag (variable) / null / translated keyword (variable) / null / text (variable).

This grounds the tainted value names (`zeroIndexKeyword`, `translatedKeywordStartIdx`, `translatedKeywordLength`) in the on-the-wire structure.

**Section 3 — Hop-by-hop walkthrough**

One subsection per node in `trace.yaml` path + source + sink. For each, include:
- The fenced `csharp` code block with verbatim lines from the post-fix snippet at the recorded line (5–15 lines of context).
- Taint state at entry/exit.
- Why the node is source/propagator/sanitizer/sink.
- For each sanitizer hop: explain `establishes_bound` (target / relation / upper_bound or lower_bound) and `on_failure` (return_early + no exception).

**Section 4 — Sanitizer presence**

Replaces the pre-fix "Sanitizer absence" section. Side-by-side (or stacked) view of pre-fix vs. post-fix at each sanitizer's location. Use the pre-fix snippet at `fixtures/imagesharp-3079-prefix/snippets/...` to show the pre-fix state.

**Section 5 — Open schema questions — resolution status**

- **O1** — resolved in milestone B. (Cross-reference only.)
- **O2** — still open. `data` (span aggregate) → scalar (`zeroIndexKeyword`, `translatedKeywordLength`) via `field_load` mirrors #3074's pattern. No new pressure.
- **O3** — still open. PNG decode is synchronous.
- **O4** — still open. #3079 does not traverse `Nullable<T>.Value`.
- **O5 — NEW.** Compound sanitizer conditions: the fix's first new check is `if (zeroIndexKeyword < 0 || zeroIndexKeyword + 4 > data.Length) return;` — a disjunction of two conditions. The fixture collapses to the single meaningful upper bound (`zeroIndexKeyword <= data.Length - 4`) and preserves the full check text in `note:`. Deferred until an analyzer needs to read compound conditions mechanically.

- [ ] **Step 10.3: Read-through**

Confirm a cold reader can follow the narrative end-to-end.

- [ ] **Step 10.4: Commit**

```bash
git add fixtures/imagesharp-3079-postfix/trace.md
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: #3079 post-fix trace.md narrative — return_early, lower bounds, span_access sinks"
```

---

## Task 11: Author pre-fix `trace.md`

Narrative companion for the pre-fix fixture. Mirrors post-fix's structure with a "Sanitizer absence" section replacing "Sanitizer presence".

**Files:**
- Create: `fixtures/imagesharp-3079-prefix/trace.md`

- [ ] **Step 11.1: Read inputs**

- `fixtures/imagesharp-3079-prefix/trace.yaml`
- `fixtures/imagesharp-3079-prefix/snippets/.../PngDecoderCore.cs`
- `fixtures/imagesharp-3074-prefix/trace.md` — structural model.
- `fixtures/imagesharp-3079-postfix/trace.md` — cross-reference; ensure sections align.

- [ ] **Step 11.2: Write `trace.md` following #3074 pre-fix's structure**

Sections identical to post-fix Task 10, with these differences:

- **Summary**: describes the bug as present (attacker can craft an iTXt chunk that hits `data.Slice` with a negative count, producing `ArgumentOutOfRangeException` — a DoS vector).
- **Section 3 hop-by-hop**: NO sanitizer hops; ends at the unguarded `data.Slice(...)` sink.
- **Section 4 — Sanitizer absence**: for each of the two missing sanitizers, quote the post-fix lines (from `fixtures/imagesharp-3079-postfix/snippets/...`) and explain what the fix establishes. Cite the `sanitizer_absence[i]` entries from `trace.yaml` verbatim.
- **Section 5 — Open schema questions**: same content as post-fix (O1 resolved, O2/O3/O4 still open, O5 new).

- [ ] **Step 11.3: Read-through**

- [ ] **Step 11.4: Commit**

```bash
git add fixtures/imagesharp-3079-prefix/trace.md
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: #3079 pre-fix trace.md narrative — two missing sanitizers, span_slice sink"
```

---

## Task 12: Annotate #3074 fixtures with O5 cross-reference

One-line addition to each #3074 `trace.md` so a reader knows O5 surfaced in #3079.

**Files:**
- Modify: `fixtures/imagesharp-3074-prefix/trace.md`
- Modify: `fixtures/imagesharp-3074-postfix/trace.md`

- [ ] **Step 12.1: Find the "Open schema questions" section in the pre-fix trace.md**

```bash
grep -n 'Open schema questions' fixtures/imagesharp-3074-prefix/trace.md
```

Navigate to the end of that section (after O1/O2/O3/O4 entries).

- [ ] **Step 12.2: Append an O5 bullet to the pre-fix trace.md**

After the O4 bullet (or at the end of the Open questions section), add:

```markdown
### O5 — Compound sanitizer conditions (new in milestone A)

Surfaced by `fixtures/imagesharp-3079-postfix/` and the schema-v0.2
extension documented in
`docs/superpowers/specs/2026-04-17-imagesharp-3079-trace-design.md`. Fix
checks of the form `if (A < 0 || A + N > data.Length) return;` are
disjunctions of two conditions but `establishes_bound` records one bound
pair. Milestone A collapses such disjunctions to the meaningful single
bound with the full check text preserved in `note:`. Deferred.
```

- [ ] **Step 12.3: Same annotation for the post-fix trace.md**

Repeat the above edit for `fixtures/imagesharp-3074-postfix/trace.md`.

- [ ] **Step 12.4: Commit**

```bash
git add fixtures/imagesharp-3074-prefix/trace.md fixtures/imagesharp-3074-postfix/trace.md
git -c user.email="lukasik.pawel@gmail.com" -c user.name="Pawel Lukasik" commit -m "fixture: annotate #3074 trace.md files with O5 cross-reference (surfaced in milestone A)"
```

---

## Task 13: Final cross-check

- [ ] **Step 13.1: All four fixtures validate green**

```bash
for d in imagesharp-3074-prefix imagesharp-3074-postfix imagesharp-3079-prefix imagesharp-3079-postfix; do
  dotnet run --project tools/ValidateFixture -- \
    fixtures/$d/trace.yaml --snippets-dir fixtures/$d/snippets
done
```

Expected: four `OK: ...`, all exit 0.

- [ ] **Step 13.2: All tests pass**

```bash
dotnet test
```

Expected: 35 passing (25 before A + 2 for FX015 + 6 for FX024 + 2 for FX023 refinement).

- [ ] **Step 13.3: Build clean**

```bash
dotnet build --no-incremental
```

Expected: 0 warnings, 0 errors.

- [ ] **Step 13.4: Shared clone untouched**

```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && git status
```

Expected: `nothing to commit, working tree clean`.

- [ ] **Step 13.5: Done-criteria review**

Confirm each of the spec's done criteria:
1. Both #3079 fixtures validate OK → 13.1.
2. Both #3074 fixtures still validate OK → 13.1.
3. Validator gains FX015 + FX024 + refined FX023; tests green → 13.2.
4. Build clean (0 warnings) → 13.3.
5. Post-fix trace.md explains return_early, lower bounds, span_access sinks → Task 10.
6. O5 recorded in both #3079 trace.md files AND cross-referenced in both #3074 trace.md files → Tasks 10, 11, 12.
7. Shared clone untouched → 13.4.

- [ ] **Step 13.6: Final fixup commit (if any)**

```bash
git add -A
git commit -m "fixture: milestone A cross-check fixups" || echo "nothing to commit"
```

---

## Out of scope for this plan

- Any analyzer code (Roslyn / Cecil / ILLink).
- Milestone C — tech-choice decision.
- O2, O3, O4 schema extensions — still open, deferred until a fixture pressures them.
- M1 tech-debt cleanup — still deferred (unifying `Require<T>`/`RequireField<T>`, removing unused `using YamlDotNet.Serialization.NamingConventions`, `.gitattributes` for fixture files, parsing `sanitizer_absence.location` for file:line resolution).
- Tracing sites 1 (in `ReadCompressedTextChunk`) from #3079 — modeled as out of scope; Sites 2+3 of `ReadInternationalTextChunk` already exercise `return_early` and multi-sanitizer-per-path.
- A third fixture pair covering a different #3079 site — not needed.

---

## Revision history

- **2026-04-17** — Plan authored from spec `2026-04-17-imagesharp-3079-trace-design.md`.
- **2026-04-18** — Implemented. Schema v0.1 → v0.2 (closed `SinkKinds` / `SinkApis` vocabs, `AccessExpression`, FX015/FX024, FX023 lower-bound refinement). Pre/post fixtures committed: snippets `c28b5b1`, fix-files `2970535`, post-fix trace.yaml `bcc07ae`, pre-fix trace.yaml `7a828fd`, post-fix trace.md `e2a0b9d`, pre-fix trace.md `fee147a`. O5 (compound sanitizer conditions) cross-referenced on M1/M2 trace.md (`c9e8f8e`); mechanical handling deferred. Pre-fix fixture became milestone-C's bonus reproduction target — closed in commit `0ca0692`.
