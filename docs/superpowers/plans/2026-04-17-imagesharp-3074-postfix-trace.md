# ImageSharp #3074 Post-Fix Trace — Implementation Plan

**Status:** Implemented 2026-04-17. See revision history at end.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a post-fix ground-truth trace of ImageSharp #3074 that exercises open schema question O1, extend the validator with sanitizer-node completeness rules (FX013/FX014/FX023), and restructure the fixtures directory to host pre/post pairs.

**Architecture:** Additive schema evolution (v0 → v0.1) — new optional fields `establishes_bound` and `on_failure` on `PathNode`, enforced only on sanitizer nodes. Fixture directory split into `imagesharp-3074-prefix/` and `imagesharp-3074-postfix/`. Post-fix snippet pinned to fix merge commit `461c021...` via `git show`. Six path hops: same 0–3 as pre-fix, new sanitizer hop 4 at post-fix line 1551, arithmetic hop 5 at ~line 1557, sink at ~line 1606.

**Tech Stack:** .NET 10, YamlDotNet 15.1.6, xUnit, Shouldly. Same as milestone 1.

**Spec reference:** `docs/superpowers/specs/2026-04-17-imagesharp-3074-postfix-trace-design.md` (commit `3ed7dcc`).

---

## File Structure

**Directory rename (Task 1):**
- `fixtures/imagesharp-3074/` → `fixtures/imagesharp-3074-prefix/`
- `fixtures/imagesharp-3074-prefix/prefix-snippets/` → `fixtures/imagesharp-3074-prefix/snippets/`

**Validator changes (Tasks 2–6):**
- Modify: `tools/ValidateFixture/FixtureDocument.cs` — add `EstablishesBound`, `OnFailure` POCOs; extend `PathNode`.
- Modify: `tools/ValidateFixture/Vocabularies.cs` — add `Relations`, `FailureKinds` frozen sets.
- Modify: `tools/ValidateFixture/FixtureValidator.cs` — add FX013/FX014/FX023 checks.
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` — add tests for the three new diagnostics.

**Post-fix fixture (Tasks 7–10):**
- Create: `fixtures/imagesharp-3074-postfix/fix-files.txt`
- Create: `fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs`
- Create: `fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs.meta.json`
- Create: `fixtures/imagesharp-3074-postfix/trace.yaml`
- Create: `fixtures/imagesharp-3074-postfix/trace.md`

**Pre-fix narrative patch (Task 11):**
- Modify: `fixtures/imagesharp-3074-prefix/trace.md` — one-line O1-resolved annotation.

---

## Task 1: Directory restructure

Rename the M1 fixture to indicate it's the pre-fix variant, rename its snippets subdirectory to drop the doubled pre/post redundancy, and create the empty post-fix sibling directory.

**Files:**
- Rename: `fixtures/imagesharp-3074/` → `fixtures/imagesharp-3074-prefix/`
- Rename: `fixtures/imagesharp-3074-prefix/prefix-snippets/` → `fixtures/imagesharp-3074-prefix/snippets/`
- Create: `fixtures/imagesharp-3074-postfix/` (empty directory — populated in Tasks 7–10)

- [ ] **Step 1.1: Rename parent directory**

```bash
git mv fixtures/imagesharp-3074 fixtures/imagesharp-3074-prefix
```

- [ ] **Step 1.2: Rename snippets subdirectory**

```bash
git mv fixtures/imagesharp-3074-prefix/prefix-snippets fixtures/imagesharp-3074-prefix/snippets
```

- [ ] **Step 1.3: Create empty post-fix directory**

Directories aren't tracked by git directly; create the dir and a `.gitkeep` so it survives the commit.

```bash
mkdir -p fixtures/imagesharp-3074-postfix
touch fixtures/imagesharp-3074-postfix/.gitkeep
```

(The `.gitkeep` will be removed in Task 7 when real content lands. Don't bother deleting it here.)

- [ ] **Step 1.4: Verify validator still accepts the renamed pre-fix fixture**

Run:
```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3074-prefix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3074-prefix/snippets
```

Expected: `OK: fixtures/imagesharp-3074-prefix/trace.yaml`, exit 0.

If this fails, the `--snippets-dir` argument was pointing at the old location in some test or config — track down and fix before committing.

- [ ] **Step 1.5: Verify tests still green**

Run: `dotnet test`
Expected: 17 passing, 0 failing.

- [ ] **Step 1.6: Commit**

```bash
git add -A
git commit -m "fixture: rename imagesharp-3074/{,prefix-}snippets -> imagesharp-3074-prefix/snippets"
```

---

## Task 2: Schema POCOs

Add the two new optional-property classes and extend `PathNode`. This is a structural change with no tests — existing 17 tests must stay green to confirm deserialization of the M1 pre-fix YAML is unaffected.

**Files:**
- Modify: `tools/ValidateFixture/FixtureDocument.cs`

- [ ] **Step 2.1: Add new POCOs and extend PathNode**

Open `tools/ValidateFixture/FixtureDocument.cs`. Append the two new classes after the existing `FixEvidence` class:

```csharp
public sealed class EstablishesBound
{
    [YamlMember(Alias = "target")]      public string? Target      { get; init; }
    [YamlMember(Alias = "relation")]    public string? Relation    { get; init; }
    [YamlMember(Alias = "upper_bound")] public string? UpperBound  { get; init; }
    [YamlMember(Alias = "lower_bound")] public string? LowerBound  { get; init; }
}

public sealed class OnFailure
{
    [YamlMember(Alias = "kind")]      public string? Kind      { get; init; }
    [YamlMember(Alias = "exception")] public string? Exception { get; init; }
}
```

In the `PathNode` class, after the existing `Note` property (around line 28), add:

```csharp
    [YamlMember(Alias = "establishes_bound")] public EstablishesBound? EstablishesBound { get; init; }
    [YamlMember(Alias = "on_failure")]        public OnFailure?        OnFailure        { get; init; }
```

- [ ] **Step 2.2: Build**

Run: `dotnet build`
Expected: 0 errors, 0 warnings.

- [ ] **Step 2.3: Run existing tests — expect 17 green (no regression)**

Run: `dotnet test`
Expected: 17 passing, 0 failing.

- [ ] **Step 2.4: Commit**

```bash
git add tools/ValidateFixture/FixtureDocument.cs
git commit -m "validator: add EstablishesBound + OnFailure POCOs on PathNode (schema v0.1)"
```

---

## Task 3: Vocabularies

Add the two new closed vocabularies. Again structural — tests come in subsequent tasks that actually check against these sets.

**Files:**
- Modify: `tools/ValidateFixture/Vocabularies.cs`

- [ ] **Step 3.1: Extend Vocabularies.cs**

After the existing `DispatchKinds` field, add:

```csharp
    public static readonly FrozenSet<string> Relations = new HashSet<string>(StringComparer.Ordinal)
    {
        "<", "<=", "==", "!=", ">=", ">",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> FailureKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "throw", "return_early", "clamp", "skip",
    }.ToFrozenSet(StringComparer.Ordinal);
```

- [ ] **Step 3.2: Build**

Run: `dotnet build`
Expected: 0 errors, 0 warnings.

- [ ] **Step 3.3: Existing tests still pass**

Run: `dotnet test`
Expected: 17 passing.

- [ ] **Step 3.4: Commit**

```bash
git add tools/ValidateFixture/Vocabularies.cs
git commit -m "validator: add Relations and FailureKinds vocabularies"
```

---

## Task 4: FX013 — invalid `establishes_bound.relation`

TDD cycle. Sanitizer path node with `establishes_bound.relation` outside the `Relations` vocabulary → FX013.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 4.1: Write failing test**

Add to `FixtureValidatorTests.cs`:

```csharp
[Fact]
public void PathNode_InvalidEstablishesBoundRelation_ReportsFX013()
{
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
            establishes_bound: { target: x, relation: "~~", upper_bound: y }
            on_failure: { kind: throw, exception: E }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX013" && d.Message.Contains("relation") && d.Message.Contains("~~"));
}
```

- [ ] **Step 4.2: Run — expect 1 new failure (FX013 not emitted yet)**

Run: `dotnet test`
Expected: 1 failure (the new test), 17 still passing.

- [ ] **Step 4.3: Add FX013 check to validator**

In `FixtureValidator.cs`, inside the `Validate` method, in the path-iteration block that already contains the vocab checks (around the `CheckVocab(node.Role, ...)` calls), append after the dispatch-kind check:

```csharp
                if (node.EstablishesBound is { Relation: { } rel })
                {
                    CheckVocab(rel, Vocabularies.Relations, "FX013", $"path[{i}].establishes_bound.relation", diagnostics);
                }
```

- [ ] **Step 4.4: Run — green**

Run: `dotnet test`
Expected: 18 passing.

- [ ] **Step 4.5: Commit**

```bash
git add tools/
git commit -m "validator: FX013 — establishes_bound.relation must be in Relations vocab"
```

---

## Task 5: FX014 — invalid `on_failure.kind`

Same pattern as Task 4, for the other new vocab.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 5.1: Write failing test**

Add to `FixtureValidatorTests.cs`:

```csharp
[Fact]
public void PathNode_InvalidOnFailureKind_ReportsFX014()
{
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
            establishes_bound: { target: x, relation: "<=", upper_bound: y }
            on_failure: { kind: pray, exception: E }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX014" && d.Message.Contains("on_failure.kind") && d.Message.Contains("pray"));
}
```

- [ ] **Step 5.2: Run — 1 failure**

Run: `dotnet test`
Expected: 1 new failure.

- [ ] **Step 5.3: Add FX014 check**

In `FixtureValidator.cs`, immediately below the FX013 block added in Task 4:

```csharp
                if (node.OnFailure is { Kind: { } fk })
                {
                    CheckVocab(fk, Vocabularies.FailureKinds, "FX014", $"path[{i}].on_failure.kind", diagnostics);
                }
```

- [ ] **Step 5.4: Run — green**

Run: `dotnet test`
Expected: 19 passing.

- [ ] **Step 5.5: Commit**

```bash
git add tools/
git commit -m "validator: FX014 — on_failure.kind must be in FailureKinds vocab"
```

---

## Task 6: FX023 — sanitizer node completeness

TDD for the per-field requirements on sanitizer nodes. Uses a `[Theory]` so all six required-field cases plus the conditional `exception` case live in one test.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 6.1: Write failing tests (Theory + helper)**

Add to `FixtureValidatorTests.cs`. The `BuildSanitizerYaml` helper parameterizes the sanitizer's field values; passing `null` for any field leaves that YAML key out entirely.

```csharp
[Theory]
[InlineData("target",      "establishes_bound.target")]
[InlineData("relation",    "establishes_bound.relation")]
[InlineData("upper_bound", "establishes_bound.upper_bound")]
[InlineData("kind",        "on_failure.kind")]
public void SanitizerNode_MissingRequiredField_ReportsFX023(string omit, string expectedWhere)
{
    var yaml = BuildSanitizerYaml(omit);
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX023" && d.Message.Contains(expectedWhere));
}

[Fact]
public void SanitizerNode_ThrowWithoutException_ReportsFX023()
{
    var yaml = BuildSanitizerYaml(omit: "exception");
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX023" && d.Message.Contains("on_failure.exception"));
}

[Fact]
public void SanitizerNode_NonThrowDoesNotRequireException()
{
    // kind: clamp — exception is not required.
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
            establishes_bound: { target: x, relation: "<=", upper_bound: y }
            on_failure: { kind: clamp }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldNotContain(d => d.Code == "FX023");
}

private static string BuildSanitizerYaml(string omit)
{
    // Each field is emitted only if omit != <field>.
    string target     = omit == "target"      ? "" : "target: x,";
    string relation   = omit == "relation"    ? "" : "relation: \"<=\",";
    string upperBound = omit == "upper_bound" ? "" : "upper_bound: y";
    string kind       = omit == "kind"        ? "" : "kind: throw,";
    string exception  = omit == "exception"   ? "" : "exception: E";

    return $$"""
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
            establishes_bound: { {{target}} {{relation}} {{upperBound}} }
            on_failure: { {{kind}} {{exception}} }
        sanitizer_absence: []
        """;
}
```

- [ ] **Step 6.2: Run — expect 6 new failures (4 theory rows + 2 facts)**

Run: `dotnet test`
Expected: 6 failures.

- [ ] **Step 6.3: Add FX023 block to validator**

In `FixtureValidator.cs`, inside the path loop that Task 5 extended, append after the FX014 check:

```csharp
                if (string.Equals(node.Role, "sanitizer", StringComparison.Ordinal))
                {
                    if (node.EstablishesBound is null)
                    {
                        diagnostics.Add(new Diagnostic("FX023", $"sanitizer node path[{i}] missing required field: establishes_bound"));
                    }
                    else
                    {
                        RequireField(node.EstablishesBound.Target,     "FX023", $"path[{i}].establishes_bound.target",      diagnostics);
                        RequireField(node.EstablishesBound.Relation,   "FX023", $"path[{i}].establishes_bound.relation",    diagnostics);
                        RequireField(node.EstablishesBound.UpperBound, "FX023", $"path[{i}].establishes_bound.upper_bound", diagnostics);
                    }

                    if (node.OnFailure is null)
                    {
                        diagnostics.Add(new Diagnostic("FX023", $"sanitizer node path[{i}] missing required field: on_failure"));
                    }
                    else
                    {
                        RequireField(node.OnFailure.Kind, "FX023", $"path[{i}].on_failure.kind", diagnostics);
                        if (string.Equals(node.OnFailure.Kind, "throw", StringComparison.Ordinal))
                        {
                            RequireField(node.OnFailure.Exception, "FX023", $"path[{i}].on_failure.exception", diagnostics);
                        }
                    }
                }
```

Note: `RequireField<T>` already exists as a static local function in `Validate` — reuse it directly from this new block.

- [ ] **Step 6.4: Run — green**

Run: `dotnet test`
Expected: 25 passing (19 from Task 5 + 4 theory + 2 facts).

- [ ] **Step 6.5: Commit**

```bash
git add tools/
git commit -m "validator: FX023 — sanitizer node completeness (establishes_bound + on_failure)"
```

---

## Task 7: Extract post-fix snippet

Pin the post-fix content to the fix merge commit.

**Files:**
- Create: `fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs`
- Create: `fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs.meta.json`
- Delete: `fixtures/imagesharp-3074-postfix/.gitkeep`

- [ ] **Step 7.1: Create snippets directory and extract content**

```bash
mkdir -p fixtures/imagesharp-3074-postfix/snippets
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show 461c021608802370374afabd5d3c2720b3e46f04:src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs \
  > /mnt/c/work/dotnet-taint-analyzer/fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
cd /mnt/c/work/dotnet-taint-analyzer
```

- [ ] **Step 7.2: Verify the fix's check IS present in the snippet**

Run:
```bash
grep -n 'Offset.*>.*stream.Length' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
```
Expected: a match around line 1551 showing `this.fileHeader.Value.Offset > stream.Length`.

If no match: the SHA is wrong, or the file path changed. Stop and report.

- [ ] **Step 7.3: Compute sha256 and write the meta sidecar**

Run:
```bash
sha256sum fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
```
Note the hex string.

Create `fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs.meta.json`:

```json
{
  "source_path": "src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs",
  "recovered_against_sha": "461c021608802370374afabd5d3c2720b3e46f04",
  "recovery_method": "git-show-at-fix-merge",
  "sha256": "<hex from sha256sum>"
}
```

- [ ] **Step 7.4: Remove the placeholder `.gitkeep`**

```bash
rm fixtures/imagesharp-3074-postfix/.gitkeep
```

- [ ] **Step 7.5: Shared clone is untouched**

Run: `cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 7.6: Commit**

```bash
git add fixtures/imagesharp-3074-postfix/
git commit -m "fixture: post-fix snippet pinned to fix merge commit 461c021 (#3075)"
```

---

## Task 8: Post-fix `fix-files.txt`

Duplicate of the pre-fix file — 1 line.

**Files:**
- Create: `fixtures/imagesharp-3074-postfix/fix-files.txt`

- [ ] **Step 8.1: Write `fix-files.txt`**

Contents:
```
src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs
```

(One line, trailing newline.)

- [ ] **Step 8.2: Commit**

```bash
git add fixtures/imagesharp-3074-postfix/fix-files.txt
git commit -m "fixture: post-fix fix-files.txt (same one file as pre-fix)"
```

---

## Task 9: Author post-fix `trace.yaml`

Six path hops — same 0–3 as pre-fix, new sanitizer at hop 4, arithmetic at hop 5. Line numbers must be verified against the post-fix snippet; hops AT or BELOW pre-fix line 1551 shift down by 6 (the fix inserts a 6-line block).

**Files:**
- Create: `fixtures/imagesharp-3074-postfix/trace.yaml`

- [ ] **Step 9.1: Determine exact post-fix line numbers**

For each line of interest, run a grep against the post-fix snippet:

```bash
grep -n 'this.ReadImageHeaders(stream' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: line 133 (unchanged — above the insertion point).

grep -n 'stream.Read(buffer, 0, BmpFileHeader.Size)' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: line 1480 (unchanged).

grep -n 'this.ReadFileHeader(stream)' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: line 1523 (unchanged).

grep -n 'this.fileHeader.Value.Offset > stream.Length' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: line 1551 (the sanitizer).

grep -n 'colorMapSizeBytes = this.fileHeader.Value.Offset' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: ~line 1557 (shifted from pre-fix 1551 by the 6-line insertion).

grep -n 'palette = new byte\[colorMapSizeBytes\]' \
  fixtures/imagesharp-3074-postfix/snippets/src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
# Expected: ~line 1606 (shifted from pre-fix 1600).
```

If any expected line differs from reality: record the actual line and use it below. Do not guess.

- [ ] **Step 9.2: Write `trace.yaml`**

Using the line numbers you verified in 9.1, write the following into `fixtures/imagesharp-3074-postfix/trace.yaml`. The `<post-fix-line-X>` placeholders are substituted with the numbers from 9.1 — typically 133, 1480, 1523, 1551, 1557, 1606.

```yaml
vuln_id: imagesharp-3074-postfix
fix_commit: 461c021608802370374afabd5d3c2720b3e46f04
fix_pr: https://github.com/SixLabors/ImageSharp/pull/3075
description: BMP decoder after the fix — attacker-controlled fileHeader.Value.Offset
             is bounded against stream.Length before it reaches the
             colorMapSizeBytes arithmetic and the subsequent allocation.

source:
  kind: decoder_entry
  method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.Decode
  file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
  line: 128
  role: source
  tainted_value_in: stream
  transformation: read_stream
  tainted_value_out: stream
  tainted_inputs:
    - name: fileHeader.Offset
      origin: header_field:Offset

sink:
  kind: allocation
  api: new_array
  method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadImageHeaders
  file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
  line: <post-fix line of palette = new byte[colorMapSizeBytes]>
  role: sink
  tainted_value_in: colorMapSizeBytes
  transformation: arithmetic
  tainted_value_out: palette
  size_expression: "colorMapSizeBytes"

path:
  - hop: 0
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.Decode
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: 133
    role: propagator
    tainted_value_in: stream
    transformation: identity
    tainted_value_out: stream
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: Decode forwards stream to ReadImageHeaders.

  - hop: 1
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadImageHeaders
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: 1523
    role: propagator
    tainted_value_in: stream
    transformation: identity
    tainted_value_out: stream
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: ReadImageHeaders delegates file-header reading to ReadFileHeader.

  - hop: 2
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadFileHeader
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: 1480
    role: propagator
    tainted_value_in: stream
    transformation: read_stream
    tainted_value_out: fileHeader
    dispatch:
      kind: virtual
      static_type: SixLabors.ImageSharp.IO.BufferedReadStream
      resolved_targets:
        - SixLabors.ImageSharp.IO.BufferedReadStream.Read
      closure_boundary: false
    note: >
      stream.Read dispatches virtually; BufferedReadStream is sealed and
      overrides Read, so CHA closure is exactly one concrete target inside
      the ImageSharp assembly.

  - hop: 3
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadImageHeaders
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: <post-fix line of the sanitizer check — typically 1551>
    role: propagator
    tainted_value_in: fileHeader
    transformation: field_load
    tainted_value_out: fileHeader.Value.Offset
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: this.fileHeader.Value.Offset loaded from the Nullable<BmpFileHeader> struct.

  - hop: 4
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadImageHeaders
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: <post-fix line of the sanitizer check — typically 1551>
    role: sanitizer
    tainted_value_in: fileHeader.Value.Offset
    transformation: identity
    tainted_value_out: fileHeader.Value.Offset
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore
      resolved_targets: []
      closure_boundary: false
    establishes_bound:
      target: fileHeader.Value.Offset
      relation: "<="
      upper_bound: stream.Length
    on_failure:
      kind: throw
      exception: InvalidImageContentException
    note: >
      The fix's guard. Offset is compared to stream.Length; if it exceeds
      stream.Length, BmpThrowHelper.ThrowInvalidImageContentException is
      invoked and the decode aborts. The fall-through path establishes
      Offset <= stream.Length.

  - hop: 5
    method: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.ReadImageHeaders
    file: src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs
    line: <post-fix line of the arithmetic — typically 1557>
    role: propagator
    tainted_value_in: fileHeader.Value.Offset
    transformation: arithmetic
    tainted_value_out: colorMapSizeBytes
    dispatch:
      kind: direct
      static_type: SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore
      resolved_targets: []
      closure_boundary: false
    note: >
      colorMapSizeBytes = Offset - BmpFileHeader.Size - infoHeader.HeaderSize.
      Because hop 4 established Offset <= stream.Length, a forward-folding
      analyzer will derive colorMapSizeBytes <= stream.Length - BmpFileHeader.Size
      - infoHeader.HeaderSize, which is a safe bound given realistic
      infoHeader.HeaderSize and BmpFileHeader.Size values.

sanitizer_absence: []
```

- [ ] **Step 9.3: Run the validator**

```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3074-postfix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3074-postfix/snippets
```

Expected: `OK: fixtures/imagesharp-3074-postfix/trace.yaml`, exit 0.

If FX041 (line out of range) fires, your line numbers from 9.1 were wrong — re-grep, correct the YAML, re-run.

If FX023 fires, a sanitizer-required field is missing — fix and re-run.

- [ ] **Step 9.4: Also re-validate the pre-fix fixture (no regression)**

```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3074-prefix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3074-prefix/snippets
```

Expected: `OK: fixtures/imagesharp-3074-prefix/trace.yaml`, exit 0.

- [ ] **Step 9.5: Commit**

```bash
git add fixtures/imagesharp-3074-postfix/trace.yaml
git commit -m "fixture: post-fix trace.yaml with sanitizer hop 4 exercising establishes_bound + on_failure"
```

---

## Task 10: Author post-fix `trace.md`

Narrative companion mirroring M1's structure with deltas for the sanitizer.

**Files:**
- Create: `fixtures/imagesharp-3074-postfix/trace.md`

Structure (each is one section of `trace.md`):

- [ ] **Step 10.1: Section 1 — Summary**

One paragraph: bug is the same as pre-fix; fix inserted a single `if`-check at post-fix line 1551 guarding the `colorMapSizeBytes` arithmetic. The attacker can no longer induce OOM — any `Offset > stream.Length` aborts the decode via `InvalidImageContentException` before the allocation runs.

- [ ] **Step 10.2: Section 2 — BMP header reference**

Copy verbatim from pre-fix `trace.md` — the header structure itself doesn't change between pre and post. Reference at `fixtures/imagesharp-3074-prefix/trace.md` section 2.

- [ ] **Step 10.3: Section 3 — Hop-by-hop walkthrough**

One subsection per source, each path node, and the sink. For the first four (source + hops 0–3), they are structurally identical to pre-fix; you can adapt the pre-fix prose nearly verbatim.

The new subsection is **hop 4 (sanitizer)**. It must:
- Quote the pre-fix lines at post-fix 1551–1555 (the `if (...) throw ...` block).
- Explain the `establishes_bound` and `on_failure` fields and what they mean.
- Note that subsequent hops do NOT carry inherited state per fixture schema v0.1 — the analyzer is expected to fold the bound forward.
- Cite the CHA detail for `BmpThrowHelper.ThrowInvalidImageContentException` (static method call → direct dispatch).

For hop 5 (arithmetic), cite the line and explain that the incoming tainted value is the same `fileHeader.Value.Offset` but under the bound established at hop 4.

- [ ] **Step 10.4: Section 4 — Sanitizer presence**

Replaces pre-fix's "Sanitizer absence" section. Side-by-side or stacked view of pre-fix vs. post-fix for lines 1549–1557 of the file. Explain why the check is sufficient: no further arithmetic can produce an unsafe value, because `Offset <= stream.Length` bounds the subsequent subtraction given realistic constants for `BmpFileHeader.Size` and `infoHeader.HeaderSize`.

- [ ] **Step 10.5: Section 5 — Open schema questions — resolution status**

- **O1** — **RESOLVED** in this milestone. Introduction of `establishes_bound` and `on_failure` fields on sanitizer nodes captures the observable effect of the check. Downstream hops do not carry inherited state; the analyzer's forward-folding responsibility is explicit.
- **O2** — Still open. Field_load + arithmetic on consecutive lines still felt marginally clunky in hops 3–5.
- **O3** — Still open. No async edge exercised by this trace.
- **O4** — Still open. `Nullable<T>.Value` access still modelled as `field_load`.

- [ ] **Step 10.6: Final read-through**

Read the whole `trace.md` end-to-end. Confirm that a reader who knows only the pre-fix narrative can follow what changed and why the bug is gone.

- [ ] **Step 10.7: Commit**

```bash
git add fixtures/imagesharp-3074-postfix/trace.md
git commit -m "fixture: post-fix trace.md narrative — sanitizer presence + O1 resolved"
```

---

## Task 11: Annotate pre-fix `trace.md` with O1 resolution

One-line edit so a reader of the pre-fix narrative knows where O1 got resolved.

**Files:**
- Modify: `fixtures/imagesharp-3074-prefix/trace.md`

- [ ] **Step 11.1: Locate the Open schema questions section**

Open `fixtures/imagesharp-3074-prefix/trace.md`. Find the section titled "Open schema questions" (section 5 in the M1 narrative).

- [ ] **Step 11.2: Replace the O1 bullet**

Find the bullet starting with `**O1**` (describes `taint_value_state` / `bounded_by` as "untested because no sanitizer exists pre-fix"). Replace it with:

```markdown
- **O1** — **RESOLVED in milestone B** (see `fixtures/imagesharp-3074-postfix/trace.md`
  and `docs/superpowers/specs/2026-04-17-imagesharp-3074-postfix-trace-design.md`).
  The `establishes_bound` and `on_failure` fields on sanitizer nodes capture
  the bound that a sanitizer establishes and the control-flow disposition on
  failure.
```

Leave O2/O3/O4 bullets unchanged.

- [ ] **Step 11.3: Commit**

```bash
git add fixtures/imagesharp-3074-prefix/trace.md
git commit -m "fixture: annotate pre-fix trace.md — O1 resolved in milestone B"
```

---

## Task 12: Final cross-check

- [ ] **Step 12.1: Both fixtures validate green**

```bash
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3074-prefix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3074-prefix/snippets
dotnet run --project tools/ValidateFixture -- \
  fixtures/imagesharp-3074-postfix/trace.yaml \
  --snippets-dir fixtures/imagesharp-3074-postfix/snippets
```

Expected: both `OK: ...`, exit 0.

- [ ] **Step 12.2: All tests pass**

Run: `dotnet test`
Expected: 25 passing, 0 failing (17 M1 + 8 M2: 1 FX013 + 1 FX014 + 4 theory + 2 facts for FX023).

- [ ] **Step 12.3: Build clean**

Run: `dotnet build --no-incremental`
Expected: 0 warnings, 0 errors.

- [ ] **Step 12.4: Shared ImageSharp clone untouched**

Run: `cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 12.5: Done-criteria review**

Eyeball each of the spec's done criteria:
1. Pre-fix fixture validates OK → Step 12.1.
2. Post-fix fixture validates OK → Step 12.1.
3. Tests green + 0 warnings → Steps 12.2, 12.3.
4. `file:line` resolution enforced by validator → implicit in 12.1.
5. Post-fix `trace.md` readable end-to-end → Task 10 final read-through.
6. O1 resolved note in both `trace.md` files → Tasks 10 and 11.
7. Shared clone untouched → Step 12.4.

- [ ] **Step 12.6: Final commit if any fixups were needed**

```bash
git add -A
git commit -m "fixture: milestone B cross-check fixups" || echo "nothing to commit"
```

---

## Out of scope for this plan

- Any analyzer code (Roslyn / Cecil / ILLink).
- Milestone A (second-bug fixture) — a separate brainstorm + plan cycle.
- Schema evolution for O2, O3, O4 — deferred until a fixture actually pressures them.
- Validator tech-debt cleanup: unifying `Require<T>` and `RequireField<T>`, removing unused `using YamlDotNet.Serialization.NamingConventions`, `.gitattributes` for fixture files, adding `sanitizer_absence.location` file:line parsing.
- Any adjustments to the decoder's CHA closure for hops that don't need it (hops 0, 1, 3, 4, 5 are all direct dispatch).
- Post-fix line-number variance: if the fix in the shared clone's object database differs from the 6-line-insertion assumption for any reason, the verified line numbers in Step 9.1 are authoritative — do not try to "correct" them back to the assumed values.

---

## Revision history

- **2026-04-17** — Plan authored from spec `2026-04-17-imagesharp-3074-postfix-trace-design.md`.
- **2026-04-17** — Implemented. Schema v0 → v0.1 (`establishes_bound`, `on_failure`, `Relations`, `FailureKinds`); FX013/FX014/FX023 validator additions. Pre-fix renamed to `fixtures/imagesharp-3074-prefix/` (`8f0c892`); post-fix fixture committed at `e03cc4d`/`4765b6c`/`e05859b`/`d9c7e0b`. Open question O1 (sanitizer fields) closed by this milestone — annotated on pre-fix trace.md in commit `e021581`. The post-fix fixture became milestone-C's primary post-fix regression target (commit `648ba08`).
