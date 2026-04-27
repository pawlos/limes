# ImageSharp #3074 Trace — Implementation Plan

**Status:** Implemented 2026-04-17. See revision history at end.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a machine-checkable ground-truth trace (YAML fixture + narrative + pre-fix code snippets) of the source→sink path in the ImageSharp #3074 BMP decoder OOM, plus the tooling that validates future fixtures in the same schema.

**Architecture:** Two independent units. (1) A .NET 10 console project `ValidateFixture` (with an xUnit test project) that parses a trace YAML and verifies schema conformance and file:line resolution. (2) The fixture artifacts under `fixtures/imagesharp-3074/` — pre-fix snippets extracted via `git log -p` from the shared shallow clone at `/mnt/c/work/dotnet-fuzzing/external/ImageSharp`, plus `trace.yaml` and `trace.md` produced by hand-walking the call graph in those snippets.

**Tech Stack:**
- .NET 10 (SDK pinned via `global.json`).
- YamlDotNet for YAML parsing in the validator.
- xUnit + Shouldly for validator tests.
- No Python, no shell beyond the git commands run against the shared clone.

**Spec reference:** `docs/superpowers/specs/2026-04-16-imagesharp-3074-trace-design.md` (commit `fbde612`).

---

## File Structure

Files created by this plan, grouped by responsibility:

**Repo scaffolding**
- `.gitignore` — .NET + VS/Rider defaults
- `global.json` — pins SDK to .NET 10
- `TaintAnalyzer.sln` — solution containing the two projects below

**Fixture validator (`tools/ValidateFixture/`)**
- `ValidateFixture.csproj` — console app, net10.0, references YamlDotNet
- `Program.cs` — CLI: `ValidateFixture <trace.yaml> [--snippets-dir <path>]`; prints diagnostics; exit 0 on pass, 1 on fail
- `FixtureDocument.cs` — POCO model of the fixture (bound by YamlDotNet deserializer)
- `Vocabularies.cs` — static `HashSet<string>` for each closed vocabulary from the spec
- `FixtureValidator.cs` — pure validation logic; takes a parsed `FixtureDocument` + an optional snippets directory; returns `IReadOnlyList<Diagnostic>`

**Validator tests (`tools/ValidateFixture.Tests/`)**
- `ValidateFixture.Tests.csproj` — xUnit + Shouldly, references `ValidateFixture`
- `FixtureValidatorTests.cs` — one test class per validation capability
- `TestData/*.yaml` — small hand-written fixtures exercising each validation rule

**Fixture artifacts (`fixtures/imagesharp-3074/`)**
- `fix-files.txt` — newline-delimited list of source files changed by PR #3075
- `prefix-snippets/<PathEncoded>.cs` — reconstructed pre-fix content of each file
- `prefix-snippets/<PathEncoded>.meta.json` — provenance (upstream path, SHA reconstructed against, SHA-256 of content)
- `trace.yaml` — the machine-checkable fixture itself
- `trace.md` — the narrative companion

---

## Task 1: Repo scaffolding

**Files:**
- Create: `.gitignore`, `global.json`, `TaintAnalyzer.sln`

- [ ] **Step 1.1: Write `.gitignore`**

```gitignore
# .NET
bin/
obj/
*.user
.vs/
.vscode/
*.suo
*.DS_Store

# Rider/VS
.idea/

# Tools
TestResults/
*.log
```

- [ ] **Step 1.2: Write `global.json`**

```json
{
  "sdk": {
    "version": "10.0.103",
    "rollForward": "latestFeature"
  }
}
```

- [ ] **Step 1.3: Create empty solution**

Run: `dotnet new sln -n TaintAnalyzer`
Expected: creates `TaintAnalyzer.sln` in repo root.

- [ ] **Step 1.4: Verify SDK**

Run: `dotnet --version`
Expected: `10.0.103` (from `global.json`).

- [ ] **Step 1.5: Commit**

```bash
git add .gitignore global.json TaintAnalyzer.sln
git commit -m "scaffolding: .gitignore, SDK pin to .NET 10.0.103, empty solution"
```

---

## Task 2: Validator project + first failing test

Bootstrap both projects at once (they're tiny) so we can run a failing test in step 2.5 — the canonical TDD red bar.

**Files:**
- Create: `tools/ValidateFixture/ValidateFixture.csproj`
- Create: `tools/ValidateFixture/Program.cs`
- Create: `tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj`
- Create: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 2.1: Create validator console project**

Run:
```bash
dotnet new console -n ValidateFixture -o tools/ValidateFixture --framework net10.0
dotnet add tools/ValidateFixture/ValidateFixture.csproj package YamlDotNet --version 15.1.6
dotnet sln TaintAnalyzer.sln add tools/ValidateFixture/ValidateFixture.csproj
```

- [ ] **Step 2.2: Create test project**

Run:
```bash
dotnet new xunit -n ValidateFixture.Tests -o tools/ValidateFixture.Tests --framework net10.0
dotnet add tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj package Shouldly
dotnet add tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj reference tools/ValidateFixture/ValidateFixture.csproj
dotnet sln TaintAnalyzer.sln add tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj
```

- [ ] **Step 2.3: Write placeholder `Program.cs`**

File: `tools/ValidateFixture/Program.cs`
```csharp
namespace TaintAnalyzer.ValidateFixture;

public static class Program
{
    public static int Main(string[] args) => 0;
}
```

- [ ] **Step 2.4: Write failing test for validator existence**

File: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`
```csharp
using Shouldly;
using TaintAnalyzer.ValidateFixture;
using Xunit;

namespace TaintAnalyzer.ValidateFixture.Tests;

public class FixtureValidatorTests
{
    [Fact]
    public void EmptyInput_ReturnsMissingVulnIdDiagnostic()
    {
        var validator = new FixtureValidator();
        var diagnostics = validator.Validate(yaml: "{}", snippetsDir: null);
        diagnostics.ShouldContain(d => d.Code == "FX001" && d.Message.Contains("vuln_id"));
    }
}
```

- [ ] **Step 2.5: Run and verify it fails with compile error**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: compile error — `FixtureValidator` does not exist. This is the red bar.

- [ ] **Step 2.6: Introduce minimal `FixtureValidator` + `Diagnostic`**

File: `tools/ValidateFixture/FixtureValidator.cs`
```csharp
namespace TaintAnalyzer.ValidateFixture;

public sealed record Diagnostic(string Code, string Message);

public sealed class FixtureValidator
{
    public IReadOnlyList<Diagnostic> Validate(string yaml, string? snippetsDir)
    {
        var diagnostics = new List<Diagnostic>();
        if (!yaml.Contains("vuln_id"))
        {
            diagnostics.Add(new Diagnostic("FX001", "missing required field: vuln_id"));
        }
        return diagnostics;
    }
}
```

(Substring check is intentionally crude — the next task replaces it with real parsing. This is the minimum code to pass the test.)

- [ ] **Step 2.7: Run tests — green bar**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: 1 passing, 0 failing.

- [ ] **Step 2.8: Commit**

```bash
git add tools/ TaintAnalyzer.sln
git commit -m "validator: scaffolding + FX001 missing-vuln_id diagnostic (TDD red→green)"
```

---

## Task 3: Real YAML parsing + required top-level fields

Replace the substring check with a proper parse and check all required top-level fields listed in the spec.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Create: `tools/ValidateFixture/FixtureDocument.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

Required top-level fields (from spec): `vuln_id`, `fix_commit`, `fix_pr`, `description`, `source`, `sink`, `path`, `sanitizer_absence`.

- [ ] **Step 3.1: Write failing tests for each required field**

Add to `FixtureValidatorTests.cs`:
```csharp
[Theory]
[InlineData("vuln_id", "FX001")]
[InlineData("fix_commit", "FX002")]
[InlineData("fix_pr", "FX003")]
[InlineData("description", "FX004")]
[InlineData("source", "FX005")]
[InlineData("sink", "FX006")]
[InlineData("path", "FX007")]
[InlineData("sanitizer_absence", "FX008")]
public void EmptyInput_ReportsMissingRequiredField(string fieldName, string code)
{
    var diagnostics = new FixtureValidator().Validate("{}", snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == code && d.Message.Contains(fieldName));
}

[Fact]
public void MalformedYaml_ReportsFX000()
{
    var diagnostics = new FixtureValidator().Validate(":::not yaml:::", snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX000");
}
```

The previous `EmptyInput_ReturnsMissingVulnIdDiagnostic` test is subsumed by the theory — delete it.

- [ ] **Step 3.2: Run tests — expect 9 failures**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: 9 failures (8 theory cases + malformed yaml).

- [ ] **Step 3.3: Create `FixtureDocument.cs` POCO**

File: `tools/ValidateFixture/FixtureDocument.cs`
```csharp
using YamlDotNet.Serialization;

namespace TaintAnalyzer.ValidateFixture;

public sealed class FixtureDocument
{
    [YamlMember(Alias = "vuln_id")] public string? VulnId { get; init; }
    [YamlMember(Alias = "fix_commit")] public string? FixCommit { get; init; }
    [YamlMember(Alias = "fix_pr")] public string? FixPr { get; init; }
    [YamlMember(Alias = "description")] public string? Description { get; init; }
    [YamlMember(Alias = "source")] public PathNode? Source { get; init; }
    [YamlMember(Alias = "sink")] public PathNode? Sink { get; init; }
    [YamlMember(Alias = "path")] public List<PathNode>? Path { get; init; }
    [YamlMember(Alias = "sanitizer_absence")] public List<SanitizerAbsence>? SanitizerAbsence { get; init; }
}

public sealed class PathNode
{
    [YamlMember(Alias = "hop")] public int? Hop { get; init; }
    [YamlMember(Alias = "method")] public string? Method { get; init; }
    [YamlMember(Alias = "file")] public string? File { get; init; }
    [YamlMember(Alias = "line")] public int? Line { get; init; }
    [YamlMember(Alias = "role")] public string? Role { get; init; }
    [YamlMember(Alias = "tainted_value_in")] public string? TaintedValueIn { get; init; }
    [YamlMember(Alias = "transformation")] public string? Transformation { get; init; }
    [YamlMember(Alias = "tainted_value_out")] public string? TaintedValueOut { get; init; }
    [YamlMember(Alias = "dispatch")] public Dispatch? Dispatch { get; init; }
    [YamlMember(Alias = "note")] public string? Note { get; init; }

    // Fields used only on the top-level `source` / `sink` shapes.
    [YamlMember(Alias = "kind")] public string? Kind { get; init; }
    [YamlMember(Alias = "tainted_inputs")] public List<TaintedInput>? TaintedInputs { get; init; }
    [YamlMember(Alias = "api")] public string? Api { get; init; }
    [YamlMember(Alias = "size_expression")] public string? SizeExpression { get; init; }
}

public sealed class Dispatch
{
    [YamlMember(Alias = "kind")] public string? Kind { get; init; }
    [YamlMember(Alias = "static_type")] public string? StaticType { get; init; }
    [YamlMember(Alias = "resolved_targets")] public List<string>? ResolvedTargets { get; init; }
    [YamlMember(Alias = "closure_boundary")] public bool? ClosureBoundary { get; init; }
}

public sealed class TaintedInput
{
    [YamlMember(Alias = "name")] public string? Name { get; init; }
    [YamlMember(Alias = "origin")] public string? Origin { get; init; }
}

public sealed class SanitizerAbsence
{
    [YamlMember(Alias = "location")] public string? Location { get; init; }
    [YamlMember(Alias = "expected_check")] public string? ExpectedCheck { get; init; }
    [YamlMember(Alias = "tainted_value")] public string? TaintedValue { get; init; }
    [YamlMember(Alias = "present_pre_fix")] public bool? PresentPreFix { get; init; }
    [YamlMember(Alias = "present_post_fix")] public bool? PresentPostFix { get; init; }
    [YamlMember(Alias = "fix_evidence")] public FixEvidence? FixEvidence { get; init; }
}

public sealed class FixEvidence
{
    [YamlMember(Alias = "commit")] public string? Commit { get; init; }
    [YamlMember(Alias = "added_lines")] public string? AddedLines { get; init; }
}
```

- [ ] **Step 3.4: Replace validator body**

File: `tools/ValidateFixture/FixtureValidator.cs`
```csharp
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer.ValidateFixture;

public sealed record Diagnostic(string Code, string Message);

public sealed class FixtureValidator
{
    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public IReadOnlyList<Diagnostic> Validate(string yaml, string? snippetsDir)
    {
        var diagnostics = new List<Diagnostic>();

        FixtureDocument? doc;
        try
        {
            doc = s_deserializer.Deserialize<FixtureDocument>(yaml);
        }
        catch (YamlException ex)
        {
            diagnostics.Add(new Diagnostic("FX000", $"malformed YAML: {ex.Message}"));
            return diagnostics;
        }

        if (doc is null)
        {
            diagnostics.Add(new Diagnostic("FX000", "document is empty"));
            return diagnostics;
        }

        Require(doc.VulnId, "FX001", "vuln_id", diagnostics);
        Require(doc.FixCommit, "FX002", "fix_commit", diagnostics);
        Require(doc.FixPr, "FX003", "fix_pr", diagnostics);
        Require(doc.Description, "FX004", "description", diagnostics);
        Require(doc.Source, "FX005", "source", diagnostics);
        Require(doc.Sink, "FX006", "sink", diagnostics);
        Require(doc.Path, "FX007", "path", diagnostics);
        Require(doc.SanitizerAbsence, "FX008", "sanitizer_absence", diagnostics);

        return diagnostics;
    }

    private static void Require<T>(T? value, string code, string name, List<Diagnostic> diagnostics)
    {
        if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
        {
            diagnostics.Add(new Diagnostic(code, $"missing required field: {name}"));
        }
    }
}
```

- [ ] **Step 3.5: Run tests — expect 9 passing**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: all tests green.

- [ ] **Step 3.6: Commit**

```bash
git add tools/
git commit -m "validator: real YAML parse + required top-level fields FX000..FX008"
```

---

## Task 4: Closed-vocabulary checks

Enforce `role`, `transformation`, and `dispatch.kind` closed vocabularies from the spec on every path node.

**Files:**
- Create: `tools/ValidateFixture/Vocabularies.cs`
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`
- Create: `tools/ValidateFixture.Tests/TestData/minimal_valid.yaml`

- [ ] **Step 4.1: Write failing tests**

Add to `FixtureValidatorTests.cs`:
```csharp
[Fact]
public void PathNode_InvalidRole_ReportsFX010()
{
    var yaml = BuildYaml(pathRole: "hatstand");
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX010" && d.Message.Contains("role") && d.Message.Contains("hatstand"));
}

[Fact]
public void PathNode_InvalidTransformation_ReportsFX011()
{
    var yaml = BuildYaml(pathTransformation: "transmute");
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX011" && d.Message.Contains("transformation") && d.Message.Contains("transmute"));
}

[Fact]
public void PathNode_InvalidDispatchKind_ReportsFX012()
{
    var yaml = BuildYaml(pathDispatchKind: "telepathy");
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX012" && d.Message.Contains("dispatch.kind") && d.Message.Contains("telepathy"));
}

[Fact]
public void ValidMinimalFixture_ReportsNoDiagnostics()
{
    var yaml = File.ReadAllText("TestData/minimal_valid.yaml");
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldBeEmpty();
}

private static string BuildYaml(
    string pathRole = "propagator",
    string pathTransformation = "identity",
    string pathDispatchKind = "direct")
    => $"""
       vuln_id: test
       fix_commit: 0000000000000000000000000000000000000000
       fix_pr: https://example/pr/1
       description: test
       source: {{ kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }}
       sink: {{ kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }}
       path:
         - hop: 0
           method: M
           file: f
           line: 1
           role: {pathRole}
           tainted_value_in: x
           transformation: {pathTransformation}
           tainted_value_out: x
           dispatch: {{ kind: {pathDispatchKind} }}
       sanitizer_absence: []
       """;
```

- [ ] **Step 4.2: Create `TestData/minimal_valid.yaml`**

File: `tools/ValidateFixture.Tests/TestData/minimal_valid.yaml`
```yaml
vuln_id: test
fix_commit: 0000000000000000000000000000000000000000
fix_pr: https://example/pr/1
description: test
source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
path:
  - hop: 0
    method: M
    file: f
    line: 1
    role: propagator
    tainted_value_in: x
    transformation: identity
    tainted_value_out: x
    dispatch: { kind: direct }
sanitizer_absence: []
```

In `ValidateFixture.Tests.csproj`, ensure this file is copied to output. Add to the `.csproj`:
```xml
<ItemGroup>
  <None Update="TestData\**\*.yaml">
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </None>
</ItemGroup>
```

- [ ] **Step 4.3: Run tests — expect 4 failures**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: 4 new failures (3 invalid-vocab + 1 `ValidMinimalFixture`).

- [ ] **Step 4.4: Create `Vocabularies.cs`**

File: `tools/ValidateFixture/Vocabularies.cs`
```csharp
namespace TaintAnalyzer.ValidateFixture;

public static class Vocabularies
{
    public static readonly HashSet<string> Roles = new(StringComparer.Ordinal)
    {
        "source", "propagator", "sanitizer", "sink",
    };

    public static readonly HashSet<string> Transformations = new(StringComparer.Ordinal)
    {
        "identity", "read_stream", "field_load", "arithmetic",
        "cast", "array_index", "stream_offset",
    };

    public static readonly HashSet<string> DispatchKinds = new(StringComparer.Ordinal)
    {
        "direct", "virtual", "interface", "async_continuation",
        "delegate", "reflection", "unknown",
    };
}
```

- [ ] **Step 4.5: Extend validator to check vocabularies on every path node**

Append to the `Validate` method in `FixtureValidator.cs`, after the top-level required-field checks:
```csharp
if (doc.Path is { } path)
{
    for (int i = 0; i < path.Count; i++)
    {
        var node = path[i];
        CheckVocab(node.Role, Vocabularies.Roles, "FX010", $"path[{i}].role", diagnostics);
        CheckVocab(node.Transformation, Vocabularies.Transformations, "FX011", $"path[{i}].transformation", diagnostics);
        if (node.Dispatch is { Kind: { } dk })
        {
            CheckVocab(dk, Vocabularies.DispatchKinds, "FX012", $"path[{i}].dispatch.kind", diagnostics);
        }
    }
}

static void CheckVocab(string? value, HashSet<string> allowed, string code, string where, List<Diagnostic> diagnostics)
{
    if (value is not null && !allowed.Contains(value))
    {
        diagnostics.Add(new Diagnostic(code, $"invalid value '{value}' at {where}; allowed: {string.Join(", ", allowed.Order())}"));
    }
}
```

- [ ] **Step 4.6: Run tests — green**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: all tests pass.

- [ ] **Step 4.7: Commit**

```bash
git add tools/
git commit -m "validator: closed-vocab checks for role/transformation/dispatch.kind (FX010-FX012)"
```

---

## Task 5: Per-node completeness + sanitizer_absence sanity

Each path node must have `hop`, `method`, `file`, `line`, `role`, `tainted_value_in`, `tainted_value_out`, `transformation`, `dispatch.kind`. The `sanitizer_absence` entries must have `location`, `expected_check`, `tainted_value`, `present_pre_fix`, `present_post_fix`.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 5.1: Write failing tests**

Add to `FixtureValidatorTests.cs`:
```csharp
[Fact]
public void PathNode_MissingLine_ReportsFX020()
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
            role: propagator
            tainted_value_in: x
            transformation: identity
            tainted_value_out: x
            dispatch: { kind: direct }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX020" && d.Message.Contains("path[0].line"));
}

[Fact]
public void SanitizerAbsence_MissingExpectedCheck_ReportsFX030()
{
    var yaml = """
        vuln_id: t
        fix_commit: 0
        fix_pr: u
        description: d
        source: { kind: decoder_entry, method: M, file: f, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
        sink: { kind: allocation, api: new_array, file: f, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
        path: []
        sanitizer_absence:
          - location: f:3
            tainted_value: x
            present_pre_fix: false
            present_post_fix: true
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);
    diagnostics.ShouldContain(d => d.Code == "FX030" && d.Message.Contains("expected_check"));
}
```

- [ ] **Step 5.2: Run — expect 2 failures**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: 2 new failures.

- [ ] **Step 5.3: Add per-node completeness checks**

Append to `FixtureValidator.Validate` after the vocab checks:
```csharp
if (doc.Path is { } pathNodes)
{
    for (int i = 0; i < pathNodes.Count; i++)
    {
        var n = pathNodes[i];
        RequireField(n.Hop, "FX020", $"path[{i}].hop", diagnostics);
        RequireField(n.Method, "FX020", $"path[{i}].method", diagnostics);
        RequireField(n.File, "FX020", $"path[{i}].file", diagnostics);
        RequireField(n.Line, "FX020", $"path[{i}].line", diagnostics);
        RequireField(n.Role, "FX020", $"path[{i}].role", diagnostics);
        RequireField(n.TaintedValueIn, "FX020", $"path[{i}].tainted_value_in", diagnostics);
        RequireField(n.TaintedValueOut, "FX020", $"path[{i}].tainted_value_out", diagnostics);
        RequireField(n.Transformation, "FX020", $"path[{i}].transformation", diagnostics);
        RequireField(n.Dispatch?.Kind, "FX020", $"path[{i}].dispatch.kind", diagnostics);
    }
}

if (doc.SanitizerAbsence is { } sas)
{
    for (int i = 0; i < sas.Count; i++)
    {
        var s = sas[i];
        RequireField(s.Location, "FX030", $"sanitizer_absence[{i}].location", diagnostics);
        RequireField(s.ExpectedCheck, "FX030", $"sanitizer_absence[{i}].expected_check", diagnostics);
        RequireField(s.TaintedValue, "FX030", $"sanitizer_absence[{i}].tainted_value", diagnostics);
        RequireField(s.PresentPreFix, "FX030", $"sanitizer_absence[{i}].present_pre_fix", diagnostics);
        RequireField(s.PresentPostFix, "FX030", $"sanitizer_absence[{i}].present_post_fix", diagnostics);
    }
}

static void RequireField<T>(T? value, string code, string where, List<Diagnostic> diagnostics)
{
    if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
    {
        diagnostics.Add(new Diagnostic(code, $"missing field: {where}"));
    }
}
```

- [ ] **Step 5.4: Run — green**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: all pass.

- [ ] **Step 5.5: Commit**

```bash
git add tools/
git commit -m "validator: per-node completeness checks (FX020) and sanitizer_absence checks (FX030)"
```

---

## Task 6: file:line resolution

Every `path[*].file` and `sanitizer_absence[*].location` (format `<file>:<line>`) must resolve against the snippets directory (if provided). If `snippetsDir` is null, skip silently — this lets the validator double as a pure schema check in some contexts.

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 6.1: Write failing tests**

Add to `FixtureValidatorTests.cs`:
```csharp
[Fact]
public void FileRef_NotInSnippetsDir_ReportsFX040()
{
    using var temp = new TempDirectory();
    var yaml = """
        vuln_id: t
        fix_commit: 0
        fix_pr: u
        description: d
        source: { kind: decoder_entry, method: M, file: missing.cs, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
        sink: { kind: allocation, api: new_array, file: missing.cs, line: 2, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
        path:
          - hop: 0
            method: M
            file: missing.cs
            line: 5
            role: propagator
            tainted_value_in: x
            transformation: identity
            tainted_value_out: x
            dispatch: { kind: direct }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: temp.Path);
    diagnostics.ShouldContain(d => d.Code == "FX040" && d.Message.Contains("missing.cs"));
}

[Fact]
public void FileRef_LineOutOfRange_ReportsFX041()
{
    using var temp = new TempDirectory();
    File.WriteAllText(Path.Combine(temp.Path, "present.cs"), "line1\nline2\n");
    var yaml = """
        vuln_id: t
        fix_commit: 0
        fix_pr: u
        description: d
        source: { kind: decoder_entry, method: M, file: present.cs, line: 1, role: source, tainted_value_in: x, transformation: read_stream, tainted_value_out: x }
        sink: { kind: allocation, api: new_array, file: present.cs, line: 1, size_expression: x, method: M, role: sink, tainted_value_in: x, transformation: array_index, tainted_value_out: x }
        path:
          - hop: 0
            method: M
            file: present.cs
            line: 99
            role: propagator
            tainted_value_in: x
            transformation: identity
            tainted_value_out: x
            dispatch: { kind: direct }
        sanitizer_absence: []
        """;
    var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: temp.Path);
    diagnostics.ShouldContain(d => d.Code == "FX041" && d.Message.Contains("path[0]") && d.Message.Contains("99"));
}

private sealed class TempDirectory : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("fixture-tests-").FullName;
    public void Dispose() { try { Directory.Delete(Path, recursive: true); } catch { /* ignore */ } }
}
```

- [ ] **Step 6.2: Run — expect 2 failures**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: 2 new failures.

- [ ] **Step 6.3: Add file:line resolution**

Append to `FixtureValidator.Validate` after all existing checks:
```csharp
if (snippetsDir is not null && doc.Path is { } pn)
{
    for (int i = 0; i < pn.Count; i++)
    {
        CheckFileLine(pn[i].File, pn[i].Line, $"path[{i}]", snippetsDir, diagnostics);
    }
    // Also check source/sink top-level shapes.
    if (doc.Source is { } src) CheckFileLine(src.File, src.Line, "source", snippetsDir, diagnostics);
    if (doc.Sink is { } snk) CheckFileLine(snk.File, snk.Line, "sink", snippetsDir, diagnostics);
}

static void CheckFileLine(string? file, int? line, string where, string snippetsDir, List<Diagnostic> diagnostics)
{
    if (file is null || line is null) return; // already reported by FX020
    var full = Path.Combine(snippetsDir, file);
    if (!File.Exists(full))
    {
        diagnostics.Add(new Diagnostic("FX040", $"{where}: file not found in snippets dir: {file}"));
        return;
    }
    int count = File.ReadLines(full).Count();
    if (line.Value < 1 || line.Value > count)
    {
        diagnostics.Add(new Diagnostic("FX041", $"{where}: line {line.Value} out of range in {file} (has {count} lines)"));
    }
}
```

- [ ] **Step 6.4: Run — green**

Run: `dotnet test tools/ValidateFixture.Tests`
Expected: all pass.

- [ ] **Step 6.5: Commit**

```bash
git add tools/
git commit -m "validator: resolve file:line refs against snippets dir (FX040/FX041)"
```

---

## Task 7: CLI wiring

Make `dotnet run --project tools/ValidateFixture -- <trace.yaml> --snippets-dir <dir>` work end-to-end with proper exit codes.

**Files:**
- Modify: `tools/ValidateFixture/Program.cs`

- [ ] **Step 7.1: Replace `Program.cs` body**

File: `tools/ValidateFixture/Program.cs`
```csharp
namespace TaintAnalyzer.ValidateFixture;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
            return 2;
        }

        var yamlPath = args[0];
        string? snippetsDir = null;
        for (int i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--snippets-dir") snippetsDir = args[i + 1];
        }

        if (!File.Exists(yamlPath))
        {
            Console.Error.WriteLine($"error: file not found: {yamlPath}");
            return 2;
        }

        var yaml = File.ReadAllText(yamlPath);
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir);

        foreach (var d in diagnostics)
        {
            Console.Error.WriteLine($"{d.Code}: {d.Message}");
        }

        if (diagnostics.Count == 0)
        {
            Console.WriteLine($"OK: {yamlPath}");
            return 0;
        }

        Console.Error.WriteLine($"FAIL: {diagnostics.Count} diagnostic(s)");
        return 1;
    }
}
```

- [ ] **Step 7.2: Smoke-test the CLI**

Run:
```bash
dotnet run --project tools/ValidateFixture -- tools/ValidateFixture.Tests/TestData/minimal_valid.yaml
```
Expected: `OK: tools/ValidateFixture.Tests/TestData/minimal_valid.yaml`, exit 0.

- [ ] **Step 7.3: Commit**

```bash
git add tools/ValidateFixture/Program.cs
git commit -m "validator: CLI with exit codes (0 pass, 1 diagnostics, 2 usage/io)"
```

---

## Task 8: Determine file scope of PR #3075

Find the set of source files changed by the fix. The shared clone at `/mnt/c/work/dotnet-fuzzing/external/ImageSharp` is shallow; the fix merge `461c021...` has no accessible parent. But HEAD is post-fix and its history contains the fix, so we can inspect the fix via `git log HEAD --grep` and `git log HEAD -p -- <file>`.

**Files:**
- Create: `fixtures/imagesharp-3074/fix-files.txt`

- [ ] **Step 8.1: List commits near the fix for file scope**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git log HEAD --oneline --grep="3074"
```
Expected: at least `461c02160 Merge pull request #3075 from SixLabors/bp/fixIssue3074` plus any feature-branch commits. Note each SHA.

- [ ] **Step 8.2: Show the file list of each fix-branch commit**

For each non-merge SHA from step 8.1 (expected: `e5b71e8e9` and possibly others), run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show --stat --format="" <sha>
```
Expected: a list of files changed. Collect all unique `src/**/*.cs` paths.

- [ ] **Step 8.3: Cross-check by grepping HEAD's history for files with a commit referencing 3074**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  for f in $(git log --all --pretty=format: --name-only --grep="3074" | sort -u); do \
    [ -n "$f" ] && echo "$f"; \
  done
```
Expected: a small superset of step 8.2, filtered to `src/**/*.cs` (exclude test files for now — milestone 1 traces production code, not the regression test).

- [ ] **Step 8.4: Write `fix-files.txt`**

File: `fixtures/imagesharp-3074/fix-files.txt` — one path per line, relative to the ImageSharp repo root, `src/**/*.cs` only. Expected to be 1–3 files.

- [ ] **Step 8.5: Commit**

```bash
git add fixtures/imagesharp-3074/fix-files.txt
git commit -m "fixture: record files changed by ImageSharp PR #3075"
```

---

## Task 9: Extract pre-fix snippets

For each file in `fix-files.txt`, reconstruct the pre-fix content by finding the fix's diff in HEAD's history and reversing it.

**Files:**
- Create: `fixtures/imagesharp-3074/prefix-snippets/<PathEncoded>.cs`
- Create: `fixtures/imagesharp-3074/prefix-snippets/<PathEncoded>.meta.json`

**Path encoding:** `src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs` → `src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs` (replace `/` with `__`). This keeps one directory depth so every snippet sits next to its `.meta.json`.

- [ ] **Step 9.1: For each file, find the fix commit that touched it**

Run (substitute `<file>`):
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git log HEAD --oneline --grep="3074\|3075" -- <file>
```
Expected: the SHA of the commit on the feature branch that contained the fix's change to this file (not the merge). Note it.

- [ ] **Step 9.2: Get the post-fix content at that SHA**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show <fix-sha>:<file> > /tmp/postfix.cs
```

- [ ] **Step 9.3: Get the diff introduced by that commit**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show <fix-sha> -- <file> > /tmp/fix.patch
```

- [ ] **Step 9.4: Reverse-apply the patch to produce pre-fix content**

Run:
```bash
cd /tmp && cp postfix.cs prefix.cs && \
  git apply --reverse --unidiff-zero /tmp/fix.patch --directory=/tmp/ 2>&1 || \
  patch -R -p1 < /tmp/fix.patch  # fallback
```
If both fail because the fix commit is a merge or is shallow-cut at a boundary, materialize pre-fix by hand: take `/tmp/postfix.cs` and remove the lines the fix added (per `fix.patch`), restore the lines the fix removed. Record the manual step in the meta file.

- [ ] **Step 9.5: Save the pre-fix snippet**

Copy `/tmp/prefix.cs` to `fixtures/imagesharp-3074/prefix-snippets/<PathEncoded>.cs`.

- [ ] **Step 9.6: Write `.meta.json` sidecar**

File: `fixtures/imagesharp-3074/prefix-snippets/<PathEncoded>.meta.json`
```json
{
  "source_path": "src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs",
  "recovered_against_sha": "<fix-sha>",
  "recovery_method": "git-apply-reverse | manual",
  "sha256": "<sha256 of the .cs file>"
}
```
Compute sha256: `sha256sum fixtures/imagesharp-3074/prefix-snippets/<PathEncoded>.cs`.

- [ ] **Step 9.7: Repeat 9.1–9.6 for every file in `fix-files.txt`**

- [ ] **Step 9.8: Commit**

```bash
git add fixtures/imagesharp-3074/prefix-snippets/
git commit -m "fixture: pre-fix snippets reconstructed from PR #3075 diff"
```

---

## Task 10: Trace — identify source and sink

Start with the easy anchors: the entry point and the allocation the fix guarded.

**Files:**
- Create: `fixtures/imagesharp-3074/trace.yaml` (partial — source + sink only at this stage)

- [ ] **Step 10.1: Identify the BMP decoder entry point**

Open `fixtures/imagesharp-3074/prefix-snippets/<...>BmpDecoderCore.cs`. Find the public method that takes a `Stream` (or `BufferedReadStream`) and returns an `Image<TPixel>` — typically `Decode<TPixel>(BufferedReadStream, CancellationToken)` or similar. Record method name, file, and start line. This is the `source` node.

- [ ] **Step 10.2: Identify the sink allocation**

In the pre-fix snippet, find the allocation the fix's `Offset`-check guards. Search (in the pre-fix snippet, not HEAD):
```bash
grep -nE 'new byte\[|ArrayPool|Rent\(' fixtures/imagesharp-3074/prefix-snippets/*.cs
```
Cross-reference with the fix's `expected_check` wording ("Offset greater than stream length when reading bitmap colorMapSize"): the sink is the allocation sized by `colorMapSize`. Record method, file, line, `api` (one of: `new_array`, `array_pool_rent`, `alloc_hglobal`, `memory_pool_rent`, `stackalloc`), and the `size_expression`.

- [ ] **Step 10.3: Write `trace.yaml` source + sink**

File: `fixtures/imagesharp-3074/trace.yaml`
```yaml
vuln_id: imagesharp-3074
fix_commit: 461c021608802370374afabd5d3c2720b3e46f04
fix_pr: https://github.com/SixLabors/ImageSharp/pull/3075
description: BMP decoder OOM — unchecked allocation sized by attacker-controlled
             colorMapSize derived from the header Offset field.

source:
  kind: decoder_entry
  method: <fq name from step 10.1>
  file: <path-encoded snippet file>
  line: <line>
  role: source
  tainted_value_in: <param name, typically "stream">
  transformation: read_stream
  tainted_value_out: <name>
  tainted_inputs:
    - name: <e.g. infoHeader.Offset>
      origin: header_field:Offset

sink:
  kind: allocation
  api: <new_array | array_pool_rent | ...>
  method: <fq name of containing method>
  file: <path-encoded snippet file>
  line: <line>
  role: sink
  tainted_value_in: <name at sink>
  transformation: <array_index | arithmetic | ...>
  tainted_value_out: <name>
  size_expression: <exact string, e.g. "colorMapSizeBytes">

path: []
sanitizer_absence: []
```

- [ ] **Step 10.4: Run the validator — expect diagnostics for empty path**

Run: `dotnet run --project tools/ValidateFixture -- fixtures/imagesharp-3074/trace.yaml --snippets-dir fixtures/imagesharp-3074/prefix-snippets`
Expected: source/sink line refs resolve; `path` is an empty array but that's allowed by the schema (it's `FX007`-present, just empty). No schema errors. If the validator complains about anything other than a missing sanitizer_absence entry, fix the YAML before proceeding.

- [ ] **Step 10.5: Commit**

```bash
git add fixtures/imagesharp-3074/trace.yaml
git commit -m "fixture: trace.yaml anchors — source (BMP decoder entry) and sink (colorMap allocation)"
```

---

## Task 11: Trace — walk the hops from source to sink

Hand-walk the call graph within the pre-fix snippet, adding one `path` node per call or significant transformation on the tainted value. The validator enforces completeness after each edit; you cannot skip fields.

- [ ] **Step 11.1: Starting from the source method, find the first callee that consumes the tainted stream or a header field derived from it**

Use grep on the pre-fix snippet: look for calls like `Read*(...)`, `DecodeColorMap(...)`, `Stream.Seek(...)`. Record the first callee. For that call site, determine:
- `method` (caller side — containing method that emits the call)
- `file`, `line` (at the call)
- `role: propagator`
- `transformation` (from the v0 vocab)
- `tainted_value_in` / `tainted_value_out`
- `dispatch` — for a non-virtual method call, `kind: direct`; for `Stream.Read` via abstract `Stream`, `kind: virtual` and populate `static_type: System.IO.Stream`, with an initial `resolved_targets: []` to be filled in Task 12.

- [ ] **Step 11.2: Append the hop to `trace.yaml`**

Under `path:`, add a node:
```yaml
  - hop: 0
    method: <fq caller>
    file: <path-encoded>
    line: <line>
    role: propagator
    tainted_value_in: <name in>
    transformation: <vocab value>
    tainted_value_out: <name out>
    dispatch:
      kind: <direct|virtual|interface>
      static_type: <optional>
      resolved_targets: []
      closure_boundary: false
    note: <why this is a propagator>
```

- [ ] **Step 11.3: Run the validator**

Run: `dotnet run --project tools/ValidateFixture -- fixtures/imagesharp-3074/trace.yaml --snippets-dir fixtures/imagesharp-3074/prefix-snippets`
Expected: no new schema errors. If `line` was wrong, validator reports FX041 — fix and re-run until green.

- [ ] **Step 11.4: Repeat 11.1–11.3 for each subsequent hop**

Stop condition: the callee of the current hop is the sink method itself (i.e., the code that performs the allocation). At that point the trace arc is closed and the sink node (already in `trace.yaml`) becomes the final destination.

Estimate: 3–6 hops total for BMP #3074 (decoder entry → info-header reader → color-map reader → allocation). Actual count may differ.

- [ ] **Step 11.5: Commit once all hops are in**

```bash
git add fixtures/imagesharp-3074/trace.yaml
git commit -m "fixture: all propagator hops from source to sink in #3074 trace"
```

---

## Task 12: CHA closure for virtual/interface edges

For every `path[*]` node with `dispatch.kind ∈ {virtual, interface}`, populate `resolved_targets` with the set of concrete implementations reachable *within the ImageSharp assembly*. Anything that escapes (e.g., `Stream.Read` resolves to `FileStream.Read`, `MemoryStream.Read`, etc., all in `System.Private.CoreLib`) gets `closure_boundary: true` and an empty `resolved_targets`.

- [ ] **Step 12.1: For each virtual/interface hop, identify overrides in ImageSharp source**

For `<static_type>.<method>`, search the shared clone:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  grep -rn "override\s\+[A-Za-z_][A-Za-z0-9_]*\s\+<method>\s*(" src/
```
Plus interface implementations:
```bash
grep -rn ":\s*<static_type>" src/ | head -50
```

Record concrete methods in `resolved_targets` as fully qualified names (`SixLabors.ImageSharp.Foo.Bar.MethodName`).

- [ ] **Step 12.2: Decide `closure_boundary`**

If all resolved targets are within SixLabors.ImageSharp.* → `closure_boundary: false`. Otherwise → `closure_boundary: true`, and leave a `note` explaining where the target lives (e.g., "`System.IO.Stream.Read` — dispatch resolves to runtime-provided stream classes outside analyzed assembly").

- [ ] **Step 12.3: Update each hop's dispatch record**

Edit `trace.yaml` in place.

- [ ] **Step 12.4: Run the validator**

Run: `dotnet run --project tools/ValidateFixture -- fixtures/imagesharp-3074/trace.yaml --snippets-dir fixtures/imagesharp-3074/prefix-snippets`
Expected: no errors.

- [ ] **Step 12.5: Commit**

```bash
git add fixtures/imagesharp-3074/trace.yaml
git commit -m "fixture: CHA closure + closure_boundary for virtual/interface edges in #3074 trace"
```

---

## Task 13: Sanitizer absence

Record exactly the check the fix added and prove the pre-fix snippet lacks it.

- [ ] **Step 13.1: Extract the fix's diff for the key file**

Run:
```bash
cd /mnt/c/work/dotnet-fuzzing/external/ImageSharp && \
  git show <fix-sha-from-task-9> -- <file>
```
Focus on the `+` lines — those are what the fix added. Identify the line(s) that guard the tainted value.

- [ ] **Step 13.2: Populate `sanitizer_absence` in `trace.yaml`**

```yaml
sanitizer_absence:
  - location: <pre-fix-snippet-file>:<line-where-check-should-have-been>
    expected_check: "<verbatim description, e.g., 'infoHeader.Offset <= stream.Length before computing colorMapSize'>"
    tainted_value: <name>
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: <fix-sha>
      added_lines: <file>:<start>-<end>
```

- [ ] **Step 13.3: Run the validator**

Run: `dotnet run --project tools/ValidateFixture -- fixtures/imagesharp-3074/trace.yaml --snippets-dir fixtures/imagesharp-3074/prefix-snippets`
Expected: no errors.

- [ ] **Step 13.4: Commit**

```bash
git add fixtures/imagesharp-3074/trace.yaml
git commit -m "fixture: sanitizer_absence — check that PR #3075 added and pre-fix lacks"
```

---

## Task 14: Narrative companion

Write `trace.md` as a prose walk through `trace.yaml`, structured per the spec ("Narrative companion" section: summary, header reference, hop-by-hop, sanitizer absence, open schema questions).

**Files:**
- Create: `fixtures/imagesharp-3074/trace.md`

- [ ] **Step 14.1: Write the Summary section**

One paragraph: the vulnerability, the header field that drives it, the allocation that blows up, the one-line fix.

- [ ] **Step 14.2: Write the Header Reference table**

A small table of BMP header fields relevant to the trace — at minimum: `bfOffBits` (file offset of pixel data), `biSize` (info header size), `biClrUsed`, and whichever Offset/size field drives `colorMapSize`. Each row: offset, name, width, role in this vulnerability.

- [ ] **Step 14.3: Write Hop-by-Hop sections**

One subsection per `path` node + source + sink. For each, include:
- A fenced code block of the exact pre-fix lines (extracted from the snippet file at the recorded line; 5–15 lines of context).
- The tainted value's state at entry / exit.
- Why this hop is a propagator / sink.
- For virtual/interface edges: the CHA closure and whether it crosses the assembly boundary.

- [ ] **Step 14.4: Write Sanitizer Absence section**

Side-by-side pre-fix vs. post-fix snippets showing the missing check. Explain why its absence causes the OOM.

- [ ] **Step 14.5: Write Open Schema Questions section**

List any v0 schema inadequacies surfaced during the trace (expected candidates from the spec: O1 taint_value_state, O2 aggregate vs. scalar, O3 async — the last is unexercised in BMP and should be recorded as "untested, schema field exists"). For each, a concrete example of what the schema couldn't cleanly capture.

- [ ] **Step 14.6: Read-through**

Read `trace.md` end-to-end as if you didn't know the bug. Anywhere you'd have to jump to the YAML or the snippets to understand what's happening, expand the narrative inline.

- [ ] **Step 14.7: Commit**

```bash
git add fixtures/imagesharp-3074/trace.md
git commit -m "fixture: narrative companion for #3074 trace"
```

---

## Task 15: Final cross-check

- [ ] **Step 15.1: Full validator run**

Run: `dotnet run --project tools/ValidateFixture -- fixtures/imagesharp-3074/trace.yaml --snippets-dir fixtures/imagesharp-3074/prefix-snippets`
Expected: `OK: fixtures/imagesharp-3074/trace.yaml`, exit 0.

- [ ] **Step 15.2: All tests still pass**

Run: `dotnet test`
Expected: all validator tests pass.

- [ ] **Step 15.3: Solution builds clean**

Run: `dotnet build --no-incremental`
Expected: 0 warnings, 0 errors.

- [ ] **Step 15.4: Done-criteria checklist (from spec §Done criteria)**

Verify manually:
1. `trace.yaml` uses only vocabulary values — validator enforces this; re-reading not required.
2. Every `path[*].file:line` resolves — validator enforces FX040/FX041.
3. Every `path[*].method` is fully qualified; any pre-fix-only method is noted in `trace.md`.
4. `sanitizer_absence[*].fix_evidence.added_lines` cites the exact lines the fix added.
5. `trace.md` is readable end-to-end without the reader knowing the bug — re-read one more time cold.
6. Every virtual/interface edge has populated `resolved_targets` OR `closure_boundary: true` with a note — validator cannot catch this; eyeball.

- [ ] **Step 15.5: Final commit (if any fixups were needed)**

```bash
git add -A
git commit -m "fixture: final cross-check fixups for #3074 trace" || echo "nothing to commit"
```

---

## Out of scope for this plan

- Any analyzer code (Roslyn / Cecil / ILLink).
- Decisions on analyzer tech stack.
- Additional fixtures (#3067, #3071, #3078, #3079, #3082).
- Running the decoder / producing a crash PoC for #3074.
- Generalizing the fixture schema beyond v0.

---

## Revision history

- **2026-04-16** — Plan authored from spec `2026-04-16-imagesharp-3074-trace-design.md`.
- **2026-04-17** — Implemented. `ValidateFixture` + `ValidateFixture.Tests` projects committed; pre-fix fixture authored under what became `fixtures/imagesharp-3074-prefix/` after the M1→M-B rename in commit `8f0c892`. The validator (FX001–FX051) shipped here is still in active use through milestones C and D. Open question O1 (sanitizer node fields) was the explicit handoff to milestone B.
