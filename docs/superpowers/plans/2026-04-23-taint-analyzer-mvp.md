# Milestone C: Cecil-Based MVP Taint Analyzer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tools/TaintAnalyzer/` — a Mono.Cecil-based console app that reads a .NET DLL + rules.yaml and emits a `trace.yaml` conforming to schema v0.2. Extend `ValidateFixture` with a `--compare` mode (FX060/FX061/FX062/FX063) and prove end-to-end reproduction of the ImageSharp #3074 pre-fix AND post-fix ground-truth fixtures.

**Architecture:** Five components with single responsibilities — `RulesDocument` (YAML POCO), `AssemblyContext` (Cecil wrapper), `CallGraph` (flow-type narrowing + CHA closure), `TaintWalker` (forward IL pass with symbolic stack, local-taint map, and per-`this`-method field-taint summary), `TraceEmitter` (HopRecords → YAML). Plus two hardcoded shape-matcher files (`SinkShapes`, `SanitizerShapes`). Analyzer output is compared against ground truth via a new `ValidateFixture --compare` mode with four diagnostics. Test fixtures are a single sibling csproj (`TaintAnalyzer.Tests.Fixtures`) that compiles to a DLL+PDB pair consumed by all analyzer-component tests. ImageSharp is materialized per commit via `git archive | tar -x` to avoid touching the shared (shallow) clone.

**Tech Stack:** .NET 10 (SDK pinned in `global.json`), Mono.Cecil 0.11.6 + Mono.Cecil.Pdb 0.11.6, YamlDotNet 15.1.6 (already used by validator), xUnit 2.9.3, Shouldly 4.3.0. No new runtime dependencies in the validator project.

**Spec reference:** `docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md` at commits `7454e6d` → `5411e29` → `cb84690`.

---

## File Structure

**New analyzer project — `tools/TaintAnalyzer/`:**
- `TaintAnalyzer.csproj` — exe, net10.0, Mono.Cecil + YamlDotNet.
- `Program.cs` — CLI: arg parse, wire components, exit codes.
- `RulesDocument.cs` — POCO + loader + signature-form validator + nearest-candidate suggestion.
- `AssemblyContext.cs` — Cecil wrapper, method lookup by `FullName`, sequence-point access.
- `HopRecord.cs` — data classes: `HopRecord`, `HopKind`, `ResolvedDispatch`, `EmittedSanitizerAbsence`, `MethodSummary`.
- `SymbolicStack.cs` — value-type abstraction for the IL evaluation stack during taint tracking.
- `TaintState.cs` — mutable per-method state: locals map, `this`-field map, arg taint bitmask.
- `CallGraph.cs` — two-step virtual resolution (flow-type narrow → CHA), `closure_boundary` decision.
- `SinkShapes.cs` — three matchers (`MatchNewArr`, `MatchArrayPoolRent`, `MatchReadOnlySpanSlice`).
- `SanitizerShapes.cs` — two matchers + throw-helper predicate + branch-direction detector + bound extractor.
- `TaintWalker.cs` — forward IL pass, cross-method recursion with memoization, sequence-point fallback.
- `TraceEmitter.cs` — HopRecords → YAML via YamlDotNet, pre-fix `sanitizer_absence` synthesis.

**New analyzer tests — `tools/TaintAnalyzer.Tests/`:**
- `TaintAnalyzer.Tests.csproj` — xunit, Shouldly, ProjectReference to TaintAnalyzer.
- `RulesDocumentLoaderTests.cs`
- `AssemblyContextTests.cs`
- `CallGraphTests.cs`
- `SinkShapesTests.cs`
- `SanitizerShapesTests.cs`
- `TaintWalkerTests.cs`
- `TraceEmitterTests.cs`

**New test-fixture project — `tools/TaintAnalyzer.Tests.Fixtures/`:**
- `TaintAnalyzer.Tests.Fixtures.csproj` — library, net10.0, `<DebugType>portable</DebugType>`, sealed subclass IL needed.
- `Fixtures.cs` — C# source exercising every IL shape we test (one file, many classes/methods).

**Modified validator — `tools/ValidateFixture/`:**
- `FixtureValidator.cs` — add `Compare(groundTruth, analyzerOutput)` with FX060/FX061/FX062/FX063 diagnostics.
- `Program.cs` — add `--compare` subcommand branch.

**Modified validator tests — `tools/ValidateFixture.Tests/`:**
- `FixtureValidatorTests.cs` — add `CompareTests` nested class covering each diagnostic including metadata exemption and ±2-line tolerance.

**Solution + build-infrastructure:**
- `TaintAnalyzer.sln` — add three new csprojs.
- `.gitignore` — add `artifacts/`.

**Build script:**
- `scripts/materialize-imagesharp-3074.sh` — `git archive | tar -x` pre-fix and post-fix commits, `dotnet build -c Debug`.

**Rules files:**
- `fixtures/imagesharp-3074-prefix/rules.yaml`
- `fixtures/imagesharp-3074-postfix/rules.yaml`

---

## Task overview

1. Scaffold three new projects, wire solution, pin Cecil/YamlDotNet, `artifacts/` gitignored.
2. `RulesDocument.cs` + loader + signature-form validation.
3. `HopRecord.cs` + `SymbolicStack.cs` + `TaintState.cs` data classes.
4. `AssemblyContext.cs` + tests against a checked-in fixture DLL.
5. `SinkShapes.cs` + tests.
6. `SanitizerShapes.cs` throw-helper predicate + branch-direction detector + tests.
7. `SanitizerShapes.cs` bound extractor (compare-and-throw, compare-and-return-early) + tests.
8. `CallGraph.cs` two-step virtual resolution + tests.
9. `TaintWalker.cs` intra-method forward pass (stack + locals + arithmetic) + tests.
10. `TaintWalker.cs` `stfld`/`ldfld` on `this` + per-method summary + tests.
11. `TaintWalker.cs` cross-method recursion + memoization + tests.
12. `TaintWalker.cs` sanitizer + sink dispatch + sequence-point fallback + tests.
13. `TraceEmitter.cs` HopRecords → YAML + pre-fix `sanitizer_absence` synthesis + tests.
14. `Program.cs` CLI wiring + exit codes.
15. Validator `--compare` FX060 source mismatch.
16. Validator `--compare` FX061 sink mismatch + metadata exemption.
17. Validator `--compare` FX062 sanitizer_absence with ±2-line tolerance.
18. Validator `--compare` FX063 sanitizer hop with full bound match.
19. Validator `--compare` CLI wiring + diagnostic format.
20. `scripts/materialize-imagesharp-3074.sh` + `.gitignore` entry.
21. Rules files for #3074 pre-fix and post-fix.
22. End-to-end: pre-fix run + compare → exit 0.
23. End-to-end: post-fix run + compare → exit 0.
24. Bonus: #3079 pre-fix reproduction check.
25. Final cross-check: full test suite green, clean build, doc touch-ups.

---

## Task 1: Scaffold projects, wire solution, pin packages, gitignore `artifacts/`

**Files:**
- Create: `tools/TaintAnalyzer/TaintAnalyzer.csproj`
- Create: `tools/TaintAnalyzer/Program.cs` (placeholder so project builds)
- Create: `tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
- Create: `tools/TaintAnalyzer.Tests/ScaffoldingTest.cs` (single sanity test)
- Create: `tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj`
- Create: `tools/TaintAnalyzer.Tests.Fixtures/Placeholder.cs`
- Modify: `TaintAnalyzer.sln`
- Modify: `.gitignore`

- [ ] **Step 1.1: Write `tools/TaintAnalyzer/TaintAnalyzer.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RootNamespace>TaintAnalyzer</RootNamespace>
    <AssemblyName>TaintAnalyzer</AssemblyName>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Mono.Cecil" Version="0.11.6" />
    <PackageReference Include="YamlDotNet" Version="15.1.6" />
  </ItemGroup>

</Project>
```

- [ ] **Step 1.2: Write a placeholder `tools/TaintAnalyzer/Program.cs`**

```csharp
namespace TaintAnalyzer;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.Error.WriteLine("TaintAnalyzer: not yet implemented");
        return 2;
    }
}
```

- [ ] **Step 1.3: Write `tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`**

The test project references the analyzer project (to test its types) AND has a build-order dependency on the Fixtures project (to ensure the fixture DLL is built before tests run). The Fixtures project reference uses `ReferenceOutputAssembly="false"` — we don't want the Fixtures types in the test's reference set; we only want its DLL on disk for Cecil to read. `CopyToOutputDirectory` of the fixture assembly is wired so tests can find it at `Fixtures/*.dll`.

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <RootNamespace>TaintAnalyzer.Tests</RootNamespace>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="coverlet.collector" Version="6.0.4" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.14.1" />
    <PackageReference Include="Shouldly" Version="4.3.0" />
    <PackageReference Include="xunit" Version="2.9.3" />
    <PackageReference Include="xunit.runner.visualstudio" Version="3.1.4" />
  </ItemGroup>

  <ItemGroup>
    <Using Include="Xunit" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\TaintAnalyzer\TaintAnalyzer.csproj" />
    <ProjectReference Include="..\TaintAnalyzer.Tests.Fixtures\TaintAnalyzer.Tests.Fixtures.csproj"
                      ReferenceOutputAssembly="false"
                      Private="false" />
  </ItemGroup>

  <Target Name="CopyFixtureAssembly" AfterTargets="Build">
    <ItemGroup>
      <FixtureFiles Include="..\TaintAnalyzer.Tests.Fixtures\bin\$(Configuration)\$(TargetFramework)\TaintAnalyzer.Tests.Fixtures.*" />
    </ItemGroup>
    <Copy SourceFiles="@(FixtureFiles)"
          DestinationFolder="$(OutDir)Fixtures\"
          SkipUnchangedFiles="true" />
  </Target>

</Project>
```

- [ ] **Step 1.4: Write a single sanity test at `tools/TaintAnalyzer.Tests/ScaffoldingTest.cs`**

This test will be deleted in Task 2 when real tests appear, but confirms now that the project compiles and runs.

```csharp
namespace TaintAnalyzer.Tests;

public class ScaffoldingTest
{
    [Fact]
    public void ScaffoldingCompiles() => true.ShouldBeTrue();
}
```

Add a `using Shouldly;` at the top if xUnit/`ImplicitUsings` doesn't pick it up (it doesn't).

```csharp
using Shouldly;

namespace TaintAnalyzer.Tests;

public class ScaffoldingTest
{
    [Fact]
    public void ScaffoldingCompiles() => true.ShouldBeTrue();
}
```

- [ ] **Step 1.5: Write `tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj`**

Library, Debug-portable-PDB so sequence points are always available.

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <DebugType>portable</DebugType>
    <DebugSymbols>true</DebugSymbols>
    <Optimize>false</Optimize>
    <RootNamespace>TaintAnalyzer.Tests.Fixtures</RootNamespace>
  </PropertyGroup>

</Project>
```

- [ ] **Step 1.6: Write placeholder `tools/TaintAnalyzer.Tests.Fixtures/Placeholder.cs`**

This file gets replaced in later tasks. It exists now so the project has something to compile.

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

public static class Placeholder
{
    public static int Answer() => 42;
}
```

- [ ] **Step 1.7: Add the three projects to `TaintAnalyzer.sln`**

Run (from the repo root):

```bash
dotnet sln TaintAnalyzer.sln add \
  tools/TaintAnalyzer/TaintAnalyzer.csproj \
  tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj
```

Expected: "Project ... added to the solution." for each of the three.

- [ ] **Step 1.8: Append `artifacts/` to `.gitignore`**

Open `.gitignore` and append at the end:

```
# Materialized ImageSharp source trees and their build outputs
artifacts/
```

- [ ] **Step 1.9: Build everything**

Run: `dotnet build TaintAnalyzer.sln`
Expected: 0 errors, 0 warnings. Five projects reported built (two existing + three new).

- [ ] **Step 1.10: Run tests**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all existing ValidateFixture tests pass + the 1 new `ScaffoldingCompiles` test passes. Report line shows `Passed: <N+1>, Failed: 0`.

- [ ] **Step 1.11: Commit**

```bash
git add .gitignore TaintAnalyzer.sln tools/TaintAnalyzer tools/TaintAnalyzer.Tests tools/TaintAnalyzer.Tests.Fixtures
git commit -m "analyzer: scaffold TaintAnalyzer, TaintAnalyzer.Tests, TaintAnalyzer.Tests.Fixtures projects"
```

---

## Task 2: `RulesDocument.cs` — POCO, loader, signature-form validation

**Files:**
- Create: `tools/TaintAnalyzer/RulesDocument.cs`
- Create: `tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs`
- Delete: `tools/TaintAnalyzer.Tests/ScaffoldingTest.cs`

**Responsibility.** Parse a `rules.yaml` file into a `RulesDocument`, validate each `source_methods` entry against the signature form the spec prescribes (Cecil-`FullName`-compatible), and (at CLI time later) produce nearest-candidate suggestions for mis-spelled signatures. The loader here produces a `RulesDocument` + a separate `ValidateSignatures(AssemblyContext)` call added in later tasks (we do signature lexical validation only here; the "does this method exist in the assembly" check comes once AssemblyContext exists).

- [ ] **Step 2.1: Write `tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs` first (TDD)**

Start with tests that drive the API. The loader takes a YAML string, returns `RulesDocument` or throws `RulesDocumentException` with a message an engineer can act on.

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RulesDocumentLoaderTests
{
    [Fact]
    public void Load_ValidDocument_PopulatesFields()
    {
        const string yaml = """
            vuln_id: imagesharp-3074
            source_methods:
              - SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
            """;

        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBe("imagesharp-3074");
        doc.SourceMethods.ShouldHaveSingleItem();
        doc.SourceMethods[0].ShouldContain("BmpDecoderCore::Decode");
    }

    [Fact]
    public void Load_MissingSourceMethods_Throws()
    {
        const string yaml = "vuln_id: imagesharp-3074\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("source_methods");
        ex.Message.ShouldContain("required");
    }

    [Fact]
    public void Load_EmptySourceMethodsList_Throws()
    {
        const string yaml = """
            vuln_id: imagesharp-3074
            source_methods: []
            """;

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("source_methods");
        ex.Message.ShouldContain("empty");
    }

    [Fact]
    public void Load_OmittedVulnId_IsNull()
    {
        const string yaml = """
            source_methods:
              - Ns.Type::M(System.Int32)
            """;

        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBeNull();
    }

    [Theory]
    [InlineData("NoDoubleColon(Arg)", "missing '::'")]
    [InlineData("Ns.Type::Method", "missing '(' / ')'")]
    [InlineData("Ns.Type::Method(Arg", "missing '(' / ')'")]
    [InlineData("Ns.Type::Method Arg)", "no spaces")]
    [InlineData("Ns.Type::(Arg)", "empty method name")]
    [InlineData("::Method(Arg)", "empty declaring type")]
    public void Load_MalformedSignature_ThrowsWithActionableMessage(string sig, string expectedMessageFragment)
    {
        var yaml = $"source_methods:\n  - {sig}\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain(sig);
        ex.Message.ShouldContain(expectedMessageFragment);
    }

    [Fact]
    public void Load_MalformedYaml_ThrowsWithContext()
    {
        const string yaml = "source_methods:\n  - [broken\n";

        var ex = Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml));
        ex.Message.ShouldContain("YAML");
    }
}
```

- [ ] **Step 2.2: Delete the scaffolding test**

Run: `rm tools/TaintAnalyzer.Tests/ScaffoldingTest.cs`

- [ ] **Step 2.3: Run tests to confirm they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: compilation error — `RulesDocument` and `RulesDocumentException` are undefined.

- [ ] **Step 2.4: Write `tools/TaintAnalyzer/RulesDocument.cs`**

```csharp
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer;

public sealed class RulesDocumentException : Exception
{
    public RulesDocumentException(string message) : base(message) { }
    public RulesDocumentException(string message, Exception inner) : base(message, inner) { }
}

public sealed class RulesDocument
{
    [YamlMember(Alias = "vuln_id")] public string? VulnId { get; init; }
    [YamlMember(Alias = "source_methods")] public List<string> SourceMethods { get; init; } = new();

    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public static RulesDocument Load(string yaml)
    {
        RulesDocument? doc;
        try
        {
            doc = s_deserializer.Deserialize<RulesDocument>(yaml);
        }
        catch (YamlException ex)
        {
            throw new RulesDocumentException($"malformed YAML: {ex.Message}", ex);
        }

        if (doc is null)
        {
            throw new RulesDocumentException("rules document is empty");
        }

        if (doc.SourceMethods is null || doc.SourceMethods.Count == 0)
        {
            var state = doc.SourceMethods is null ? "required" : "empty";
            throw new RulesDocumentException($"source_methods is {state}: at least one entry expected");
        }

        foreach (var sig in doc.SourceMethods)
        {
            ValidateSignatureShape(sig);
        }

        return doc;
    }

    // Signature form: "Namespace.Type::Method(Param1,Param2,...)" — no spaces, non-empty declaring type
    // and method name, balanced parens. Full Cecil-FullName compatibility (generic arity, grave accents)
    // is handled implicitly by Cecil's string comparison at lookup time — we only enforce the surface shape.
    private static void ValidateSignatureShape(string sig)
    {
        if (sig.Contains(' '))
        {
            throw new RulesDocumentException($"invalid signature '{sig}': no spaces allowed in source_methods entries");
        }

        int colon = sig.IndexOf("::", StringComparison.Ordinal);
        if (colon < 0)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': missing '::' between declaring type and method name");
        }
        if (colon == 0)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': empty declaring type before '::'");
        }

        int paren = sig.IndexOf('(', colon + 2);
        int lastParen = sig.Length > 0 ? sig[^1] == ')' ? sig.Length - 1 : -1 : -1;
        if (paren < 0 || lastParen < 0 || lastParen <= paren)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': missing '(' / ')' bracketing the parameter list");
        }

        if (paren == colon + 2)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': empty method name between '::' and '('");
        }
    }
}
```

- [ ] **Step 2.5: Run tests to confirm they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: 11 tests passing (1 valid-load + 4 error-cases + 6 theory rows).

- [ ] **Step 2.6: Commit**

```bash
git add tools/TaintAnalyzer/RulesDocument.cs tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs tools/TaintAnalyzer.Tests/ScaffoldingTest.cs
git commit -m "analyzer: RulesDocument POCO + loader with signature-shape validation"
```

---

## Task 3: `HopRecord.cs`, `SymbolicStack.cs`, `TaintState.cs` — data classes

These are pure data — no tests yet. Tests come when the types get consumed by the walker in Task 9 onward.

**Files:**
- Create: `tools/TaintAnalyzer/HopRecord.cs`
- Create: `tools/TaintAnalyzer/SymbolicStack.cs`
- Create: `tools/TaintAnalyzer/TaintState.cs`

- [ ] **Step 3.1: Write `tools/TaintAnalyzer/HopRecord.cs`**

```csharp
namespace TaintAnalyzer;

public enum HopRole { Source, Propagator, Sanitizer, Sink }

public enum SinkKind { Allocation, SpanAccess }

public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex }

public enum FailureKind { Throw, ReturnEarly }

public sealed class ResolvedDispatch
{
    public required string Kind { get; init; }            // "direct" or "virtual"
    public required string StaticType { get; init; }
    public required IReadOnlyList<string> ResolvedTargets { get; init; }
    public required bool ClosureBoundary { get; init; }
}

public sealed class EstablishesBound
{
    public required string Target { get; init; }
    public required string Relation { get; init; }
    public string? UpperBound { get; init; }
    public string? LowerBound { get; init; }
}

public sealed class OnFailure
{
    public required FailureKind Kind { get; init; }
    public string? Exception { get; init; }
}

public sealed class HopRecord
{
    public required int Hop { get; init; }
    public required string Method { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required HopRole Role { get; init; }
    public required string TaintedValueIn { get; init; }
    public required string Transformation { get; init; }
    public required string TaintedValueOut { get; init; }
    public ResolvedDispatch? Dispatch { get; init; }
    public string? Note { get; init; }

    // Sanitizer-only
    public EstablishesBound? EstablishesBound { get; init; }
    public OnFailure? OnFailure { get; init; }

    // Sink-only
    public SinkKind? SinkKind { get; init; }
    public SinkApi? SinkApi { get; init; }
    public string? SizeExpression { get; init; }
    public string? AccessExpression { get; init; }
}

public sealed class EmittedSanitizerAbsence
{
    public required string Location { get; init; }        // "file:line"
    public required string ExpectedCheck { get; init; }
    public required string TaintedValue { get; init; }
}

// Per-method analysis summary used for cross-method propagation.
public sealed class MethodSummary
{
    public required string MethodFullName { get; init; }
    public required int TaintedParamBitmask { get; init; }
    public required bool ReturnsTainted { get; init; }
    public required IReadOnlyList<string> NewlyTaintedThisFields { get; init; }
    public required IReadOnlyList<HopRecord> Hops { get; init; }
    public required IReadOnlyList<EmittedSanitizerAbsence> Absences { get; init; }
    public required bool ReachedSink { get; init; }
}
```

- [ ] **Step 3.2: Write `tools/TaintAnalyzer/SymbolicStack.cs`**

The symbolic stack tracks which stack slots are "tainted" and carries a short provenance string (a readable name like `"stream"`, `"fileHeader"`, or `"fileHeader.Value.Offset"`) used in `tainted_value_in` / `tainted_value_out`. Fixed max depth of 64 is ample for well-formed IL.

```csharp
namespace TaintAnalyzer;

public readonly record struct StackSlot(bool Tainted, string Provenance)
{
    public static readonly StackSlot Untainted = new(false, "");
    public static StackSlot TaintedWith(string provenance) => new(true, provenance);
}

public sealed class SymbolicStack
{
    private readonly StackSlot[] _slots = new StackSlot[64];
    public int Depth { get; private set; }

    public void Push(StackSlot s)
    {
        if (Depth >= _slots.Length)
        {
            throw new InvalidOperationException("symbolic stack overflow");
        }
        _slots[Depth++] = s;
    }

    public StackSlot Pop()
    {
        if (Depth == 0)
        {
            throw new InvalidOperationException("symbolic stack underflow");
        }
        return _slots[--Depth];
    }

    public StackSlot Peek(int offsetFromTop = 0)
    {
        int idx = Depth - 1 - offsetFromTop;
        if (idx < 0)
        {
            throw new InvalidOperationException("symbolic stack underflow on peek");
        }
        return _slots[idx];
    }

    public bool AnyTainted()
    {
        for (int i = 0; i < Depth; i++)
        {
            if (_slots[i].Tainted) return true;
        }
        return false;
    }

    public void Clear() => Depth = 0;
}
```

- [ ] **Step 3.3: Write `tools/TaintAnalyzer/TaintState.cs`**

```csharp
using Mono.Cecil;

namespace TaintAnalyzer;

// Mutable state threaded through TaintWalker's forward pass over one method body.
public sealed class TaintState
{
    public SymbolicStack Stack { get; } = new();

    // Local variable taint by `VariableDefinition.Index`.
    public Dictionary<int, StackSlot> Locals { get; } = new();

    // Argument taint (by index; 0 = `this` for instance methods).
    public Dictionary<int, StackSlot> Args { get; } = new();

    // Field taint on the `this` receiver, keyed by `FieldDefinition.FullName`.
    public Dictionary<string, StackSlot> ThisFields { get; } = new();

    // Static-field taint, keyed by `FieldDefinition.FullName`.
    public Dictionary<string, StackSlot> StaticFields { get; } = new();
}
```

- [ ] **Step 3.4: Build**

Run: `dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj`
Expected: 0 errors, 0 warnings.

- [ ] **Step 3.5: Run all tests (nothing should regress)**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing, count unchanged from Task 2.

- [ ] **Step 3.6: Commit**

```bash
git add tools/TaintAnalyzer/HopRecord.cs tools/TaintAnalyzer/SymbolicStack.cs tools/TaintAnalyzer/TaintState.cs
git commit -m "analyzer: HopRecord, SymbolicStack, TaintState data classes"
```

---

## Task 4: `AssemblyContext.cs` — Cecil wrapper + tests

**Files:**
- Create: `tools/TaintAnalyzer/AssemblyContext.cs`
- Create: `tools/TaintAnalyzer.Tests/AssemblyContextTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Placeholder.cs` → rename to `Fixtures.cs`, expand.

**Responsibility.** Load an assembly with its PDB, expose `MethodDefinition` lookup by FQ name, expose sequence points keyed by `Instruction`. Auto-detect portable vs. Windows PDB (Cecil's default `SymbolReaderProvider` does this).

- [ ] **Step 4.1: Replace `Placeholder.cs` with `Fixtures.cs`**

Delete `tools/TaintAnalyzer.Tests.Fixtures/Placeholder.cs`. Create `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

// Fixture 1: a minimal class with one identifiable method for AssemblyContext tests.
// Future tasks extend this file with additional types; this file is the single
// sibling-csproj source per the milestone-C spec.
public static class SimpleShapes
{
    public static int Identity(int x) => x;
}
```

- [ ] **Step 4.2: Write the test file at `tools/TaintAnalyzer.Tests/AssemblyContextTests.cs` (TDD)**

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class AssemblyContextTests
{
    // Path relative to the test assembly's output dir. Task 1's csproj copies
    // the fixture DLL+PDB to `Fixtures/` under the test bin.
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Load_ReadsAssemblyWithSymbols()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        ctx.Assembly.ShouldNotBeNull();
        ctx.Assembly.MainModule.HasSymbols.ShouldBeTrue();
    }

    [Fact]
    public void FindMethod_ByCecilFullName_ReturnsDefinition()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Cecil's MethodReference.FullName shape: "<ReturnType> <Namespace.Type>::<Method>(<Params>)".
        // AssemblyContext.FindMethod accepts either the full "Ret Type::Method(Params)" form
        // OR the shorter "Type::Method(Params)" form used in rules files.
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");

        m.ShouldNotBeNull();
        m!.Name.ShouldBe("Identity");
    }

    [Fact]
    public void FindMethod_UnknownSignature_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::DoesNotExist(System.Int32)").ShouldBeNull();
    }

    [Fact]
    public void SequencePoints_AvailableForUserMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");
        m.ShouldNotBeNull();

        var anyWithPoint = false;
        foreach (var ins in m!.Body.Instructions)
        {
            if (m.DebugInformation.GetSequencePoint(ins) is { } sp && !sp.IsHidden)
            {
                sp.Document.Url.ShouldContain("Fixtures.cs");
                sp.StartLine.ShouldBeGreaterThan(0);
                anyWithPoint = true;
                break;
            }
        }
        anyWithPoint.ShouldBeTrue();
    }

    [Fact]
    public void Load_MissingPdb_Throws()
    {
        // Copy the fixture DLL to a temp path, do NOT copy its PDB, and confirm Load throws.
        var tmpDir = Path.Combine(Path.GetTempPath(), "TaintAnalyzerTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpDir);
        try
        {
            var dllCopy = Path.Combine(tmpDir, "noSymbols.dll");
            File.Copy(FixturePath, dllCopy);

            var ex = Should.Throw<AssemblyContextException>(() => AssemblyContext.Load(dllCopy));
            ex.Message.ShouldContain("symbols");
            ex.Message.ShouldContain("noSymbols.dll");
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }
}
```

- [ ] **Step 4.3: Run tests to confirm they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: compilation errors — `AssemblyContext`, `AssemblyContextException` undefined.

- [ ] **Step 4.4: Write `tools/TaintAnalyzer/AssemblyContext.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class AssemblyContextException : Exception
{
    public AssemblyContextException(string message) : base(message) { }
    public AssemblyContextException(string message, Exception inner) : base(message, inner) { }
}

public sealed class AssemblyContext : IDisposable
{
    public AssemblyDefinition Assembly { get; }

    private readonly Dictionary<string, MethodDefinition> _methodsByFullName;
    private readonly Dictionary<string, MethodDefinition> _methodsByShortSignature;

    private AssemblyContext(AssemblyDefinition asm)
    {
        Assembly = asm;

        _methodsByFullName = new Dictionary<string, MethodDefinition>(StringComparer.Ordinal);
        _methodsByShortSignature = new Dictionary<string, MethodDefinition>(StringComparer.Ordinal);

        foreach (var type in asm.MainModule.GetTypes())
        {
            foreach (var m in type.Methods)
            {
                _methodsByFullName[m.FullName] = m;
                var shortSig = BuildShortSignature(m);
                _methodsByShortSignature[shortSig] = m;
            }
        }
    }

    public static AssemblyContext Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new AssemblyContextException($"assembly not found: {path}");
        }

        var rp = new ReaderParameters
        {
            ReadSymbols = true,
            ReadWrite = false,
            InMemory = true,
        };

        AssemblyDefinition asm;
        try
        {
            asm = AssemblyDefinition.ReadAssembly(path, rp);
        }
        catch (Exception ex)
        {
            throw new AssemblyContextException(
                $"failed to load assembly with symbols at {path}: ensure a portable or Windows PDB sits next to the DLL. ({ex.Message})",
                ex);
        }

        return new AssemblyContext(asm);
    }

    // Accepts either full Cecil signature ("ReturnType Namespace.Type::Method(Params)")
    // OR short signature ("Namespace.Type::Method(Params)" — return type elided) as the
    // rules file form.
    public MethodDefinition? FindMethod(string signature)
    {
        if (_methodsByFullName.TryGetValue(signature, out var full))
        {
            return full;
        }
        if (_methodsByShortSignature.TryGetValue(signature, out var sh))
        {
            return sh;
        }
        return null;
    }

    public IEnumerable<MethodDefinition> AllMethods() => _methodsByFullName.Values;

    public IEnumerable<string> AllSignatures() => _methodsByShortSignature.Keys;

    public SequencePoint? GetSequencePoint(MethodDefinition method, Instruction instruction)
    {
        var direct = method.DebugInformation.GetSequencePoint(instruction);
        if (direct is { IsHidden: false })
        {
            return direct;
        }

        // Fallback: walk backward to the nearest non-hidden sequence point.
        for (var cur = instruction.Previous; cur is not null; cur = cur.Previous)
        {
            var sp = method.DebugInformation.GetSequencePoint(cur);
            if (sp is { IsHidden: false })
            {
                return sp;
            }
        }
        return null;
    }

    public void Dispose() => Assembly.Dispose();

    private static string BuildShortSignature(MethodDefinition m)
    {
        var ps = new List<string>(m.Parameters.Count);
        foreach (var p in m.Parameters)
        {
            ps.Add(p.ParameterType.FullName);
        }
        return $"{m.DeclaringType.FullName}::{m.Name}({string.Join(",", ps)})";
    }
}
```

A note on the `Load_MissingPdb_Throws` test: Mono.Cecil with `ReadSymbols = true` throws (typically `SymbolsNotFoundException`) when the PDB is missing. We wrap and surface the message.

- [ ] **Step 4.5: Run tests to confirm they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: 5 tests passing (the existing 11 from Task 2 plus 5 new). Total: 16.

- [ ] **Step 4.6: Commit**

```bash
git add tools/TaintAnalyzer/AssemblyContext.cs tools/TaintAnalyzer.Tests/AssemblyContextTests.cs tools/TaintAnalyzer.Tests.Fixtures/Placeholder.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: AssemblyContext — Cecil wrapper with FullName lookup and sequence-point fallback"
```

---

## Task 5: `SinkShapes.cs` + tests

**Files:**
- Create: `tools/TaintAnalyzer/SinkShapes.cs`
- Create: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add sink-shape fixture methods.

**Responsibility.** Three pure-function matchers: `MatchNewArr`, `MatchArrayPoolRent`, `MatchReadOnlySpanSlice`. Each takes the current `Instruction` and a `SymbolicStack` view and returns a `SinkMatch?` when the instruction is a sink shape AND the critical argument (size / index) is tainted. Matchers are shallow — they do not walk back through the IL, they only look at the stack as it stands.

- [ ] **Step 5.1: Extend `Fixtures.cs` with sink-shape methods**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
using System.Buffers;

namespace TaintAnalyzer.Tests.Fixtures;

public static class SinkFixtures
{
    // newarr shape: `new byte[size]` — emits `newarr`.
    public static byte[] NewByteArray(int size) => new byte[size];

    // ArrayPool.Rent shape.
    public static byte[] ArrayPoolRent(int size) => ArrayPool<byte>.Shared.Rent(size);

    // ReadOnlySpan<T>.Slice shape. Wraps a byte[] to a ROS<byte>, then slices.
    public static ReadOnlySpan<byte> SliceSpan(ReadOnlySpan<byte> src, int start, int length)
        => src.Slice(start, length);
}
```

- [ ] **Step 5.2: Write `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SinkShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    [Fact]
    public void MatchNewArr_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::NewByteArray(System.Int32)");

        var newarr = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Newarr);
        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("size"));

        var match = SinkShapes.MatchNewArr(newarr, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.NewArray);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchNewArr_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::NewByteArray(System.Int32)");
        var newarr = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Newarr);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchNewArr(newarr, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchArrayPoolRent_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::ArrayPoolRent(System.Int32)");

        var callRent = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr &&
            mr.Name == "Rent" &&
            mr.DeclaringType.FullName.StartsWith("System.Buffers.ArrayPool", StringComparison.Ordinal));

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);               // the ArrayPool<byte>.Shared receiver
        stack.Push(StackSlot.TaintedWith("size"));     // the `size` arg

        var match = SinkShapes.MatchArrayPoolRent(callRent, stack);
        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.ArrayPoolRent);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchArrayPoolRent_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::ArrayPoolRent(System.Int32)");
        var callRent = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr &&
            mr.Name == "Rent");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchArrayPoolRent(callRent, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchReadOnlySpanSlice_EitherArgTainted_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::SliceSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32,System.Int32)");

        var callSlice = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Slice" &&
            mr.DeclaringType.FullName.StartsWith("System.ReadOnlySpan", StringComparison.Ordinal));

        // Stack layout for a ROS<T>::Slice(int,int) instance call: [this, start, length]
        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                   // receiver
        stack.Push(StackSlot.TaintedWith("start"));        // tainted start
        stack.Push(StackSlot.Untainted);                   // untainted length

        var match = SinkShapes.MatchReadOnlySpanSlice(callSlice, stack);
        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SpanAccess);
        match.Api.ShouldBe(SinkApi.SpanSlice);
        match.SizeProvenance.ShouldBe("start");
    }

    [Fact]
    public void MatchReadOnlySpanSlice_BothArgsUntainted_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::SliceSpan(System.ReadOnlySpan`1<System.Byte>,System.Int32,System.Int32)");
        var callSlice = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr && mr.Name == "Slice");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchReadOnlySpanSlice(callSlice, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchNewArr_NonNewarrInstruction_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");
        var anyInstruction = m.Body.Instructions.First();

        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("x"));

        SinkShapes.MatchNewArr(anyInstruction, stack).ShouldBeNull();
    }
}
```

- [ ] **Step 5.3: Run tests to confirm they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: compilation error — `SinkShapes`, `SinkMatch` undefined.

- [ ] **Step 5.4: Write `tools/TaintAnalyzer/SinkShapes.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class SinkMatch
{
    public required SinkKind Kind { get; init; }
    public required SinkApi Api { get; init; }
    public required string SizeProvenance { get; init; }
}

public static class SinkShapes
{
    public static SinkMatch? MatchNewArr(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Newarr) return null;
        if (stack.Depth == 0) return null;

        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.NewArray,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    public static SinkMatch? MatchArrayPoolRent(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "Rent") return null;
        if (!mr.DeclaringType.FullName.StartsWith("System.Buffers.ArrayPool", StringComparison.Ordinal))
        {
            return null;
        }
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.Int32") return null;

        if (stack.Depth < 2) return null;
        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.ArrayPoolRent,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    public static SinkMatch? MatchReadOnlySpanSlice(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "Slice") return null;
        if (!mr.DeclaringType.FullName.StartsWith("System.ReadOnlySpan", StringComparison.Ordinal))
        {
            return null;
        }

        // Slice(int32) — one-arg overload (start only)
        // Slice(int32, int32) — two-arg overload (start + length)
        int argCount = mr.Parameters.Count;
        if (argCount is not (1 or 2)) return null;
        if (stack.Depth < argCount + 1) return null;   // +1 for receiver

        // For the two-arg overload, either `start` or `length` tainted qualifies.
        // For the one-arg, only `start` is a slot.
        StackSlot? taintedSlot = null;
        for (int i = 0; i < argCount; i++)
        {
            var slot = stack.Peek(i);
            if (slot.Tainted)
            {
                taintedSlot = slot;
                break;
            }
        }

        if (taintedSlot is null) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SpanAccess,
            Api = SinkApi.SpanSlice,
            SizeProvenance = taintedSlot.Value.Provenance,
        };
    }
}
```

- [ ] **Step 5.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: 7 new tests passing. Total: 23.

If the `MatchReadOnlySpanSlice` tests can't find the `Slice` call in `SliceSpan` (because Roslyn sometimes emits `ReadOnlySpan`'s Slice via the indexer), swap the `SliceSpan` body to explicitly call `src.Slice(start, length)` as written — the test already does. Re-check `FixturePath` copy semantics from Task 1.3 if the fixture DLL can't be found.

- [ ] **Step 5.6: Commit**

```bash
git add tools/TaintAnalyzer/SinkShapes.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: SinkShapes — newarr / ArrayPool.Rent / ReadOnlySpan.Slice matchers"
```

---

## Task 6: `SanitizerShapes.cs` — throw-helper predicate + branch-direction detector

This task builds the scaffolding (`SanitizerShapes` static class, `ThrowHelperPredicate`, `BranchSides` data) without yet emitting `EstablishesBound`. Task 7 adds bound extraction and the full matcher.

**Files:**
- Create: `tools/TaintAnalyzer/SanitizerShapes.cs`
- Create: `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add sanitizer-shape fixtures.

- [ ] **Step 6.1: Extend `Fixtures.cs` with sanitizer fixtures**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
using System.Diagnostics.CodeAnalysis;

namespace TaintAnalyzer.Tests.Fixtures;

// Throw-helpers — various shapes the predicate must classify.
public static class ThrowHelpers
{
    [DoesNotReturn]
    public static void ThrowOutOfRange(string name)
        => throw new ArgumentOutOfRangeException(name);

    [DoesNotReturn]
    public static void ThrowInvalidImageContentException(string msg)
        => throw new InvalidOperationException(msg);

    // Starts with "Throw", has [DoesNotReturn], but does NOT actually throw on all paths.
    // Predicate should still accept (DoesNotReturn takes precedence).
    [DoesNotReturn]
    public static void ThrowByAssertFailure()
    {
        // Intentionally empty — will raise ExecutionEngineException at runtime; still marked DoesNotReturn.
        throw new InvalidOperationException("unreachable");
    }

    // Non-throw-helpers — predicate must reject each.
    public static void DoWork() { }                              // no Throw prefix
    public static void ThrowSomething() { }                      // name OK but no DoesNotReturn, body returns
    public static int  ThrowInt() { throw new Exception(); }     // non-void return
}

// Sanitizer fixtures — different shapes the matcher must recognize.
public static class SanitizerFixtures
{
    // Shape A: compiler-negated branch (`if (x > y) throw` → IL `ble.un SAFE; <throw>; SAFE:`).
    public static void NegatedBranchThrow(int x, int y)
    {
        if (x > y)
        {
            ThrowHelpers.ThrowOutOfRange(nameof(x));
        }
    }

    // Shape B: explicit else branch (`if (x <= y) { /*safe*/ } else { throw }` →
    // typically IL `bgt ELSE; /*safe*/ br END; ELSE: <throw>; END:`).
    public static void NonNegatedBranchThrow(int x, int y)
    {
        if (x <= y)
        {
            // safe body, intentionally empty
        }
        else
        {
            ThrowHelpers.ThrowOutOfRange(nameof(x));
        }
    }

    // Shape C: return-early — `if (x < 0) return;`
    public static int ReturnEarlyOnNegative(int x)
    {
        if (x < 0) return -1;
        return x * 2;
    }

    // Shape D: no sanitizer — straight-line code, for negative tests.
    public static int NoSanitizer(int x) => x * 2;
}
```

- [ ] **Step 6.2: Write the tests scoped to Task 6 capabilities**

Create `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`:

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SanitizerShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    // --- Throw-helper predicate tests (Task 6) ---

    [Theory]
    [InlineData("ThrowOutOfRange",                     true)]
    [InlineData("ThrowInvalidImageContentException",   true)]
    [InlineData("ThrowByAssertFailure",                true)]  // DoesNotReturn marker wins
    [InlineData("DoWork",                              false)] // no Throw prefix
    [InlineData("ThrowSomething",                      false)] // no DoesNotReturn, body returns
    [InlineData("ThrowInt",                            false)] // non-void return
    public void IsThrowHelper_Classifies(string methodName, bool expected)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowHelpers" && md.Name == methodName);

        SanitizerShapes.IsThrowHelper(m).ShouldBe(expected);
    }

    [Fact]
    public void ResolveExceptionType_FromThrowHelperBody_ReturnsFirstNewobjType()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods()
            .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ThrowHelpers" && md.Name == "ThrowOutOfRange");

        SanitizerShapes.ResolveExceptionType(m).ShouldBe("System.ArgumentOutOfRangeException");
    }

    [Fact]
    public void ResolveExceptionType_FallsBackToNameSuffix_WhenBodyUnresolvable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        // We fabricate the fallback scenario by calling the helper for a method whose body
        // the implementation deliberately ignores. For this test, verify direct-suffix resolution
        // works on a representative helper name.
        SanitizerShapes.NameSuffixException("ThrowInvalidImageContentException")
            .ShouldBe("InvalidImageContentException");
        SanitizerShapes.NameSuffixException("ThrowOutOfRange")
            .ShouldBe("OutOfRange");
        SanitizerShapes.NameSuffixException("DoWork")
            .ShouldBeNull();
    }

    // --- Branch-direction detector tests (Task 6) ---

    [Fact]
    public void DetectBranchSides_NegatedBranchThrow_ThrowSideIsFallThrough()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NegatedBranchThrow(System.Int32,System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);

        sides.ShouldNotBeNull();
        sides!.FailureSideIsBranchTarget.ShouldBeFalse();  // `ble.un SAFE` — fall-through is the failure (throw) body
    }

    [Fact]
    public void DetectBranchSides_NonNegatedBranchThrow_ThrowSideIsBranchTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NonNegatedBranchThrow(System.Int32,System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);

        sides.ShouldNotBeNull();
        sides!.FailureSideIsBranchTarget.ShouldBeTrue();   // `bgt ELSE` — branch target is the failure (throw) body
    }

    [Fact]
    public void DetectBranchSides_ReturnEarly_FailureSideIsBranchTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::ReturnEarlyOnNegative(System.Int32)");
        var branch = FindConditionalBranch(m);

        var sides = SanitizerShapes.DetectBranchSides(branch, m);
        sides.ShouldNotBeNull();
        sides!.FailureKind.ShouldBe(FailureKind.ReturnEarly);
    }

    [Fact]
    public void DetectBranchSides_NoSanitizer_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NoSanitizer(System.Int32)");

        // No conditional branch in the body at all -> trivially no sanitizer.
        var anyCondBranch = m.Body.Instructions.FirstOrDefault(i => IsConditionalBranch(i.OpCode));
        anyCondBranch.ShouldBeNull();
    }

    private static Instruction FindConditionalBranch(MethodDefinition m)
        => m.Body.Instructions.First(i => IsConditionalBranch(i.OpCode));

    private static bool IsConditionalBranch(OpCode op)
        => op.FlowControl == FlowControl.Cond_Branch && op.Code != Code.Switch;
}
```

- [ ] **Step 6.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: compilation error — `SanitizerShapes` and its members undefined.

- [ ] **Step 6.4: Write Task 6's slice of `tools/TaintAnalyzer/SanitizerShapes.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class BranchSides
{
    public required bool FailureSideIsBranchTarget { get; init; }
    public required FailureKind FailureKind { get; init; }
    public required MethodReference? ThrowHelper { get; init; }   // null when FailureKind == ReturnEarly
}

public static class SanitizerShapes
{
    private const string DoesNotReturnFullName = "System.Diagnostics.CodeAnalysis.DoesNotReturnAttribute";

    public static bool IsThrowHelper(MethodDefinition m)
    {
        if (m.ReturnType.FullName != "System.Void") return false;
        if (!m.Name.StartsWith("Throw", StringComparison.Ordinal)) return false;

        foreach (var ca in m.CustomAttributes)
        {
            if (ca.AttributeType.FullName == DoesNotReturnFullName) return true;
        }

        // Fallback: every return path ends in throw. For MVP we accept the simpler heuristic —
        // the body contains at least one `throw` and no `ret` instruction at all.
        if (m.Body is null) return false;
        bool hasThrow = false, hasRet = false;
        foreach (var ins in m.Body.Instructions)
        {
            if (ins.OpCode == OpCodes.Throw || ins.OpCode == OpCodes.Rethrow) hasThrow = true;
            if (ins.OpCode == OpCodes.Ret) hasRet = true;
        }
        return hasThrow && !hasRet;
    }

    public static string? ResolveExceptionType(MethodDefinition throwHelper)
    {
        // Walk the body for the first `newobj <ExceptionCtor>` and return the declaring type's FullName.
        if (throwHelper.Body is not null)
        {
            foreach (var ins in throwHelper.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Newobj && ins.Operand is MethodReference ctor)
                {
                    return ctor.DeclaringType.FullName;
                }
            }
        }
        return NameSuffixException(throwHelper.Name);
    }

    // Extract the type-suffix of a throw-helper name: "ThrowInvalidImageContentException" → "InvalidImageContentException".
    public static string? NameSuffixException(string helperName)
    {
        if (!helperName.StartsWith("Throw", StringComparison.Ordinal)) return null;
        var suffix = helperName.Substring(5);
        return string.IsNullOrEmpty(suffix) ? null : suffix;
    }

    // Identify failure/safe sides of a conditional branch. Returns null when no branch side
    // structurally maps to "failure" (throw-helper call then exit, or unconditional ret).
    public static BranchSides? DetectBranchSides(Instruction conditionalBranch, MethodDefinition containingMethod)
    {
        if (conditionalBranch.OpCode.FlowControl != FlowControl.Cond_Branch
            || conditionalBranch.OpCode.Code == Code.Switch)
        {
            return null;
        }

        var target = (Instruction)conditionalBranch.Operand;
        var fallThrough = conditionalBranch.Next;
        if (fallThrough is null) return null;

        var branchTargetOutcome = ClassifyArm(target, containingMethod);
        var fallThroughOutcome  = ClassifyArm(fallThrough, containingMethod);

        // "Failure" = the arm that reaches a throw-helper-exit or a ret without further propagation.
        bool targetIsFailure = branchTargetOutcome.IsFailure;
        bool fallIsFailure   = fallThroughOutcome.IsFailure;

        if (targetIsFailure == fallIsFailure)
        {
            // Neither arm (or both) look like failure — not a sanitizer shape.
            return null;
        }

        var failureOutcome = targetIsFailure ? branchTargetOutcome : fallThroughOutcome;

        return new BranchSides
        {
            FailureSideIsBranchTarget = targetIsFailure,
            FailureKind = failureOutcome.Kind,
            ThrowHelper = failureOutcome.ThrowHelper,
        };
    }

    private readonly record struct ArmOutcome(bool IsFailure, FailureKind Kind, MethodReference? ThrowHelper);

    // Walk straight-line IL from `start`, bounded by a small budget, looking for:
    //  - a call to a throw-helper followed by exit (throw or ret) → failure with kind=Throw
    //  - an unconditional `ret` with no side effects beyond local stores → failure with kind=ReturnEarly
    // Branches in the arm body abort the classification (not a straight-line failure body).
    private static ArmOutcome ClassifyArm(Instruction start, MethodDefinition method)
    {
        const int budget = 40;
        var cur = start;
        int steps = 0;
        while (cur is not null && steps++ < budget)
        {
            if (cur.OpCode.FlowControl == FlowControl.Cond_Branch
                || cur.OpCode == OpCodes.Switch)
            {
                return new ArmOutcome(false, default, null);
            }

            if ((cur.OpCode == OpCodes.Call || cur.OpCode == OpCodes.Callvirt)
                && cur.Operand is MethodReference mr)
            {
                var resolved = SafeResolve(mr);
                if (resolved is not null && IsThrowHelper(resolved))
                {
                    return new ArmOutcome(true, FailureKind.Throw, mr);
                }
                // A non-throw-helper call means the arm has side effects — not a pure failure body.
                return new ArmOutcome(false, default, null);
            }

            if (cur.OpCode == OpCodes.Throw || cur.OpCode == OpCodes.Rethrow)
            {
                return new ArmOutcome(true, FailureKind.Throw, null);
            }

            if (cur.OpCode == OpCodes.Ret)
            {
                return new ArmOutcome(true, FailureKind.ReturnEarly, null);
            }

            if (cur.OpCode.FlowControl == FlowControl.Branch)
            {
                // An unconditional branch mid-arm — follow it once.
                cur = (Instruction)cur.Operand;
                continue;
            }

            cur = cur.Next;
        }
        return new ArmOutcome(false, default, null);
    }

    private static MethodDefinition? SafeResolve(MethodReference mr)
    {
        try { return mr.Resolve(); }
        catch { return null; }
    }
}
```

- [ ] **Step 6.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapes"`
Expected: 11 new tests passing (6 throw-helper theory rows + 2 ResolveException + 3 branch-direction + 1 no-sanitizer = 12; adjust expected count to whatever xUnit reports; all passing).

- [ ] **Step 6.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing. No regressions.

- [ ] **Step 6.7: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: SanitizerShapes — throw-helper predicate + branch-direction detector"
```

---

## Task 7: `SanitizerShapes.cs` — bound extractor + full matcher

**Files:**
- Modify: `tools/TaintAnalyzer/SanitizerShapes.cs`
- Modify: `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add per-opcode fixtures (bgt/blt/bge/ble/beq/bne).

- [ ] **Step 7.1: Extend `Fixtures.cs` with one fixture per bound-extraction row**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

// Each method has exactly one conditional branch, all with `x` as the left operand and `y` as the right,
// a throw-helper on the failure side. The matcher should produce (target=x, relation/upper|lower=y).
public static class SanitizerBoundsFixtures
{
    // Compiler-negated forms (fall-through = throw) — Roslyn typically emits these for simple if-throw.
    public static void GtThrow(int x, int y) { if (x >  y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x <= y
    public static void LtThrow(int x, int y) { if (x <  y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x >= y
    public static void GeThrow(int x, int y) { if (x >= y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x <  y
    public static void LeThrow(int x, int y) { if (x <= y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x >  y
    public static void EqThrow(int x, int y) { if (x == y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x != y
    public static void NeThrow(int x, int y) { if (x != y) ThrowHelpers.ThrowOutOfRange(nameof(x)); }  // safe: x == y

    // Explicit-else form (branch-target = throw).
    public static void GtThrowElse(int x, int y)
    {
        if (x <= y) { /* safe */ }
        else { ThrowHelpers.ThrowOutOfRange(nameof(x)); }
    }
}
```

- [ ] **Step 7.2: Extend `SanitizerShapesTests.cs` with matcher tests**

Append at the end of the class:

```csharp
    // --- Full matcher: compare-and-throw / compare-and-return-early (Task 7) ---

    [Theory]
    [InlineData("GtThrow", ">",  "y", true,  null)]   // safe: x <= y → relation "<=", upper_bound y. Table maps it as "> / upper_bound y when fall-through-safe".
    [InlineData("LtThrow", "<",  null, null, "y")]    // safe: x >= y → relation ">=", lower_bound y.
    [InlineData("GeThrow", ">=", "y", true,  null)]   // safe: x < y  → relation "<",  upper_bound y.
    [InlineData("LeThrow", "<=", null, null, "y")]    // safe: x > y  → relation ">",  lower_bound y.
    [InlineData("EqThrow", "==", "y", true,  null)]   // safe: x != y → relation "!=", upper_bound y (single-value convention).
    [InlineData("NeThrow", "!=", "y", true,  null)]   // safe: x == y → relation "==", upper_bound y.
    public void MatchCompareAndThrow_Negated_EmitsCorrectBound(
        string fixtureName, string taintedSideOperator, string? expectedUpper, bool? _, string? expectedLower)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.AllMethods().First(md =>
            md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.SanitizerBoundsFixtures"
            && md.Name == fixtureName);

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        match!.OnFailure.Kind.ShouldBe(FailureKind.Throw);
        match.OnFailure.Exception.ShouldBe("System.ArgumentOutOfRangeException");
        match.EstablishesBound.Target.ShouldBe("x");

        // Expected relation from the operator mapping in the spec.
        var expectedRelation = fixtureName switch
        {
            "GtThrow" => "<=",
            "LtThrow" => ">=",
            "GeThrow" => "<",
            "LeThrow" => ">",
            "EqThrow" => "!=",
            "NeThrow" => "==",
            _ => throw new InvalidOperationException(),
        };
        match.EstablishesBound.Relation.ShouldBe(expectedRelation);
        match.EstablishesBound.UpperBound.ShouldBe(expectedUpper);
        match.EstablishesBound.LowerBound.ShouldBe(expectedLower);
    }

    [Fact]
    public void MatchCompareAndThrow_ExplicitElse_FlipsDirectionCorrectly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerBoundsFixtures::GtThrowElse(System.Int32,System.Int32)");

        var match = SanitizerShapes.MatchCompareAndThrow(m);

        match.ShouldNotBeNull();
        // Same semantic end result as GtThrow: safe side says x <= y.
        match!.EstablishesBound.Relation.ShouldBe("<=");
        match.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.UpperBound.ShouldBe("y");
    }

    [Fact]
    public void MatchCompareAndReturnEarly_EmitsReturnEarlyHop()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::ReturnEarlyOnNegative(System.Int32)");

        var match = SanitizerShapes.MatchCompareAndReturnEarly(m);

        match.ShouldNotBeNull();
        match!.OnFailure.Kind.ShouldBe(FailureKind.ReturnEarly);
        match.EstablishesBound.Target.ShouldBe("x");
        match.EstablishesBound.Relation.ShouldBe(">=");
        match.EstablishesBound.LowerBound.ShouldBe("0");
    }

    [Fact]
    public void MatchCompareAndThrow_NoSanitizer_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SanitizerFixtures::NoSanitizer(System.Int32)");

        SanitizerShapes.MatchCompareAndThrow(m).ShouldBeNull();
    }
```

- [ ] **Step 7.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapes"`
Expected: compilation error — `MatchCompareAndThrow`, `MatchCompareAndReturnEarly`, and `SanitizerMatch` undefined.

- [ ] **Step 7.4: Add the matcher and bound extractor to `SanitizerShapes.cs`**

Append to `tools/TaintAnalyzer/SanitizerShapes.cs`:

```csharp
public sealed class SanitizerMatch
{
    public required EstablishesBound EstablishesBound { get; init; }
    public required OnFailure OnFailure { get; init; }
    public required int ComparisonIlOffset { get; init; }        // IL offset of the conditional branch
}
```

Then add these static methods inside the existing `public static class SanitizerShapes` — insert before the closing brace of the class:

```csharp
    public static SanitizerMatch? MatchCompareAndThrow(MethodDefinition method)
        => MatchSanitizer(method, requiredFailureKind: FailureKind.Throw);

    public static SanitizerMatch? MatchCompareAndReturnEarly(MethodDefinition method)
        => MatchSanitizer(method, requiredFailureKind: FailureKind.ReturnEarly);

    private static SanitizerMatch? MatchSanitizer(MethodDefinition method, FailureKind requiredFailureKind)
    {
        if (method.Body is null) return null;

        foreach (var ins in method.Body.Instructions)
        {
            if (ins.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
            if (ins.OpCode == OpCodes.Switch) continue;

            var sides = DetectBranchSides(ins, method);
            if (sides is null) continue;
            if (sides.FailureKind != requiredFailureKind) continue;

            var operands = ExtractComparisonOperands(ins, method);
            if (operands is null) continue;

            var bound = ReadBoundFromSafeSide(ins.OpCode.Code, operands.Value, sides.FailureSideIsBranchTarget);
            if (bound is null) continue;

            string? exception = null;
            if (sides.FailureKind == FailureKind.Throw && sides.ThrowHelper is { } helper)
            {
                var resolved = SafeResolve(helper);
                exception = resolved is not null ? ResolveExceptionType(resolved) : NameSuffixException(helper.Name);
            }

            return new SanitizerMatch
            {
                EstablishesBound = bound,
                OnFailure = new OnFailure
                {
                    Kind = sides.FailureKind,
                    Exception = exception,
                },
                ComparisonIlOffset = ins.Offset,
            };
        }

        return null;
    }

    private readonly record struct ComparisonOperands(string Left, string Right);

    // Walk back from the conditional branch to its two stack operands.
    // Handles the simplest shapes we need for #3074/#3079: ldarg/ldarg.N, ldloc, ldfld, ldc.*.
    private static ComparisonOperands? ExtractComparisonOperands(Instruction branch, MethodDefinition method)
    {
        // IL comparison is: <push left>; <push right>; <cond_branch>
        var rightIns = branch.Previous;
        if (rightIns is null) return null;
        var leftIns  = rightIns.Previous;
        if (leftIns is null) return null;

        var right = OperandName(rightIns, method);
        var left  = OperandName(leftIns, method);
        if (right is null || left is null) return null;

        return new ComparisonOperands(left, right);
    }

    private static string? OperandName(Instruction ins, MethodDefinition method)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Ldarg_0: return method.HasThis ? "this" : method.Parameters[0].Name;
            case Code.Ldarg_1: return method.HasThis ? method.Parameters[0].Name : method.Parameters[1].Name;
            case Code.Ldarg_2: return method.HasThis ? method.Parameters[1].Name : method.Parameters[2].Name;
            case Code.Ldarg_3: return method.HasThis ? method.Parameters[2].Name : method.Parameters[3].Name;
            case Code.Ldarg:
            case Code.Ldarg_S when ins.Operand is ParameterDefinition:
                return ((ParameterDefinition)ins.Operand).Name;
            case Code.Ldloc:
            case Code.Ldloc_S:
                return ((VariableDefinition)ins.Operand).Name ?? $"loc_{((VariableDefinition)ins.Operand).Index}";
            case Code.Ldloc_0: return LocalName(method, 0);
            case Code.Ldloc_1: return LocalName(method, 1);
            case Code.Ldloc_2: return LocalName(method, 2);
            case Code.Ldloc_3: return LocalName(method, 3);
            case Code.Ldfld:
                return ins.Operand is FieldReference fr ? fr.Name : null;
            case Code.Ldsfld:
                return ins.Operand is FieldReference sfr ? $"{sfr.DeclaringType.Name}.{sfr.Name}" : null;
            case Code.Ldc_I4_0: return "0";
            case Code.Ldc_I4_1: return "1";
            case Code.Ldc_I4_2: return "2";
            case Code.Ldc_I4_3: return "3";
            case Code.Ldc_I4_4: return "4";
            case Code.Ldc_I4_5: return "5";
            case Code.Ldc_I4_6: return "6";
            case Code.Ldc_I4_7: return "7";
            case Code.Ldc_I4_8: return "8";
            case Code.Ldc_I4_M1: return "-1";
            case Code.Ldc_I4:
            case Code.Ldc_I4_S:
                return ins.Operand?.ToString();
        }
        return null;
    }

    private static string LocalName(MethodDefinition m, int idx)
    {
        if (m.Body?.Variables is { } vars && idx < vars.Count)
        {
            return vars[idx].Name ?? $"loc_{idx}";
        }
        return $"loc_{idx}";
    }

    // Spec's bound-extraction table. `branchTakenIsFailure = true` means the branch TARGET is the failure
    // side (explicit-else form); `false` means the fall-through is the failure side (compiler-negated form).
    private static EstablishesBound? ReadBoundFromSafeSide(Code opCode, ComparisonOperands ops, bool branchTargetIsFailure)
    {
        // "Taken predicate" is the condition under which the conditional branch fires.
        // If failure = branch-target, the safe side is fall-through where the taken-predicate is false (negate).
        // If failure = fall-through,  the safe side is branch-target where the taken-predicate is true.
        bool safeIsTaken = branchTargetIsFailure;  // safe = the side that's NOT failure

        string relation;
        string? upper = null, lower = null;

        switch (opCode)
        {
            case Code.Bgt:
            case Code.Bgt_Un:
                (relation, lower, upper) = safeIsTaken
                    ? (">",  ops.Right, null)
                    : ("<=", null,     ops.Right);
                break;
            case Code.Blt:
            case Code.Blt_Un:
                (relation, lower, upper) = safeIsTaken
                    ? ("<",  null,     ops.Right)
                    : (">=", ops.Right, null);
                break;
            case Code.Bge:
            case Code.Bge_Un:
                (relation, lower, upper) = safeIsTaken
                    ? (">=", ops.Right, null)
                    : ("<",  null,     ops.Right);
                break;
            case Code.Ble:
            case Code.Ble_Un:
                (relation, lower, upper) = safeIsTaken
                    ? ("<=", null,     ops.Right)
                    : (">",  ops.Right, null);
                break;
            case Code.Beq:
                // single-value: use upper_bound convention per spec.
                (relation, upper) = safeIsTaken
                    ? ("==", ops.Right)
                    : ("!=", ops.Right);
                break;
            case Code.Bne_Un:
                (relation, upper) = safeIsTaken
                    ? ("!=", ops.Right)
                    : ("==", ops.Right);
                break;
            default:
                return null;
        }

        return new EstablishesBound
        {
            Target = ops.Left,
            Relation = relation,
            UpperBound = upper,
            LowerBound = lower,
        };
    }
```

Assign-into-tuple with explicit upper/lower nulls keeps the map legible; the alternative (one local per field) is wordier.

- [ ] **Step 7.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapes"`
Expected: 6 theory rows + `ExplicitElse` + `ReturnEarly` + `NoSanitizer` tests pass. Plus Task 6's tests still green.

Note on fixture fragility: Roslyn's IL emit for these shapes is stable for `-c Debug` builds of net10.0 but not guaranteed across compiler versions. If `MatchCompareAndThrow_Negated_EmitsCorrectBound` fails on a specific opcode row, disassemble the fixture DLL (`ildasm` or `dotnet ildasm`) to confirm the opcode Roslyn emitted — the bound-extraction table assumes exactly these opcodes.

- [ ] **Step 7.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 7.7: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: SanitizerShapes — bound extractor + compare-and-throw/return-early matchers"
```

---

## Task 8: `CallGraph.cs` — two-step virtual resolution + tests

**Files:**
- Create: `tools/TaintAnalyzer/CallGraph.cs`
- Create: `tools/TaintAnalyzer.Tests/CallGraphTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add call-graph fixtures.

**Responsibility.** At a single call site (a `call` or `callvirt` instruction plus the symbolic stack at that point), compute `ResolvedDispatch` per the spec: two-step — flow-type narrowing of the receiver then CHA closure within the analyzed assembly.

The callgraph "component" here is exposed as a pair of pure static methods — `ResolveCallSite(method, instruction, receiverTypeHint)` and `IsWithinAnalyzedAssembly(type, context)` — rather than a full graph data structure. The spec describes building the graph "given entry methods" but the walker uses it call-site-at-a-time; no global graph is needed.

- [ ] **Step 8.1: Extend `Fixtures.cs` with call-graph fixtures**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

// Abstract base + two concrete subclasses for CHA tests.
public abstract class Reader
{
    public abstract int Read(byte[] buffer, int offset, int count);
}

public sealed class BufferedReader : Reader       // sealed — CHA closure to exactly one target
{
    public override int Read(byte[] buffer, int offset, int count) => count;
}

public sealed class NetworkReader : Reader        // a second subclass, also sealed
{
    public override int Read(byte[] buffer, int offset, int count) => 0;
}

public static class CallGraphFixtures
{
    // Virtual call where the local is typed as the sealed subclass — flow-type narrowing
    // should pick this up and resolve to exactly one target (`BufferedReader.Read`).
    public static int ReadViaNarrowedLocal(byte[] buf)
    {
        BufferedReader r = new BufferedReader();   // local typed as sealed subclass
        return r.Read(buf, 0, buf.Length);
    }

    // Virtual call where the local is typed as the abstract base — no narrowing.
    // CHA closure within the analyzed assembly must find both overrides; since the
    // analyzed assembly contains both, closure_boundary = false and two resolved targets.
    public static int ReadViaAbstract(Reader r, byte[] buf)
        => r.Read(buf, 0, buf.Length);

    // Direct (static) call.
    public static int DirectCall()
        => SimpleShapes.Identity(1);

    // Virtual call into an external type (System.IO.Stream.ReadByte) — unresolvable within assembly.
    public static int ExternalVirtualCall(System.IO.Stream s) => s.ReadByte();
}
```

- [ ] **Step 8.2: Write `tools/TaintAnalyzer.Tests/CallGraphTests.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class CallGraphTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    [Fact]
    public void ResolveCallSite_DirectCall_EmitsDirectDispatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::DirectCall()");
        var call = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Call &&
            i.Operand is MethodReference mr && mr.Name == "Identity");

        var dispatch = CallGraph.ResolveCallSite(m, call, receiverStaticType: null, ctx);

        dispatch.Kind.ShouldBe("direct");
        dispatch.ClosureBoundary.ShouldBeFalse();
        dispatch.ResolvedTargets.ShouldBeEmpty();  // direct calls: spec convention is empty list
    }

    [Fact]
    public void ResolveCallSite_VirtualCall_WithNarrowedSealedLocal_ResolvesToOneTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ReadViaNarrowedLocal(System.Byte[])");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "Read");

        // Receiver flow-type: the local is typed as TaintAnalyzer.Tests.Fixtures.BufferedReader.
        var bufferedReader = ctx.Assembly.MainModule.GetType("TaintAnalyzer.Tests.Fixtures.BufferedReader");
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: bufferedReader, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.StaticType.ShouldBe("TaintAnalyzer.Tests.Fixtures.BufferedReader");
        dispatch.ClosureBoundary.ShouldBeFalse();
        dispatch.ResolvedTargets.ShouldHaveSingleItem();
        dispatch.ResolvedTargets[0].ShouldContain("BufferedReader::Read");
    }

    [Fact]
    public void ResolveCallSite_VirtualCall_AbstractReceiver_CHAClosureWithinAssembly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ReadViaAbstract(TaintAnalyzer.Tests.Fixtures.Reader,System.Byte[])");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "Read");

        var reader = ctx.Assembly.MainModule.GetType("TaintAnalyzer.Tests.Fixtures.Reader");
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: reader, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.ClosureBoundary.ShouldBeFalse();  // all subclasses within this assembly
        dispatch.ResolvedTargets.Count.ShouldBe(2);
        dispatch.ResolvedTargets.ShouldContain(s => s.Contains("BufferedReader::Read"));
        dispatch.ResolvedTargets.ShouldContain(s => s.Contains("NetworkReader::Read"));
    }

    [Fact]
    public void ResolveCallSite_ExternalAssemblyCall_SetsClosureBoundary()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ExternalVirtualCall(System.IO.Stream)");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "ReadByte");

        // Receiver flow-type could not be narrowed — pass the call-site's declaring type.
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: null, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.ClosureBoundary.ShouldBeTrue();
        dispatch.ResolvedTargets.ShouldBeEmpty();   // nothing within analyzed assembly
    }
}
```

- [ ] **Step 8.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~CallGraph"`
Expected: compilation error — `CallGraph.ResolveCallSite` undefined.

- [ ] **Step 8.4: Write `tools/TaintAnalyzer/CallGraph.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public static class CallGraph
{
    public static ResolvedDispatch ResolveCallSite(
        MethodDefinition containingMethod,
        Instruction callInstruction,
        TypeDefinition? receiverStaticType,
        AssemblyContext context)
    {
        var callee = callInstruction.Operand as MethodReference
            ?? throw new ArgumentException("instruction is not a call", nameof(callInstruction));

        // Non-virtual dispatch.
        if (callInstruction.OpCode != OpCodes.Callvirt)
        {
            return new ResolvedDispatch
            {
                Kind = "direct",
                StaticType = callee.DeclaringType.FullName,
                ResolvedTargets = Array.Empty<string>(),
                ClosureBoundary = false,
            };
        }

        // Virtual dispatch. Two-step resolution.
        var staticType = receiverStaticType ?? SafeResolve(callee.DeclaringType);
        if (staticType is null || !IsWithinAnalyzedAssembly(staticType, context))
        {
            // Receiver class is outside the analyzed assembly — we have no reliable subclass closure.
            return new ResolvedDispatch
            {
                Kind = "virtual",
                StaticType = (receiverStaticType ?? callee.DeclaringType.Resolve()?.AsTypeReference() ?? callee.DeclaringType).FullName,
                ResolvedTargets = Array.Empty<string>(),
                ClosureBoundary = true,
            };
        }

        // CHA closure: find every override of `callee` on `staticType` or any of its descendants within the analyzed assembly.
        var targets = new List<string>();
        bool closureBoundary = false;

        foreach (var candidate in DescendantsWithin(staticType, context))
        {
            foreach (var m in candidate.Methods)
            {
                if (!m.IsVirtual) continue;
                if (m.Name != callee.Name) continue;
                if (!ParameterShapesMatch(m, callee)) continue;
                targets.Add($"{m.DeclaringType.FullName}::{m.Name}");
            }
        }

        // Include the exact base-class definition if it is itself non-abstract and matches.
        foreach (var m in staticType.Methods)
        {
            if (!m.IsVirtual) continue;
            if (m.IsAbstract) continue;
            if (m.Name != callee.Name) continue;
            if (!ParameterShapesMatch(m, callee)) continue;
            var key = $"{m.DeclaringType.FullName}::{m.Name}";
            if (!targets.Contains(key, StringComparer.Ordinal))
            {
                targets.Add(key);
            }
        }

        // A non-sealed receiver whose subclass set cannot be closed within the analyzed assembly:
        // we approximate "closed" as "receiver type is sealed OR every candidate subclass is sealed
        // OR the receiver and all descendants are within the analyzed assembly AND the class is internal/
        // sealed enough to be effectively closed". For MVP: if the receiver type is not sealed AND not
        // abstract (i.e. instantiable base), flag closure_boundary = true since an external assembly could
        // subclass it. For abstract base with subclasses all sealed in-assembly, closure is complete.
        if (!staticType.IsSealed && !staticType.IsAbstract)
        {
            closureBoundary = true;
        }
        if (staticType.IsAbstract)
        {
            // Check each descendant — if any is non-sealed and non-abstract, closure incomplete.
            foreach (var d in DescendantsWithin(staticType, context))
            {
                if (!d.IsSealed && !d.IsAbstract) { closureBoundary = true; break; }
            }
        }

        return new ResolvedDispatch
        {
            Kind = "virtual",
            StaticType = staticType.FullName,
            ResolvedTargets = targets,
            ClosureBoundary = closureBoundary,
        };
    }

    public static bool IsWithinAnalyzedAssembly(TypeDefinition type, AssemblyContext ctx)
        => type.Module.Assembly == ctx.Assembly;

    private static IEnumerable<TypeDefinition> DescendantsWithin(TypeDefinition root, AssemblyContext ctx)
    {
        foreach (var t in ctx.Assembly.MainModule.GetTypes())
        {
            if (t == root) continue;
            if (IsDescendantOf(t, root)) yield return t;
        }
    }

    private static bool IsDescendantOf(TypeDefinition candidate, TypeDefinition ancestor)
    {
        var cur = candidate;
        while (cur?.BaseType is { } baseRef)
        {
            var baseDef = SafeResolve(baseRef);
            if (baseDef is null) return false;
            if (baseDef == ancestor) return true;
            cur = baseDef;
        }
        return false;
    }

    private static bool ParameterShapesMatch(MethodDefinition impl, MethodReference callee)
    {
        if (impl.Parameters.Count != callee.Parameters.Count) return false;
        for (int i = 0; i < impl.Parameters.Count; i++)
        {
            if (impl.Parameters[i].ParameterType.FullName != callee.Parameters[i].ParameterType.FullName)
            {
                return false;
            }
        }
        return true;
    }

    private static TypeDefinition? SafeResolve(TypeReference tr)
    {
        try { return tr.Resolve(); }
        catch { return null; }
    }
}

internal static class CecilExtensions
{
    public static TypeReference AsTypeReference(this TypeDefinition td) => td;
}
```

- [ ] **Step 8.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~CallGraph"`
Expected: 4 tests passing.

If `ResolveCallSite_VirtualCall_AbstractReceiver` fails with `ResolvedTargets.Count == 3`, it means the abstract `Reader::Read` got counted — the loop that adds base-class non-abstract methods should skip `IsAbstract`; confirm that guard is in place. If the count is 1, it means `DescendantsWithin` didn't find both subclasses — debug by enumerating `ctx.Assembly.MainModule.GetTypes()` and confirming both `BufferedReader` and `NetworkReader` are present.

- [ ] **Step 8.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 8.7: Commit**

```bash
git add tools/TaintAnalyzer/CallGraph.cs tools/TaintAnalyzer.Tests/CallGraphTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: CallGraph — flow-type narrowing + CHA closure"
```

---

## Task 9: `TaintWalker.cs` — intra-method forward pass (Part 1 of 4)

This task produces a minimal `TaintWalker` that handles straight-line IL through `ldarg` / `stloc` / `ldloc` / arithmetic / `newarr` inside a single method. Cross-method, object-field, sanitizer-dispatch, and sequence-point fallback all come in Tasks 10–12.

**Files:**
- Create: `tools/TaintAnalyzer/TaintWalker.cs`
- Create: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add walker fixtures.

- [ ] **Step 9.1: Extend `Fixtures.cs` with the intra-method walker fixture**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

public static class WalkerFixtures
{
    // Straight-line taint: tainted param `size` flows through a local into `new byte[size]`.
    public static byte[] IntraMethodAllocation(int size)
    {
        int n = size + 4;                // arithmetic transformation
        byte[] buf = new byte[n];        // newarr sink, tainted size
        return buf;
    }

    // Negative: no tainted input reaches newarr.
    public static byte[] IntraMethodNoTaint()
    {
        return new byte[16];
    }
}
```

- [ ] **Step 9.2: Write `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`**

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class TaintWalkerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Walk_TaintedParamReachesNewarr_RecordsSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();

        var sinkHop = summary.Hops.Last();
        sinkHop.Role.ShouldBe(HopRole.Sink);
        sinkHop.SinkKind.ShouldBe(SinkKind.Allocation);
        sinkHop.SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_NoTaintedInput_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodNoTaint()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse();
        summary.Hops.OfType<HopRecord>().Where(h => h.Role == HopRole.Sink).ShouldBeEmpty();
    }
}
```

- [ ] **Step 9.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: compilation error — `TaintWalker` undefined.

- [ ] **Step 9.4: Write `tools/TaintAnalyzer/TaintWalker.cs`**

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class TaintWalker
{
    private readonly AssemblyContext _context;
    private readonly Dictionary<(string fullName, int bitmask), MethodSummary> _memo = new();

    public TaintWalker(AssemblyContext context) => _context = context;

    public MethodSummary Walk(MethodDefinition method, int taintedParamBitmask)
    {
        var key = (method.FullName, taintedParamBitmask);
        if (_memo.TryGetValue(key, out var cached))
        {
            return cached;
        }

        // Sentinel to break recursion on cyclic call graphs. Task 11 refines this.
        var placeholder = new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = false,
            NewlyTaintedThisFields = Array.Empty<string>(),
            Hops = Array.Empty<HopRecord>(),
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = false,
        };
        _memo[key] = placeholder;

        var summary = WalkMethodBody(method, taintedParamBitmask);
        _memo[key] = summary;
        return summary;
    }

    private MethodSummary WalkMethodBody(MethodDefinition method, int taintedParamBitmask)
    {
        var state = new TaintState();
        SeedArgumentTaint(method, taintedParamBitmask, state);

        var hops = new List<HopRecord>();
        bool reachedSink = false;
        int hopCounter = 0;

        if (method.Body is null)
        {
            return new MethodSummary
            {
                MethodFullName = method.FullName,
                TaintedParamBitmask = taintedParamBitmask,
                ReturnsTainted = false,
                NewlyTaintedThisFields = Array.Empty<string>(),
                Hops = hops,
                Absences = Array.Empty<EmittedSanitizerAbsence>(),
                ReachedSink = false,
            };
        }

        foreach (var ins in method.Body.Instructions)
        {
            if (HandleSinkMatch(method, ins, state, hops, ref hopCounter))
            {
                reachedSink = true;
                // Continue iterating — future hops won't add more for this path, but multi-sink
                // methods could in principle produce additional sink records.
            }

            StepInstruction(method, ins, state);
        }

        bool returnsTainted = false;  // refined in Task 11
        return new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = returnsTainted,
            NewlyTaintedThisFields = Array.Empty<string>(),
            Hops = hops,
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = reachedSink,
        };
    }

    private static void SeedArgumentTaint(MethodDefinition method, int bitmask, TaintState state)
    {
        int argOffset = method.HasThis ? 1 : 0;
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (((bitmask >> i) & 1) != 0)
            {
                state.Args[i + argOffset] = StackSlot.TaintedWith(method.Parameters[i].Name);
            }
            else
            {
                state.Args[i + argOffset] = StackSlot.Untainted;
            }
        }
        if (method.HasThis && ((bitmask & (1 << method.Parameters.Count)) != 0 ||
                               (bitmask & (1 << 31)) != 0))  // reserved-bit convention unused for MVP
        {
            state.Args[0] = StackSlot.TaintedWith("this");
        }
    }

    // Returns true when this instruction is a sink and its critical argument is tainted.
    private bool HandleSinkMatch(MethodDefinition method, Instruction ins, TaintState state, List<HopRecord> hops, ref int hopCounter)
    {
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack);

        if (m is null) return false;

        var sp = _context.GetSequencePoint(method, ins);
        hops.Add(new HopRecord
        {
            Hop = hopCounter++,
            Method = $"{method.DeclaringType.FullName}.{method.Name}",
            File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
            Line = sp?.StartLine ?? 0,
            Role = HopRole.Sink,
            TaintedValueIn = m.SizeProvenance,
            Transformation = "identity",
            TaintedValueOut = m.SizeProvenance,
            SinkKind = m.Kind,
            SinkApi = m.Api,
            SizeExpression = m.Kind == SinkKind.Allocation ? m.SizeProvenance : null,
            AccessExpression = m.Kind == SinkKind.SpanAccess ? m.SizeProvenance : null,
        });
        return true;
    }

    private static void StepInstruction(MethodDefinition method, Instruction ins, TaintState state)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Nop:
            case Code.Ret:
                break;

            case Code.Ldarg_0: state.Stack.Push(state.Args.GetValueOrDefault(0, StackSlot.Untainted)); break;
            case Code.Ldarg_1: state.Stack.Push(state.Args.GetValueOrDefault(1, StackSlot.Untainted)); break;
            case Code.Ldarg_2: state.Stack.Push(state.Args.GetValueOrDefault(2, StackSlot.Untainted)); break;
            case Code.Ldarg_3: state.Stack.Push(state.Args.GetValueOrDefault(3, StackSlot.Untainted)); break;
            case Code.Ldarg:
            case Code.Ldarg_S:
                {
                    var pd = (ParameterDefinition)ins.Operand;
                    int idx = pd.Index + (method.HasThis ? 1 : 0);
                    state.Stack.Push(state.Args.GetValueOrDefault(idx, StackSlot.Untainted));
                    break;
                }

            case Code.Stloc_0: state.Locals[0] = state.Stack.Pop(); break;
            case Code.Stloc_1: state.Locals[1] = state.Stack.Pop(); break;
            case Code.Stloc_2: state.Locals[2] = state.Stack.Pop(); break;
            case Code.Stloc_3: state.Locals[3] = state.Stack.Pop(); break;
            case Code.Stloc:
            case Code.Stloc_S:
                state.Locals[((VariableDefinition)ins.Operand).Index] = state.Stack.Pop();
                break;

            case Code.Ldloc_0: state.Stack.Push(state.Locals.GetValueOrDefault(0, StackSlot.Untainted)); break;
            case Code.Ldloc_1: state.Stack.Push(state.Locals.GetValueOrDefault(1, StackSlot.Untainted)); break;
            case Code.Ldloc_2: state.Stack.Push(state.Locals.GetValueOrDefault(2, StackSlot.Untainted)); break;
            case Code.Ldloc_3: state.Stack.Push(state.Locals.GetValueOrDefault(3, StackSlot.Untainted)); break;
            case Code.Ldloc:
            case Code.Ldloc_S:
                state.Stack.Push(state.Locals.GetValueOrDefault(((VariableDefinition)ins.Operand).Index, StackSlot.Untainted));
                break;

            case Code.Ldc_I4_0:
            case Code.Ldc_I4_1:
            case Code.Ldc_I4_2:
            case Code.Ldc_I4_3:
            case Code.Ldc_I4_4:
            case Code.Ldc_I4_5:
            case Code.Ldc_I4_6:
            case Code.Ldc_I4_7:
            case Code.Ldc_I4_8:
            case Code.Ldc_I4_M1:
            case Code.Ldc_I4:
            case Code.Ldc_I4_S:
            case Code.Ldc_I8:
            case Code.Ldc_R4:
            case Code.Ldc_R8:
            case Code.Ldnull:
            case Code.Ldstr:
                state.Stack.Push(StackSlot.Untainted);
                break;

            case Code.Add:
            case Code.Sub:
            case Code.Mul:
            case Code.Div:
            case Code.Rem:
            case Code.And:
            case Code.Or:
            case Code.Xor:
            case Code.Shl:
            case Code.Shr:
            case Code.Shr_Un:
            case Code.Add_Ovf:
            case Code.Add_Ovf_Un:
            case Code.Sub_Ovf:
            case Code.Sub_Ovf_Un:
            case Code.Mul_Ovf:
            case Code.Mul_Ovf_Un:
                {
                    var rhs = state.Stack.Pop();
                    var lhs = state.Stack.Pop();
                    state.Stack.Push(lhs.Tainted || rhs.Tainted
                        ? StackSlot.TaintedWith(CombineProvenance(lhs, rhs))
                        : StackSlot.Untainted);
                    break;
                }

            case Code.Neg:
            case Code.Not:
            case Code.Conv_I:
            case Code.Conv_I1:
            case Code.Conv_I2:
            case Code.Conv_I4:
            case Code.Conv_I8:
            case Code.Conv_U:
            case Code.Conv_U1:
            case Code.Conv_U2:
            case Code.Conv_U4:
            case Code.Conv_U8:
            case Code.Conv_R4:
            case Code.Conv_R8:
                // Unary on top-of-stack: keep taint, preserve provenance.
                // (pop and push back as-is)
                break;

            case Code.Newarr:
                {
                    // Size arg on top is the only operand; replace with untainted array reference.
                    state.Stack.Pop();
                    state.Stack.Push(StackSlot.Untainted);
                    break;
                }

            case Code.Pop:
                state.Stack.Pop();
                break;

            case Code.Dup:
                {
                    var top = state.Stack.Peek();
                    state.Stack.Push(top);
                    break;
                }

            // Branches in intra-method MVP: treat as sequential — Task 12 adds the sanitizer walk.
            case Code.Br:
            case Code.Br_S:
            case Code.Beq:
            case Code.Beq_S:
            case Code.Bge:
            case Code.Bge_S:
            case Code.Bge_Un:
            case Code.Bge_Un_S:
            case Code.Bgt:
            case Code.Bgt_S:
            case Code.Bgt_Un:
            case Code.Bgt_Un_S:
            case Code.Ble:
            case Code.Ble_S:
            case Code.Ble_Un:
            case Code.Ble_Un_S:
            case Code.Blt:
            case Code.Blt_S:
            case Code.Blt_Un:
            case Code.Blt_Un_S:
            case Code.Bne_Un:
            case Code.Bne_Un_S:
            case Code.Brfalse:
            case Code.Brfalse_S:
            case Code.Brtrue:
            case Code.Brtrue_S:
                // Pop comparison operands; don't model control flow in MVP.
                {
                    int pops = ins.OpCode.StackBehaviourPop switch
                    {
                        StackBehaviour.Pop1_pop1 => 2,
                        StackBehaviour.Popi_popi => 2,
                        StackBehaviour.Popi => 1,
                        _ => 0,
                    };
                    for (int i = 0; i < pops && state.Stack.Depth > 0; i++) state.Stack.Pop();
                    break;
                }

            default:
                // Conservative fallback: pop the operand stack to the opcode's declared pop count,
                // then push untainted to the declared push count.
                ApplyStackBehavior(ins, state);
                break;
        }
    }

    private static void ApplyStackBehavior(Instruction ins, TaintState state)
    {
        int pops = ins.OpCode.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 => 1,
            StackBehaviour.Popi => 1,
            StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 => 2,
            StackBehaviour.Popi_popi => 2,
            StackBehaviour.Popi_pop1 => 2,
            StackBehaviour.Popi_popi8 => 2,
            StackBehaviour.Popref_pop1 => 2,
            StackBehaviour.Popi_popi_popi => 3,
            StackBehaviour.Popref_popi_popi => 3,
            StackBehaviour.Popref_popi_pop1 => 3,
            StackBehaviour.Popref_popi_popi8 => 3,
            StackBehaviour.Popref_popi_popr4 => 3,
            StackBehaviour.Popref_popi_popr8 => 3,
            StackBehaviour.Popref_popi_popref => 3,
            StackBehaviour.PopAll => state.Stack.Depth,
            _ => 0,
        };
        for (int i = 0; i < pops && state.Stack.Depth > 0; i++) state.Stack.Pop();

        int pushes = ins.OpCode.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 => 1,
            StackBehaviour.Push1_push1 => 2,
            StackBehaviour.Pushi => 1,
            StackBehaviour.Pushi8 => 1,
            StackBehaviour.Pushr4 => 1,
            StackBehaviour.Pushr8 => 1,
            StackBehaviour.Pushref => 1,
            _ => 0,
        };
        for (int i = 0; i < pushes; i++) state.Stack.Push(StackSlot.Untainted);
    }

    private static string CombineProvenance(StackSlot a, StackSlot b)
    {
        if (a.Tainted && b.Tainted) return $"{a.Provenance}+{b.Provenance}";
        return a.Tainted ? a.Provenance : b.Provenance;
    }
}
```

- [ ] **Step 9.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: 2 tests passing.

- [ ] **Step 9.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 9.7: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: TaintWalker — intra-method forward pass (ldarg, stloc/ldloc, arithmetic, newarr)"
```

---

## Task 10: `TaintWalker.cs` — `stfld`/`ldfld` on `this` + per-method field summary (Part 2 of 4)

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs`
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add field-taint fixtures.

**Responsibility.** Extend the walker to track taint on `this`-rooted fields. When a tainted value is stored to `this.F`, the state records that field as tainted. Later reads of `this.F` produce a tainted slot with `F` as provenance. The per-method `MethodSummary.NewlyTaintedThisFields` collects every `this`-field tainted during the walk for use by Task 11's cross-method summary.

- [ ] **Step 10.1: Extend `Fixtures.cs` with field-taint fixtures**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

public sealed class FieldTaintHost
{
    public int payloadSize;
    public int safeConstant = 16;

    // Stores tainted `size` to `this.payloadSize`. Walker should mark `payloadSize` as newly tainted on `this`.
    public void StoreToField(int size)
    {
        this.payloadSize = size;
    }

    // Reads `this.payloadSize` (pre-tainted by caller's summary) and uses it at a sink.
    public byte[] AllocateFromField()
    {
        return new byte[this.payloadSize];
    }

    // Reads `this.safeConstant` — should not be tainted since no caller has tainted it.
    public byte[] AllocateFromSafeConstant()
    {
        return new byte[this.safeConstant];
    }
}
```

- [ ] **Step 10.2: Extend `TaintWalkerTests.cs`**

Append to `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` inside the existing class:

```csharp
    [Fact]
    public void Walk_StoresTaintedValueToThisField_RecordsFieldInSummary()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::StoreToField(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("payloadSize");
    }

    [Fact]
    public void Walk_ReadsPreTaintedThisField_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // Seed `this.payloadSize` as tainted via the TaintWalker's external-seed API (added in this task).
        var method = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromField()")!;
        var summary = walker.WalkWithSeed(method,
            taintedParamBitmask: 0b0,
            taintedThisFields: new[] { "payloadSize" });

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.Last().SinkApi.ShouldBe(SinkApi.NewArray);
    }

    [Fact]
    public void Walk_ReadsUntaintedThisField_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.FieldTaintHost::AllocateFromSafeConstant()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse();
    }
```

- [ ] **Step 10.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: compilation error — `WalkWithSeed` undefined. Additionally `StoreToField` test may fail: `NewlyTaintedThisFields` stays empty because the walker doesn't handle `stfld` yet.

- [ ] **Step 10.4: Extend `TaintWalker.cs` with field handling and external-seed API**

At the top of the `TaintWalker` class, add the `WalkWithSeed` entry point and modify `WalkMethodBody` to accept an optional pre-seeded set of `this`-fields. Replace the existing `public MethodSummary Walk(...)` and private `WalkMethodBody` with:

```csharp
    public MethodSummary Walk(MethodDefinition method, int taintedParamBitmask)
        => WalkWithSeed(method, taintedParamBitmask, taintedThisFields: Array.Empty<string>());

    public MethodSummary WalkWithSeed(MethodDefinition method, int taintedParamBitmask, IReadOnlyCollection<string> taintedThisFields)
    {
        var key = (method.FullName, taintedParamBitmask);
        // Memo keyed only by method+param bitmask for MVP. Seeded this-fields are a caller-specific
        // refinement; we accept the cache collision risk for now — Task 11 adds per-`this`-field-set keying
        // if it turns out to matter for the #3074 fixture.
        if (_memo.TryGetValue(key, out var cached) && taintedThisFields.Count == 0)
        {
            return cached;
        }

        var placeholder = new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = false,
            NewlyTaintedThisFields = Array.Empty<string>(),
            Hops = Array.Empty<HopRecord>(),
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = false,
        };
        if (taintedThisFields.Count == 0) _memo[key] = placeholder;

        var summary = WalkMethodBody(method, taintedParamBitmask, taintedThisFields);
        if (taintedThisFields.Count == 0) _memo[key] = summary;
        return summary;
    }

    private MethodSummary WalkMethodBody(
        MethodDefinition method,
        int taintedParamBitmask,
        IReadOnlyCollection<string> taintedThisFields)
    {
        var state = new TaintState();
        SeedArgumentTaint(method, taintedParamBitmask, state);
        SeedThisFieldTaint(method, taintedThisFields, state);

        var hops = new List<HopRecord>();
        bool reachedSink = false;
        int hopCounter = 0;
        var newlyTaintedFields = new HashSet<string>(StringComparer.Ordinal);

        if (method.Body is null)
        {
            return new MethodSummary
            {
                MethodFullName = method.FullName,
                TaintedParamBitmask = taintedParamBitmask,
                ReturnsTainted = false,
                NewlyTaintedThisFields = Array.Empty<string>(),
                Hops = hops,
                Absences = Array.Empty<EmittedSanitizerAbsence>(),
                ReachedSink = false,
            };
        }

        foreach (var ins in method.Body.Instructions)
        {
            if (HandleSinkMatch(method, ins, state, hops, ref hopCounter))
            {
                reachedSink = true;
            }

            StepInstruction(method, ins, state, newlyTaintedFields);
        }

        return new MethodSummary
        {
            MethodFullName = method.FullName,
            TaintedParamBitmask = taintedParamBitmask,
            ReturnsTainted = false,
            NewlyTaintedThisFields = newlyTaintedFields.ToArray(),
            Hops = hops,
            Absences = Array.Empty<EmittedSanitizerAbsence>(),
            ReachedSink = reachedSink,
        };
    }

    private static void SeedThisFieldTaint(MethodDefinition method, IReadOnlyCollection<string> fields, TaintState state)
    {
        if (!method.HasThis || fields.Count == 0) return;
        var declaringType = method.DeclaringType;
        foreach (var name in fields)
        {
            var fd = declaringType.Fields.FirstOrDefault(f => f.Name == name);
            if (fd is null) continue;
            state.ThisFields[fd.FullName] = StackSlot.TaintedWith(name);
        }
    }
```

Change the signature of `StepInstruction` from `(MethodDefinition, Instruction, TaintState)` to `(MethodDefinition, Instruction, TaintState, HashSet<string>)` and route the new parameter through. Add new cases for `Ldfld`/`Stfld`/`Ldsfld`/`Stsfld`:

```csharp
    private static void StepInstruction(MethodDefinition method, Instruction ins, TaintState state, HashSet<string> newlyTaintedFields)
    {
        switch (ins.OpCode.Code)
        {
            // ... (existing cases unchanged) ...

            case Code.Ldfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var receiver = state.Stack.Pop();
                    if (receiver.Tainted)
                    {
                        // Taint propagates on field-load from a tainted struct/object.
                        state.Stack.Push(StackSlot.TaintedWith($"{receiver.Provenance}.{fr.Name}"));
                        break;
                    }
                    // Receiver is `this` (Ldarg.0) whose per-field taint map we track:
                    if (state.ThisFields.TryGetValue(fr.FullName, out var fieldSlot) && fieldSlot.Tainted)
                    {
                        state.Stack.Push(fieldSlot);
                        break;
                    }
                    state.Stack.Push(StackSlot.Untainted);
                    break;
                }

            case Code.Ldsfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    if (state.StaticFields.TryGetValue(fr.FullName, out var sfld) && sfld.Tainted)
                    {
                        state.Stack.Push(sfld);
                    }
                    else
                    {
                        state.Stack.Push(StackSlot.Untainted);
                    }
                    break;
                }

            case Code.Stfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var value = state.Stack.Pop();
                    var receiver = state.Stack.Pop();
                    if (value.Tainted && receiver.Tainted && receiver.Provenance == "this")
                    {
                        state.ThisFields[fr.FullName] = StackSlot.TaintedWith(fr.Name);
                        newlyTaintedFields.Add(fr.Name);
                    }
                    break;
                }

            case Code.Stsfld:
                {
                    var fr = (FieldReference)ins.Operand;
                    var value = state.Stack.Pop();
                    if (value.Tainted)
                    {
                        state.StaticFields[fr.FullName] = StackSlot.TaintedWith($"{fr.DeclaringType.Name}.{fr.Name}");
                    }
                    break;
                }

            // ... rest of the switch ...
        }
    }
```

Note on the `receiver.Provenance == "this"` check: the `Ldarg_0` case in `StepInstruction` already pushes whatever is in `state.Args[0]`. For the seeded-taint pattern (caller passes `this` as tainted-receiver), `state.Args[0]` is `StackSlot.TaintedWith("this")`. For methods whose `this` was never explicitly seeded as tainted but whose fields we nonetheless track, `stfld` still fires when the value is tainted — we refine the guard:

Replace `if (value.Tainted && receiver.Tainted && receiver.Provenance == "this")` with:

```csharp
                    bool receiverIsThisRooted = receiver.Provenance == "this" ||
                        (!receiver.Tainted && InstructionIsLdarg0(FindStfldReceiverSource(ins)));

                    if (value.Tainted && receiverIsThisRooted)
                    {
                        state.ThisFields[fr.FullName] = StackSlot.TaintedWith(fr.Name);
                        newlyTaintedFields.Add(fr.Name);
                    }
```

…and add helpers inside the class:

```csharp
    private static Instruction? FindStfldReceiverSource(Instruction stfld)
    {
        // stfld stack pattern: ..., obj, value, <stfld>
        // The "obj" is the instruction whose push put it two-behind. For linear IL this is
        // typically stfld.Previous.Previous if that instruction pushes exactly one slot.
        var a = stfld.Previous;
        if (a is null) return null;
        var b = a.Previous;
        return b;
    }

    private static bool InstructionIsLdarg0(Instruction? ins)
        => ins is not null && ins.OpCode.Code is Code.Ldarg_0;
```

This is a heuristic adequate for Debug-built IL where Roslyn doesn't reorder evaluation around `stfld`. If it misbehaves on the #3074 fixture, Task 22's debugging surfaces it.

- [ ] **Step 10.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: 5 tests passing (2 existing + 3 new).

- [ ] **Step 10.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 10.7: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: TaintWalker — stfld/ldfld on this, static fields, per-method NewlyTaintedThisFields"
```

---

## Task 11: `TaintWalker.cs` — cross-method recursion + memoization (Part 3 of 4)

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs`
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add cross-method fixtures.

**Responsibility.** At `call`/`callvirt` instructions, if any argument on the stack is tainted, recursively analyze the callee with that parameter bitmask. Merge the callee's summary into the caller's state: (a) if the callee returns tainted, push a tainted stack slot representing the return value; (b) if the callee's summary lists newly-tainted `this`-fields AND the caller's receiver was `this`, update the caller's `ThisFields` map accordingly; (c) propagator hops for the call are appended to the caller's hop list when the callee's summary has `ReachedSink == true` (the caller is on the path to the sink).

- [ ] **Step 11.1: Extend `Fixtures.cs` with cross-method fixtures**

Append:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

public sealed class CrossMethodHost
{
    public int stored;

    // Cross-method: caller passes tainted `n` to helper; helper stores to this.stored.
    public void CrossMethodStore(int n)
    {
        StoreHelper(n);
    }

    public void StoreHelper(int n)
    {
        this.stored = n;
    }

    // Cross-method: caller reads this.stored (pre-tainted via StoreHelper) and uses at sink.
    public byte[] CrossMethodAllocate()
    {
        StoreHelper(1);         // untainted constant; stored becomes untainted in isolation
        return new byte[this.stored];
    }

    // Tainted return: helper returns its tainted arg; caller uses the return at a sink.
    public byte[] CrossMethodTaintedReturn(int n)
    {
        int m = Echo(n);
        return new byte[m];
    }

    private static int Echo(int x) => x;
}
```

- [ ] **Step 11.2: Extend `TaintWalkerTests.cs`**

Append to the existing class:

```csharp
    [Fact]
    public void Walk_CallsHelperThatStoresToThisField_MergesFieldTaint()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodStore(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.NewlyTaintedThisFields.ShouldContain("stored");
    }

    [Fact]
    public void Walk_HelperReturnsTaintedValue_SinkFires()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodTaintedReturn(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Walk_MemoizesByMethodAndBitmask()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodStore(System.Int32)")!;
        var first = walker.Walk(m, 0b1);
        var second = walker.Walk(m, 0b1);

        // Same object reference: memoized.
        second.ShouldBeSameAs(first);

        // Different bitmask: different summary.
        var zero = walker.Walk(m, 0b0);
        zero.ShouldNotBeSameAs(first);
    }
```

- [ ] **Step 11.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: `CallsHelperThatStoresToThisField_MergesFieldTaint` fails — `NewlyTaintedThisFields` is empty because the caller doesn't yet recurse into the callee. `HelperReturnsTaintedValue_SinkFires` fails — the `Echo` return isn't carried as tainted.

- [ ] **Step 11.4: Add cross-method handling to `TaintWalker.cs`**

Inside `StepInstruction`, add a `Code.Call` / `Code.Callvirt` case handling cross-method. Put it before the `default` fallback so the generic `ApplyStackBehavior` doesn't process it:

```csharp
            case Code.Call:
            case Code.Callvirt:
                HandleCall(method, ins, state, newlyTaintedFields);
                break;
```

Then add the `HandleCall` helper inside the class. This is the largest single chunk of Task 11:

```csharp
    private void HandleCall(MethodDefinition callerMethod, Instruction ins, TaintState state, HashSet<string> newlyTaintedFields)
    {
        var callee = (MethodReference)ins.Operand;
        var paramCount = callee.Parameters.Count;
        bool hasThisOnStack = callee.HasThis;

        // Snapshot the args off the stack in order: [receiver?], arg0, arg1, ...
        // Stack top = last arg.
        int totalPops = paramCount + (hasThisOnStack ? 1 : 0);
        if (state.Stack.Depth < totalPops)
        {
            // Malformed or unsupported shape — pop what's there and treat as untainted return.
            for (int i = 0; i < state.Stack.Depth; i++) state.Stack.Pop();
            if (!IsVoidReturn(callee)) state.Stack.Push(StackSlot.Untainted);
            return;
        }

        var argSlots = new StackSlot[paramCount];
        for (int i = paramCount - 1; i >= 0; i--)
        {
            argSlots[i] = state.Stack.Pop();
        }
        var receiverSlot = hasThisOnStack ? state.Stack.Pop() : default;

        // Sink matching is already handled by HandleSinkMatch before StepInstruction runs.
        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolve(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: push untainted return (conservative). Any tainted return from an external call
            // would need source_methods modelling.
            if (!IsVoidReturn(callee)) state.Stack.Push(StackSlot.Untainted);
            return;
        }

        int bitmask = 0;
        for (int i = 0; i < paramCount; i++)
        {
            if (argSlots[i].Tainted) bitmask |= (1 << i);
        }

        // Cross-method walk.
        var calleeSummary = Walk(resolved, bitmask);

        // Return-value taint propagation: if the callee returns a value and any arg was tainted,
        // for MVP we over-approximate — return is tainted when any tainted arg was passed.
        // (A more precise version computes ReturnsTainted from the callee body; we leave that hook
        // but keep the conservative policy here.)
        bool callReturnIsTainted = !IsVoidReturn(callee) && (bitmask != 0 || calleeSummary.ReturnsTainted);

        // `this`-field taint propagation: the callee's NewlyTaintedThisFields apply to the caller's
        // receiver ONLY when the caller's receiver was `this`.
        bool receiverIsCallerThis = hasThisOnStack && IsReceiverCallerThis(receiverSlot, ins);
        if (receiverIsCallerThis && resolved.HasThis)
        {
            foreach (var fName in calleeSummary.NewlyTaintedThisFields)
            {
                var fd = resolved.DeclaringType.Fields.FirstOrDefault(f => f.Name == fName);
                if (fd is null) continue;
                state.ThisFields[fd.FullName] = StackSlot.TaintedWith(fName);
                newlyTaintedFields.Add(fName);
            }
        }

        if (!IsVoidReturn(callee))
        {
            var provenance = callReturnIsTainted
                ? CombineProvenance(argSlots, $"{callee.DeclaringType.Name}.{callee.Name}")
                : "";
            state.Stack.Push(callReturnIsTainted ? StackSlot.TaintedWith(provenance) : StackSlot.Untainted);
        }
    }

    private static string CombineProvenance(StackSlot[] args, string fallback)
    {
        foreach (var s in args)
        {
            if (s.Tainted) return s.Provenance;
        }
        return fallback;
    }

    private static bool IsVoidReturn(MethodReference mr)
        => mr.ReturnType.FullName == "System.Void";

    private static MethodDefinition? SafeResolve(MethodReference mr)
    {
        try { return mr.Resolve(); }
        catch { return null; }
    }

    // Whether the receiver passed to the callee is the caller's own `this`.
    // Heuristic: in Debug IL, `ldarg.0; <arg-push>*; call` is the common shape.
    private static bool IsReceiverCallerThis(StackSlot receiverSlot, Instruction call)
    {
        if (receiverSlot.Provenance == "this" && receiverSlot.Tainted) return true;
        // Fallback: scan backward for the receiver-push. We already popped it, but its source instruction
        // is the one whose push aligned to `this`. If the IL shape is `ldarg.0; ...; call`, the receiver
        // source is the nearest `ldarg.0` preceding the call with no intervening push/pop that would shift it.
        // For the MVP we accept the provenance-string check above and return false otherwise.
        return false;
    }
```

Now also refine the memoization key — the `Walk` entry point remains correct (method + bitmask). For the sentinel case in `Walk` (recursive-entry), the placeholder already returns an empty summary, which is correct for cycle-breaking: a recursive self-call doesn't newly taint anything.

- [ ] **Step 11.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: all 8 tests passing (2 from Task 9 + 3 from Task 10 + 3 from Task 11).

- [ ] **Step 11.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 11.7: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: TaintWalker — cross-method recursion with FullName+bitmask memoization"
```

---

## Task 12: `TaintWalker.cs` — sanitizer dispatch + sequence-point fallback (Part 4 of 4)

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs`
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`

**Responsibility.** After every instruction step, scan for a `SanitizerShapes.MatchCompareAndThrow` / `MatchCompareAndReturnEarly` attached to the current method — emit a sanitizer hop (exactly once per method walk). Additionally, in any pre-fix trace, synthesize `sanitizer_absence` entries for each path that reaches a sink without passing a sanitizer hop. Sequence-point fallback (walk backward to nearest non-hidden SP) is already in `AssemblyContext.GetSequencePoint`; this task only adds one test to confirm it's invoked.

Note: the spec already places sequence-point fallback in `TaintWalker`'s responsibilities — implementation delegates to `AssemblyContext.GetSequencePoint` (Task 4) so there's nothing new to add in the walker beyond already using that method.

- [ ] **Step 12.1: Extend `Fixtures.cs` with sanitizer-in-context fixture**

Append:

```csharp
namespace TaintAnalyzer.Tests.Fixtures;

public sealed class SanitizerInContext
{
    // `n` tainted → sanitizer hop → sink. Sanitizer does not clear taint (per spec), so sink still fires.
    public byte[] SanitizedAllocate(int n)
    {
        if (n > 1024) ThrowHelpers.ThrowOutOfRange(nameof(n));
        return new byte[n];
    }
}
```

- [ ] **Step 12.2: Extend `TaintWalkerTests.cs`**

Append to the existing class:

```csharp
    [Fact]
    public void Walk_WithSanitizerOnPath_RecordsSanitizerHopAndStillReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SanitizerInContext::SanitizedAllocate(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sanitizer);
        var sanitizerHop = summary.Hops.First(h => h.Role == HopRole.Sanitizer);
        sanitizerHop.EstablishesBound.ShouldNotBeNull();
        sanitizerHop.EstablishesBound!.Relation.ShouldBe("<=");
        sanitizerHop.OnFailure.ShouldNotBeNull();
        sanitizerHop.OnFailure!.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void Walk_PreFix_SynthesizesSanitizerAbsence()
    {
        // The intra-method allocation fixture from Task 9 has no sanitizer on the path; the walker
        // should emit exactly one sanitizer_absence entry pointing at the propagator hop immediately
        // preceding the sink (which for this fixture is the `new byte[n]` hop itself — the "propagator
        // immediately preceding" collapses to the arithmetic hop before it).
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.Absences.ShouldHaveSingleItem();
        var absence = summary.Absences[0];
        absence.Location.ShouldEndWith("Fixtures.cs:" + absence.Location.Split(':').Last());
        absence.TaintedValue.ShouldNotBeNullOrEmpty();
        absence.ExpectedCheck.ShouldContain("must be bounded before reaching");
    }

    [Fact]
    public void GetSequencePoint_UsesFallbackForHiddenInstructions()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)")!;

        // `nop` in Debug IL may or may not have a sequence point. Regardless, GetSequencePoint must
        // never return null for the *first* instruction of a non-trivial Debug body — the method-prologue
        // sequence point falls on `ldarg`/`nop`/`stloc`.
        var first = m.Body.Instructions.First();
        var sp = ctx.GetSequencePoint(m, first);
        sp.ShouldNotBeNull();
        sp!.StartLine.ShouldBeGreaterThan(0);
    }
```

- [ ] **Step 12.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected:
- `Walk_WithSanitizerOnPath_...`: fails — no sanitizer hop emitted.
- `Walk_PreFix_SynthesizesSanitizerAbsence`: fails — `Absences` empty.

- [ ] **Step 12.4: Emit sanitizer hops in `TaintWalker.cs`**

At the very start of `WalkMethodBody` (after `SeedThisFieldTaint` but before the instruction loop), add:

```csharp
        var sanitizerMatch = SanitizerShapes.MatchCompareAndThrow(method)
                          ?? SanitizerShapes.MatchCompareAndReturnEarly(method);
        HopRecord? pendingSanitizerHop = null;
        if (sanitizerMatch is not null)
        {
            // Emit at the IL offset of the comparison's conditional branch.
            var branchIns = method.Body.Instructions.FirstOrDefault(i => i.Offset == sanitizerMatch.ComparisonIlOffset);
            var sp = branchIns is null ? null : _context.GetSequencePoint(method, branchIns);
            pendingSanitizerHop = new HopRecord
            {
                Hop = 0,                         // patched after the walk below so hops are contiguous
                Method = $"{method.DeclaringType.FullName}.{method.Name}",
                File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
                Line = sp?.StartLine ?? 0,
                Role = HopRole.Sanitizer,
                TaintedValueIn = sanitizerMatch.EstablishesBound.Target,
                Transformation = "identity",
                TaintedValueOut = sanitizerMatch.EstablishesBound.Target,
                EstablishesBound = sanitizerMatch.EstablishesBound,
                OnFailure = sanitizerMatch.OnFailure,
                Dispatch = new ResolvedDispatch
                {
                    Kind = "direct",
                    StaticType = method.DeclaringType.FullName,
                    ResolvedTargets = Array.Empty<string>(),
                    ClosureBoundary = false,
                },
            };
        }
```

At the end of `WalkMethodBody`, right before the `return new MethodSummary { ... }`, splice the sanitizer hop in at its IL order and synthesize `sanitizer_absence` for pre-fix (no sanitizer + reached sink):

```csharp
        if (pendingSanitizerHop is not null)
        {
            // Insert the sanitizer hop at a position that comes before the sink but after the setup
            // propagators. For MVP, put it right before the last hop (the sink).
            int insertAt = hops.Count > 0 && hops[^1].Role == HopRole.Sink ? hops.Count - 1 : hops.Count;
            hops.Insert(insertAt, pendingSanitizerHop with { Hop = insertAt });
            // Renumber.
            for (int i = 0; i < hops.Count; i++) hops[i] = hops[i] with { Hop = i };
        }

        var absences = new List<EmittedSanitizerAbsence>();
        if (pendingSanitizerHop is null && reachedSink && hops.Count > 0)
        {
            // Point at the propagator hop immediately preceding the sink, per spec.
            var sinkHop = hops.Last(h => h.Role == HopRole.Sink);
            var preSinkIdx = Math.Max(0, hops.IndexOf(sinkHop) - 1);
            var preSink = hops.Count > 0 ? hops[preSinkIdx] : sinkHop;
            var sinkFile = sinkHop.File;
            var sinkLine = sinkHop.Line;
            var sinkApiDisplay = sinkHop.SinkApi switch
            {
                SinkApi.NewArray => "new_array",
                SinkApi.ArrayPoolRent => "array_pool_rent",
                SinkApi.SpanSlice => "span_slice",
                SinkApi.SpanIndex => "span_index",
                _ => "unknown",
            };
            absences.Add(new EmittedSanitizerAbsence
            {
                Location = $"{preSink.File}:{preSink.Line}",
                TaintedValue = preSink.TaintedValueOut,
                ExpectedCheck = $"{preSink.TaintedValueOut} must be bounded before reaching {sinkApiDisplay} at {sinkFile}:{sinkLine}",
            });
        }
```

Update the return to include `Absences = absences`. (Replace the `Absences = Array.Empty<...>()` line.)

Also, `HopRecord` needs `with`-clause support — declare it as a `record` rather than `class`. Open `tools/TaintAnalyzer/HopRecord.cs` and change `public sealed class HopRecord` to `public sealed record HopRecord`. All `init`-only properties already work with records; the `with`-expressions in `WalkMethodBody` then compile.

- [ ] **Step 12.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalker"`
Expected: all 11 tests passing.

- [ ] **Step 12.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 12.7: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer/HopRecord.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: TaintWalker — sanitizer hop emission + pre-fix sanitizer_absence synthesis"
```

---

## Task 13: `TraceEmitter.cs` — HopRecords → YAML + source/sink nodes

**Files:**
- Create: `tools/TaintAnalyzer/TraceEmitter.cs`
- Create: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`

**Responsibility.** Take the source method, the walker's accumulated hops + absences, plus the `RulesDocument`, and produce a YAML string that a ValidateFixture run on `validate` (not `--compare`) would accept as well-formed. The emitter constructs a `FixtureDocument`-shaped object tree and hands it to YamlDotNet.

The emitter imports the existing `FixtureDocument`/`PathNode`/`SanitizerAbsence` types from `TaintAnalyzer.ValidateFixture` namespace — the analyzer and validator share the same YAML shape definitions. Add a project reference from the analyzer to the validator project so we don't duplicate POCOs.

- [ ] **Step 13.1: Add project reference**

Modify `tools/TaintAnalyzer/TaintAnalyzer.csproj`:

```xml
  <ItemGroup>
    <PackageReference Include="Mono.Cecil" Version="0.11.6" />
    <PackageReference Include="YamlDotNet" Version="15.1.6" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\ValidateFixture\ValidateFixture.csproj" />
  </ItemGroup>
```

- [ ] **Step 13.2: Write `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`**

```csharp
using Shouldly;
using TaintAnalyzer;
using TaintAnalyzer.ValidateFixture;
using YamlDotNet.Serialization;

namespace TaintAnalyzer.Tests;

public class TraceEmitterTests
{
    [Fact]
    public void Emit_SyntheticHops_ProducesValidYaml()
    {
        var rules = new RulesDocument { VulnId = "test-0001", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
        };
        var propagator = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Propagator,
            TaintedValueIn = "stream", Transformation = "arithmetic", TaintedValueOut = "size",
            Dispatch = new ResolvedDispatch { Kind = "direct", StaticType = "Ns.T", ResolvedTargets = Array.Empty<string>(), ClosureBoundary = false },
        };
        var sink = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size",
        };
        var absences = new List<EmittedSanitizerAbsence>
        {
            new() { Location = "T.cs:15", TaintedValue = "size", ExpectedCheck = "size must be bounded before reaching new_array at T.cs:20" },
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, propagator, sink }, absences);

        yaml.ShouldContain("vuln_id: test-0001");
        yaml.ShouldContain("method: Ns.T.M");
        yaml.ShouldContain("kind: allocation");
        yaml.ShouldContain("api: new_array");
        yaml.ShouldContain("tainted_value: size");
        yaml.ShouldContain("expected_check: ");
    }

    [Fact]
    public void Emit_PostFixWithSanitizer_EmitsEmptySanitizerAbsenceList()
    {
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 1, Role = HopRole.Source,
            TaintedValueIn = "n", Transformation = "read_stream", TaintedValueOut = "n",
        };
        var sanitizerHop = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 2, Role = HopRole.Sanitizer,
            TaintedValueIn = "n", Transformation = "identity", TaintedValueOut = "n",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "1024" },
            OnFailure = new OnFailure { Kind = FailureKind.Throw, Exception = "System.ArgumentOutOfRangeException" },
            Dispatch = new ResolvedDispatch { Kind = "direct", StaticType = "Ns.T", ResolvedTargets = Array.Empty<string>(), ClosureBoundary = false },
        };
        var sink = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 3, Role = HopRole.Sink,
            TaintedValueIn = "n", Transformation = "identity", TaintedValueOut = "n",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sanitizerHop, sink },
            Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldContain("sanitizer_absence: []");
    }

    [Fact]
    public void Emit_OmittedVulnId_DoesNotEmitKey()
    {
        var rules = new RulesDocument { VulnId = null, SourceMethods = new() { "Ns.T::M()" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 1, Role = HopRole.Source,
            TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
        };
        var sink = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 2, Role = HopRole.Sink,
            TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "x",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sink }, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldNotContain("vuln_id:");
    }
}
```

- [ ] **Step 13.3: Run tests to confirm failure**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TraceEmitter"`
Expected: compilation error — `TraceEmitter` undefined.

- [ ] **Step 13.4: Write `tools/TaintAnalyzer/TraceEmitter.cs`**

```csharp
using TaintAnalyzer.ValidateFixture;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer;

public static class TraceEmitter
{
    private static readonly ISerializer s_serializer = new SerializerBuilder()
        .WithNamingConvention(NullNamingConvention.Instance)   // emitter uses YamlMember aliases on FixtureDocument
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();

    public static string Emit(
        RulesDocument rules,
        IReadOnlyList<HopRecord> hops,
        IReadOnlyList<EmittedSanitizerAbsence> absences)
    {
        var sourceHop = hops.First(h => h.Role == HopRole.Source);
        var sinkHop = hops.First(h => h.Role == HopRole.Sink);

        var doc = new FixtureDocument
        {
            VulnId = rules.VulnId,
            Source = PathNodeFromHop(sourceHop),
            Sink = PathNodeFromHop(sinkHop),
            Path = hops
                .Where(h => h.Role is HopRole.Propagator or HopRole.Sanitizer)
                .Select(PathNodeFromHop)
                .ToList(),
            SanitizerAbsence = absences
                .Select(a => new SanitizerAbsence
                {
                    Location = a.Location,
                    TaintedValue = a.TaintedValue,
                    ExpectedCheck = a.ExpectedCheck,
                })
                .ToList(),
        };

        return s_serializer.Serialize(doc);
    }

    private static PathNode PathNodeFromHop(HopRecord h)
    {
        var pn = new PathNode
        {
            Hop = h.Role is HopRole.Source or HopRole.Sink ? null : h.Hop,
            Method = h.Method,
            File = h.File,
            Line = h.Line,
            Role = h.Role switch
            {
                HopRole.Source => "source",
                HopRole.Propagator => "propagator",
                HopRole.Sanitizer => "sanitizer",
                HopRole.Sink => "sink",
                _ => "unknown",
            },
            TaintedValueIn = h.TaintedValueIn,
            Transformation = h.Transformation,
            TaintedValueOut = h.TaintedValueOut,
            Note = h.Note,
        };

        if (h.Dispatch is { } d)
        {
            pn = pn with { };  // no-op; PathNode is a class — we'll assign through `init`-setters via a fresh object.
        }

        var dispatch = h.Dispatch is { } d2
            ? new Dispatch
            {
                Kind = d2.Kind,
                StaticType = d2.StaticType,
                ResolvedTargets = d2.ResolvedTargets.ToList(),
                ClosureBoundary = d2.ClosureBoundary,
            }
            : null;

        var eb = h.EstablishesBound is { } bound
            ? new EstablishesBound { Target = bound.Target, Relation = bound.Relation, UpperBound = bound.UpperBound, LowerBound = bound.LowerBound }
            : null;

        var onFail = h.OnFailure is { } of
            ? new OnFailure
            {
                Kind = of.Kind switch { FailureKind.Throw => "throw", FailureKind.ReturnEarly => "return_early", _ => "unknown" },
                Exception = of.Exception,
            }
            : null;

        // Re-construct with the nested types. `PathNode` has `init` setters so we cannot mutate — emit a full copy.
        return new PathNode
        {
            Hop = pn.Hop, Method = pn.Method, File = pn.File, Line = pn.Line, Role = pn.Role,
            TaintedValueIn = pn.TaintedValueIn, Transformation = pn.Transformation, TaintedValueOut = pn.TaintedValueOut,
            Note = pn.Note,
            Dispatch = dispatch,
            EstablishesBound = eb,
            OnFailure = onFail,
            Kind = h.Role == HopRole.Sink ? SinkKindToString(h.SinkKind) :
                   h.Role == HopRole.Source ? "decoder_entry" : null,
            Api = h.Role == HopRole.Sink ? SinkApiToString(h.SinkApi) : null,
            SizeExpression = h.SizeExpression,
            AccessExpression = h.AccessExpression,
        };
    }

    private static string? SinkKindToString(SinkKind? k) => k switch
    {
        SinkKind.Allocation => "allocation",
        SinkKind.SpanAccess => "span_access",
        _ => null,
    };

    private static string? SinkApiToString(SinkApi? a) => a switch
    {
        SinkApi.NewArray => "new_array",
        SinkApi.ArrayPoolRent => "array_pool_rent",
        SinkApi.SpanSlice => "span_slice",
        SinkApi.SpanIndex => "span_index",
        _ => null,
    };
}
```

If YamlDotNet doesn't expose `DefaultValuesHandling.OmitNull` as written, the alternative is `.ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)` with `using YamlDotNet.Serialization;` (same namespace). If the API differs in 15.1.6, replace with `.DisableAliases()` + explicit `ShouldSerialize*` methods on FixtureDocument. For MVP: accept that null properties serialize as `~` rather than being omitted; the validator's `IgnoreUnmatchedProperties` makes this a non-issue for `--compare`.

- [ ] **Step 13.5: Run tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TraceEmitter"`
Expected: 3 tests passing. If `Emit_PostFixWithSanitizer_EmitsEmptySanitizerAbsenceList` fails because YamlDotNet emits `sanitizer_absence:\n  []` across two lines, relax the assertion to `yaml.ShouldMatch(@"sanitizer_absence:\s*\[\s*\]");`.

If `Emit_OmittedVulnId_DoesNotEmitKey` fails because YamlDotNet emits `vuln_id: null` instead of omitting the line, add `[YamlIgnore]`-via-`ShouldSerializeVulnId()` on `FixtureDocument` — but the spec says VulnId's absence should be YAML-absent. Fix the emitter by using a dynamic object when `VulnId` is null, or by serializing to a dictionary and removing the null key.

- [ ] **Step 13.6: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 13.7: Commit**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer/TaintAnalyzer.csproj tools/TaintAnalyzer.Tests/TraceEmitterTests.cs
git commit -m "analyzer: TraceEmitter — HopRecords to trace.yaml via shared FixtureDocument POCOs"
```

---

## Task 14: `Program.cs` — CLI wiring + exit codes

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`

**Responsibility.** Parse `<target.dll> --rules <rules.yaml> [--output <trace.yaml>]`. Load rules, resolve each `source_methods` entry against the target via `AssemblyContext.FindMethod`, error with nearest-candidate suggestions on miss. Walk each source. Emit trace. Stdout default, file when `--output` present. Exit codes per spec: 0 = trace emitted, 1 = IO/parse/analysis error, 2 = usage error.

- [ ] **Step 14.1: Replace `tools/TaintAnalyzer/Program.cs`**

```csharp
using TaintAnalyzer;

namespace TaintAnalyzer;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            PrintUsage();
            return 2;
        }

        string? target = null;
        string? rulesPath = null;
        string? outputPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--rules")
            {
                if (++i >= args.Length) { Console.Error.WriteLine("error: --rules requires a path"); return 2; }
                rulesPath = args[i];
            }
            else if (a == "--output")
            {
                if (++i >= args.Length) { Console.Error.WriteLine("error: --output requires a path"); return 2; }
                outputPath = args[i];
            }
            else if (a.StartsWith("--", StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"error: unknown flag {a}");
                PrintUsage();
                return 2;
            }
            else if (target is null)
            {
                target = a;
            }
            else
            {
                Console.Error.WriteLine($"error: unexpected positional argument: {a}");
                PrintUsage();
                return 2;
            }
        }

        if (target is null || rulesPath is null)
        {
            PrintUsage();
            return 2;
        }

        if (!File.Exists(target))
        {
            Console.Error.WriteLine($"error: target assembly not found: {target}");
            return 1;
        }
        if (!File.Exists(rulesPath))
        {
            Console.Error.WriteLine($"error: rules file not found: {rulesPath}");
            return 1;
        }

        RulesDocument rules;
        try
        {
            rules = RulesDocument.Load(File.ReadAllText(rulesPath));
        }
        catch (RulesDocumentException ex)
        {
            Console.Error.WriteLine($"error: rules: {ex.Message}");
            return 1;
        }

        AssemblyContext context;
        try
        {
            context = AssemblyContext.Load(target);
        }
        catch (AssemblyContextException ex)
        {
            Console.Error.WriteLine($"error: assembly: {ex.Message}");
            return 1;
        }

        using (context)
        {
            var walker = new TaintWalker(context);
            var allHops = new List<HopRecord>();
            var allAbsences = new List<EmittedSanitizerAbsence>();

            foreach (var sig in rules.SourceMethods)
            {
                var source = context.FindMethod(sig);
                if (source is null)
                {
                    var suggestion = SuggestNearest(context, sig);
                    Console.Error.WriteLine($"error: source method not found: {sig}");
                    if (suggestion is not null) Console.Error.WriteLine($"   closest in target: {suggestion}");
                    return 1;
                }

                // Seed: every non-receiver parameter tainted (source defines which params are attacker-controlled).
                int bitmask = (1 << source.Parameters.Count) - 1;
                var summary = walker.Walk(source, bitmask);

                // Emit a `source` hop from the source method's first sequence point.
                var sp = source.Body is null ? null : context.GetSequencePoint(source, source.Body.Instructions.First());
                allHops.Add(new HopRecord
                {
                    Hop = 0,
                    Method = $"{source.DeclaringType.FullName}.{source.Name}",
                    File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
                    Line = sp?.StartLine ?? 0,
                    Role = HopRole.Source,
                    TaintedValueIn = source.Parameters.FirstOrDefault()?.Name ?? "arg0",
                    Transformation = "read_stream",
                    TaintedValueOut = source.Parameters.FirstOrDefault()?.Name ?? "arg0",
                });
                allHops.AddRange(summary.Hops);
                allAbsences.AddRange(summary.Absences);
            }

            var yaml = TraceEmitter.Emit(rules, allHops, allAbsences);

            if (outputPath is null)
            {
                Console.Write(yaml);
            }
            else
            {
                File.WriteAllText(outputPath, yaml);
            }
        }

        return 0;
    }

    private static string? SuggestNearest(AssemblyContext ctx, string sig)
    {
        int bestDist = int.MaxValue;
        string? best = null;
        foreach (var candidate in ctx.AllSignatures())
        {
            var d = Distance(sig, candidate);
            if (d < bestDist)
            {
                bestDist = d;
                best = candidate;
            }
        }
        return best;
    }

    // Simple Levenshtein; cheap to reimplement, no extra dependency.
    private static int Distance(string a, string b)
    {
        var dp = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) dp[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) dp[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
                dp[i, j] = a[i - 1] == b[j - 1]
                    ? dp[i - 1, j - 1]
                    : 1 + Math.Min(dp[i - 1, j - 1], Math.Min(dp[i - 1, j], dp[i, j - 1]));
        return dp[a.Length, b.Length];
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: TaintAnalyzer <target.dll> --rules <rules.yaml> [--output <trace.yaml>]");
    }
}
```

- [ ] **Step 14.2: Build**

Run: `dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj`
Expected: 0 errors, 0 warnings.

- [ ] **Step 14.3: Manual smoke test — usage error**

Run: `dotnet run --project tools/TaintAnalyzer --`
Expected: exit code 2, usage message on stderr.

- [ ] **Step 14.4: Manual smoke test — run against fixture DLL**

Generate a throwaway rules file and run against the test-fixtures DLL:

```bash
cat > /tmp/rules-smoke.yaml <<'YAML'
vuln_id: smoke
source_methods:
  - TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodAllocation(System.Int32)
YAML

dotnet build tools/TaintAnalyzer.Tests.Fixtures --nologo --verbosity quiet
FIXDLL="tools/TaintAnalyzer.Tests.Fixtures/bin/Debug/net10.0/TaintAnalyzer.Tests.Fixtures.dll"
dotnet run --project tools/TaintAnalyzer -- "$FIXDLL" --rules /tmp/rules-smoke.yaml
echo "exit=$?"
```

Expected: exit 0. Stdout contains `vuln_id: smoke`, `kind: allocation`, `api: new_array`, and a `sanitizer_absence:` block with one entry.

- [ ] **Step 14.5: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 14.6: Commit**

```bash
git add tools/TaintAnalyzer/Program.cs
git commit -m "analyzer: CLI — arg parse, nearest-signature suggestion, stdout/output, exit codes"
```

---

## Task 15: Validator `--compare` mode — FX060 source mismatch

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs` — add `Compare(...)` method.
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` — add `CompareTests` nested class.

**Responsibility.** First of four comparison diagnostics. The `Compare` method takes two already-parsed `FixtureDocument`s (ground-truth and analyzer-output) and emits diagnostics when their `source` shapes disagree on `method`, `file`, or `line`. The diagnostic format follows the spec: `FXNNN <short category>: <field> expected=<X> actual=<Y> [at <loc>]`.

- [ ] **Step 15.1: Write the test slice for FX060**

Append to `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` — add a nested class at the end of the existing `FixtureValidatorTests` class body (or as a new class in the same file):

```csharp
public class CompareTests
{
    private static FixtureDocument Doc(string method, string file, int line, string? sinkMethod = null, int? sinkLine = null)
    {
        return new FixtureDocument
        {
            VulnId = "v", FixCommit = "c", FixPr = "p", Description = "d",
            Source = new PathNode { Method = method, File = file, Line = line, Role = "source",
                                    TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" },
            Sink = new PathNode { Method = sinkMethod ?? method, File = file, Line = sinkLine ?? line + 10,
                                  Role = "sink", Kind = "allocation", Api = "new_array",
                                  SizeExpression = "x",
                                  TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" },
            Path = new List<PathNode>(),
            SanitizerAbsence = new List<SanitizerAbsence>(),
        };
    }

    [Fact]
    public void Compare_EqualSources_EmitsNoFX060()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        var actual = Doc("Ns.T.M", "T.cs", 10);

        var diags = new FixtureValidator().Compare(gt, actual);

        diags.ShouldNotContain(d => d.Code == "FX060");
    }

    [Fact]
    public void Compare_DifferentSourceMethod_EmitsFX060()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        var actual = Doc("Ns.T.Other", "T.cs", 10);

        var diags = new FixtureValidator().Compare(gt, actual);

        diags.ShouldContain(d => d.Code == "FX060" && d.Message.Contains("method") && d.Message.Contains("expected=Ns.T.M") && d.Message.Contains("actual=Ns.T.Other"));
    }

    [Fact]
    public void Compare_DifferentSourceLine_EmitsFX060()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        var actual = Doc("Ns.T.M", "T.cs", 11);

        var diags = new FixtureValidator().Compare(gt, actual);

        diags.ShouldContain(d => d.Code == "FX060" && d.Message.Contains("line") && d.Message.Contains("expected=10") && d.Message.Contains("actual=11"));
    }
}
```

- [ ] **Step 15.2: Run the tests — confirm failure**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --filter "FullyQualifiedName~CompareTests"`
Expected: compilation error — `FixtureValidator.Compare` undefined.

- [ ] **Step 15.3: Add `Compare` method to `FixtureValidator.cs`**

At the end of `FixtureValidator` class (before the closing brace), add:

```csharp
    public IReadOnlyList<Diagnostic> Compare(FixtureDocument groundTruth, FixtureDocument actual)
    {
        var diags = new List<Diagnostic>();

        // FX060 — source mismatch
        CompareSource(groundTruth.Source, actual.Source, diags);

        return diags;
    }

    private static void CompareSource(PathNode? gt, PathNode? actual, List<Diagnostic> diags)
    {
        if (gt is null || actual is null)
        {
            if (gt is null && actual is null) return;
            diags.Add(new Diagnostic("FX060", $"source mismatch: field expected={(gt is null ? "<null>" : "<present>")} actual={(actual is null ? "<null>" : "<present>")}"));
            return;
        }

        if (!string.Equals(gt.Method, actual.Method, StringComparison.Ordinal))
        {
            diags.Add(new Diagnostic("FX060", $"source mismatch: method expected={gt.Method} actual={actual.Method}"));
        }
        if (!string.Equals(gt.File, actual.File, StringComparison.Ordinal))
        {
            diags.Add(new Diagnostic("FX060", $"source mismatch: file expected={gt.File} actual={actual.File}"));
        }
        if (gt.Line != actual.Line)
        {
            diags.Add(new Diagnostic("FX060", $"source mismatch: line expected={gt.Line} actual={actual.Line} at {actual.File ?? "<unknown>"}"));
        }
    }
```

- [ ] **Step 15.4: Run tests**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --filter "FullyQualifiedName~CompareTests"`
Expected: 3 tests passing.

- [ ] **Step 15.5: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 15.6: Commit**

```bash
git add tools/ValidateFixture/FixtureValidator.cs tools/ValidateFixture.Tests/FixtureValidatorTests.cs
git commit -m "validator: FX060 source mismatch — Compare entrypoint"
```

---

## Task 16: Validator `--compare` — FX061 sink mismatch + metadata exemption

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 16.1: Add tests for FX061 and metadata exemption**

Append to `CompareTests`:

```csharp
    [Fact]
    public void Compare_EqualSinks_EmitsNoFX061()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 20);
        var actual = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 20);

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldNotContain(d => d.Code == "FX061");
    }

    [Fact]
    public void Compare_DifferentSinkLine_EmitsFX061()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 20);
        var actual = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 22);

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX061" && d.Message.Contains("line") && d.Message.Contains("expected=20") && d.Message.Contains("actual=22"));
    }

    [Fact]
    public void Compare_DifferentSinkKind_EmitsFX061()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 20);
        var actual = Doc("Ns.T.M", "T.cs", 10, "Ns.T.M", 20);
        actual.Sink = new PathNode { Method = "Ns.T.M", File = "T.cs", Line = 20, Role = "sink",
                                     Kind = "span_access", Api = "span_slice", AccessExpression = "x",
                                     TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX061" && d.Message.Contains("kind"));
    }

    [Fact]
    public void Compare_MetadataFieldsDiffer_EmitsNoDiagnostic()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        var actual = Doc("Ns.T.M", "T.cs", 10);
        // VulnId/FixCommit/FixPr/Description on analyzer-side intentionally empty.
        actual.VulnId = null;
        actual.FixCommit = null;
        actual.FixPr = null;
        actual.Description = null;

        var diags = new FixtureValidator().Compare(gt, actual);

        diags.ShouldBeEmpty();
    }
```

Note: the `Doc` helper builds instances with `init`-only setters — to mutate `actual.Sink` the way `Compare_DifferentSinkKind` wants, change the `Sink` and other object properties in `FixtureDocument`/`PathNode` to have setters (remove `init`). The YamlMember aliases remain; deserialization still works with plain setters. Double-check the existing validator tests pass afterward — they construct these via YAML deserializer, which doesn't care about `init` vs `set`.

- [ ] **Step 16.2: Relax `init` to `set` on `FixtureDocument` / `PathNode` setters used in compare tests**

Open `tools/ValidateFixture/FixtureDocument.cs`. Change the following properties from `init` to `set`:
- `FixtureDocument.VulnId`, `.FixCommit`, `.FixPr`, `.Description`, `.Source`, `.Sink`, `.Path`, `.SanitizerAbsence`

All other properties on `PathNode` etc. can stay `init` — the tests in Task 16 only mutate top-level `FixtureDocument` properties and the `Sink` object assignment.

- [ ] **Step 16.3: Run tests — confirm failures**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --filter "FullyQualifiedName~CompareTests"`
Expected: the three FX061 tests fail because FX061 isn't emitted yet; the metadata-exemption test passes (no diagnostic emitted at all).

- [ ] **Step 16.4: Add FX061 check to `Compare`**

Extend `Compare` and add a `CompareSink` helper:

```csharp
    public IReadOnlyList<Diagnostic> Compare(FixtureDocument groundTruth, FixtureDocument actual)
    {
        var diags = new List<Diagnostic>();

        CompareSource(groundTruth.Source, actual.Source, diags);
        CompareSink(groundTruth.Sink, actual.Sink, diags);

        return diags;
    }

    private static void CompareSink(PathNode? gt, PathNode? actual, List<Diagnostic> diags)
    {
        if (gt is null || actual is null)
        {
            if (gt is null && actual is null) return;
            diags.Add(new Diagnostic("FX061", $"sink mismatch: field expected={(gt is null ? "<null>" : "<present>")} actual={(actual is null ? "<null>" : "<present>")}"));
            return;
        }

        if (!string.Equals(gt.Method, actual.Method, StringComparison.Ordinal))
            diags.Add(new Diagnostic("FX061", $"sink mismatch: method expected={gt.Method} actual={actual.Method}"));
        if (!string.Equals(gt.File, actual.File, StringComparison.Ordinal))
            diags.Add(new Diagnostic("FX061", $"sink mismatch: file expected={gt.File} actual={actual.File}"));
        if (gt.Line != actual.Line)
            diags.Add(new Diagnostic("FX061", $"sink mismatch: line expected={gt.Line} actual={actual.Line} at {actual.File ?? "<unknown>"}"));
        if (!string.Equals(gt.Kind, actual.Kind, StringComparison.Ordinal))
            diags.Add(new Diagnostic("FX061", $"sink mismatch: kind expected={gt.Kind} actual={actual.Kind}"));
        if (!string.Equals(gt.Api, actual.Api, StringComparison.Ordinal))
            diags.Add(new Diagnostic("FX061", $"sink mismatch: api expected={gt.Api} actual={actual.Api}"));
    }
```

- [ ] **Step 16.5: Run tests**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj`
Expected: all passing (existing + 7 compare-tests total so far).

- [ ] **Step 16.6: Commit**

```bash
git add tools/ValidateFixture/FixtureValidator.cs tools/ValidateFixture/FixtureDocument.cs tools/ValidateFixture.Tests/FixtureValidatorTests.cs
git commit -m "validator: FX061 sink mismatch + metadata-field exemption"
```

---

## Task 17: Validator `--compare` — FX062 sanitizer_absence with ±2-line tolerance

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 17.1: Add FX062 tests**

Append to `CompareTests`:

```csharp
    [Fact]
    public void Compare_EqualAbsences_EmitsNoFX062()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "x <= N", PresentPreFix = false, PresentPostFix = true },
        };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "x must be bounded before reaching new_array at T.cs:20" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldNotContain(d => d.Code == "FX062");
    }

    [Fact]
    public void Compare_AbsenceLineOffByOne_Tolerated()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "author prose" },
        };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:19", TaintedValue = "x", ExpectedCheck = "analyzer summary" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldNotContain(d => d.Code == "FX062");
    }

    [Fact]
    public void Compare_AbsenceLineOffByThree_EmitsFX062()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "a" },
        };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:21", TaintedValue = "x", ExpectedCheck = "b" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("location"));
    }

    [Fact]
    public void Compare_AbsenceDifferentFile_EmitsFX062()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "a" },
        };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "Other.cs:18", TaintedValue = "x", ExpectedCheck = "b" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("file"));
    }

    [Fact]
    public void Compare_AbsenceCountMismatch_EmitsFX062()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "a" },
            new() { Location = "T.cs:19", TaintedValue = "y", ExpectedCheck = "b" },
        };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.SanitizerAbsence = new List<SanitizerAbsence>
        {
            new() { Location = "T.cs:18", TaintedValue = "x", ExpectedCheck = "c" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("count"));
    }
```

- [ ] **Step 17.2: Run tests — confirm failure**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --filter "FullyQualifiedName~CompareTests"`
Expected: 5 new tests fail (FX062 not emitted); existing 7 pass.

- [ ] **Step 17.3: Add FX062 check**

Extend `Compare`:

```csharp
    public IReadOnlyList<Diagnostic> Compare(FixtureDocument groundTruth, FixtureDocument actual)
    {
        var diags = new List<Diagnostic>();

        CompareSource(groundTruth.Source, actual.Source, diags);
        CompareSink(groundTruth.Sink, actual.Sink, diags);
        CompareSanitizerAbsence(groundTruth.SanitizerAbsence, actual.SanitizerAbsence, diags);

        return diags;
    }

    private static void CompareSanitizerAbsence(List<SanitizerAbsence>? gt, List<SanitizerAbsence>? actual, List<Diagnostic> diags)
    {
        var gtList = gt ?? new List<SanitizerAbsence>();
        var actList = actual ?? new List<SanitizerAbsence>();

        if (gtList.Count != actList.Count)
        {
            diags.Add(new Diagnostic("FX062", $"sanitizer_absence mismatch: count expected={gtList.Count} actual={actList.Count}"));
            return;
        }

        for (int i = 0; i < gtList.Count; i++)
        {
            var e = gtList[i];
            var a = actList[i];

            var (eFile, eLine) = ParseLocation(e.Location);
            var (aFile, aLine) = ParseLocation(a.Location);

            if (!string.Equals(eFile, aFile, StringComparison.Ordinal))
            {
                diags.Add(new Diagnostic("FX062",
                    $"sanitizer_absence mismatch: file expected={eFile} actual={aFile} for hop {i} (expected_check expected=\"{e.ExpectedCheck}\" actual=\"{a.ExpectedCheck}\")"));
            }
            else if (eLine is int el && aLine is int al && Math.Abs(el - al) > 2)
            {
                diags.Add(new Diagnostic("FX062",
                    $"sanitizer_absence mismatch: location expected={el} actual={al} (tolerance=±2) for hop {i} (expected_check expected=\"{e.ExpectedCheck}\" actual=\"{a.ExpectedCheck}\")"));
            }

            if (!string.Equals(e.TaintedValue, a.TaintedValue, StringComparison.Ordinal))
            {
                diags.Add(new Diagnostic("FX062",
                    $"sanitizer_absence mismatch: tainted_value expected={e.TaintedValue} actual={a.TaintedValue} for hop {i}"));
            }
        }
    }

    private static (string? file, int? line) ParseLocation(string? location)
    {
        if (string.IsNullOrEmpty(location)) return (null, null);
        int colon = location.LastIndexOf(':');
        if (colon < 0) return (location, null);
        var filePart = location.Substring(0, colon);
        var linePart = location.Substring(colon + 1);
        return (filePart, int.TryParse(linePart, out var ln) ? ln : null);
    }
```

- [ ] **Step 17.4: Run tests**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj`
Expected: all passing.

- [ ] **Step 17.5: Commit**

```bash
git add tools/ValidateFixture/FixtureValidator.cs tools/ValidateFixture.Tests/FixtureValidatorTests.cs
git commit -m "validator: FX062 sanitizer_absence mismatch with ±2-line tolerance + expected_check context"
```

---

## Task 18: Validator `--compare` — FX063 sanitizer hop with full bound match

**Files:**
- Modify: `tools/ValidateFixture/FixtureValidator.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

- [ ] **Step 18.1: Add FX063 tests**

Append to `CompareTests`:

```csharp
    private static PathNode SanNode(int line, string target, string relation, string? upper = null, string? lower = null,
                                    string failKind = "throw", string? exception = "System.ArgumentOutOfRangeException")
    {
        return new PathNode
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = line, Role = "sanitizer",
            TaintedValueIn = target, Transformation = "identity", TaintedValueOut = target,
            EstablishesBound = new EstablishesBound { Target = target, Relation = relation, UpperBound = upper, LowerBound = lower },
            OnFailure = new OnFailure { Kind = failKind, Exception = exception },
        };
    }

    [Fact]
    public void Compare_EqualSanitizerHops_EmitsNoFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N") };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldNotContain(d => d.Code == "FX063");
    }

    [Fact]
    public void Compare_SanitizerHopLineDiffers_EmitsFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(16, "x", "<=", upper: "N") };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("line"));
    }

    [Fact]
    public void Compare_SanitizerHopRelationDiffers_EmitsFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(15, "x", "<", upper: "N") };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("relation"));
    }

    [Fact]
    public void Compare_SanitizerHopUpperBoundDiffers_EmitsFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "M") };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("upper_bound"));
    }

    [Fact]
    public void Compare_SanitizerHopFailureKindDiffers_EmitsFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N", failKind: "throw") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N", failKind: "return_early", exception: null) };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("on_failure.kind"));
    }

    [Fact]
    public void Compare_SanitizerHopThrowExceptionDiffers_EmitsFX063()
    {
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N", exception: "System.ArgumentOutOfRangeException") };
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode> { SanNode(15, "x", "<=", upper: "N", exception: "System.InvalidOperationException") };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("on_failure.exception"));
    }

    [Fact]
    public void Compare_NonSanitizerHopsNotCompared_NoFX063()
    {
        // Different propagator hop counts — spec says intermediate propagators are informational, not failures.
        var gt = Doc("Ns.T.M", "T.cs", 10);
        gt.Path = new List<PathNode>();
        var actual = Doc("Ns.T.M", "T.cs", 10);
        actual.Path = new List<PathNode>
        {
            new PathNode { Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = "propagator",
                           TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" },
        };

        var diags = new FixtureValidator().Compare(gt, actual);
        diags.ShouldNotContain(d => d.Code == "FX063");
    }
```

- [ ] **Step 18.2: Run tests — confirm failure**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --filter "FullyQualifiedName~CompareTests"`
Expected: 6 of the 7 new tests fail; `Compare_NonSanitizerHopsNotCompared` passes (no FX063 defined yet).

- [ ] **Step 18.3: Add FX063 check**

Extend `Compare`:

```csharp
    public IReadOnlyList<Diagnostic> Compare(FixtureDocument groundTruth, FixtureDocument actual)
    {
        var diags = new List<Diagnostic>();

        CompareSource(groundTruth.Source, actual.Source, diags);
        CompareSink(groundTruth.Sink, actual.Sink, diags);
        CompareSanitizerAbsence(groundTruth.SanitizerAbsence, actual.SanitizerAbsence, diags);
        CompareSanitizerHops(groundTruth.Path, actual.Path, diags);

        return diags;
    }

    private static void CompareSanitizerHops(List<PathNode>? gt, List<PathNode>? actual, List<Diagnostic> diags)
    {
        var gtSans = (gt ?? new List<PathNode>()).Where(n => n.Role == "sanitizer").ToList();
        var actSans = (actual ?? new List<PathNode>()).Where(n => n.Role == "sanitizer").ToList();

        if (gtSans.Count != actSans.Count)
        {
            diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: count expected={gtSans.Count} actual={actSans.Count}"));
            // Continue — index-align as best we can for finer diagnostics.
        }

        int n = Math.Min(gtSans.Count, actSans.Count);
        for (int i = 0; i < n; i++)
        {
            var e = gtSans[i];
            var a = actSans[i];

            if (!string.Equals(e.File, a.File, StringComparison.Ordinal))
            {
                diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: file expected={e.File} actual={a.File} for hop {i}"));
            }
            if (e.Line != a.Line)
            {
                diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: line expected={e.Line} actual={a.Line} for hop {i}"));
            }

            if (e.EstablishesBound is { } eb)
            {
                if (a.EstablishesBound is not { } ab)
                {
                    diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: establishes_bound expected=<present> actual=<null> for hop {i}"));
                }
                else
                {
                    if (!string.Equals(eb.Target, ab.Target, StringComparison.Ordinal))
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: establishes_bound.target expected={eb.Target} actual={ab.Target} for hop {i}"));
                    if (!string.Equals(eb.Relation, ab.Relation, StringComparison.Ordinal))
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: establishes_bound.relation expected={eb.Relation} actual={ab.Relation} for hop {i}"));
                    if (eb.UpperBound is not null && !string.Equals(eb.UpperBound, ab.UpperBound, StringComparison.Ordinal))
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: establishes_bound.upper_bound expected={eb.UpperBound} actual={ab.UpperBound ?? "<null>"} for hop {i}"));
                    if (eb.LowerBound is not null && !string.Equals(eb.LowerBound, ab.LowerBound, StringComparison.Ordinal))
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: establishes_bound.lower_bound expected={eb.LowerBound} actual={ab.LowerBound ?? "<null>"} for hop {i}"));
                }
            }

            if (e.OnFailure is { } of)
            {
                if (a.OnFailure is not { } af)
                {
                    diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: on_failure expected=<present> actual=<null> for hop {i}"));
                }
                else
                {
                    if (!string.Equals(of.Kind, af.Kind, StringComparison.Ordinal))
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: on_failure.kind expected={of.Kind} actual={af.Kind} for hop {i}"));
                    if (string.Equals(of.Kind, "throw", StringComparison.Ordinal) &&
                        !string.Equals(of.Exception, af.Exception, StringComparison.Ordinal))
                    {
                        diags.Add(new Diagnostic("FX063", $"sanitizer hop mismatch: on_failure.exception expected={of.Exception} actual={af.Exception ?? "<null>"} for hop {i}"));
                    }
                }
            }
        }
    }
```

- [ ] **Step 18.4: Run tests**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj`
Expected: all passing.

- [ ] **Step 18.5: Commit**

```bash
git add tools/ValidateFixture/FixtureValidator.cs tools/ValidateFixture.Tests/FixtureValidatorTests.cs
git commit -m "validator: FX063 sanitizer hop mismatch with relation + upper/lower + on_failure match"
```

---

## Task 19: Validator `--compare` — CLI wiring + unified diagnostic format

**Files:**
- Modify: `tools/ValidateFixture/Program.cs`
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` — one end-to-end test invoking the CLI path.

- [ ] **Step 19.1: Wire `--compare` into `Program.cs`**

Replace the body of `Main` in `tools/ValidateFixture/Program.cs`:

```csharp
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 2;
        }

        if (args[0] == "--compare")
        {
            return RunCompare(args);
        }

        return RunValidate(args);
    }

    private static int RunValidate(string[] args)
    {
        if (args.Length < 1)
        {
            PrintUsage();
            return 2;
        }

        var yamlPath = args[0];
        string? snippetsDir = null;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--snippets-dir")
            {
                if (i + 1 >= args.Length)
                {
                    Console.Error.WriteLine("error: --snippets-dir requires a directory argument");
                    PrintUsage();
                    return 2;
                }
                snippetsDir = args[i + 1];
                i++;
            }
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

    private static int RunCompare(string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 2;
        }

        var gtPath = args[1];
        var actualPath = args[2];

        if (!File.Exists(gtPath))  { Console.Error.WriteLine($"error: ground-truth not found: {gtPath}");  return 2; }
        if (!File.Exists(actualPath)) { Console.Error.WriteLine($"error: analyzer output not found: {actualPath}"); return 2; }

        FixtureDocument gt, actual;
        try
        {
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().IgnoreUnmatchedProperties().Build();
            gt = deserializer.Deserialize<FixtureDocument>(File.ReadAllText(gtPath))
                ?? throw new InvalidOperationException("ground-truth is empty");
            actual = deserializer.Deserialize<FixtureDocument>(File.ReadAllText(actualPath))
                ?? throw new InvalidOperationException("analyzer output is empty");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: malformed fixture: {ex.Message}");
            return 2;
        }

        var diags = new FixtureValidator().Compare(gt, actual);

        foreach (var d in diags)
        {
            Console.Error.WriteLine($"{d.Code} {d.Message}");
        }

        if (diags.Count == 0)
        {
            Console.WriteLine("OK: equivalence");
            return 0;
        }

        Console.Error.WriteLine($"FAIL: {diags.Count} diagnostic(s)");
        return 1;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
        Console.Error.WriteLine("       ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>");
    }
```

- [ ] **Step 19.2: Build**

Run: `dotnet build tools/ValidateFixture/ValidateFixture.csproj`
Expected: 0 errors, 0 warnings.

- [ ] **Step 19.3: Full-suite regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing — including the existing validate-path tests that use the CLI.

- [ ] **Step 19.4: Manual smoke test — end-to-end equivalence**

Create two identical YAML files and compare them:

```bash
cat > /tmp/eq-a.yaml <<'YAML'
vuln_id: x
fix_commit: abc
fix_pr: 1
description: d
source: {method: Ns.T.M, file: T.cs, line: 1, role: source, tainted_value_in: x, transformation: identity, tainted_value_out: x}
sink: {method: Ns.T.M, file: T.cs, line: 2, role: sink, kind: allocation, api: new_array, size_expression: x, tainted_value_in: x, transformation: identity, tainted_value_out: x}
path: []
sanitizer_absence: []
YAML
cp /tmp/eq-a.yaml /tmp/eq-b.yaml

dotnet run --project tools/ValidateFixture -- --compare /tmp/eq-a.yaml /tmp/eq-b.yaml
echo "exit=$?"
```

Expected: `OK: equivalence`, exit 0.

Now break the sink line on one side:

```bash
sed -i 's/line: 2, role: sink/line: 3, role: sink/' /tmp/eq-b.yaml
dotnet run --project tools/ValidateFixture -- --compare /tmp/eq-a.yaml /tmp/eq-b.yaml
echo "exit=$?"
```

Expected: stderr shows `FX061 sink mismatch: line expected=2 actual=3 at T.cs`, exit 1.

- [ ] **Step 19.5: Commit**

```bash
git add tools/ValidateFixture/Program.cs
git commit -m "validator: --compare CLI mode with unified FXNNN diagnostic format"
```

---

## Task 20: `scripts/materialize-imagesharp-3074.sh` + confirm `.gitignore`

**Files:**
- Create: `scripts/materialize-imagesharp-3074.sh`
- Verify: `.gitignore` (already updated in Task 1.8; confirm the entry is present).

**Responsibility.** Extract ImageSharp at two pinned commits into `artifacts/<sha>/`, build each in Debug, leave DLLs where the end-to-end tasks can find them. Read-only against the shared clone per memory policy.

- [ ] **Step 20.1: Verify `.gitignore` already has `artifacts/`**

Run: `grep -n '^artifacts/' .gitignore`
Expected: one hit, line showing `artifacts/`.
If missing, append `artifacts/` and `git add .gitignore && git commit -m "gitignore artifacts/"`.

- [ ] **Step 20.2: Write `scripts/materialize-imagesharp-3074.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Materialize pre-fix and post-fix ImageSharp trees for milestone C end-to-end runs.
# Uses `git archive` against the shared clone (/mnt/c/work/dotnet-fuzzing/external/ImageSharp)
# so shallowness doesn't propagate and the shared clone's working tree is not touched.

SHARED_CLONE="${SHARED_CLONE:-/mnt/c/work/dotnet-fuzzing/external/ImageSharp}"
PRE_FIX_SHA="67bac23cff7c32743d0c8e166e9cccbf567837e0"
POST_FIX_SHA="461c021608802370374afabd5d3c2720b3e46f04"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "${SHARED_CLONE}/.git" ]]; then
  echo "error: shared clone not found at ${SHARED_CLONE}" >&2
  exit 2
fi

materialize_one() {
  local sha="$1"
  local dest="${ARTIFACTS}/${sha}"
  if [[ -f "${dest}/src/ImageSharp/ImageSharp.csproj" ]]; then
    echo "[materialize] ${sha} already present at ${dest}"
    return 0
  fi
  echo "[materialize] extracting ${sha} via git archive..."
  mkdir -p "${dest}"
  git -C "${SHARED_CLONE}" archive "${sha}" | tar -x -C "${dest}"
}

build_one() {
  local sha="$1"
  local dest="${ARTIFACTS}/${sha}"
  echo "[build] dotnet build ${sha}..."
  dotnet build "${dest}/src/ImageSharp/ImageSharp.csproj" -c Debug --nologo --verbosity minimal
}

materialize_one "${PRE_FIX_SHA}"
materialize_one "${POST_FIX_SHA}"
build_one "${PRE_FIX_SHA}"
build_one "${POST_FIX_SHA}"

echo
echo "[ok] pre-fix  DLL: ${ARTIFACTS}/${PRE_FIX_SHA}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll"
echo "[ok] post-fix DLL: ${ARTIFACTS}/${POST_FIX_SHA}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll"
```

Make executable: `chmod +x scripts/materialize-imagesharp-3074.sh`.

- [ ] **Step 20.3: Dry-run the script**

Run: `./scripts/materialize-imagesharp-3074.sh`
Expected: two extractions, two builds. Build may emit nullable / obsolete warnings but should finish with `Build succeeded`. Exit 0. Output reports full paths to both DLLs.

If `dotnet build` fails with missing SDK, check `global.json` — the pre-fix commit may require an older `.NET` SDK than our 10.0.x. The script will error out and Task 22 will need an SDK-version workaround (`global.json` copy into `artifacts/<sha>/` pinning a compatible version).

- [ ] **Step 20.4: Commit**

```bash
git add scripts/materialize-imagesharp-3074.sh
git commit -m "scripts: materialize-imagesharp-3074.sh — git archive extraction + dotnet build -c Debug"
```

---

## Task 21: Rules files for #3074 pre-fix and post-fix

**Files:**
- Create: `fixtures/imagesharp-3074-prefix/rules.yaml`
- Create: `fixtures/imagesharp-3074-postfix/rules.yaml`

- [ ] **Step 21.1: Write `fixtures/imagesharp-3074-prefix/rules.yaml`**

The source is the sync BMP decoder entry. Signature form follows Cecil's FullName convention — fully qualified, comma-separated parameter types, no spaces. Target the sync overload only per the spec.

```yaml
vuln_id: imagesharp-3074
source_methods:
  - SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
```

- [ ] **Step 21.2: Write `fixtures/imagesharp-3074-postfix/rules.yaml`**

Same source. (Post-fix differs at the sanitizer site inside the callee, not at the source.)

```yaml
vuln_id: imagesharp-3074
source_methods:
  - SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
```

- [ ] **Step 21.3: Sanity-check via the analyzer's rules loader**

Run a tiny one-liner to validate both load cleanly:

```bash
dotnet run --project tools/TaintAnalyzer -- /dev/null --rules fixtures/imagesharp-3074-prefix/rules.yaml 2>&1 | grep -E "(rules|not found)" || true
```

Expected: the rules file loads (any error will come from `/dev/null` not being a valid DLL, which is Task 22's problem, not a rules problem). If the output contains `error: rules:`, fix the YAML.

- [ ] **Step 21.4: Commit**

```bash
git add fixtures/imagesharp-3074-prefix/rules.yaml fixtures/imagesharp-3074-postfix/rules.yaml
git commit -m "fixture: rules.yaml for #3074 pre-fix and post-fix — sync BmpDecoderCore::Decode source"
```

---

## Task 22: End-to-end — pre-fix run + compare → exit 0

**Files:**
- No new code. This task runs the analyzer against the materialized pre-fix build and iterates on any mismatches until `ValidateFixture --compare` exits 0.

**Expected diagnostic pattern on first run.** The analyzer is an MVP; the ground-truth fixture was human-authored. Mismatches on the first end-to-end run are normal and point to either:
- A bug in the analyzer (fix the analyzer).
- An overly strict ground-truth assertion (rare — the fixtures have already passed review).
- A fixture line-number drift (Debug-build sequence points may differ from the authored line — regenerate the fixture's snippet file from the Debug-built source if that happens; the spec's risk table calls this out).

- [ ] **Step 22.1: Materialize (if not already)**

Run: `./scripts/materialize-imagesharp-3074.sh`
Expected: both `SixLabors.ImageSharp.dll` + `.pdb` exist under `artifacts/<sha>/src/ImageSharp/bin/Debug/`.

- [ ] **Step 22.2: Run the analyzer against pre-fix**

```bash
PRE_FIX_SHA="67bac23cff7c32743d0c8e166e9cccbf567837e0"
DLL=$(ls artifacts/${PRE_FIX_SHA}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll | head -1)

dotnet run --project tools/TaintAnalyzer -- \
  "$DLL" \
  --rules fixtures/imagesharp-3074-prefix/rules.yaml \
  --output /tmp/analyzer-3074-prefix.yaml

echo "exit=$?"
```

Expected: exit 0. `/tmp/analyzer-3074-prefix.yaml` exists and is non-empty. (A non-zero exit here means the analyzer crashed or couldn't load the DLL — debug with `--verbose`-equivalent by adding `Console.Error.WriteLine` in `Program.cs` temporarily.)

- [ ] **Step 22.3: Compare against ground truth**

```bash
dotnet run --project tools/ValidateFixture -- --compare \
  fixtures/imagesharp-3074-prefix/trace.yaml \
  /tmp/analyzer-3074-prefix.yaml
echo "exit=$?"
```

Expected first-run outcome (likely): one or more `FXNNN` diagnostics. Likely categories:
- **FX060/FX061** line-number mismatches (±1 or ±2): Debug-build sequence points may differ from the fixture's hand-authored lines. Approach: disassemble with `ildasm` to confirm the IL line for the source method's prologue, then decide whether to update the fixture's `source.line` / `sink.line` or investigate an analyzer bug.
- **FX062** `count` mismatch: the analyzer may emit more / fewer `sanitizer_absence` entries than the one the fixture has. Check `/tmp/analyzer-3074-prefix.yaml` — there should be exactly one entry. Count > 1 means the walker visited multiple paths to the sink; for MVP, collapse duplicates by `(file,line,tainted_value)` in `TaintWalker.WalkMethodBody`.
- **FX063** shouldn't fire on pre-fix (no sanitizer hops). If it does, the analyzer is synthesizing a spurious sanitizer hop somewhere.

- [ ] **Step 22.4: Iterate on each diagnostic**

For each failing diagnostic, the loop is: add a dedicated unit test replicating the shape in `TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (TDD), fix the analyzer, rerun Steps 22.2 + 22.3. Commit each fix individually with a message of the form `analyzer: fix <short symptom>`.

Until the `--compare` run exits 0, Task 22 is not complete. When stuck, debug against the live pre-fix DLL with ad-hoc scripts; avoid modifying the ground-truth fixture unless line-number drift is confirmed via disassembly.

- [ ] **Step 22.5: Final successful run + commit the rules-smoke-test output snapshot (optional)**

Once `--compare` exits 0:

```bash
dotnet run --project tools/ValidateFixture -- --compare \
  fixtures/imagesharp-3074-prefix/trace.yaml \
  /tmp/analyzer-3074-prefix.yaml
```

Expected: stdout `OK: equivalence`, exit 0.

Do NOT commit `/tmp/analyzer-3074-prefix.yaml`. The artifact is a by-product — the CI/plan-execution narrative is sufficient evidence.

- [ ] **Step 22.6: Regression — full analyzer+validator test suite still green**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all tests passing, count unchanged from the end of Task 19.

- [ ] **Step 22.7: Commit the state** (even if no file changed in this task, the bar is a green end-to-end run; if any analyzer fixes landed they've been committed in Step 22.4 loops)

```bash
git status
# If nothing to commit, that's fine. Otherwise:
# git commit -m "analyzer: end-to-end #3074 pre-fix equivalence with ground truth"
```

---

## Task 23: End-to-end — post-fix run + compare → exit 0

**Files:**
- No new code. Same as Task 22 but for the post-fix commit.

**Difference from pre-fix.** The post-fix fixture has sanitizer hops in `path` (the `if (offset > stream.Length) throw InvalidImageContentException` check at the fix commit) and an empty `sanitizer_absence: []`. The analyzer must emit matching sanitizer hops — exactly the same as the ground truth on `file:line`, `establishes_bound.target/relation/upper_bound`, and `on_failure.kind/exception`.

- [ ] **Step 23.1: Run the analyzer against post-fix**

```bash
POST_FIX_SHA="461c021608802370374afabd5d3c2720b3e46f04"
DLL=$(ls artifacts/${POST_FIX_SHA}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll | head -1)

dotnet run --project tools/TaintAnalyzer -- \
  "$DLL" \
  --rules fixtures/imagesharp-3074-postfix/rules.yaml \
  --output /tmp/analyzer-3074-postfix.yaml
echo "exit=$?"
```

Expected: exit 0. Output file non-empty.

- [ ] **Step 23.2: Compare against ground truth**

```bash
dotnet run --project tools/ValidateFixture -- --compare \
  fixtures/imagesharp-3074-postfix/trace.yaml \
  /tmp/analyzer-3074-postfix.yaml
echo "exit=$?"
```

Expected first-run outcome: likely mismatches on `establishes_bound.upper_bound` (how the analyzer reconstructs `stream.Length` as an operand name — the fixture may write it as `stream.Length`, the analyzer may emit `Length` or `this.stream.Length`). The bound-extractor's `OperandName` in `SanitizerShapes.cs` determines this; refine it until the comparison matches.

Also likely: `on_failure.exception` class-name mismatch. The fixture may list `SixLabors.ImageSharp.InvalidImageContentException` whereas the analyzer may emit the short name. Align via `ResolveExceptionType`'s path: prefer the fully-qualified `FullName` of the first `newobj` target type.

- [ ] **Step 23.3: Iterate**

Same TDD loop as Task 22.4: add a unit test, fix, rerun.

- [ ] **Step 23.4: Final successful run**

Run: `dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-postfix/trace.yaml /tmp/analyzer-3074-postfix.yaml`
Expected: `OK: equivalence`, exit 0.

- [ ] **Step 23.5: Regression**

Run: `dotnet test TaintAnalyzer.sln`
Expected: all passing.

- [ ] **Step 23.6: Commit**

```bash
# If Task 23 landed analyzer fixes, they've been committed individually.
# This commit closes out the end-to-end checkpoint.
git status
```

---

## Task 24: Bonus — #3079 pre-fix reproduction check

**Files:**
- Create: `fixtures/imagesharp-3079-prefix/rules.yaml`
- Create: `scripts/materialize-imagesharp-3079.sh`
- No analyzer changes.

**Responsibility.** Spec success-criterion #7: run the unmodified analyzer against the #3079 pre-fix commit and attempt `--compare`. Any mismatch goes into milestone D's input, not this milestone's scope. Passing is a bonus; failing is informational.

The #3079 pre-fix commit is `89face0b8^1` (main-parent of the fix merge `89face0b8`). We materialize it the same way as #3074.

- [ ] **Step 24.1: Look up the #3079 pre-fix SHA**

Run:

```bash
git -C /mnt/c/work/dotnet-fuzzing/external/ImageSharp rev-parse 89face0b8^1
```

Record the resulting 40-char SHA — call it `SHA_3079_PRE`. Capture the fix-merge SHA too (`git -C ... rev-parse 89face0b8`) for completeness.

- [ ] **Step 24.2: Write `scripts/materialize-imagesharp-3079.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

SHARED_CLONE="${SHARED_CLONE:-/mnt/c/work/dotnet-fuzzing/external/ImageSharp}"
# Set by Step 24.1 lookup — fill in the resolved SHA.
PRE_FIX_SHA="${PRE_FIX_SHA:?must be set — see Task 24.1}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "${SHARED_CLONE}/.git" ]]; then
  echo "error: shared clone not found at ${SHARED_CLONE}" >&2
  exit 2
fi

dest="${ARTIFACTS}/${PRE_FIX_SHA}"
if [[ ! -f "${dest}/src/ImageSharp/ImageSharp.csproj" ]]; then
  echo "[materialize] extracting ${PRE_FIX_SHA} via git archive..."
  mkdir -p "${dest}"
  git -C "${SHARED_CLONE}" archive "${PRE_FIX_SHA}" | tar -x -C "${dest}"
fi

echo "[build] dotnet build ${PRE_FIX_SHA}..."
dotnet build "${dest}/src/ImageSharp/ImageSharp.csproj" -c Debug --nologo --verbosity minimal

echo "[ok] #3079 pre-fix DLL: ${dest}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll"
```

Make executable: `chmod +x scripts/materialize-imagesharp-3079.sh`.

- [ ] **Step 24.3: Write `fixtures/imagesharp-3079-prefix/rules.yaml`**

The source for #3079 is `PngDecoderCore.Decode`. Check the fixture's ground truth (`fixtures/imagesharp-3079-prefix/trace.yaml`) for the exact source-method signature and copy it verbatim into rules, converting to Cecil FullName shape.

Read the fixture file:

```bash
grep 'method:' fixtures/imagesharp-3079-prefix/trace.yaml | head -1
```

Use the `source.method` value (typically `SixLabors.ImageSharp.Formats.Png.PngDecoderCore.Decode`) and construct the signature:

```yaml
vuln_id: imagesharp-3079
source_methods:
  - SixLabors.ImageSharp.Formats.Png.PngDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
```

If the fixture source-method signature differs (e.g. the generic arity on `Decode<T>`), adjust accordingly. The signature-shape validator will catch any obvious malformation when we run the analyzer.

- [ ] **Step 24.4: Materialize and build #3079 pre-fix**

Run: `PRE_FIX_SHA=<resolved-sha-from-step-24.1> ./scripts/materialize-imagesharp-3079.sh`
Expected: `SixLabors.ImageSharp.dll` + `.pdb` present under `artifacts/<sha>/src/ImageSharp/bin/Debug/`.

- [ ] **Step 24.5: Run the analyzer**

```bash
SHA_3079_PRE="<from-step-24.1>"
DLL=$(ls artifacts/${SHA_3079_PRE}/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.dll | head -1)

dotnet run --project tools/TaintAnalyzer -- \
  "$DLL" \
  --rules fixtures/imagesharp-3079-prefix/rules.yaml \
  --output /tmp/analyzer-3079-prefix.yaml
echo "exit=$?"
```

Expected: exit 0 (analyzer may not reproduce the fixture but it should not crash).

- [ ] **Step 24.6: Attempt the compare**

```bash
dotnet run --project tools/ValidateFixture -- --compare \
  fixtures/imagesharp-3079-prefix/trace.yaml \
  /tmp/analyzer-3079-prefix.yaml
echo "exit=$?"
```

Possible outcomes:
- **Exit 0** — #3079 is covered by unchanged milestone-C components; update memory with this finding; milestone D scope shrinks accordingly.
- **Non-zero** — the diagnostics printed are the milestone-D input. Capture the output for the milestone-D scoping:

```bash
dotnet run --project tools/ValidateFixture -- --compare \
  fixtures/imagesharp-3079-prefix/trace.yaml \
  /tmp/analyzer-3079-prefix.yaml 2>&1 | tee /tmp/3079-bonus-diagnostics.txt
```

Do NOT chase these diagnostics in this task; they belong to milestone D.

- [ ] **Step 24.7: Record the outcome in the spec**

Open `docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md` and append a short note under "Revision history":

```markdown
- **YYYY-MM-DD (bonus-check outcome).** Ran #3079 pre-fix unchanged through milestone-C analyzer. Result: <PASS — no component changes needed | FAIL — diagnostics captured in /tmp/3079-bonus-diagnostics.txt — feeds milestone D>.
```

Replace placeholders with the actual date and outcome.

- [ ] **Step 24.8: Commit**

```bash
git add fixtures/imagesharp-3079-prefix/rules.yaml scripts/materialize-imagesharp-3079.sh docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md
git commit -m "fixture+scripts: #3079 rules + materialize script; record milestone-C bonus outcome"
```

---

## Task 25: Final cross-check — full green suite, clean build, docs touch-ups

**Files:**
- No mandatory files. Optional: `docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md` status line.

- [ ] **Step 25.1: Clean build from scratch**

```bash
rm -rf **/bin **/obj
dotnet build TaintAnalyzer.sln
```

Expected: 0 errors. Warnings are acceptable as long as no analyzer-component warning is new. (The existing ImageSharp code emitted no warnings in CI per recent commits; new ones suggest code quality we should address.)

- [ ] **Step 25.2: Full test suite**

Run: `dotnet test TaintAnalyzer.sln --nologo`
Expected: every analyzer and validator test passing. Specifically:
- `tools/TaintAnalyzer.Tests/` — all tests from Tasks 2–13 green.
- `tools/ValidateFixture.Tests/` — existing validator tests + all `CompareTests` from Tasks 15–18 green.

- [ ] **Step 25.3: Smoke-test the analyzer's CLI usage messages**

Run each of these to confirm exit-code conventions:

```bash
# 2 — usage error, no args
dotnet run --project tools/TaintAnalyzer ; echo "exit=$?"

# 2 — usage error, missing --rules
dotnet run --project tools/TaintAnalyzer -- /tmp/nonexistent.dll ; echo "exit=$?"

# 1 — file-not-found
dotnet run --project tools/TaintAnalyzer -- /tmp/nonexistent.dll --rules /tmp/nonexistent.yaml ; echo "exit=$?"
```

Expected: exit codes `2`, `2`, `1` respectively, each with a clear stderr message.

- [ ] **Step 25.4: Update the spec `Status` line**

Open `docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md`. At the top:

Replace:
```
**Status:** Approved 2026-04-19; revised 2026-04-23 after design review.
```

With:
```
**Status:** Approved 2026-04-19; revised 2026-04-23 after design review. Implemented <YYYY-MM-DD> — all success criteria met (1–6 required; #7 bonus — see Revision history for outcome).
```

Fill in the actual completion date.

- [ ] **Step 25.5: Final commit**

```bash
git add docs/superpowers/specs/2026-04-19-taint-analyzer-mvp-design.md
git commit -m "Design spec: milestone C — implementation complete"
```

- [ ] **Step 25.6: Announce completion**

Print the final status:

```bash
echo "=== milestone C complete ==="
echo "all tests:"
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet | tail -3
echo
echo "end-to-end checks:"
echo "  #3074 pre-fix:  $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/analyzer-3074-prefix.yaml 2>&1 | tail -1)"
echo "  #3074 post-fix: $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-postfix/trace.yaml /tmp/analyzer-3074-postfix.yaml 2>&1 | tail -1)"
```

Expected: both end-to-end lines say `OK: equivalence`.

---

## Self-review

**1. Spec coverage.** Walking through each spec section:
- *Tech choice (Cecil):* pinned in Task 1 csproj.
- *MVP scope — reproduce #3074 pre/post:* Tasks 22 + 23 verify end-to-end.
- *Non-goals:* respected — no async/MoveNext, no NativeAOT, no Part-2 symbex.
- *Components (`RulesDocument`, `AssemblyContext`, `CallGraph`, `TaintWalker`, `TraceEmitter`):* Tasks 2, 4, 8, 9–12, 13 respectively.
- *`SinkShapes.cs`, `SanitizerShapes.cs` (throw-helper predicate, branch-direction, bound extractor):* Tasks 5, 6, 7.
- *Signature-form validation + nearest-candidate suggestion:* Tasks 2, 14 respectively.
- *Sequence-point fallback:* `AssemblyContext.GetSequencePoint` in Task 4, exercised in Task 12.
- *Flow-type narrowing + CHA:* Task 8.
- *`stfld`/`stsfld`, object-field taint summary:* Task 10.
- *Cross-method recursion + memoization keyed by `FullName`+bitmask:* Task 11.
- *TaintWalker sanitizer hop emission:* Task 12.
- *`TraceEmitter` pre-fix `sanitizer_absence` synthesis:* Task 12 + Task 13 (synthesis in walker, YAML in emitter).
- *CLI — stdout default, exit codes:* Task 14.
- *Validator `--compare` FX060/FX061/FX062/FX063 with metadata exemption, ±2-line tolerance, unified format:* Tasks 15–19.
- *`git archive | tar -x` materialization:* Task 20.
- *Rules file location (next to fixture):* Task 21.
- *Success criteria #1 (unit tests — seven named classes):* covered by Tasks 2, 4, 5, 6/7, 8, 9–12, 13 — the seven classes `RulesDocumentLoaderTests`, `AssemblyContextTests`, `CallGraphTests`, `SinkShapesTests`, `SanitizerShapesTests`, `TaintWalkerTests`, `TraceEmitterTests` are all authored.
- *Success criteria #2 (FX060–FX063 tests):* Tasks 15–18.
- *Success criteria #3–4 (end-to-end #3074 pre/post):* Tasks 22–23.
- *Success criteria #5 (existing validator tests still pass):* checked in Steps 1.10, 19.3, 25.2.
- *Success criteria #6 (shared clone untouched, `artifacts/` gitignored):* Task 1.8, Task 20, `git archive`-only workflow.
- *Success criteria #7 (bonus #3079):* Task 24.

No gaps identified.

**2. Placeholder scan.** No `TBD`, `TODO`, `implement later`, or placeholder-code instances inside task steps. Each step with code shows the code; each step with a command shows the command and expected output. Task 22 and 23's iterate-on-diagnostic loops are open-ended by nature (end-to-end bugs are unpredictable) but the methodology is explicit: reproduce as unit test, fix, rerun.

**3. Type consistency.**
- `SinkKind` / `SinkApi` / `FailureKind` enum members used identically across `HopRecord.cs`, `SinkShapes.cs`, `SanitizerShapes.cs`, `TaintWalker.cs`, `TraceEmitter.cs`. ✓
- `HopRecord` declared as a `record` (Task 12 changes) so `with` expressions compile. ✓
- `ResolvedDispatch.ResolvedTargets` is `IReadOnlyList<string>` consistently (required `init`). ✓
- `MethodSummary.NewlyTaintedThisFields` is `IReadOnlyList<string>`; Task 10/11 populate via `HashSet<string>.ToArray()`. ✓
- `AssemblyContext.FindMethod` accepts the short signature form matching what Task 2's loader validates and what Task 21's rules files use. ✓
- `FixtureValidator.Compare` takes two `FixtureDocument` instances and Task 19's CLI deserializes them with `DeserializerBuilder().IgnoreUnmatchedProperties()` matching the existing validator pattern. ✓
- `PathNode.Dispatch`, `.EstablishesBound`, `.OnFailure` are reused from `ValidateFixture`'s existing types — the analyzer references the validator's DLL (Task 13.1) rather than duplicating them. ✓

No inconsistencies found.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-23-taint-analyzer-mvp.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatches a fresh subagent per task, reviews between tasks, fast iteration. Useful here because the plan is long (25 tasks, mostly TDD-shaped) and each task produces a focused commit.

**2. Inline Execution** — executes tasks in the current session using `superpowers:executing-plans`, batch-executed with checkpoints for review. Faster for the early scaffolding tasks but will push context usage hard by the time we reach Tasks 9–12 (TaintWalker iteration).

Which approach?
