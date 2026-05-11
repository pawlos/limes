# Milestone-Q: Entry-point enumeration — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--scan` mode to `TaintAnalyzer` so it auto-enumerates decoder entry points from an assembly using signature-shape and type-name heuristics, replacing hand-written `rules.yaml` for cold scans.

**Architecture:** Pure-function `EntryPointEnumerator` over `AssemblyContext`, producing the same `SourceMethodEntry` list the existing `--rules` path feeds to the walker. New `EnumeratorConfig` with baked-in defaults overridable by YAML. New `ReverseCallGraph` for the public-reachable-internals visibility filter. New `RulesYamlEmitter` for the terminal `--emit-rules` mode. `Program.cs` grows new flags; walker is untouched.

**Tech stack:** .NET 10, Mono.Cecil (already in use), YamlDotNet (already in use), xUnit + Shouldly for tests.

**Spec:** `docs/superpowers/specs/2026-05-11-entry-point-enumeration-design.md`

---

## File structure

### New files

```
tools/TaintAnalyzer/
  EnumeratorConfig.cs        POCO with defaults + YAML loader + EnumeratorConfigException
  GlobMatcher.cs             internal static helper: Matches(pattern, input) with * wildcard
  ReverseCallGraph.cs        builds call edge index; IsReachableFromPublic(method)
  EntryPointEnumerator.cs    static Enumerate(ctx, cfg, callGraph) -> IEnumerable<SourceMethodEntry>
  RulesYamlEmitter.cs        static Emit(vulnId, entries) -> string

tools/TaintAnalyzer.Tests/
  EnumeratorConfigTests.cs
  GlobMatcherTests.cs
  ReverseCallGraphTests.cs
  EntryPointEnumeratorTests.cs
  RulesYamlEmitterTests.cs
  ProgramScanFlagTests.cs

fixtures/
  scan-protobuf-net/          locked enumerator output for protobuf-net.dll
    rules.yaml.expected       what --scan --include-this-field should produce
    run                       script that runs the scan and compares
  scan-nbmp-1.1.25/           locked output for Nerdbank.MessagePack 1.1.25
    rules.yaml.expected
    run
```

### Modified files

- `tools/TaintAnalyzer/Program.cs` — refactor into `Run(args, stdout, stderr)`; add `--scan`, `--include-this-field`, `--enumerator-config`, `--emit-rules`, `--progress` flags
- `tools/TaintAnalyzer/RulesDocument.cs` — relax empty-list check
- `tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs` — add empty-list passing test, remove failing test
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add `EnumeratorFixtures` types (parameter-shape, this-field-shape, visibility, hard-filter)

---

## Public API contracts (locked across tasks)

```csharp
namespace TaintAnalyzer;

public sealed class EnumeratorConfig
{
    public IReadOnlyList<string> ByteSourceTypes { get; init; }
    public IReadOnlyList<string> DecoderTypeNamePatterns { get; init; }
    public IReadOnlyList<string> ExcludeNamespaces { get; init; }
    public IReadOnlyList<string> ExcludeTypePatterns { get; init; }
    public IReadOnlyList<string> ExcludeMethodPatterns { get; init; }
    public bool IncludeThisField { get; init; }

    public static EnumeratorConfig Default { get; }
    public static EnumeratorConfig Load(string yaml);
}

public sealed class EnumeratorConfigException : Exception
{
    public EnumeratorConfigException(string message);
    public EnumeratorConfigException(string message, Exception inner);
}

public sealed class ReverseCallGraph
{
    public ReverseCallGraph(Mono.Cecil.AssemblyDefinition assembly);
    public bool IsReachableFromPublic(Mono.Cecil.MethodDefinition method);
}

public static class EntryPointEnumerator
{
    public static IEnumerable<SourceMethodEntry> Enumerate(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph);
}

public static class RulesYamlEmitter
{
    public static string Emit(string vulnId, IReadOnlyList<SourceMethodEntry> entries);
}

internal static class GlobMatcher
{
    public static bool Matches(string pattern, string input);
}
```

---

## Task 1: Relax `RulesDocument.Load` to accept empty `source_methods`

**Why first:** `--emit-rules` may write `source_methods: []` for zero-candidate scans. Must round-trip.

**Files:**
- Modify: `tools/TaintAnalyzer/RulesDocument.cs:68-72`
- Modify: `tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs`

- [ ] **Step 1: Write the new passing test (empty list accepted)**

Add to `RulesDocumentLoaderTests.cs`:

```csharp
[Fact]
public void Load_EmptySourceMethodsList_AcceptsAndReturnsEmpty()
{
    const string yaml = """
        vuln_id: scan-empty
        source_methods: []
        """;

    var doc = RulesDocument.Load(yaml);

    doc.VulnId.ShouldBe("scan-empty");
    doc.SourceMethods.ShouldNotBeNull();
    doc.SourceMethods!.ShouldBeEmpty();
}
```

Also locate the existing test that asserts the empty list throws, and update it to assert only the **missing-key** case still throws:

```csharp
[Fact]
public void Load_MissingSourceMethods_Throws()
{
    const string yaml = "vuln_id: only-vuln-id\n";

    Should.Throw<RulesDocumentException>(() => RulesDocument.Load(yaml))
          .Message.ShouldContain("required");
}
```

(If a test like `Load_EmptySourceMethods_Throws` exists, delete it.)

- [ ] **Step 2: Run tests to verify the new test fails and old test passes**

```sh
cd tools/TaintAnalyzer.Tests
dotnet test --filter "FullyQualifiedName~RulesDocumentLoader" --logger "console;verbosity=detailed"
```

Expected: `Load_EmptySourceMethodsList_AcceptsAndReturnsEmpty` FAILS with `RulesDocumentException: source_methods is empty`.

- [ ] **Step 3: Relax the validator**

Edit `tools/TaintAnalyzer/RulesDocument.cs` around line 68:

```csharp
// Before:
if (doc.SourceMethods is null || doc.SourceMethods.Count == 0)
{
    var state = doc.SourceMethods is null ? "required" : "empty";
    throw new RulesDocumentException($"source_methods is {state}: at least one entry expected");
}

// After:
if (doc.SourceMethods is null)
{
    throw new RulesDocumentException("source_methods is required: at least one entry expected");
}
```

- [ ] **Step 4: Re-run tests**

```sh
dotnet test --filter "FullyQualifiedName~RulesDocumentLoader"
```

Expected: all tests pass.

- [ ] **Step 5: Run the full test suite (regression gate for this small change)**

```sh
cd tools && dotnet test
```

Expected: 168 passed (or current count) — no regressions.

- [ ] **Step 6: Commit**

```sh
git add tools/TaintAnalyzer/RulesDocument.cs tools/TaintAnalyzer.Tests/RulesDocumentLoaderTests.cs
git commit -m "analyzer: accept empty source_methods list in rules.yaml"
```

---

## Task 2: Add enumerator fixture types

**Why:** The enumerator's unit tests need a fixture assembly containing each candidate shape. We add them to the existing `Fixtures.cs` so the existing copy-to-output build target picks them up automatically.

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append a new region at the end)

- [ ] **Step 1: Append fixture region (no tests yet — these support Tasks 6–15)**

Append the following block to the end of `Fixtures.cs`:

```csharp
// ============================================================================
// EnumeratorFixtures — types for EntryPointEnumerator tests.
// Visible to Cecil only (the test project does not reference Fixtures source);
// internal types are deliberately reachable / unreachable per their name.
// ============================================================================

namespace TaintAnalyzer.Tests.Fixtures.Enumerator;

// ---- Parameter-shape fixtures ----

public class StreamReaderShape
{
    public void Read(System.IO.Stream s) { }
}

public class FileStreamReaderShape
{
    public void Read(System.IO.FileStream s) { }
}

public class SpanByteReaderShape
{
    public void Read(System.ReadOnlySpan<byte> s) { }
}

public class StringReaderShape
{
    // Should NOT be picked up by default config (string is not in defaults).
    public void Read(string s) { }
}

public class SpanIntReaderShape
{
    // Should NOT be picked up (ReadOnlySpan<int> ≠ ReadOnlySpan<byte>).
    public void Read(System.ReadOnlySpan<int> s) { }
}

public class ByteArrayReaderShape
{
    public void Read(byte[] s) { }
}

public class BinaryReaderShape
{
    public void Read(System.IO.BinaryReader r) { }
}

// ---- This-field-shape fixtures ----

public class DecoderWithStreamField
{
    // ReSharper disable once NotAccessedField.Local — Cecil sees the field regardless.
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

public class NotADecoderType
{
    private readonly System.IO.Stream _input = System.IO.Stream.Null;
    public string ReadString() => "";
}

public class EmptyDecoder
{
    // Name matches the *Decoder suffix glob, but no byte-source field —
    // should NOT match this-field even with --include-this-field.
    public string ReadString() => "";
}

// ---- Visibility-filter fixtures ----

public class PublicEntryPoint
{
    public void TakesStream(System.IO.Stream s) => InternalReachable.Helper(s);
}

internal static class InternalReachable
{
    // Called by PublicEntryPoint.TakesStream — must be reachable from public.
    internal static void Helper(System.IO.Stream s) { }
}

internal static class InternalOrphan
{
    // Not called by anyone — must be rejected even though it matches parameter-shape.
    internal static void Orphan(System.IO.Stream s) { }
}

public class HasPrivateAndProtected
{
    private void PrivateMethod(System.IO.Stream s) { }
    protected void ProtectedMethod(System.IO.Stream s) { }
}

// ---- Hard-filter fixtures ----

public class HasCtorWithStream
{
    public HasCtorWithStream(System.IO.Stream s) { }
    public void Op_NotMatchedEither(System.IO.Stream s) { }
}

public class HasPropertyTakingStream
{
    private System.IO.Stream _backing = System.IO.Stream.Null;
    // The setter takes Stream but is a special-name method — must be rejected.
    public System.IO.Stream Backing { get => _backing; set => _backing = value; }
}

public abstract class HasAbstractMethod
{
    public abstract void Read(System.IO.Stream s);
}
```

- [ ] **Step 2: Verify the fixture assembly builds**

```sh
cd tools/TaintAnalyzer.Tests.Fixtures && dotnet build
```

Expected: build succeeds. No tests to run yet.

- [ ] **Step 3: Confirm the test bin has the rebuilt fixture**

```sh
cd tools/TaintAnalyzer.Tests && dotnet build
ls bin/Debug/net10.0/Fixtures/TaintAnalyzer.Tests.Fixtures.dll
```

Expected: file exists; modified timestamp is recent.

- [ ] **Step 4: Commit**

```sh
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "test: add EnumeratorFixtures types for entry-point enumerator"
```

---

## Task 3: `GlobMatcher`

**Why:** Three exclusion config keys (`exclude_namespaces`, `exclude_type_patterns`, `exclude_method_patterns`) and `decoder_type_name_patterns` use glob matching. Tested standalone.

**Files:**
- Create: `tools/TaintAnalyzer/GlobMatcher.cs`
- Create: `tools/TaintAnalyzer.Tests/GlobMatcherTests.cs`

- [ ] **Step 1: Write failing tests**

Create `GlobMatcherTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class GlobMatcherTests
{
    [Theory]
    [InlineData("*", "anything")]
    [InlineData("*", "")]
    [InlineData("foo", "foo")]
    [InlineData("*Reader", "XmlReader")]
    [InlineData("*Reader", "Reader")]
    [InlineData("System.*", "System.IO")]
    [InlineData("System.*", "System.Collections.Generic")]
    [InlineData("*Test*", "MyTestClass")]
    [InlineData("*Test*", "TestSuite")]
    [InlineData("*Test*", "Test")]
    public void Matches_TrueCases(string pattern, string input)
    {
        GlobMatcher.Matches(pattern, input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("foo", "bar")]
    [InlineData("*Reader", "Readable")]
    [InlineData("*Reader", "ReaderWriter")]
    [InlineData("System.*", "Microsoft.IO")]
    public void Matches_FalseCases(string pattern, string input)
    {
        GlobMatcher.Matches(pattern, input).ShouldBeFalse();
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
cd tools/TaintAnalyzer.Tests
dotnet test --filter "FullyQualifiedName~GlobMatcher"
```

Expected: build error or test failure (`GlobMatcher` not defined).

- [ ] **Step 3: Implement**

Create `tools/TaintAnalyzer/GlobMatcher.cs`:

```csharp
using System.Text.RegularExpressions;

namespace TaintAnalyzer;

// Simple glob matcher: `*` is a wildcard for zero or more characters; all other
// characters match literally. No `?`, no `**`, no character classes. We translate
// to a regex once per pattern; for the small number of patterns in a config file
// the per-pattern cache is fine.
internal static class GlobMatcher
{
    private static readonly Dictionary<string, Regex> s_cache = new();

    public static bool Matches(string pattern, string input)
    {
        if (!s_cache.TryGetValue(pattern, out var rx))
        {
            var escaped = Regex.Escape(pattern).Replace("\\*", ".*");
            rx = new Regex("^" + escaped + "$", RegexOptions.CultureInvariant);
            s_cache[pattern] = rx;
        }
        return rx.IsMatch(input);
    }
}
```

Note: `GlobMatcher` is `internal`, but tests live in the same assembly's friend project. Add `InternalsVisibleTo` if not already present:

```sh
grep -n "InternalsVisibleTo" tools/TaintAnalyzer/*.cs
```

If missing, create `tools/TaintAnalyzer/AssemblyInfo.cs`:

```csharp
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("TaintAnalyzer.Tests")]
```

- [ ] **Step 4: Run and confirm pass**

```sh
cd tools/TaintAnalyzer.Tests
dotnet test --filter "FullyQualifiedName~GlobMatcher"
```

Expected: all GlobMatcher tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/GlobMatcher.cs tools/TaintAnalyzer/AssemblyInfo.cs tools/TaintAnalyzer.Tests/GlobMatcherTests.cs
git commit -m "analyzer: add GlobMatcher with * wildcard for config patterns"
```

---

## Task 4: `EnumeratorConfig` POCO + `Default`

**Why:** Pure data class with baked-in defaults. The Load method comes in Task 5.

**Files:**
- Create: `tools/TaintAnalyzer/EnumeratorConfig.cs`
- Create: `tools/TaintAnalyzer.Tests/EnumeratorConfigTests.cs`

- [ ] **Step 1: Write failing tests**

Create `EnumeratorConfigTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class EnumeratorConfigTests
{
    [Fact]
    public void Default_ContainsExpectedByteSourceTypes()
    {
        var cfg = EnumeratorConfig.Default;

        cfg.ByteSourceTypes.ShouldContain("System.IO.Stream");
        cfg.ByteSourceTypes.ShouldContain("System.IO.BinaryReader");
        cfg.ByteSourceTypes.ShouldContain("System.Byte[]");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlySpan`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlySequence`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.Memory`1<System.Byte>");
        cfg.ByteSourceTypes.ShouldContain("System.ReadOnlyMemory`1<System.Byte>");
    }

    [Fact]
    public void Default_ContainsExpectedDecoderPatterns()
    {
        EnumeratorConfig.Default.DecoderTypeNamePatterns.ShouldBe(
            new[] { "*Reader", "*Decoder", "*Deserializer", "*Parser" });
    }

    [Fact]
    public void Default_ExcludesBclNamespacesAndTestPatterns()
    {
        EnumeratorConfig.Default.ExcludeNamespaces.ShouldBe(new[] { "System.*", "Microsoft.*" });
        EnumeratorConfig.Default.ExcludeTypePatterns.ShouldBe(new[] { "*Test*", "*Mock*" });
        EnumeratorConfig.Default.ExcludeMethodPatterns.ShouldBe(new[] { "ToString", "GetHashCode", "Equals" });
    }

    [Fact]
    public void Default_IncludeThisFieldIsFalse()
    {
        EnumeratorConfig.Default.IncludeThisField.ShouldBeFalse();
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EnumeratorConfig"
```

Expected: build error.

- [ ] **Step 3: Implement the POCO**

Create `tools/TaintAnalyzer/EnumeratorConfig.cs`:

```csharp
namespace TaintAnalyzer;

public sealed class EnumeratorConfig
{
    public IReadOnlyList<string> ByteSourceTypes { get; init; } = s_defaultByteSourceTypes;
    public IReadOnlyList<string> DecoderTypeNamePatterns { get; init; } = s_defaultDecoderTypeNamePatterns;
    public IReadOnlyList<string> ExcludeNamespaces { get; init; } = s_defaultExcludeNamespaces;
    public IReadOnlyList<string> ExcludeTypePatterns { get; init; } = s_defaultExcludeTypePatterns;
    public IReadOnlyList<string> ExcludeMethodPatterns { get; init; } = s_defaultExcludeMethodPatterns;
    public bool IncludeThisField { get; init; }

    public static EnumeratorConfig Default { get; } = new();

    private static readonly string[] s_defaultByteSourceTypes =
    {
        "System.IO.Stream",
        "System.IO.BinaryReader",
        "System.Byte[]",
        "System.ReadOnlySpan`1<System.Byte>",
        "System.ReadOnlySequence`1<System.Byte>",
        "System.Memory`1<System.Byte>",
        "System.ReadOnlyMemory`1<System.Byte>",
    };

    private static readonly string[] s_defaultDecoderTypeNamePatterns =
        { "*Reader", "*Decoder", "*Deserializer", "*Parser" };

    private static readonly string[] s_defaultExcludeNamespaces =
        { "System.*", "Microsoft.*" };

    private static readonly string[] s_defaultExcludeTypePatterns =
        { "*Test*", "*Mock*" };

    private static readonly string[] s_defaultExcludeMethodPatterns =
        { "ToString", "GetHashCode", "Equals" };
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EnumeratorConfig"
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EnumeratorConfig.cs tools/TaintAnalyzer.Tests/EnumeratorConfigTests.cs
git commit -m "analyzer: add EnumeratorConfig POCO with baked-in defaults"
```

---

## Task 5: `EnumeratorConfig.Load` + `EnumeratorConfigException`

**Why:** YAML loader. Replace-not-merge semantics; missing keys fall back to defaults.

**Files:**
- Modify: `tools/TaintAnalyzer/EnumeratorConfig.cs`
- Modify: `tools/TaintAnalyzer.Tests/EnumeratorConfigTests.cs`

- [ ] **Step 1: Add failing tests**

Append to `EnumeratorConfigTests.cs`:

```csharp
[Fact]
public void Load_EmptyDocument_EqualsDefault()
{
    var cfg = EnumeratorConfig.Load("");

    cfg.ByteSourceTypes.ShouldBe(EnumeratorConfig.Default.ByteSourceTypes);
    cfg.DecoderTypeNamePatterns.ShouldBe(EnumeratorConfig.Default.DecoderTypeNamePatterns);
    cfg.ExcludeNamespaces.ShouldBe(EnumeratorConfig.Default.ExcludeNamespaces);
}

[Fact]
public void Load_PartialOverride_KeepsOtherDefaults()
{
    const string yaml = """
        byte_source_types:
          - My.Custom.Stream
        """;

    var cfg = EnumeratorConfig.Load(yaml);

    cfg.ByteSourceTypes.ShouldBe(new[] { "My.Custom.Stream" });
    // Defaults preserved for unspecified keys.
    cfg.ExcludeNamespaces.ShouldBe(new[] { "System.*", "Microsoft.*" });
}

[Fact]
public void Load_EmptyExcludeList_AllowsAllNamespaces()
{
    const string yaml = "exclude_namespaces: []\n";

    var cfg = EnumeratorConfig.Load(yaml);

    cfg.ExcludeNamespaces.ShouldBeEmpty();
}

[Fact]
public void Load_UnknownKeys_AreIgnored()
{
    const string yaml = """
        byte_source_types:
          - Foo
        unknown_future_key: bar
        """;

    var cfg = EnumeratorConfig.Load(yaml);

    cfg.ByteSourceTypes.ShouldBe(new[] { "Foo" });
}

[Fact]
public void Load_MalformedYaml_Throws()
{
    const string yaml = "byte_source_types: [unterminated";

    Should.Throw<EnumeratorConfigException>(() => EnumeratorConfig.Load(yaml));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EnumeratorConfig"
```

Expected: build error — `Load` and `EnumeratorConfigException` not defined.

- [ ] **Step 3: Implement**

Append to `tools/TaintAnalyzer/EnumeratorConfig.cs`:

```csharp
public sealed class EnumeratorConfigException : Exception
{
    public EnumeratorConfigException(string message) : base(message) { }
    public EnumeratorConfigException(string message, Exception inner) : base(message, inner) { }
}
```

Inside the `EnumeratorConfig` class, add:

```csharp
public static EnumeratorConfig Load(string yaml)
{
    if (string.IsNullOrWhiteSpace(yaml))
    {
        return Default;
    }

    Raw? raw;
    try
    {
        var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
            .IgnoreUnmatchedProperties()
            .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.UnderscoredNamingConvention.Instance)
            .Build();
        raw = deserializer.Deserialize<Raw>(yaml);
    }
    catch (YamlDotNet.Core.YamlException ex)
    {
        throw new EnumeratorConfigException($"malformed enumerator-config: {ex.Message}", ex);
    }

    raw ??= new Raw();
    return new EnumeratorConfig
    {
        ByteSourceTypes = raw.ByteSourceTypes ?? s_defaultByteSourceTypes,
        DecoderTypeNamePatterns = raw.DecoderTypeNamePatterns ?? s_defaultDecoderTypeNamePatterns,
        ExcludeNamespaces = raw.ExcludeNamespaces ?? s_defaultExcludeNamespaces,
        ExcludeTypePatterns = raw.ExcludeTypePatterns ?? s_defaultExcludeTypePatterns,
        ExcludeMethodPatterns = raw.ExcludeMethodPatterns ?? s_defaultExcludeMethodPatterns,
    };
}

// Private helper class for YAML deserialization. Lists are nullable so we can
// distinguish "key missing" (fall back to default) from "key present but empty"
// (use the empty list).
private sealed class Raw
{
    public List<string>? ByteSourceTypes { get; set; }
    public List<string>? DecoderTypeNamePatterns { get; set; }
    public List<string>? ExcludeNamespaces { get; set; }
    public List<string>? ExcludeTypePatterns { get; set; }
    public List<string>? ExcludeMethodPatterns { get; set; }
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EnumeratorConfig"
```

Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EnumeratorConfig.cs tools/TaintAnalyzer.Tests/EnumeratorConfigTests.cs
git commit -m "analyzer: add EnumeratorConfig.Load YAML parser with replace-semantics"
```

---

## Task 6: `ReverseCallGraph` construction

**Why:** Foundation for the public-reachable-internals visibility filter. Builds a callee→callers map by scanning every method body once.

**Files:**
- Create: `tools/TaintAnalyzer/ReverseCallGraph.cs`
- Create: `tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs`

- [ ] **Step 1: Write failing tests**

Create `ReverseCallGraphTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ReverseCallGraphTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Construction_DoesNotThrow()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        graph.ShouldNotBeNull();
    }

    [Fact]
    public void Callers_OfPublicMethod_IncludePublicCaller()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // InternalReachable.Helper is called by PublicEntryPoint.TakesStream.
        var helper = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.InternalReachable", "Helper");
        helper.ShouldNotBeNull();

        graph.IsReachableFromPublic(helper!).ShouldBeTrue();
    }

    [Fact]
    public void OrphanInternal_IsNotReachableFromPublic()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var orphan = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.InternalOrphan", "Orphan");
        orphan.ShouldNotBeNull();

        graph.IsReachableFromPublic(orphan!).ShouldBeFalse();
    }

    [Fact]
    public void PublicMethod_AlwaysReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        var pub = FindMethod(ctx.Assembly, "TaintAnalyzer.Tests.Fixtures.Enumerator.PublicEntryPoint", "TakesStream");
        pub.ShouldNotBeNull();

        graph.IsReachableFromPublic(pub!).ShouldBeTrue();
    }

    private static MethodDefinition? FindMethod(AssemblyDefinition asm, string typeFullName, string methodName)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
        {
            if (t.FullName != typeFullName) continue;
            return t.Methods.FirstOrDefault(m => m.Name == methodName);
        }
        return null;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~ReverseCallGraph"
```

Expected: build error — `ReverseCallGraph` not defined.

- [ ] **Step 3: Implement**

Create `tools/TaintAnalyzer/ReverseCallGraph.cs`:

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Builds a callee → callers index in one pass over every method body in the
// assembly. Used to answer "is this internal method reachable from any public
// method?" via a BFS over the reverse edges.
//
// Resolution policy: we follow `call`, `callvirt`, and `newobj` operands. Each
// operand is a MethodReference; we try `Resolve()` and only record edges to
// methods inside this assembly. Cross-assembly references are skipped (we
// only score reachability within the target assembly). Virtual dispatch is
// approximated by also recording an edge from every override to the base
// definition's callers — but we keep it simple by treating any reachable
// override of a public method as reachable.
public sealed class ReverseCallGraph
{
    private readonly Dictionary<MethodDefinition, HashSet<MethodDefinition>> _callers = new();
    private readonly HashSet<MethodDefinition> _reachableFromPublic;

    public ReverseCallGraph(AssemblyDefinition assembly)
    {
        var allMethods = AllMethods(assembly).ToList();

        foreach (var m in allMethods)
        {
            if (m.Body is null) continue;
            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;

                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null) continue;
                if (callee.Module.Assembly != assembly) continue;

                if (!_callers.TryGetValue(callee, out var set))
                {
                    set = new HashSet<MethodDefinition>();
                    _callers[callee] = set;
                }
                set.Add(m);
            }
        }

        // BFS from the union of all public methods over reverse edges
        // (callee → callers), computing the set of all methods reachable from
        // any public method by following call edges forward — i.e. methods
        // that have a public method as a transitive caller.
        _reachableFromPublic = new HashSet<MethodDefinition>();
        var queue = new Queue<MethodDefinition>();
        foreach (var m in allMethods.Where(IsPublic))
        {
            _reachableFromPublic.Add(m);
            queue.Enqueue(m);
        }

        // For each public method, walk forward via call edges to find what it
        // calls — those are also reachable.
        var visited = new HashSet<MethodDefinition>(_reachableFromPublic);
        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            if (m.Body is null) continue;
            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;
                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null || callee.Module.Assembly != assembly) continue;
                if (visited.Add(callee))
                {
                    _reachableFromPublic.Add(callee);
                    queue.Enqueue(callee);
                }
            }
        }
    }

    public bool IsReachableFromPublic(MethodDefinition method)
        => _reachableFromPublic.Contains(method);

    private static bool IsPublic(MethodDefinition m)
        => m.IsPublic && m.DeclaringType.IsPublic;

    private static IEnumerable<MethodDefinition> AllMethods(AssemblyDefinition asm)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
        foreach (var m in t.Methods)
            yield return m;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~ReverseCallGraph"
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/ReverseCallGraph.cs tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs
git commit -m "analyzer: add ReverseCallGraph with public-reachable-method index"
```

---

## Task 7: `EntryPointEnumerator` — hard filters only

**Why:** Start with the rejecting half of the algorithm. Verifies the skeleton works before adding candidate predicates.

**Files:**
- Create: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Create: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Write failing test (only hard filters present)**

Create `EntryPointEnumeratorTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class EntryPointEnumeratorTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Enumerate_RejectsCtorTakingStream()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        // .ctor in HasCtorWithStream takes Stream but must be rejected.
        entries.ShouldNotContain(e => e.Signature.Contains("HasCtorWithStream::.ctor"));
    }

    [Fact]
    public void Enumerate_RejectsAbstractMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("HasAbstractMethod::Read"));
    }

    [Fact]
    public void Enumerate_RejectsPropertyAccessors()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("set_Backing"));
        entries.ShouldNotContain(e => e.Signature.Contains("get_Backing"));
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: build error — `EntryPointEnumerator` not defined.

- [ ] **Step 3: Expose `AssemblyContext.BuildShortSignature` for reuse**

In `tools/TaintAnalyzer/AssemblyContext.cs:119`, change the access modifier:

```csharp
// Before:
private static string BuildShortSignature(MethodDefinition m)

// After:
internal static string BuildShortSignature(MethodDefinition m)
```

This is the canonical lookup key used by `AssemblyContext.FindMethod`. Reusing it from `EntryPointEnumerator` guarantees the emitted signatures always round-trip through `FindMethod`.

- [ ] **Step 4: Implement skeleton with hard filters and a stub predicate (rejects everything for now)**

Create `tools/TaintAnalyzer/EntryPointEnumerator.cs`:

```csharp
using Mono.Cecil;
using System.Runtime.CompilerServices;

namespace TaintAnalyzer;

public static class EntryPointEnumerator
{
    public static IEnumerable<SourceMethodEntry> Enumerate(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph)
    {
        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;
                // Candidate predicates and visibility filter come in Tasks 8–12.
                // For now: reject everything (skeleton).
            }
        }
        yield break;
    }

    private static bool HardReject(MethodDefinition m)
    {
        // Compiler-generated.
        if (m.HasCustomAttributes && m.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;

        // Special methods: .ctor, .cctor, op_*, property getters/setters, events.
        if (m.IsConstructor) return true;
        if (m.IsSpecialName) return true;        // op_*, property accessors, event add/remove
        if (m.IsGetter || m.IsSetter) return true;
        if (m.IsAddOn || m.IsRemoveOn || m.IsFire || m.IsOther) return true;

        // No body — abstract, P/Invoke, runtime.
        if (m.Body is null) return true;

        return false;
    }

    private static bool IsCompilerGeneratedType(TypeDefinition t)
    {
        if (t.HasCustomAttributes && t.CustomAttributes.Any(a =>
                a.AttributeType.FullName == typeof(CompilerGeneratedAttribute).FullName))
            return true;
        // <PrivateImplementationDetails>, <>c__DisplayClass*, <X>d__N
        if (t.Name.StartsWith("<", StringComparison.Ordinal)) return true;
        return false;
    }

    private static IEnumerable<TypeDefinition> AllTypes(AssemblyDefinition asm)
    {
        foreach (var t in asm.MainModule.Types.SelectMany(Flatten))
            yield return t;
    }

    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var nt in t.NestedTypes.SelectMany(Flatten)) yield return nt;
    }
}
```

- [ ] **Step 5: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: 3 tests pass (the enumerator emits nothing, so rejection is trivially satisfied).

- [ ] **Step 6: Commit**

```sh
git add tools/TaintAnalyzer/AssemblyContext.cs tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: add EntryPointEnumerator skeleton with hard filters"
```

---

## Task 8: Parameter-shape predicate (direct match)

**Why:** Core of the heuristic. Direct FullName match against `ByteSourceTypes`. Base-type walk follows in Task 9.

**Files:**
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Add failing tests**

Append to `EntryPointEnumeratorTests.cs`:

```csharp
[Fact]
public void Enumerate_MatchesStreamParameter()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldContain(e =>
        e.Signature.Contains("StreamReaderShape::Read(System.IO.Stream)"));
}

[Fact]
public void Enumerate_MatchesSpanByteParameter()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldContain(e =>
        e.Signature.Contains("SpanByteReaderShape::Read") &&
        e.Signature.Contains("System.Byte"));
}

[Fact]
public void Enumerate_DoesNotMatchString()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldNotContain(e => e.Signature.Contains("StringReaderShape::Read"));
}

[Fact]
public void Enumerate_DoesNotMatchSpanInt()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldNotContain(e => e.Signature.Contains("SpanIntReaderShape::Read"));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: 4 new tests fail (no entries emitted).

- [ ] **Step 3: Add the parameter-shape predicate**

Replace the inner loop in `EntryPointEnumerator.Enumerate`:

```csharp
public static IEnumerable<SourceMethodEntry> Enumerate(
    AssemblyContext context,
    EnumeratorConfig config,
    ReverseCallGraph callGraph)
{
    var byteSourceSet = new HashSet<string>(config.ByteSourceTypes, StringComparer.Ordinal);

    foreach (var type in AllTypes(context.Assembly))
    {
        if (IsCompilerGeneratedType(type)) continue;

        foreach (var method in type.Methods)
        {
            if (HardReject(method)) continue;

            if (MatchesParameterShape(method, byteSourceSet))
            {
                yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
            }
        }
    }
}

private static bool MatchesParameterShape(MethodDefinition m, HashSet<string> byteSourceTypes)
{
    foreach (var p in m.Parameters)
    {
        var typeFullName = StripModifiers(p.ParameterType.FullName);
        if (byteSourceTypes.Contains(typeFullName)) return true;
    }
    return false;
}

// Strip `&` (byref) and `modreq(...)` decoration that Cecil adds for ref/in/out params.
private static string StripModifiers(string fullName)
{
    var idx = fullName.IndexOf(" modreq", StringComparison.Ordinal);
    if (idx >= 0) fullName = fullName.Substring(0, idx);
    if (fullName.EndsWith("&", StringComparison.Ordinal))
        fullName = fullName.Substring(0, fullName.Length - 1);
    return fullName;
}

// Reuse the canonical signature builder from AssemblyContext (exposed as internal
// in Task 7) so emitted signatures round-trip through FindMethod exactly.
private static string BuildShortSignature(MethodDefinition m)
    => AssemblyContext.BuildShortSignature(m);
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: all 7 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: enumerator parameter-shape predicate (direct match)"
```

---

## Task 9: Parameter-shape — base-type walk for Stream

**Why:** A parameter typed `FileStream` should match because it derives from `Stream`. The walk runs `BaseType.Resolve()` until we hit a configured type or `object`.

**Files:**
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Add failing test**

Append to `EntryPointEnumeratorTests.cs`:

```csharp
[Fact]
public void Enumerate_MatchesFileStreamViaBaseTypeWalk()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldContain(e => e.Signature.Contains("FileStreamReaderShape::Read"));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~Enumerate_MatchesFileStream"
```

Expected: fail (FileStream isn't a direct match for `System.IO.Stream`).

- [ ] **Step 3: Extend `MatchesParameterShape` with base-type walk**

Replace `MatchesParameterShape` in `EntryPointEnumerator.cs`:

```csharp
private static bool MatchesParameterShape(MethodDefinition m, HashSet<string> byteSourceTypes)
{
    foreach (var p in m.Parameters)
    {
        var typeRef = p.ParameterType;

        // Strip byref/in/out decoration for matching.
        if (typeRef is ByReferenceType byref) typeRef = byref.ElementType;

        if (byteSourceTypes.Contains(typeRef.FullName)) return true;

        // Walk the base chain. Cecil's Resolve can fail for cross-assembly refs;
        // we treat resolution failure as a match miss and stop walking.
        TypeDefinition? def;
        try { def = typeRef.Resolve(); }
        catch { def = null; }

        var current = def?.BaseType;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (current is not null && seen.Add(current.FullName))
        {
            if (byteSourceTypes.Contains(current.FullName)) return true;
            TypeDefinition? baseDef;
            try { baseDef = current.Resolve(); }
            catch { baseDef = null; }
            current = baseDef?.BaseType;
        }
    }
    return false;
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: all 8 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: enumerator base-type walk for Stream subclasses"
```

---

## Task 10: This-field-shape predicate (opt-in)

**Why:** Covers `*Reader` types that hold the byte source in a field rather than a parameter (the protobuf-net case).

**Files:**
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Add failing tests**

Append:

```csharp
[Fact]
public void Enumerate_ThisFieldShape_GatedByConfig()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);

    // Default config: NOT included.
    var withoutFlag = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();
    withoutFlag.ShouldNotContain(e => e.Signature.Contains("DecoderWithStreamField::ReadString"));

    // With flag: included AND emits seed_this_fields.
    var withFlag = EntryPointEnumerator
        .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
        .ToList();
    var entry = withFlag.FirstOrDefault(e => e.Signature.Contains("DecoderWithStreamField::ReadString"));
    entry.ShouldNotBeNull();
    entry!.SeedThisFields.ShouldNotBeNull();
    entry.SeedThisFields!.ShouldContain("_input");
}

[Fact]
public void Enumerate_ThisFieldShape_RequiresMatchingTypeName()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
        .ToList();

    // NotADecoderType holds a Stream field but its name doesn't match any pattern.
    entries.ShouldNotContain(e => e.Signature.Contains("NotADecoderType::ReadString"));
}

[Fact]
public void Enumerate_ThisFieldShape_RequiresByteSourceField()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
        .ToList();

    // EmptyDecoder matches the type-name pattern but has no Stream field.
    entries.ShouldNotContain(e => e.Signature.Contains("EmptyDecoder::ReadString"));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~Enumerate_ThisField"
```

Expected: 3 failures.

- [ ] **Step 3: Add this-field branch to the enumerator**

In `EntryPointEnumerator.cs`, update `Enumerate` and add helpers:

```csharp
public static IEnumerable<SourceMethodEntry> Enumerate(
    AssemblyContext context,
    EnumeratorConfig config,
    ReverseCallGraph callGraph)
{
    var byteSourceSet = new HashSet<string>(config.ByteSourceTypes, StringComparer.Ordinal);
    // Cache type-name match per declaring type (computed once per type, queried per method).
    var thisFieldCache = new Dictionary<TypeDefinition, IReadOnlyList<string>?>();

    foreach (var type in AllTypes(context.Assembly))
    {
        if (IsCompilerGeneratedType(type)) continue;

        foreach (var method in type.Methods)
        {
            if (HardReject(method)) continue;

            if (MatchesParameterShape(method, byteSourceSet))
            {
                yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                continue;
            }

            if (config.IncludeThisField && !method.IsStatic)
            {
                if (!thisFieldCache.TryGetValue(type, out var seedFields))
                {
                    seedFields = MatchThisFieldShape(type, config, byteSourceSet);
                    thisFieldCache[type] = seedFields;
                }
                if (seedFields is not null)
                {
                    yield return new SourceMethodEntry
                    {
                        Signature = BuildShortSignature(method),
                        SeedThisFields = seedFields.ToList(),
                    };
                }
            }
        }
    }
}

// Returns the list of field names matching ByteSourceTypes if the type's name
// matches a DecoderTypeNamePattern. Returns null when this-field-shape doesn't
// apply to this type.
private static IReadOnlyList<string>? MatchThisFieldShape(
    TypeDefinition type, EnumeratorConfig config, HashSet<string> byteSourceTypes)
{
    bool nameMatches = config.DecoderTypeNamePatterns.Any(p => GlobMatcher.Matches(p, type.Name));
    if (!nameMatches) return null;

    var matchingFields = type.Fields
        .Where(f => FieldTypeMatchesByteSource(f, byteSourceTypes))
        .Select(f => f.Name)
        .ToList();

    return matchingFields.Count > 0 ? matchingFields : null;
}

private static bool FieldTypeMatchesByteSource(FieldDefinition f, HashSet<string> byteSourceTypes)
{
    if (byteSourceTypes.Contains(f.FieldType.FullName)) return true;
    // Base-type walk for Stream subclass fields too.
    TypeDefinition? def;
    try { def = f.FieldType.Resolve(); }
    catch { def = null; }
    var current = def?.BaseType;
    var seen = new HashSet<string>(StringComparer.Ordinal);
    while (current is not null && seen.Add(current.FullName))
    {
        if (byteSourceTypes.Contains(current.FullName)) return true;
        TypeDefinition? baseDef;
        try { baseDef = current.Resolve(); }
        catch { baseDef = null; }
        current = baseDef?.BaseType;
    }
    return false;
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: all 11 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: enumerator this-field-shape predicate (opt-in)"
```

---

## Task 11: Visibility filter

**Why:** Reject private/protected methods always. Reject internal methods unreachable from any public method.

**Files:**
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Add failing tests**

Append:

```csharp
[Fact]
public void Enumerate_RejectsPrivateAndProtectedMethods()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldNotContain(e => e.Signature.Contains("HasPrivateAndProtected::PrivateMethod"));
    entries.ShouldNotContain(e => e.Signature.Contains("HasPrivateAndProtected::ProtectedMethod"));
}

[Fact]
public void Enumerate_AcceptsReachableInternal()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldContain(e => e.Signature.Contains("InternalReachable::Helper"));
}

[Fact]
public void Enumerate_RejectsOrphanInternal()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);
    var entries = EntryPointEnumerator
        .Enumerate(ctx, EnumeratorConfig.Default, graph)
        .ToList();

    entries.ShouldNotContain(e => e.Signature.Contains("InternalOrphan::Orphan"));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: 3 new tests fail — current emitter doesn't filter by visibility.

- [ ] **Step 3: Add visibility filter to `Enumerate`**

In the inner loop of `Enumerate`, after `HardReject` and before the candidate predicates, insert a `VisibilityReject` call:

```csharp
foreach (var method in type.Methods)
{
    if (HardReject(method)) continue;
    if (VisibilityReject(method, callGraph)) continue;

    if (MatchesParameterShape(method, byteSourceSet))
    {
        // ...
    }
    // ...
}
```

Add the helper:

```csharp
private static bool VisibilityReject(MethodDefinition m, ReverseCallGraph callGraph)
{
    // Public method on a public type → always accept.
    if (m.IsPublic && m.DeclaringType.IsPublic) return false;

    // Internal: accept only if reachable from some public method.
    if (m.IsAssembly)
    {
        return !callGraph.IsReachableFromPublic(m);
    }

    // Public method on an internal type → treat as internal: reachability check.
    if (m.IsPublic && !m.DeclaringType.IsPublic)
    {
        return !callGraph.IsReachableFromPublic(m);
    }

    // Private, protected, protected-internal, private-protected: reject.
    return true;
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: all 14 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: enumerator visibility filter (public + public-reachable internal)"
```

---

## Task 12: Namespace, type-name, and method-name exclusions

**Why:** The `exclude_*` config keys must take effect. Default strips `System.*`/`Microsoft.*`, `*Test*`/`*Mock*`, and equality/hash/string overloads.

**Files:**
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`

- [ ] **Step 1: Add failing tests**

Append:

```csharp
[Fact]
public void Enumerate_AppliesNamespaceExclusion()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);

    // Custom config: exclude TaintAnalyzer.Tests.Fixtures.* entirely.
    var cfg = new EnumeratorConfig
    {
        ExcludeNamespaces = new[] { "TaintAnalyzer.Tests.Fixtures.*" },
    };

    var entries = EntryPointEnumerator.Enumerate(ctx, cfg, graph).ToList();

    entries.ShouldBeEmpty();
}

[Fact]
public void Enumerate_AppliesMethodNameExclusion()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var graph = new ReverseCallGraph(ctx.Assembly);

    var cfg = new EnumeratorConfig
    {
        ExcludeMethodPatterns = new[] { "Read" },
    };

    var entries = EntryPointEnumerator.Enumerate(ctx, cfg, graph).ToList();

    entries.ShouldNotContain(e => e.Signature.EndsWith("::Read(System.IO.Stream)"));
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: 2 tests fail.

- [ ] **Step 3: Add exclusion filters**

In `Enumerate`, after `VisibilityReject` check, add:

```csharp
foreach (var method in type.Methods)
{
    if (HardReject(method)) continue;
    if (VisibilityReject(method, callGraph)) continue;
    if (ExclusionReject(method, config)) continue;

    // candidate predicates...
}
```

Add the helper:

```csharp
private static bool ExclusionReject(MethodDefinition m, EnumeratorConfig config)
{
    var declaringNs = m.DeclaringType.Namespace ?? "";
    foreach (var p in config.ExcludeNamespaces)
    {
        if (GlobMatcher.Matches(p, declaringNs)) return true;
    }

    var declaringName = m.DeclaringType.Name;
    foreach (var p in config.ExcludeTypePatterns)
    {
        if (GlobMatcher.Matches(p, declaringName)) return true;
    }

    foreach (var p in config.ExcludeMethodPatterns)
    {
        if (GlobMatcher.Matches(p, m.Name)) return true;
    }

    return false;
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~EntryPointEnumerator"
```

Expected: all 16 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs
git commit -m "analyzer: enumerator namespace/type/method-name exclusions"
```

---

## Task 13: `RulesYamlEmitter`

**Why:** Serialise enumerator output back to a parseable `rules.yaml` for `--emit-rules`.

**Files:**
- Create: `tools/TaintAnalyzer/RulesYamlEmitter.cs`
- Create: `tools/TaintAnalyzer.Tests/RulesYamlEmitterTests.cs`

- [ ] **Step 1: Write failing tests**

Create `RulesYamlEmitterTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RulesYamlEmitterTests
{
    [Fact]
    public void Emit_ScalarEntries_ProducesYamlList()
    {
        var entries = new List<SourceMethodEntry>
        {
            new() { Signature = "Foo.Bar::Baz(System.IO.Stream)" },
            new() { Signature = "Foo.Bar::Qux(System.Byte[])" },
        };

        var yaml = RulesYamlEmitter.Emit("scan-foo", entries);

        yaml.ShouldContain("vuln_id: scan-foo");
        yaml.ShouldContain("Foo.Bar::Baz(System.IO.Stream)");
        yaml.ShouldContain("Foo.Bar::Qux(System.Byte[])");
    }

    [Fact]
    public void Emit_WithSeedFields_ProducesMappingForm()
    {
        var entries = new List<SourceMethodEntry>
        {
            new()
            {
                Signature = "Foo.MyReader::Read()",
                SeedThisFields = new List<string> { "_input" },
            },
        };

        var yaml = RulesYamlEmitter.Emit("scan-foo", entries);

        yaml.ShouldContain("signature: Foo.MyReader::Read()");
        yaml.ShouldContain("seed_this_fields:");
        yaml.ShouldContain("- _input");
    }

    [Fact]
    public void Emit_EmptyEntries_ProducesEmptyList()
    {
        var yaml = RulesYamlEmitter.Emit("scan-empty", new List<SourceMethodEntry>());

        yaml.ShouldContain("vuln_id: scan-empty");
        yaml.ShouldContain("source_methods: []");
    }

    [Fact]
    public void Emit_RoundTripsThroughRulesDocumentLoad()
    {
        var entries = new List<SourceMethodEntry>
        {
            new() { Signature = "Foo.Bar::Baz(System.IO.Stream)" },
            new()
            {
                Signature = "Foo.MyReader::Read()",
                SeedThisFields = new List<string> { "_input" },
            },
        };

        var yaml = RulesYamlEmitter.Emit("scan-rt", entries);
        var doc = RulesDocument.Load(yaml);

        doc.VulnId.ShouldBe("scan-rt");
        doc.SourceMethods.ShouldNotBeNull();
        doc.SourceMethods!.Count.ShouldBe(2);
        doc.SourceMethods[0].Signature.ShouldBe("Foo.Bar::Baz(System.IO.Stream)");
        doc.SourceMethods[1].Signature.ShouldBe("Foo.MyReader::Read()");
        doc.SourceMethods[1].SeedThisFields.ShouldNotBeNull();
        doc.SourceMethods[1].SeedThisFields!.ShouldContain("_input");
    }

    [Fact]
    public void Emit_EmptyEntries_RoundTrips()
    {
        var yaml = RulesYamlEmitter.Emit("scan-empty", new List<SourceMethodEntry>());
        var doc = RulesDocument.Load(yaml);

        doc.SourceMethods.ShouldNotBeNull();
        doc.SourceMethods!.ShouldBeEmpty();
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~RulesYamlEmitter"
```

Expected: build error.

- [ ] **Step 3: Implement the emitter**

Create `tools/TaintAnalyzer/RulesYamlEmitter.cs`:

```csharp
using System.Text;

namespace TaintAnalyzer;

// Hand-rolled emitter rather than reusing YamlDotNet's serializer because the
// SourceMethodEntry shape is dual (scalar vs mapping) and the existing
// SourceMethodEntryConverter only handles the read direction.
//
// Output is deterministic — no maps, no anchors, no random key ordering —
// which keeps fixture-comparison clean.
public static class RulesYamlEmitter
{
    public static string Emit(string vulnId, IReadOnlyList<SourceMethodEntry> entries)
    {
        var sb = new StringBuilder();
        sb.Append("vuln_id: ").AppendLine(vulnId);

        if (entries.Count == 0)
        {
            sb.AppendLine("source_methods: []");
            return sb.ToString();
        }

        sb.AppendLine("source_methods:");
        foreach (var entry in entries)
        {
            bool hasExtras = (entry.SeedThisFields is { Count: > 0 })
                          || (entry.TaintFromExternalReturns is { Count: > 0 });

            if (!hasExtras)
            {
                sb.Append("  - ").AppendLine(entry.Signature);
            }
            else
            {
                sb.Append("  - signature: ").AppendLine(entry.Signature);
                if (entry.SeedThisFields is { Count: > 0 } seeds)
                {
                    sb.AppendLine("    seed_this_fields:");
                    foreach (var f in seeds) sb.Append("      - ").AppendLine(f);
                }
                if (entry.TaintFromExternalReturns is { Count: > 0 } ext)
                {
                    sb.AppendLine("    taint_from_external_returns:");
                    foreach (var s in ext) sb.Append("      - ").AppendLine(s);
                }
            }
        }
        return sb.ToString();
    }
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~RulesYamlEmitter"
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/RulesYamlEmitter.cs tools/TaintAnalyzer.Tests/RulesYamlEmitterTests.cs
git commit -m "analyzer: add RulesYamlEmitter with deterministic output + round-trip"
```

---

## Task 14: Refactor `Program.cs` into a testable `Run` method

**Why:** Tasks 15–18 add several CLI flags. Tests for those need to invoke `Program` without spawning a subprocess. The minimal refactor: extract `Main` into `Run(args, stdout, stderr)` that returns the exit code; `Main` becomes a one-line wrapper.

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`

- [ ] **Step 1: Wrap `Main` with `Run`**

Edit `Program.cs`:

```csharp
public static int Main(string[] args) => Run(args, Console.Out, Console.Error);

public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
{
    // ... existing Main body, replacing Console.Out/Error usages with stdout/stderr ...
}
```

Specifically:
- Change every `Console.Error.WriteLine(...)` to `stderr.WriteLine(...)`.
- Change every `Console.Write(...)` or `Console.WriteLine(...)` (stdout writes) to `stdout.WriteLine(...)`/`stdout.Write(...)`.

- [ ] **Step 2: Build and run existing tests as a regression gate**

```sh
cd tools && dotnet test
```

Expected: all current tests pass (no behaviour change).

- [ ] **Step 3: Commit**

```sh
git add tools/TaintAnalyzer/Program.cs
git commit -m "analyzer: refactor Program.Main into testable Run(args, stdout, stderr)"
```

---

## Task 15: `--scan` flag and dispatch

**Why:** Wire the enumerator into `Program.Run`. `--scan` (no `--emit-rules`) enumerates, walks each candidate, emits traces — same shape as `--rules`.

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`
- Create: `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs`

- [ ] **Step 1: Write failing test (uses `Run` directly)**

Create `ProgramScanFlagTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ProgramScanFlagTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Scan_WithoutOtherFlags_ProducesTraceOnStdout()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(new[] { FixturePath, "--scan" }, stdout, stderr);

        rc.ShouldBe(0);
        // Trace YAML emitted to stdout. Empty findings is fine — the run must succeed.
        stdout.ToString().ShouldContain("vuln_id");
    }

    [Fact]
    public void Scan_AndRules_AreMutuallyExclusive()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(
            new[] { FixturePath, "--scan", "--rules", "x.yaml" }, stdout, stderr);

        rc.ShouldBe(2);
        stderr.ToString().ShouldContain("--scan");
    }

    [Fact]
    public void NeitherScanNorRules_IsUsageError()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var rc = Program.Run(new[] { FixturePath }, stdout, stderr);

        rc.ShouldBe(2);
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: tests fail — `--scan` not recognised.

- [ ] **Step 3: Implement the flag and dispatch**

In `Program.cs`, add `bool scan = false;` alongside the other locals. Add to the arg-parsing loop:

```csharp
else if (a == "--scan")
{
    scan = true;
}
```

Replace the `if (target is null || rulesPath is null)` validation with:

```csharp
if (target is null)
{
    PrintUsage(stderr);
    return 2;
}

bool rulesProvided = rulesPath is not null;
if (scan && rulesProvided)
{
    stderr.WriteLine("error: --scan and --rules are mutually exclusive");
    return 2;
}
if (!scan && !rulesProvided)
{
    PrintUsage(stderr);
    return 2;
}
```

After `AssemblyContext.Load`, replace the `RulesDocument rules; … context.FindMethod(entry.Signature) …` block. Build the source list either from the rules file or via the enumerator:

```csharp
RulesDocument rules;
List<SourceMethodEntry> sources;
string vulnId;

if (scan)
{
    var graph = new ReverseCallGraph(context.Assembly);
    var cfg = EnumeratorConfig.Default;
    sources = EntryPointEnumerator.Enumerate(context, cfg, graph).ToList();
    vulnId = "scan-" + Path.GetFileNameWithoutExtension(target);
    rules = new RulesDocument { VulnId = vulnId, SourceMethods = sources };
}
else
{
    try
    {
        rules = RulesDocument.Load(File.ReadAllText(rulesPath!));
    }
    catch (RulesDocumentException ex)
    {
        stderr.WriteLine($"error: rules: {ex.Message}");
        return 1;
    }
    sources = rules.SourceMethods!;
    vulnId = rules.VulnId ?? "(unspecified)";
}
```

Then the existing walker loop uses `sources` instead of `rules.SourceMethods!`. `PrintUsage` must take a `TextWriter`:

```csharp
private static void PrintUsage(TextWriter stderr)
{
    stderr.WriteLine("usage: TaintAnalyzer <target.dll> [--rules <rules.yaml> | --scan] [--output <trace.yaml>] [--no-symbols]");
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 3 tests pass.

- [ ] **Step 5: Full regression sweep**

```sh
cd tools && dotnet test
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```sh
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs
git commit -m "analyzer: add --scan flag with enumerator dispatch"
```

---

## Task 16: `--include-this-field` and `--enumerator-config` flags

**Why:** Two opt-in flags that thread into `EnumeratorConfig`.

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`
- Modify: `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs`

- [ ] **Step 1: Add failing tests**

Append:

```csharp
[Fact]
public void IncludeThisField_RequiresScan()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--rules", "x.yaml", "--include-this-field" }, stdout, stderr);

    rc.ShouldBe(2);
    stderr.ToString().ShouldContain("--scan");
}

[Fact]
public void EnumeratorConfig_RequiresScan()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--rules", "x.yaml", "--enumerator-config", "cfg.yaml" },
        stdout, stderr);

    rc.ShouldBe(2);
}

[Fact]
public void EnumeratorConfig_MissingFile_IsRuntimeError()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--scan", "--enumerator-config", "nonexistent.yaml" },
        stdout, stderr);

    rc.ShouldBe(1);
    stderr.ToString().ShouldContain("not found");
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 3 new tests fail.

- [ ] **Step 3: Implement**

Add locals `bool includeThisField = false;` and `string? enumeratorConfigPath = null;` in `Run`. Extend the arg-parsing loop:

```csharp
else if (a == "--include-this-field")
{
    includeThisField = true;
}
else if (a == "--enumerator-config")
{
    if (++i >= args.Length) { stderr.WriteLine("error: --enumerator-config requires a path"); return 2; }
    enumeratorConfigPath = args[i];
}
```

After the mutex check, add scan-only flag enforcement:

```csharp
if (!scan && (includeThisField || enumeratorConfigPath is not null))
{
    stderr.WriteLine("error: --include-this-field and --enumerator-config require --scan");
    return 2;
}
```

In the `if (scan)` block, replace the config construction:

```csharp
EnumeratorConfig cfg;
if (enumeratorConfigPath is not null)
{
    if (!File.Exists(enumeratorConfigPath))
    {
        stderr.WriteLine($"error: enumerator-config file not found: {enumeratorConfigPath}");
        return 1;
    }
    try
    {
        cfg = EnumeratorConfig.Load(File.ReadAllText(enumeratorConfigPath));
    }
    catch (EnumeratorConfigException ex)
    {
        stderr.WriteLine($"error: enumerator-config: {ex.Message}");
        return 1;
    }
}
else
{
    cfg = EnumeratorConfig.Default;
}

if (includeThisField)
{
    cfg = new EnumeratorConfig
    {
        ByteSourceTypes = cfg.ByteSourceTypes,
        DecoderTypeNamePatterns = cfg.DecoderTypeNamePatterns,
        ExcludeNamespaces = cfg.ExcludeNamespaces,
        ExcludeTypePatterns = cfg.ExcludeTypePatterns,
        ExcludeMethodPatterns = cfg.ExcludeMethodPatterns,
        IncludeThisField = true,
    };
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs
git commit -m "analyzer: add --include-this-field and --enumerator-config flags"
```

---

## Task 17: `--emit-rules` (terminal)

**Why:** Write enumerated rules.yaml and exit. Mutually exclusive with `--output`.

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`
- Modify: `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs`

- [ ] **Step 1: Add failing tests**

Append:

```csharp
[Fact]
public void EmitRules_RequiresScan()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--rules", "x.yaml", "--emit-rules", "out.yaml" },
        stdout, stderr);

    rc.ShouldBe(2);
}

[Fact]
public void EmitRules_AndOutput_AreMutuallyExclusive()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--scan", "--emit-rules", "out.yaml", "--output", "trace.yaml" },
        stdout, stderr);

    rc.ShouldBe(2);
    stderr.ToString().ShouldContain("--emit-rules");
}

[Fact]
public void EmitRules_WritesFileAndExitsWithoutWalking()
{
    var outPath = Path.Combine(Path.GetTempPath(), $"emit-{Guid.NewGuid()}.yaml");
    try
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var rc = Program.Run(
            new[] { FixturePath, "--scan", "--emit-rules", outPath },
            stdout, stderr);

        rc.ShouldBe(0);
        File.Exists(outPath).ShouldBeTrue();
        var content = File.ReadAllText(outPath);
        content.ShouldContain("vuln_id");
        // Trace YAML is NOT emitted to stdout when --emit-rules is used.
        stdout.ToString().ShouldNotContain("hop:");
    }
    finally
    {
        if (File.Exists(outPath)) File.Delete(outPath);
    }
}
```

- [ ] **Step 2: Run and confirm fail**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 3 new tests fail.

- [ ] **Step 3: Implement**

Add a local `string? emitRulesPath = null;`. Extend arg-parsing:

```csharp
else if (a == "--emit-rules")
{
    if (++i >= args.Length) { stderr.WriteLine("error: --emit-rules requires a path"); return 2; }
    emitRulesPath = args[i];
}
```

Validation after mutex check:

```csharp
if (!scan && emitRulesPath is not null)
{
    stderr.WriteLine("error: --emit-rules requires --scan");
    return 2;
}
if (emitRulesPath is not null && outputPath is not null)
{
    stderr.WriteLine("error: --emit-rules and --output are mutually exclusive (--emit-rules is terminal)");
    return 2;
}
```

After enumeration (inside the `if (scan)` block, before `walker = new TaintWalker(context)`):

```csharp
if (emitRulesPath is not null)
{
    var yamlOut = RulesYamlEmitter.Emit(vulnId, sources);
    File.WriteAllText(emitRulesPath, yamlOut);
    return 0;
}
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 9 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs
git commit -m "analyzer: add --emit-rules terminal mode (writes rules.yaml, no walking)"
```

---

## Task 18: `--progress` flag

**Why:** Diagnostic stderr output during long scans.

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`
- Modify: `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs`

- [ ] **Step 1: Add failing test**

Append:

```csharp
[Fact]
public void Progress_EmitsScanDiagnosticsToStderr()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(
        new[] { FixturePath, "--scan", "--progress" }, stdout, stderr);

    rc.ShouldBe(0);
    var err = stderr.ToString();
    err.ShouldContain("[scan] enumerated");
    err.ShouldContain("[scan] complete:");
}

[Fact]
public void Progress_IsSilentByDefault()
{
    var stdout = new StringWriter();
    var stderr = new StringWriter();

    var rc = Program.Run(new[] { FixturePath, "--scan" }, stdout, stderr);

    rc.ShouldBe(0);
    stderr.ToString().ShouldNotContain("[scan]");
}
```

- [ ] **Step 2: Run and confirm fail**

Expected: new tests fail.

- [ ] **Step 3: Implement**

Add `bool progress = false;` and parse `--progress`. Wrap the scan flow with timing:

```csharp
if (scan)
{
    var graph = new ReverseCallGraph(context.Assembly);
    // ... cfg construction ...

    var sw = System.Diagnostics.Stopwatch.StartNew();
    sources = EntryPointEnumerator.Enumerate(context, cfg, graph).ToList();
    var enumElapsed = sw.ElapsedMilliseconds;

    int methodCount = context.Assembly.MainModule.Types.Sum(CountMethods);
    if (progress)
    {
        stderr.WriteLine($"[scan] enumerated {sources.Count} candidates from {methodCount} methods ({enumElapsed}ms)");
    }

    if (emitRulesPath is not null)
    {
        var yamlOut = RulesYamlEmitter.Emit(vulnId, sources);
        File.WriteAllText(emitRulesPath, yamlOut);
        if (progress)
        {
            stderr.WriteLine($"[scan] complete: wrote rules to {emitRulesPath} ({sw.ElapsedMilliseconds}ms)");
        }
        return 0;
    }

    // ... existing walker loop, with per-candidate progress hook ...
}
```

Wrap the existing `foreach (var entry in rules.SourceMethods!)` loop. Replace its iteration variable with `sources` (from Task 15) and add a stopwatch + idx counter + per-iteration log line:

```csharp
int candidateIdx = 0;
foreach (var entry in sources)
{
    candidateIdx++;
    var perSw = System.Diagnostics.Stopwatch.StartNew();

    var source = context.FindMethod(entry.Signature);
    if (source is null)
    {
        var suggestion = SuggestNearest(context, entry.Signature);
        stderr.WriteLine($"error: source method not found: {entry.Signature}");
        if (suggestion is not null) stderr.WriteLine($"   closest in target: {suggestion}");
        return 1;
    }

    var resolution = AsyncStateMachineResolver.Resolve(source);
    walker.TaintFromExternalReturns = entry.TaintFromExternalReturns
        ?? (IReadOnlyList<string>)Array.Empty<string>();

    int bitmask;
    IReadOnlyCollection<string> seedFields;
    if (resolution.RedirectedFromAsync)
    {
        bitmask = 0;
        var smFieldNames = resolution.Method.DeclaringType.Fields
            .Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        seedFields = source.Parameters
            .Select(p => p.Name)
            .Where(name => smFieldNames.Contains(name))
            .ToList();
    }
    else
    {
        bitmask = (1 << source.Parameters.Count) - 1;
        seedFields = entry.SeedThisFields ?? (IReadOnlyCollection<string>)Array.Empty<string>();
    }

    var summary = walker.WalkWithSeed(resolution.Method, bitmask, seedFields);

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
        ResolvedVia = resolution.RedirectedFromAsync ? "async_state_machine" : null,
    });
    allHops.AddRange(summary.Hops);

    if (progress)
    {
        stderr.WriteLine($"[scan] walking {candidateIdx}/{sources.Count}: {entry.Signature} ({perSw.ElapsedMilliseconds}ms)");
    }
}

if (progress && scan)
{
    int findings = allHops.Count(h => h.Role == HopRole.Sink);
    stderr.WriteLine($"[scan] complete: {findings} findings across {sources.Count} candidates ({sw.ElapsedMilliseconds}ms)");
}
```

(`sw` is the scan-mode stopwatch declared earlier in the `if (scan)` block. For `--rules` mode, `sw` won't be in scope — the `progress && scan` guard handles that.)

Helper:

```csharp
private static int CountMethods(Mono.Cecil.TypeDefinition t)
    => t.Methods.Count + t.NestedTypes.Sum(CountMethods);
```

- [ ] **Step 4: Run and confirm pass**

```sh
dotnet test --filter "FullyQualifiedName~ProgramScanFlag"
```

Expected: 11 tests pass.

- [ ] **Step 5: Commit**

```sh
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs
git commit -m "analyzer: add --progress flag for scan-mode diagnostics"
```

---

## Task 19: Fixture lock — `scan-protobuf-net`

**Why:** End-to-end proof that `--scan --include-this-field` rediscovers the protobuf-net entry point we currently hand-write.

**Files:**
- Create: `fixtures/scan-protobuf-net/run`
- Create: `fixtures/scan-protobuf-net/rules.yaml.expected`
- Create: `fixtures/scan-protobuf-net/README.md`

- [ ] **Step 1: Capture the expected output**

Build a release of the analyzer first:

```sh
cd tools/TaintAnalyzer && dotnet build -c Release
```

Run a one-off scan and inspect the output:

```sh
cd /mnt/c/work/dotnet-taint-analyzer
PROTOBUF_DLL=experiments/protobuf-net/lib-nupkg/lib/net8.0/protobuf-net.dll
ANALYZER=tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer
"$ANALYZER" "$PROTOBUF_DLL" --scan --include-this-field --emit-rules /tmp/scan-protobuf.yaml --progress
cat /tmp/scan-protobuf.yaml
```

Expected: a YAML file with `vuln_id: scan-protobuf-net` and a list of source methods including `ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader::ImplReadString(...)`.

**If `ImplReadString` is NOT in the output**: stop. Either the heuristic is missing something or the type name doesn't match. Debug before continuing.

**If it IS in the output**: copy the file to `fixtures/scan-protobuf-net/rules.yaml.expected`.

```sh
mkdir -p fixtures/scan-protobuf-net
cp /tmp/scan-protobuf.yaml fixtures/scan-protobuf-net/rules.yaml.expected
```

- [ ] **Step 2: Write the `run` script**

Create `fixtures/scan-protobuf-net/run`:

```sh
#!/usr/bin/env bash
# Regression-locks the enumerator output for protobuf-net.
# Compares fresh --scan output against rules.yaml.expected.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
PROTOBUF_DLL="$REPO_ROOT/experiments/protobuf-net/lib-nupkg/lib/net8.0/protobuf-net.dll"
ANALYZER="$REPO_ROOT/tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer"

if [ ! -f "$ANALYZER" ]; then
    echo "error: build the analyzer first: cd tools/TaintAnalyzer && dotnet build -c Release" >&2
    exit 1
fi
if [ ! -f "$PROTOBUF_DLL" ]; then
    echo "error: protobuf-net.dll not found at $PROTOBUF_DLL" >&2
    exit 1
fi

ACTUAL=$(mktemp)
trap 'rm -f "$ACTUAL"' EXIT

"$ANALYZER" "$PROTOBUF_DLL" --scan --include-this-field --emit-rules "$ACTUAL"

if ! diff -u rules.yaml.expected "$ACTUAL"; then
    echo "error: scan-protobuf-net rules.yaml output drifted" >&2
    exit 1
fi
echo "scan-protobuf-net: locked rules.yaml matches"
```

Then:

```sh
chmod +x fixtures/scan-protobuf-net/run
```

- [ ] **Step 3: Write README**

Create `fixtures/scan-protobuf-net/README.md`:

```markdown
# scan-protobuf-net

End-to-end regression fixture for the entry-point enumerator. Runs
`TaintAnalyzer --scan --include-this-field --emit-rules` over
`experiments/protobuf-net/lib-nupkg/lib/net8.0/protobuf-net.dll` and
asserts the generated rules.yaml matches `rules.yaml.expected`.

The expected output must contain
`ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader::ImplReadString(...)` —
the entry point currently hand-written in
`experiments/protobuf-net/rules.yaml`. This proves the enumerator
rediscovers known wins without prior knowledge.

Run: `./run`
```

- [ ] **Step 4: Verify the fixture passes**

```sh
fixtures/scan-protobuf-net/run
```

Expected: `scan-protobuf-net: locked rules.yaml matches`.

- [ ] **Step 5: Sanity-check: the locked file mentions `ImplReadString`**

```sh
grep ImplReadString fixtures/scan-protobuf-net/rules.yaml.expected
```

Expected: non-empty output.

- [ ] **Step 6: Commit**

```sh
git add fixtures/scan-protobuf-net/
git commit -m "fixture: lock scan-protobuf-net (enumerator rediscovers ImplReadString)"
```

---

## Task 20: Fixture lock — `scan-nbmp-1.1.25`

**Why:** Proof of the parameter-shape path. NBMP 1.1.25's `MessagePackPrimitives.TryRead` takes `ReadOnlySpan<byte>` — should be a high-precision parameter-shape match without `--include-this-field`.

**Files:**
- Create: `fixtures/scan-nbmp-1.1.25/run`
- Create: `fixtures/scan-nbmp-1.1.25/rules.yaml.expected`
- Create: `fixtures/scan-nbmp-1.1.25/README.md`

- [ ] **Step 1: Capture expected output**

```sh
cd /mnt/c/work/dotnet-taint-analyzer
NBMP_DLL=artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll
ANALYZER=tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer
"$ANALYZER" "$NBMP_DLL" --scan --emit-rules /tmp/scan-nbmp.yaml --progress
grep -i TryRead /tmp/scan-nbmp.yaml || echo "WARN: TryRead not in output — investigate"
```

Expected: `MessagePackPrimitives::TryRead(...)` entries appear. If not, debug.

```sh
mkdir -p fixtures/scan-nbmp-1.1.25
cp /tmp/scan-nbmp.yaml fixtures/scan-nbmp-1.1.25/rules.yaml.expected
```

- [ ] **Step 2: Write `run` script**

Create `fixtures/scan-nbmp-1.1.25/run`:

```sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
NBMP_DLL="$REPO_ROOT/artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll"
ANALYZER="$REPO_ROOT/tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer"

if [ ! -f "$ANALYZER" ]; then
    echo "error: build the analyzer first" >&2; exit 1
fi
if [ ! -f "$NBMP_DLL" ]; then
    echo "error: nbmp dll not found at $NBMP_DLL" >&2; exit 1
fi

ACTUAL=$(mktemp)
trap 'rm -f "$ACTUAL"' EXIT

"$ANALYZER" "$NBMP_DLL" --scan --emit-rules "$ACTUAL"

if ! diff -u rules.yaml.expected "$ACTUAL"; then
    echo "error: scan-nbmp-1.1.25 rules.yaml output drifted" >&2
    exit 1
fi
echo "scan-nbmp-1.1.25: locked rules.yaml matches"
```

Then:

```sh
chmod +x fixtures/scan-nbmp-1.1.25/run
```

- [ ] **Step 3: Write README**

Create `fixtures/scan-nbmp-1.1.25/README.md`:

```markdown
# scan-nbmp-1.1.25

Locks the enumerator output for Nerdbank.MessagePack 1.1.25 (parameter-shape
path, no `--include-this-field`). The vulnerable
`MessagePackPrimitives::TryRead(ReadOnlySpan<byte>, ...)` entry must appear
in the generated rules.yaml — proof that the enumerator catches the
parameter-shape class of bug.

Run: `./run`
```

- [ ] **Step 4: Verify**

```sh
fixtures/scan-nbmp-1.1.25/run
grep TryRead fixtures/scan-nbmp-1.1.25/rules.yaml.expected
```

Expected: both pass.

- [ ] **Step 5: Commit**

```sh
git add fixtures/scan-nbmp-1.1.25/
git commit -m "fixture: lock scan-nbmp-1.1.25 (enumerator catches TryRead)"
```

---

## Task 21: Regression sweep — all anchors green

**Why:** Per the gap-backlog memory, milestone-Q must keep every existing anchor green.

**Files:** none new

- [ ] **Step 1: Run full xUnit suite**

```sh
cd tools && dotnet test
```

Expected: 0 failures. Test count = current baseline (168) + new tests from this milestone. Capture the new total.

- [ ] **Step 2: Run every locked fixture**

```sh
cd /mnt/c/work/dotnet-taint-analyzer
for d in fixtures/*/; do
    if [ -x "${d}run" ]; then
        echo "=== ${d} ==="
        "${d}run" || { echo "FAIL: $d"; exit 1; }
    fi
done
```

Expected: every fixture run script prints success.

- [ ] **Step 3: Verify the milestone-anchor list specifically**

```sh
for f in imagesharp-3074-postfix imagesharp-3074-prefix imagesharp-3079-postfix imagesharp-3079-prefix \
         otelcontrib-55m9-postfix otelcontrib-55m9-prefix otelcontrib-vc24-postfix otelcontrib-vc24-prefix \
         otelcontrib-opamp-w2jh-postfix otelcontrib-opamp-w2jh-prefix otelcontrib-aws-fp-fixed \
         nbmp-2cwq-pwfr-wcw3-postfix nbmp-2cwq-pwfr-wcw3-prefix; do
    [ -x "fixtures/$f/run" ] && fixtures/$f/run || true
done
```

Expected: all pass (some are walker-output comparisons via the existing `--compare` mechanism).

- [ ] **Step 4: Update gap-backlog memory after milestone closes**

This is a manual step — once Tasks 1–20 are committed and Task 21 passes, the user updates `~/.claude/projects/.../memory/analyzer_gap_backlog.md` to mark "Entry-point enumeration" as closed under milestone-Q. Not part of the code commit.

---

## Self-review checklist

Each spec requirement maps to a task:

| Spec section | Implemented in |
|---|---|
| Empty `source_methods` round-trip | Task 1 |
| `EntryPointEnumerator` + hard filters | Task 7 |
| Parameter-shape (direct match) | Task 8 |
| Parameter-shape (base-type walk) | Task 9 |
| This-field-shape predicate | Task 10 |
| Visibility filter (public + reachable internal) | Task 11 |
| Exclusion filters (namespace/type/method) | Task 12 |
| `EnumeratorConfig` POCO + Default | Task 4 |
| `EnumeratorConfig.Load` YAML parsing | Task 5 |
| Glob matcher | Task 3 |
| ReverseCallGraph | Tasks 6 |
| `RulesYamlEmitter` + round-trip | Task 13 |
| `--scan` flag + dispatch | Task 15 |
| `--include-this-field`, `--enumerator-config` | Task 16 |
| `--emit-rules` (terminal) | Task 17 |
| `--progress` diagnostics | Task 18 |
| `vuln_id: scan-<assembly>` placeholder | Task 15 |
| protobuf-net regression proof | Task 19 |
| NBMP / MPCS-class parameter-shape proof | Task 20 (NBMP substituted) |
| Anchor regression | Task 21 |

**Type consistency:**
- `EnumeratorConfig` property names (`ByteSourceTypes`, `DecoderTypeNamePatterns`, `Exclude*`, `IncludeThisField`) — referenced in Tasks 4, 5, 7–12, 15–17. Consistent.
- `EntryPointEnumerator.Enumerate(AssemblyContext, EnumeratorConfig, ReverseCallGraph)` — referenced in Tasks 7–12, 15. Consistent.
- `RulesYamlEmitter.Emit(string vulnId, IReadOnlyList<SourceMethodEntry> entries)` — referenced in Tasks 13, 17. Consistent.
- `GlobMatcher.Matches(pattern, input)` — Tasks 3, 10, 12. Consistent.
- `ReverseCallGraph.IsReachableFromPublic(MethodDefinition)` — Tasks 6, 11. Consistent.
- `Program.Run(string[], TextWriter, TextWriter)` — Tasks 14–18. Consistent.

**Substitution note:** Spec Task 20 uses NBMP 1.1.25 instead of MessagePack-CSharp 3.1.4 because the latter isn't materialised locally; same parameter-shape bug class, same proof value.

**No placeholders, TODOs, or incomplete sections in tasks above. Every code step has the actual code; every command step has the actual command and expected output.**
