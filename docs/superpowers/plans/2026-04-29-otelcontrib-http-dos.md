# Milestone-H Implementation Plan — HTTP response DoS detection

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the taint analyzer to detect CWE-770 HTTP response DoS vulnerabilities — specifically `ReadAsStringAsync`/`GetStringAsync` calls without size caps — and produce fixture pairs for two OpenTelemetry CVEs (GHSA-55m9-299j-53c7 and GHSA-vc24-j8c5-2vw4).

**Architecture:** Two independent code changes (Component 1: `taint_from_external_returns` source annotation; Component 2: `MatchHttpRead` unconditional sink) followed by DLL builds and fixture pairs for the two CVEs. Phase 2 is a pure analysis pass with no code changes. Branch model: `milestone-h` off main.

**Tech Stack:** .NET 10 / xUnit / Shouldly / Mono.Cecil 0.11.6 / YamlDotNet 15.1.6. Repository: `open-telemetry/opentelemetry-dotnet-contrib` (external, built for artifacts).

**Spec reference:** `docs/superpowers/specs/2026-04-29-otelcontrib-http-dos-design.md`

**Baseline (pre-H):** 189 tests, 6/6 non-strict, 6/6 strict.

---

## Task overview

| # | Title | Session |
|---|-------|---------|
| 0 | Branch setup | — |
| 1 | `taint_from_external_returns` — schema + failing tests | 1 |
| 2 | `taint_from_external_returns` — implementation | 1 |
| 3 | HTTP sink shapes — failing tests | 1 |
| 4 | HTTP sink shapes — implementation | 1 |
| 5 | Validator vocab + coupling update | 1 |
| 6 | Commit Components 1+2 | 1 |
| 7 | Build OneCollector DLLs (pre-fix + post-fix) | 2 |
| 8 | OneCollector fixture pair | 2 |
| 9 | Build Azure Resources DLLs (pre-fix + post-fix) | 2 |
| 10 | Azure Resources fixture pair | 2 |
| 11 | Phase 2 — broad scan triage report | 3 |
| 12 | Spec status update + land on main | 3 |

---

## Task 0: Branch setup

- [ ] **Step 0.1: Create the milestone-h branch**

```bash
git checkout main && git checkout -b milestone-h
```

Expected: on branch `milestone-h`.

- [ ] **Step 0.2: Confirm baseline**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
```

Expected: 189 tests passing, 0 failures.

---

## Task 1: `taint_from_external_returns` — schema + failing tests

**Files:**
- Modify: `tools/TaintAnalyzer/RulesDocument.cs` (add property + YAML converter case)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (add fixture class)
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (add failing tests)

- [ ] **Step 1.1: Add `TaintFromExternalReturns` property to `SourceMethodEntry`**

Open `tools/TaintAnalyzer/RulesDocument.cs`. Find:

```csharp
public sealed class SourceMethodEntry
{
    public string Signature { get; init; } = "";
    public List<string>? SeedThisFields { get; init; }
```

Replace with:

```csharp
public sealed class SourceMethodEntry
{
    public string Signature { get; init; } = "";
    public List<string>? SeedThisFields { get; init; }
    public List<string>? TaintFromExternalReturns { get; init; }
```

- [ ] **Step 1.2: Add YAML parsing for `taint_from_external_returns` in `SourceMethodEntryConverter`**

In the same file, find the `switch (key)` block inside `ReadYaml`. Find the `case "seed_this_fields":` block and the `default:` case. Insert a new case between them:

```csharp
                    case "taint_from_external_returns":
                        if (parser.Current is not SequenceStart)
                        {
                            throw new RulesDocumentException("source_methods entry: 'taint_from_external_returns' must be a list");
                        }
                        parser.MoveNext();
                        taintFromExternalReturns = new List<string>();
                        while (parser.Current is not SequenceEnd)
                        {
                            if (parser.Current is not Scalar extRetScalar)
                            {
                                throw new RulesDocumentException("source_methods entry: 'taint_from_external_returns' entries must be scalar strings");
                            }
                            taintFromExternalReturns.Add(extRetScalar.Value);
                            parser.MoveNext();
                        }
                        parser.MoveNext();
                        break;
```

Also add the local variable declaration near the top of the mapping block where `seedFields` is declared (find `List<string>? seedFields = null;` and add below it):

```csharp
            List<string>? taintFromExternalReturns = null;
```

And update the `return` statement at the end of the mapping block (find `return new SourceMethodEntry { Signature = signature, SeedThisFields = seedFields };`):

```csharp
            return new SourceMethodEntry { Signature = signature, SeedThisFields = seedFields, TaintFromExternalReturns = taintFromExternalReturns };
```

- [ ] **Step 1.3: Add fixture class for `taint_from_external_returns` testing**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Append at the end of the file:

```csharp

// Milestone-H fixtures — taint_from_external_returns source annotation.
public static class ExternalReturnTaintFixtures
{
    // Calls System.IO.Path.GetFullPath (external static, no receiver, no tainted args).
    // Without TaintFromExternalReturns: path is untainted → new byte[] doesn't fire.
    // With TaintFromExternalReturns=["Path::GetFullPath"]: path is tainted → NewArray fires.
    public static byte[] AllocFromExternalPathResult()
    {
        var path = System.IO.Path.GetFullPath(".");
        return new byte[path.Length];
    }
}
```

- [ ] **Step 1.4: Add failing tests for `taint_from_external_returns`**

Open `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`. Append before the final closing `}` of the `TaintWalkerTests` class:

```csharp
    [Fact]
    public void Walk_TaintFromExternalReturns_SeededMethod_NewArraySinkFires()
    {
        // When TaintFromExternalReturns includes "Path::GetFullPath", the return is treated
        // as tainted even though no input args are tainted. The tainted path.Length then
        // flows into new byte[path.Length], firing the NewArray sink.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        walker.TaintFromExternalReturns = new[] { "Path::GetFullPath" };

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ExternalReturnTaintFixtures::AllocFromExternalPathResult()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeTrue("seeded external return must taint the call result");
        summary.Hops.ShouldContain(h => h.SinkApi == SinkApi.NewArray,
            "tainted path.Length must flow to new byte[] sink");
    }

    [Fact]
    public void Walk_TaintFromExternalReturns_NotSet_NewArrayDoesNotFire()
    {
        // Without TaintFromExternalReturns, GetFullPath returns untainted → no NewArray sink.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        // TaintFromExternalReturns defaults to empty — no external return seeding.

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.ExternalReturnTaintFixtures::AllocFromExternalPathResult()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse("no tainted input → no sink");
    }
```

- [ ] **Step 1.5: Build fixtures DLL and run new tests — expect both to fail**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_TaintFromExternalReturns"
```

Expected:
- `Walk_TaintFromExternalReturns_SeededMethod_NewArraySinkFires` — **FAIL** (`TaintWalker` has no `TaintFromExternalReturns` property yet)
- `Walk_TaintFromExternalReturns_NotSet_NewArrayDoesNotFire` — **FAIL** (same compile error)

---

## Task 2: `taint_from_external_returns` — implementation

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` (add property + helper method + modify external branch)
- Modify: `tools/TaintAnalyzer/Program.cs` (set property before each WalkWithSeed)

- [ ] **Step 2.1: Add `TaintFromExternalReturns` property to `TaintWalker`**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find the class-level fields (around lines 11-20, after `_memo` and `_depth`). Add after the existing field declarations:

```csharp
    // Set by Program.cs before each WalkWithSeed to specify which external methods
    // should have their return value treated as tainted regardless of input taint.
    // Entries are matched as "TypeName::MethodName" (class name without namespace).
    public IReadOnlyList<string> TaintFromExternalReturns { get; set; } = Array.Empty<string>();
```

- [ ] **Step 2.2: Add `MatchesTaintFromExternalReturn` private helper**

In the same file, find `private static bool IsMeaningfulLocalName` (near the other helpers around line 300). Add a new private method just above it:

```csharp
    private bool MatchesTaintFromExternalReturn(MethodReference callee)
    {
        foreach (var entry in TaintFromExternalReturns)
        {
            var sep = entry.IndexOf("::", StringComparison.Ordinal);
            if (sep < 0)
            {
                if (callee.Name == entry) return true;
            }
            else
            {
                if (callee.DeclaringType.Name == entry[..sep] && callee.Name == entry[(sep + 2)..])
                    return true;
            }
        }
        return false;
    }
```

- [ ] **Step 2.3: Modify the external branch in `HandleCall` to use `matchesTaintSource`**

Find the external branch in `HandleCall` (around line 825). The current code is:

```csharp
        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolveMethod(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: same over-approximation as in-assembly — any tainted input surfaces as
            // tainted return. Required for `Nullable<T>::get_Value()` on a tainted struct,
            // `Span<>::Slice` / `op_Implicit`, `BinaryPrimitives::ReadInt16LE(rosBuffer)`, etc.
            // (Without this, the #3074 chain `this.fileHeader.Value.Offset` drops taint at .Value.)
            if (!IsVoidReturn(callee))
            {
                if (anyTaintedInput)
                {
                    string prov;
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{CleanCalleeName(callee)}";
                    }
                    else
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}({firstTainted.Provenance})";
                    }
                    state.Stack.Push(StackSlot.TaintedWith(prov));
                }
                else
                {
                    state.Stack.Push(StackSlot.Untainted);
                }
            }
```

Replace with:

```csharp
        // If the callee is in the analyzed assembly, recurse.
        var resolved = SafeResolveMethod(callee);
        if (resolved is null || resolved.Module.Assembly != _context.Assembly)
        {
            // External: same over-approximation as in-assembly — any tainted input surfaces as
            // tainted return. Required for `Nullable<T>::get_Value()` on a tainted struct,
            // `Span<>::Slice` / `op_Implicit`, `BinaryPrimitives::ReadInt16LE(rosBuffer)`, etc.
            // (Without this, the #3074 chain `this.fileHeader.Value.Offset` drops taint at .Value.)
            // taint_from_external_returns: methods listed per-source-entry in rules.yaml whose
            // return is unconditionally tainted (models network response as attacker-controlled).
            bool matchesTaintSource = MatchesTaintFromExternalReturn(callee);

            if (!IsVoidReturn(callee))
            {
                if (anyTaintedInput || matchesTaintSource)
                {
                    string prov;
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{CleanCalleeName(callee)}";
                    }
                    else if (argSlots.Any(s => s.Tainted))
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}({firstTainted.Provenance})";
                    }
                    else
                    {
                        // Network/external source: no tainted args, taint introduced by annotation.
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}";
                    }
                    state.Stack.Push(StackSlot.TaintedWith(prov));
                }
                else
                {
                    state.Stack.Push(StackSlot.Untainted);
                }
            }
```

- [ ] **Step 2.4: Set `TaintFromExternalReturns` in `Program.cs` before each walk**

Open `tools/TaintAnalyzer/Program.cs`. Find:

```csharp
                var seedFields = entry.SeedThisFields ?? (IReadOnlyCollection<string>)Array.Empty<string>();
                var summary = walker.WalkWithSeed(source, bitmask, seedFields);
```

Replace with:

```csharp
                var seedFields = entry.SeedThisFields ?? (IReadOnlyCollection<string>)Array.Empty<string>();
                walker.TaintFromExternalReturns = entry.TaintFromExternalReturns
                    ?? (IReadOnlyList<string>)Array.Empty<string>();
                var summary = walker.WalkWithSeed(source, bitmask, seedFields);
```

- [ ] **Step 2.5: Build and run the two `taint_from_external_returns` tests — expect both to pass**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_TaintFromExternalReturns"
```

Expected: 2 passing, 0 failing.

- [ ] **Step 2.6: Run the full analyzer test suite — no regressions**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green (189 + 2 new = 191 tests passing).

---

## Task 3: HTTP sink shapes — failing tests

**Files:**
- Modify: `tools/TaintAnalyzer/HopRecord.cs` (add two `SinkApi` values)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (add HTTP fixture)
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (add failing tests)

- [ ] **Step 3.1: Add `HttpContentRead` and `HttpClientRead` to `SinkApi`**

Open `tools/TaintAnalyzer/HopRecord.cs`. Find the `SinkApi` enum:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc }
```

Replace with:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc, HttpContentRead, HttpClientRead }
```

- [ ] **Step 3.2: Add HTTP client fixture class**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Append after the `ExternalReturnTaintFixtures` class:

```csharp

// Milestone-H fixtures — HTTP content read sink shapes.
public static class HttpClientReadFixtures
{
    // Calls HttpClient.GetStringAsync (in System.Net.Http.HttpClient, external to analyzed assembly).
    // MatchHttpRead fires unconditionally on the GetStringAsync call → HttpClientRead sink.
    // Without TaintFromExternalReturns: result is untainted, new byte[] doesn't fire.
    // With TaintFromExternalReturns=["HttpClient::GetStringAsync"]: result is tainted,
    // result.Length tainted, new byte[result.Length] fires as NewArray.
    public static byte[] AllocFromHttpGetString()
    {
        using var client = new System.Net.Http.HttpClient();
        var result = client.GetStringAsync("http://example.com").GetAwaiter().GetResult();
        return new byte[result.Length];
    }
}
```

- [ ] **Step 3.3: Add failing tests for `MatchHttpRead`**

Open `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`. Append before the final closing `}`:

```csharp
    [Fact]
    public void Walk_HttpClientGetStringAsync_HttpClientReadSinkFires()
    {
        // MatchHttpRead must fire unconditionally on HttpClient.GetStringAsync even when
        // the receiver (client) is untainted and TaintFromExternalReturns is empty.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        // TaintFromExternalReturns intentionally left empty to test unconditional sink.

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.HttpClientReadFixtures::AllocFromHttpGetString()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeTrue("MatchHttpRead fires unconditionally on GetStringAsync");
        summary.Hops.ShouldContain(h => h.SinkApi == SinkApi.HttpClientRead,
            "HttpClient.GetStringAsync must produce an HttpClientRead sink hop");
        // Without TaintFromExternalReturns, result is untainted → no NewArray.
        summary.Hops.ShouldNotContain(h => h.SinkApi == SinkApi.NewArray,
            "untainted result.Length must not produce a NewArray sink");
    }

    [Fact]
    public void Walk_HttpClientGetStringAsync_WithExternalReturn_BothSinksFire()
    {
        // With TaintFromExternalReturns, GetStringAsync return is tainted → result.Length
        // tainted → new byte[result.Length] fires as NewArray in addition to HttpClientRead.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        walker.TaintFromExternalReturns = new[] { "HttpClient::GetStringAsync" };

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.HttpClientReadFixtures::AllocFromHttpGetString()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.SinkApi == SinkApi.HttpClientRead);
        summary.Hops.ShouldContain(h => h.SinkApi == SinkApi.NewArray,
            "tainted result.Length must flow to new byte[] sink");
    }
```

- [ ] **Step 3.4: Build and run new tests — expect both to fail**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_HttpClientGetStringAsync"
```

Expected: both **FAIL** (`SinkShapes.MatchHttpRead` does not exist yet).

---

## Task 4: HTTP sink shapes — implementation

**Files:**
- Modify: `tools/TaintAnalyzer/SinkShapes.cs` (add `MatchHttpRead`)
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` (`HandleSinkMatch` — add `MatchHttpRead` call)
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs` (`SinkApiToString` — add two new cases)

- [ ] **Step 4.1: Add `MatchHttpRead` to `SinkShapes.cs`**

Open `tools/TaintAnalyzer/SinkShapes.cs`. Append before the final closing `}` of the `SinkShapes` class:

```csharp
    // Milestone-H: unconditional sink for unbounded HTTP response reads.
    // Fires on any call to the listed methods regardless of receiver taint — the call itself
    // is the dangerous operation. Noise is controlled by source-entry selection in rules.yaml.
    public static SinkMatch? MatchHttpRead(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt)) return null;
        var mr = (MethodReference)instruction.Operand;
        var typeName = mr.DeclaringType.Name;
        var methodName = mr.Name;

        SinkApi? api = (typeName, methodName) switch
        {
            ("HttpContent", "ReadAsStringAsync" or "ReadAsByteArrayAsync" or "ReadAsStreamAsync")
                => SinkApi.HttpContentRead,
            ("HttpClient", "GetStringAsync" or "GetByteArrayAsync" or "GetStreamAsync")
                => SinkApi.HttpClientRead,
            _ => null,
        };
        if (api is null) return null;

        // Retrieve receiver for provenance: receiver is paramCount slots from top.
        int paramCount = mr.Parameters.Count;
        if (stack.Depth < paramCount + 1) return null;
        var receiver = stack.Peek(paramCount);
        var provenance = receiver.Tainted ? receiver.Provenance : mr.DeclaringType.Name;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = api.Value,
            SizeProvenance = provenance,
        };
    }
```

- [ ] **Step 4.2: Register `MatchHttpRead` in `HandleSinkMatch`**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack);
```

Replace with:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack)
            ?? SinkShapes.MatchHttpRead(ins, state.Stack);
```

- [ ] **Step 4.3: Add `SinkApiToString` cases in `TraceEmitter.cs`**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Find:

```csharp
    private static string? SinkApiToString(SinkApi? a) => a switch
    {
        SinkApi.NewArray => "new_array",
        SinkApi.ArrayPoolRent => "array_pool_rent",
        SinkApi.SpanSlice => "span_slice",
        SinkApi.SpanIndex => "span_index",
        SinkApi.Stackalloc => "stackalloc",
```

Replace with:

```csharp
    private static string? SinkApiToString(SinkApi? a) => a switch
    {
        SinkApi.NewArray => "new_array",
        SinkApi.ArrayPoolRent => "array_pool_rent",
        SinkApi.SpanSlice => "span_slice",
        SinkApi.SpanIndex => "span_index",
        SinkApi.Stackalloc => "stackalloc",
        SinkApi.HttpContentRead => "http_content_read",
        SinkApi.HttpClientRead => "http_client_read",
```

- [ ] **Step 4.4: Build and run the HTTP sink tests — expect both to pass**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_HttpClientGetStringAsync"
```

Expected: 2 passing.

- [ ] **Step 4.5: Run the full test suite — no regressions**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green (191 + 2 new = 193 tests passing).

---

## Task 5: Validator vocab + coupling update

**Files:**
- Modify: `tools/ValidateFixture/Vocabularies.cs` (`SinkApis` set)
- Modify: `tools/ValidateFixture/FixtureValidator.cs` (FX024 coupling rule)
- Modify: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` (new validator tests)

- [ ] **Step 5.1: Add new values to `SinkApis` vocab**

Open `tools/ValidateFixture/Vocabularies.cs`. Find:

```csharp
    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
    }.ToFrozenSet(StringComparer.Ordinal);
```

Replace with:

```csharp
    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
        "http_content_read", "http_client_read",
    }.ToFrozenSet(StringComparer.Ordinal);
```

- [ ] **Step 5.2: Update FX024 coupling rule for `allocation` kind**

Open `tools/ValidateFixture/FixtureValidator.cs`. Find:

```csharp
                    if (api is not ("new_array" or "array_pool_rent" or "alloc_hglobal" or "memory_pool_rent" or "stackalloc"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'allocation' is not compatible with sink.api '{api}' (expected one of new_array, array_pool_rent, alloc_hglobal, memory_pool_rent, stackalloc)"));
                    }
```

Replace with:

```csharp
                    if (api is not ("new_array" or "array_pool_rent" or "alloc_hglobal" or "memory_pool_rent" or "stackalloc" or "http_content_read" or "http_client_read"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'allocation' is not compatible with sink.api '{api}' (expected one of new_array, array_pool_rent, alloc_hglobal, memory_pool_rent, stackalloc, http_content_read, http_client_read)"));
                    }
```

- [ ] **Step 5.3: Add validator tests for the new api values**

Open `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`. Find an existing FX015 or FX024 test to understand the test pattern, then append new tests before the final closing `}` of the test class:

```csharp
    [Fact]
    public void Validate_HttpContentReadApi_PassesFX015AndFX024()
    {
        // http_content_read is a valid api under allocation kind — must not emit FX015 or FX024.
        var doc = MinimalDocWithSink("allocation", "http_content_read", sizeExpression: "response");
        var diags = new FixtureValidator(new RulesDocument { VulnId = "test", SourceMethods = new() { "T::M()" } })
            .Validate(doc);
        diags.ShouldNotContain(d => d.Code == "FX015");
        diags.ShouldNotContain(d => d.Code == "FX024");
    }

    [Fact]
    public void Validate_HttpClientReadApi_PassesFX015AndFX024()
    {
        // http_client_read is a valid api under allocation kind — must not emit FX015 or FX024.
        var doc = MinimalDocWithSink("allocation", "http_client_read", sizeExpression: "httpClient");
        var diags = new FixtureValidator(new RulesDocument { VulnId = "test", SourceMethods = new() { "T::M()" } })
            .Validate(doc);
        diags.ShouldNotContain(d => d.Code == "FX015");
        diags.ShouldNotContain(d => d.Code == "FX024");
    }
```

Note: `MinimalDocWithSink` is a helper you need to find or create in the test file. Check the existing test file for a helper that creates a minimal `FixtureDocument` with a given sink kind/api — use the same pattern. If no such helper exists, inline the fixture construction following the pattern of other FX024 tests in that file.

- [ ] **Step 5.4: Run the full solution test suite — all green**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
```

Expected: all tests green. New count: 193 (analyzer) + 61+ (validator) total.

---

## Task 6: Commit Components 1+2 + sanity check

- [ ] **Step 6.1: Verify all six existing fixtures still pass non-strict**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo -q

PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

for fix in imagesharp-3074-prefix imagesharp-3074-postfix imagesharp-3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        imagesharp-3074-prefix)  dll="$PRE3074" ;;
        imagesharp-3074-postfix) dll="$POST3074" ;;
        imagesharp-3079-prefix)  dll="$PRE3079" ;;
        *)                       dll="artifacts/$fix/Decoder.dll" ;;
    esac
    dotnet run --project tools/TaintAnalyzer --no-build -- "$dll" \
        --rules fixtures/$fix/rules.yaml --output /tmp/h-sanity-$fix.yaml 2>/dev/null
    out=$(dotnet run --project tools/ValidateFixture --no-build -- \
        --compare fixtures/$fix/trace.yaml /tmp/h-sanity-$fix.yaml 2>&1)
    echo "$fix exit=$? | $(echo "$out" | tail -1)"
done
```

Expected: all 6 exit=0.

If `MatchHttpRead` causes false-positive sinks in the imagesharp fixtures (HttpContent methods called during PNG/BMP decoding), the existing ground truths will fail. Investigate any failure by reading the new sink hop in the analyzer output and checking if it's a genuine BCL `HttpContent` call or a false match. Fix `MatchHttpRead` to be more precise if needed.

- [ ] **Step 6.2: Commit all Component 1+2 changes**

```bash
git add tools/TaintAnalyzer/RulesDocument.cs \
        tools/TaintAnalyzer/TaintWalker.cs \
        tools/TaintAnalyzer/Program.cs \
        tools/TaintAnalyzer/SinkShapes.cs \
        tools/TaintAnalyzer/TraceEmitter.cs \
        tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs \
        tools/TaintAnalyzer.Tests/TaintWalkerTests.cs \
        tools/ValidateFixture/Vocabularies.cs \
        tools/ValidateFixture/FixtureValidator.cs \
        tools/ValidateFixture.Tests/FixtureValidatorTests.cs

git commit -m "analyzer: milestone-H — taint_from_external_returns + MatchHttpRead sinks"
```

---

## Task 7: Build OneCollector DLLs

**Goal:** Produce two DLLs — pre-fix and post-fix — for `OpenTelemetry.Exporter.OneCollector`.

- [ ] **Step 7.1: Find the pre-fix commit SHA for OneCollector**

PR #4117 merged into `opentelemetry-dotnet-contrib`. Find its merge commit and parent:

```bash
gh api repos/open-telemetry/opentelemetry-dotnet-contrib/pulls/4117 \
    --jq '{merged_at: .merged_at, merge_commit_sha: .merge_commit_sha, base_sha: .base.sha}' 2>/dev/null
```

The `base.sha` is the commit just before the PR merged — this is the pre-fix state. Record it as `PRE_SHA_55M9`.

Also get the post-fix tag:

```bash
gh api repos/open-telemetry/opentelemetry-dotnet-contrib/git/refs/tags \
    --jq '.[] | select(.ref | contains("OneCollector-1.15.1")) | {ref: .ref, sha: .object.sha}' 2>/dev/null | head -5
```

Record the SHA of the `OneCollector-1.15.1` tag release as `POST_SHA_55M9`.

- [ ] **Step 7.2: Clone and build pre-fix OneCollector DLL**

```bash
PRE_SHA_55M9=<sha-from-step-7.1>  # fill in from above

mkdir -p /tmp/otel-55m9-pre
git clone --depth=1 --branch main \
    https://github.com/open-telemetry/opentelemetry-dotnet-contrib.git \
    /tmp/otel-contrib-repo 2>/dev/null \
    || (cd /tmp/otel-contrib-repo && git fetch)

cd /tmp/otel-contrib-repo
git checkout $PRE_SHA_55M9

# Build only the OneCollector project (isolated, no need for full repo build)
dotnet build src/OpenTelemetry.Exporter.OneCollector/OpenTelemetry.Exporter.OneCollector.csproj \
    --nologo \
    -p:DebugType=portable \
    -p:DebugSymbols=true \
    -p:Optimize=false \
    -c Debug \
    -o /tmp/otel-55m9-pre-out/
```

If the build fails due to missing dependencies, try:
```bash
dotnet restore src/OpenTelemetry.Exporter.OneCollector/OpenTelemetry.Exporter.OneCollector.csproj
dotnet build src/OpenTelemetry.Exporter.OneCollector/OpenTelemetry.Exporter.OneCollector.csproj \
    --nologo -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false -c Debug \
    -o /tmp/otel-55m9-pre-out/
```

Copy the DLL and PDB to the artifacts directory:

```bash
mkdir -p /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-pre
cp /tmp/otel-55m9-pre-out/OpenTelemetry.Exporter.OneCollector.dll \
   /tmp/otel-55m9-pre-out/OpenTelemetry.Exporter.OneCollector.pdb \
   /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-pre/

cat > /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-pre/README.md << EOF
Pre-fix build of OpenTelemetry.Exporter.OneCollector (GHSA-55m9-299j-53c7).
Source: open-telemetry/opentelemetry-dotnet-contrib @ $PRE_SHA_55M9
Vulnerable: HttpJsonPostTransport reads response body without size limit.
Built: Debug, portable PDB, Optimize=false.
EOF
```

- [ ] **Step 7.3: Build post-fix OneCollector DLL**

```bash
POST_SHA_55M9=<sha-from-step-7.1>

cd /tmp/otel-contrib-repo
git checkout $POST_SHA_55M9

dotnet restore src/OpenTelemetry.Exporter.OneCollector/OpenTelemetry.Exporter.OneCollector.csproj
dotnet build src/OpenTelemetry.Exporter.OneCollector/OpenTelemetry.Exporter.OneCollector.csproj \
    --nologo -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false -c Debug \
    -o /tmp/otel-55m9-post-out/

mkdir -p /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-post
cp /tmp/otel-55m9-post-out/OpenTelemetry.Exporter.OneCollector.dll \
   /tmp/otel-55m9-post-out/OpenTelemetry.Exporter.OneCollector.pdb \
   /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-post/

cat > /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-55m9-post/README.md << EOF
Post-fix build of OpenTelemetry.Exporter.OneCollector 1.15.1 (GHSA-55m9-299j-53c7).
Source: open-telemetry/opentelemetry-dotnet-contrib @ $POST_SHA_55M9
Fixed: PR #4117 — HttpClientHelpers enforces 4 MiB limit on response body.
Built: Debug, portable PDB, Optimize=false.
EOF
```

- [ ] **Step 7.4: Verify DLLs contain expected types**

```bash
# Check that the vulnerable class exists in the pre-fix DLL
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll \
    --rules /dev/null 2>&1 | head -5

# Find the exact Cecil signature for the vulnerable method
# (will be used in rules.yaml in Task 8)
grep -i "HttpJsonPostTransport\|SendExportRequest\|Send" \
    /tmp/otel-55m9-pre-out/*.dll 2>/dev/null || true

# Better: use a one-liner to list methods on HttpJsonPostTransport
dotnet script - << 'CSHARP' 2>/dev/null || true
using Mono.Cecil;
var a = AssemblyDefinition.ReadAssembly("artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll");
foreach (var t in a.MainModule.Types)
    if (t.Name.Contains("Transport"))
        foreach (var m in t.Methods)
            Console.WriteLine($"{t.FullName}::{m.Name}({string.Join(",", m.Parameters.Select(p => p.ParameterType.FullName))})");
CSHARP
```

If the dotnet-script approach doesn't work, use `monodis` or simply inspect the DLL with ildasm. The key is to find the exact Cecil signature of the method that calls `ReadAsStringAsync()`. The signature format for rules.yaml is `Namespace.ClassName::MethodName(ParamType1,ParamType2)`.

---

## Task 8: OneCollector fixture pair

**Files:**
- Create: `fixtures/otelcontrib-55m9-prefix/rules.yaml`
- Create: `fixtures/otelcontrib-55m9-prefix/trace.yaml`
- Create: `fixtures/otelcontrib-55m9-postfix/rules.yaml`
- Create: `fixtures/otelcontrib-55m9-postfix/trace.yaml`

- [ ] **Step 8.1: Identify the exact source method signature**

The vulnerable code in pre-fix `HttpJsonPostTransport.cs` calls `response.Content.ReadAsStringAsync()`. The entry-point method is the one that performs the HTTP send and reads the response. From the PR diff investigation, this is likely named `SendExportRequest` or similar. Determine the exact Cecil-style signature by running:

```bash
# Run analyzer against pre-fix DLL with a dummy rules.yaml to trigger the "source not found" error
# which lists available candidates
cat > /tmp/dummy-rules.yaml << 'EOF'
vuln_id: probe
source_methods:
  - OpenTelemetry.Exporter.OneCollector.Internal.Transports.HttpJsonPostTransport::SendExportRequest()
EOF

dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll \
    --rules /tmp/dummy-rules.yaml 2>&1 | head -10
```

The error output includes the exact signature suggestion. Adjust the signature in the rules.yaml accordingly.

- [ ] **Step 8.2: Write `fixtures/otelcontrib-55m9-prefix/rules.yaml`**

```bash
mkdir -p fixtures/otelcontrib-55m9-prefix
```

Write `fixtures/otelcontrib-55m9-prefix/rules.yaml` with the exact signature found in Step 8.1:

```yaml
vuln_id: otelcontrib-55m9-prefix
source_methods:
  - signature: <exact-Cecil-signature-from-step-8.1>
    taint_from_external_returns:
      - HttpClient::Send
      - HttpClient::SendAsync
```

- [ ] **Step 8.3: Run analyzer on pre-fix DLL and capture output**

```bash
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll \
    --rules fixtures/otelcontrib-55m9-prefix/rules.yaml \
    --output /tmp/otel-55m9-pre-trace.yaml

echo "exit=$?"
echo "docs=$(grep -c '^vuln_id:' /tmp/otel-55m9-pre-trace.yaml)"
grep -E "^  method:|^  api:|^  kind:" /tmp/otel-55m9-pre-trace.yaml | head -10
```

Expected: exit=0, at least 1 document, sink contains `api: http_content_read`.

If exit≠0 or no `http_content_read` sink: the source method signature may be wrong (adjust rules.yaml) or the taint chain isn't reaching `ReadAsStringAsync` (check whether `HttpClient::Send` is the right method to seed — may need `HttpClient::SendAsync` or both).

- [ ] **Step 8.4: Write `fixtures/otelcontrib-55m9-prefix/trace.yaml`**

Use the analyzer output as verbatim ground truth, prepending the metadata header:

```bash
cat > /tmp/55m9-header.yaml << 'EOF'
vuln_id: otelcontrib-55m9-prefix
fix_commit: <merge-commit-sha-of-PR-4117>
fix_pr: "https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4117"
description: >
  Pre-fix OpenTelemetry.Exporter.OneCollector: HttpJsonPostTransport reads
  the error response body via ReadAsStringAsync() without a size limit
  (GHSA-55m9-299j-53c7, CVE-2026-41484). An attacker controlling the
  backend endpoint can cause memory exhaustion via oversized error responses.

EOF
sed -n '/^source:/,$p' /tmp/otel-55m9-pre-trace.yaml >> /tmp/55m9-header.yaml
cp /tmp/55m9-header.yaml fixtures/otelcontrib-55m9-prefix/trace.yaml
```

- [ ] **Step 8.5: Verify pre-fix fixture passes `--compare` non-strict**

```bash
dotnet run --project tools/ValidateFixture --no-build -- \
    --compare fixtures/otelcontrib-55m9-prefix/trace.yaml \
    /tmp/otel-55m9-pre-trace.yaml
echo "exit=$?"
```

Expected: exit=0.

- [ ] **Step 8.6: Write post-fix `rules.yaml` (same source, same taint annotation)**

```bash
mkdir -p fixtures/otelcontrib-55m9-postfix
cp fixtures/otelcontrib-55m9-prefix/rules.yaml fixtures/otelcontrib-55m9-postfix/rules.yaml
sed -i 's/otelcontrib-55m9-prefix/otelcontrib-55m9-postfix/' fixtures/otelcontrib-55m9-postfix/rules.yaml
```

- [ ] **Step 8.7: Run analyzer on post-fix DLL and capture output**

```bash
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-55m9-post/OpenTelemetry.Exporter.OneCollector.dll \
    --rules fixtures/otelcontrib-55m9-postfix/rules.yaml \
    --output /tmp/otel-55m9-post-trace.yaml

echo "exit=$?"
echo "docs=$(grep -c '^vuln_id:' /tmp/otel-55m9-post-trace.yaml)"
grep -E "^  method:|^  api:|^  kind:|^  role:" /tmp/otel-55m9-post-trace.yaml | head -15
```

Per the spec: `http_content_read` sink NO LONGER fires (the `ReadAsStringAsync` call is replaced by `GetResponseBodyAsString`). The post-fix trace may show a `new_array` sink inside `HttpClientHelpers` with `sanitizer_absence` (the 4 MiB loop-guard is not recognized as a sanitizer — known limitation). If no sink is found at all, the output is empty — that's also acceptable (means post-fix is clean from the analyzer's perspective).

- [ ] **Step 8.8: Write `fixtures/otelcontrib-55m9-postfix/trace.yaml`**

```bash
cat > /tmp/55m9-post-header.yaml << 'EOF'
vuln_id: otelcontrib-55m9-postfix
fix_commit: <merge-commit-sha-of-PR-4117>
fix_pr: "https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4117"
description: >
  Post-fix OpenTelemetry.Exporter.OneCollector 1.15.1: response body reading
  delegated to HttpClientHelpers.TryGetResponseBodyAsString() with a 4 MiB
  ceiling. The direct ReadAsStringAsync() sink is gone. Remaining sink (if any)
  is new byte[totalRead] inside HttpClientHelpers, bounded by loop guard
  (loop-guard sanitizer shape not yet modelled — known limitation).

EOF
if [ -s /tmp/otel-55m9-post-trace.yaml ]; then
    sed -n '/^source:/,$p' /tmp/otel-55m9-post-trace.yaml >> /tmp/55m9-post-header.yaml
fi
cp /tmp/55m9-post-header.yaml fixtures/otelcontrib-55m9-postfix/trace.yaml
```

- [ ] **Step 8.9: Verify post-fix fixture passes `--compare` non-strict**

```bash
dotnet run --project tools/ValidateFixture --no-build -- \
    --compare fixtures/otelcontrib-55m9-postfix/trace.yaml \
    /tmp/otel-55m9-post-trace.yaml
echo "exit=$?"
```

Expected: exit=0.

- [ ] **Step 8.10: Commit the OneCollector fixture pair**

```bash
git add artifacts/otelcontrib-55m9-pre/ \
        artifacts/otelcontrib-55m9-post/ \
        fixtures/otelcontrib-55m9-prefix/ \
        fixtures/otelcontrib-55m9-postfix/
git commit -m "fixture: otelcontrib-55m9 pre/post-fix pair (GHSA-55m9-299j-53c7)"
```

---

## Task 9: Build Azure Resources DLLs

**Files:** `artifacts/otelcontrib-vc24-pre/`, `artifacts/otelcontrib-vc24-post/`

- [ ] **Step 9.1: Find pre-fix and post-fix SHAs for Azure Resources**

```bash
gh api repos/open-telemetry/opentelemetry-dotnet-contrib/pulls/4121 \
    --jq '{merge_commit_sha: .merge_commit_sha, base_sha: .base.sha}' 2>/dev/null

gh api repos/open-telemetry/opentelemetry-dotnet-contrib/git/refs/tags \
    --jq '.[] | select(.ref | contains("Azure") and contains("1.15.1")) | {ref: .ref, sha: .object.sha}' \
    2>/dev/null | head -5
```

Record `PRE_SHA_VC24` (base.sha of PR #4121) and `POST_SHA_VC24`.

- [ ] **Step 9.2: Build pre-fix Azure Resources DLL**

```bash
PRE_SHA_VC24=<sha-from-step-9.1>

cd /tmp/otel-contrib-repo
git checkout $PRE_SHA_VC24

dotnet restore src/OpenTelemetry.Resources.Azure/OpenTelemetry.Resources.Azure.csproj
dotnet build src/OpenTelemetry.Resources.Azure/OpenTelemetry.Resources.Azure.csproj \
    --nologo -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false -c Debug \
    -o /tmp/otel-vc24-pre-out/

mkdir -p /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-pre
cp /tmp/otel-vc24-pre-out/OpenTelemetry.Resources.Azure.dll \
   /tmp/otel-vc24-pre-out/OpenTelemetry.Resources.Azure.pdb \
   /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-pre/

cat > /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-pre/README.md << EOF
Pre-fix build of OpenTelemetry.Resources.Azure (GHSA-vc24-j8c5-2vw4).
Source: open-telemetry/opentelemetry-dotnet-contrib @ $PRE_SHA_VC24
Vulnerable: AzureVmMetaDataRequestor calls GetStringAsync without size limit.
Built: Debug, portable PDB, Optimize=false.
EOF
```

- [ ] **Step 9.3: Build post-fix Azure Resources DLL**

```bash
POST_SHA_VC24=<sha-from-step-9.1>

cd /tmp/otel-contrib-repo
git checkout $POST_SHA_VC24

dotnet restore src/OpenTelemetry.Resources.Azure/OpenTelemetry.Resources.Azure.csproj
dotnet build src/OpenTelemetry.Resources.Azure/OpenTelemetry.Resources.Azure.csproj \
    --nologo -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false -c Debug \
    -o /tmp/otel-vc24-post-out/

mkdir -p /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-post
cp /tmp/otel-vc24-post-out/OpenTelemetry.Resources.Azure.dll \
   /tmp/otel-vc24-post-out/OpenTelemetry.Resources.Azure.pdb \
   /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-post/

cat > /mnt/c/work/dotnet-taint-analyzer/artifacts/otelcontrib-vc24-post/README.md << EOF
Post-fix build of OpenTelemetry.Resources.Azure 1.15.1-beta.1 (GHSA-vc24-j8c5-2vw4).
Source: open-telemetry/opentelemetry-dotnet-contrib @ $POST_SHA_VC24
Fixed: PR #4121 — streaming with 4 MiB limit via HttpClientHelpers.
Built: Debug, portable PDB, Optimize=false.
EOF
```

---

## Task 10: Azure Resources fixture pair

**Files:** `fixtures/otelcontrib-vc24-prefix/`, `fixtures/otelcontrib-vc24-postfix/`

- [ ] **Step 10.1: Identify the source method signature for Azure**

The vulnerable method is `AzureVmMetaDataRequestor.GetAzureVmMetaDataResponseDefault()` (or similar). It calls `httpClient.GetStringAsync(url)` with an untainted local `httpClient`. Since `MatchHttpRead` fires unconditionally, we do NOT need `taint_from_external_returns` for the sink to fire. However, to propagate taint to any downstream allocation, add it anyway:

```bash
cat > /tmp/dummy-vc24.yaml << 'EOF'
vuln_id: probe
source_methods:
  - OpenTelemetry.ResourceDetectors.Azure.AzureVmMetaDataRequestor::GetAzureVmMetaDataResponseDefault()
EOF

dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-vc24-pre/OpenTelemetry.Resources.Azure.dll \
    --rules /tmp/dummy-vc24.yaml 2>&1 | head -10
```

Adjust the namespace/class from the suggestion in the error output.

- [ ] **Step 10.2: Write `fixtures/otelcontrib-vc24-prefix/rules.yaml`**

```bash
mkdir -p fixtures/otelcontrib-vc24-prefix
```

```yaml
vuln_id: otelcontrib-vc24-prefix
source_methods:
  - signature: <exact-Cecil-signature-from-step-10.1>
    taint_from_external_returns:
      - HttpClient::GetStringAsync
      - HttpClient::GetByteArrayAsync
```

- [ ] **Step 10.3: Run analyzer on pre-fix DLL and write trace.yaml**

```bash
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-vc24-pre/OpenTelemetry.Resources.Azure.dll \
    --rules fixtures/otelcontrib-vc24-prefix/rules.yaml \
    --output /tmp/otel-vc24-pre-trace.yaml

echo "exit=$? | docs=$(grep -c '^vuln_id:' /tmp/otel-vc24-pre-trace.yaml)"
grep -E "^  method:|^  api:|^  kind:" /tmp/otel-vc24-pre-trace.yaml | head -10
```

Expected: at least one document containing `api: http_client_read` sink.

```bash
cat > /tmp/vc24-header.yaml << 'EOF'
vuln_id: otelcontrib-vc24-prefix
fix_commit: <merge-commit-sha-of-PR-4121>
fix_pr: "https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4121"
description: >
  Pre-fix OpenTelemetry.Resources.Azure: AzureVmMetaDataRequestor calls
  GetStringAsync() on the Azure VM metadata endpoint without a size limit
  (GHSA-vc24-j8c5-2vw4, CVE-2026-41483). A MITM or spoofed endpoint can
  return an arbitrarily large response causing OOM.

EOF
sed -n '/^source:/,$p' /tmp/otel-vc24-pre-trace.yaml >> /tmp/vc24-header.yaml
cp /tmp/vc24-header.yaml fixtures/otelcontrib-vc24-prefix/trace.yaml

dotnet run --project tools/ValidateFixture --no-build -- \
    --compare fixtures/otelcontrib-vc24-prefix/trace.yaml /tmp/otel-vc24-pre-trace.yaml
echo "exit=$?"
```

- [ ] **Step 10.4: Write post-fix rules.yaml + trace.yaml**

```bash
mkdir -p fixtures/otelcontrib-vc24-postfix
cp fixtures/otelcontrib-vc24-prefix/rules.yaml fixtures/otelcontrib-vc24-postfix/rules.yaml
sed -i 's/otelcontrib-vc24-prefix/otelcontrib-vc24-postfix/' fixtures/otelcontrib-vc24-postfix/rules.yaml

dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/otelcontrib-vc24-post/OpenTelemetry.Resources.Azure.dll \
    --rules fixtures/otelcontrib-vc24-postfix/rules.yaml \
    --output /tmp/otel-vc24-post-trace.yaml

echo "exit=$? | docs=$(grep -c '^vuln_id:' /tmp/otel-vc24-post-trace.yaml 2>/dev/null)"

cat > /tmp/vc24-post-header.yaml << 'EOF'
vuln_id: otelcontrib-vc24-postfix
fix_commit: <merge-commit-sha-of-PR-4121>
fix_pr: "https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4121"
description: >
  Post-fix OpenTelemetry.Resources.Azure 1.15.1-beta.1: GetStringAsync replaced
  by HttpClientHelpers.GetResponseBodyAsString() with a 4 MiB ceiling.
  The direct HttpClientRead sink is gone. Remaining sink (if any) is new
  byte[totalRead] inside HttpClientHelpers, bounded by loop guard (known limitation).

EOF
if [ -s /tmp/otel-vc24-post-trace.yaml ]; then
    sed -n '/^source:/,$p' /tmp/otel-vc24-post-trace.yaml >> /tmp/vc24-post-header.yaml
fi
cp /tmp/vc24-post-header.yaml fixtures/otelcontrib-vc24-postfix/trace.yaml

dotnet run --project tools/ValidateFixture --no-build -- \
    --compare fixtures/otelcontrib-vc24-postfix/trace.yaml /tmp/otel-vc24-post-trace.yaml
echo "exit=$?"
```

- [ ] **Step 10.5: Run full solution tests — all still green**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
```

- [ ] **Step 10.6: Commit Azure fixture pair**

```bash
git add artifacts/otelcontrib-vc24-pre/ \
        artifacts/otelcontrib-vc24-post/ \
        fixtures/otelcontrib-vc24-prefix/ \
        fixtures/otelcontrib-vc24-postfix/
git commit -m "fixture: otelcontrib-vc24 pre/post-fix pair (GHSA-vc24-j8c5-2vw4)"
```

---

## Task 11: Phase 2 — broad scan triage report

**No code changes.** Build and scan 7 HTTP-adjacent OpenTelemetry packages at `main`, produce a triage report.

- [ ] **Step 11.1: Build each target package at main**

For each package, build at the current `main` of opentelemetry-dotnet-contrib:

```bash
cd /tmp/otel-contrib-repo && git checkout main && git pull

PKGS=(
    "src/OpenTelemetry.Exporter.Zipkin/OpenTelemetry.Exporter.Zipkin.csproj"
    "src/OpenTelemetry.Exporter.Jaeger/OpenTelemetry.Exporter.Jaeger.csproj"
    "src/OpenTelemetry.Exporter.OpenTelemetryProtocol/OpenTelemetry.Exporter.OpenTelemetryProtocol.csproj"
    "src/OpenTelemetry.Resources.AWS/OpenTelemetry.Resources.AWS.csproj"
    "src/OpenTelemetry.Resources.GCP/OpenTelemetry.Resources.GCP.csproj"
    "src/OpenTelemetry.Resources.Container/OpenTelemetry.Resources.Container.csproj"
    "src/OpenTelemetry.Instrumentation.Http/OpenTelemetry.Instrumentation.Http.csproj"
)

for pkg in "${PKGS[@]}"; do
    name=$(basename $(dirname $pkg))
    mkdir -p /tmp/otel-scan/$name
    dotnet restore $pkg 2>/dev/null
    dotnet build $pkg --nologo -p:DebugType=portable -p:DebugSymbols=true \
        -p:Optimize=false -c Debug -o /tmp/otel-scan/$name/ 2>/dev/null \
        && echo "$name: OK" || echo "$name: FAILED"
done
```

Skip any that fail to build (dependency issues, target framework mismatch, etc.) — note them in the report.

- [ ] **Step 11.2: For each built package, write a rules.yaml and run the analyzer**

For each package, identify the primary HTTP-entry-point class (the one that makes outbound HTTP calls). This requires brief source inspection:

```bash
# Find classes with HttpClient usage in each package
for name in Zipkin Jaeger OpenTelemetryProtocol AWS GCP Container Http; do
    grep -r "HttpClient\|GetStringAsync\|ReadAsStringAsync" \
        /tmp/otel-contrib-repo/src/OpenTelemetry.*$name*/ \
        --include="*.cs" -l 2>/dev/null | head -3
done
```

For each package with results, write a `rules.yaml`:

```yaml
vuln_id: <package-name>-scan
source_methods:
  - signature: <found-entry-method-Cecil-signature>
    taint_from_external_returns:
      - HttpClient::Send
      - HttpClient::SendAsync
      - HttpClient::GetStringAsync
      - HttpClient::GetByteArrayAsync
```

Run the analyzer:

```bash
dotnet run --project tools/TaintAnalyzer --no-build -- \
    /tmp/otel-scan/<package-name>/<Package>.dll \
    --rules /tmp/<package-name>-rules.yaml \
    --output /tmp/otel-scan/<package-name>-trace.yaml 2>/dev/null
echo "$name: docs=$(grep -c '^vuln_id:' /tmp/otel-scan/<package-name>-trace.yaml 2>/dev/null)"
```

- [ ] **Step 11.3: Triage each finding and write the report**

For each document with an `http_content_read` or `http_client_read` sink, determine:
- **Confirmed** — a direct unbounded read with no visible size cap in the call chain
- **False-positive** — the analyzer fires but inspection shows the read is bounded (e.g., a fixed-size constant is used)
- **Needs-investigation** — uncertain without deeper code reading

Write the report to `docs/otelcontrib-phase2-scan-2026-04-29.md`:

```markdown
# OpenTelemetry Contrib HTTP DoS Broad Scan — 2026-04-29

## Methodology
Analyzer: dotnet-taint-analyzer milestone-H, branch main.
Source: opentelemetry-dotnet-contrib @ main (<sha>).
Sink: http_content_read / http_client_read (MatchHttpRead, unconditional).

## Results

| Package | Entry method | Finding | Classification | Notes |
|---------|-------------|---------|----------------|-------|
| Zipkin | ... | ... | confirmed / false-positive / needs-investigation | ... |
| ... | | | | |

## Responsible Disclosure
Packages with confirmed new findings not covered by existing CVEs:
- <list or "none found">
```

- [ ] **Step 11.4: Commit the triage report**

```bash
git add docs/otelcontrib-phase2-scan-2026-04-29.md
git commit -m "docs: Phase 2 OTel HTTP DoS broad scan triage report"
```

---

## Task 12: Spec status update + land on main

**Files:** `docs/superpowers/specs/2026-04-29-otelcontrib-http-dos-design.md`

- [ ] **Step 12.1: Capture final numbers**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"

# Non-strict on all new fixtures
for fix in otelcontrib-55m9-prefix otelcontrib-55m9-postfix otelcontrib-vc24-prefix otelcontrib-vc24-postfix; do
    out=$(dotnet run --project tools/ValidateFixture --no-build -- \
        --compare "fixtures/$fix/trace.yaml" /tmp/otel-*${fix#otelcontrib-}*.yaml 2>&1 | tail -1)
    echo "$fix: $out"
done
```

- [ ] **Step 12.2: Update spec Status line**

Open `docs/superpowers/specs/2026-04-29-otelcontrib-http-dos-design.md`. Find:

```
**Status:** Approved 2026-04-29.
```

Replace with (fill actual numbers):

```
**Status:** Implementation complete 2026-04-29. taint_from_external_returns + MatchHttpRead landed. Four fixture pairs (otelcontrib-55m9 + otelcontrib-vc24) pass --compare non-strict. Phase 2 triage report in docs/. <N> tests green.
```

- [ ] **Step 12.3: Append revision-history entry**

Append to the end of the spec:

```markdown
- **2026-04-29 (implementation complete).** Components 1+2 landed; four fixture pairs authored; Phase 2 scan complete.
  - **Build/tests:** Clean build 0/0. <N> tests passing.
  - **Fixtures:** otelcontrib-55m9-prefix/postfix and otelcontrib-vc24-prefix/postfix all pass --compare non-strict.
  - **Pre-fix detection:** http_content_read sink fires in OneCollector pre-fix; http_client_read sink fires in Azure pre-fix.
  - **Post-fix:** ReadAsStringAsync/GetStringAsync calls gone; MatchHttpRead no longer fires. Remaining NewArray in HttpClientHelpers (loop-guard not modelled — deferred).
  - **Phase 2:** <summary of findings — confirmed/false-positive/needs-investigation counts>.
```

- [ ] **Step 12.4: Commit spec update**

```bash
git add docs/superpowers/specs/2026-04-29-otelcontrib-http-dos-design.md
git commit -m "docs: spec — milestone-H implementation complete"
```

- [ ] **Step 12.5: Land on main**

```bash
git checkout main
git merge --ff-only milestone-h
git branch -d milestone-h
```

---

## Self-Review

**Spec coverage:**
- *`taint_from_external_returns` YAML schema:* Task 1 Steps 1.1–1.2. ✓
- *`TaintWalker.TaintFromExternalReturns` property + `MatchesTaintFromExternalReturn`:* Task 2 Steps 2.1–2.2. ✓
- *External branch modification:* Task 2 Step 2.3. ✓
- *`Program.cs` sets property before walk:* Task 2 Step 2.4. ✓
- *`SinkApi.HttpContentRead`, `SinkApi.HttpClientRead`:* Task 3 Step 3.1. ✓
- *`SinkShapes.MatchHttpRead` (unconditional):* Task 4 Step 4.1. ✓
- *`HandleSinkMatch` registration:* Task 4 Step 4.2. ✓
- *`SinkApiToString` cases:* Task 4 Step 4.3. ✓
- *Vocab + FX024 coupling:* Task 5 Steps 5.1–5.2. ✓
- *Validator tests:* Task 5 Step 5.3. ✓
- *DoD-1 (taint_from_external_returns unit test):* Tasks 1+2. ✓
- *DoD-2 (MatchHttpRead unit tests):* Tasks 3+4. ✓
- *DoD-3 (prefix fixtures non-strict):* Tasks 8+10. ✓
- *DoD-4 (postfix fixtures non-strict):* Tasks 8+10. ✓
- *DoD-5 (existing fixtures no regression):* Task 6 Step 6.1. ✓
- *DoD-6 (build clean, tests green):* Tasks 6, 10. ✓
- *DoD-7 (Phase 2 triage report):* Task 11. ✓

**Placeholder scan:**
- Step 7.1, 9.1 require running `gh` commands to discover SHAs — intentional research steps, not placeholders.
- Step 8.1, 10.1 require discovering exact Cecil method signatures from error output — intentional, not guessable in advance.
- `<sha-from-step-X>` markers in build steps — fill in from the preceding discovery step, not TBD.
- `<exact-Cecil-signature>` in rules.yaml steps — fill in from Step 8.1/10.1 output.
- Step 5.3 mentions "find or create `MinimalDocWithSink` helper" — engineer inspects test file and follows the existing pattern; concrete enough.

**Type consistency:**
- `TaintFromExternalReturns: IReadOnlyList<string>` — declared in Step 2.1, set in Step 2.4, used in `MatchesTaintFromExternalReturn` (Step 2.2). ✓
- `SinkApi.HttpContentRead` / `SinkApi.HttpClientRead` — added Step 3.1, used in `MatchHttpRead` Step 4.1, serialized Step 4.3, validated Step 5.2. ✓
- `SinkMatch.SizeProvenance` — existing field, used in `MatchHttpRead` Step 4.1 (matches existing pattern in `MatchNewArr`). ✓
- `MatchesTaintFromExternalReturn(MethodReference)` — defined Step 2.2, called Step 2.3. ✓
