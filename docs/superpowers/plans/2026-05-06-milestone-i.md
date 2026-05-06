# Milestone-I Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two analyzer gaps that caused our 2026-04-29 OTel scans to miss CVE-2026-42348 and produce four `HttpClientHelpers` false-positives — (A) async source resolution and (B) loop-guard sanitizer — and lock the fix with a checked-in OpAmp prefix/postfix fixture pair.

**Architecture:** New `AsyncStateMachineResolver` static helper in the analyzer library detects `[AsyncStateMachine]` on source methods and redirects walking to the compiler-generated `<Name>d__N::MoveNext`. New `MatchValueClamp` matcher in `SanitizerShapes` recognises the `tainted < bounded ? tainted : bounded` IL diamond in both orientations and untaints the join slot; `TaintWalker.HandleCall` recognises `Math.Min`/`Math.Max`/`Math.Clamp` calls. Fixture pair built from real OpAmp pre-fix (`d6e87d8a`) and post-fix (`bf1fad4`) commits using a materialize script (no DLL/PDB checked in — matches existing `otelcontrib-{55m9,vc24}` pattern).

**Tech Stack:** .NET 10, C#, Mono.Cecil, xUnit, Shouldly, YamlDotNet.

**Spec:** `docs/superpowers/specs/2026-05-06-milestone-i-design.md`

---

## File Structure

**Created:**
- `tools/TaintAnalyzer/AsyncStateMachineResolver.cs` — static helper; `Resolution` record + `Resolve(MethodDefinition)`.
- `tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs` — unit tests for the resolver.
- `tools/TaintAnalyzer.Tests/AsyncSourceWalkTests.cs` — end-to-end test that walking an async source method emits a sink hop and `resolved_via` marker.
- `tools/TaintAnalyzer.Tests/MathClampTests.cs` — `Math.Min/Max/Clamp` recognizer tests in `TaintWalker.HandleCall`.
- `fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml` — same source/sink rules as postfix.
- `fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml` — ground-truth (sink fires).
- `fixtures/otelcontrib-opamp-w2jh-prefix/README.md` — pre-fix SHA + advisory link + build command.
- `fixtures/otelcontrib-opamp-w2jh-postfix/rules.yaml` — identical to prefix.
- `fixtures/otelcontrib-opamp-w2jh-postfix/trace.yaml` — empty findings.
- `fixtures/otelcontrib-opamp-w2jh-postfix/README.md` — post-fix SHA + advisory link + build command.
- `scripts/materialize-otelcontrib-opamp.sh` — clones contrib repo, checks out both SHAs, builds OpAmp.Client into `artifacts/<sha>/`.
- `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md` — scan rerun result for contrib (4 FPs → 0).
- `docs/otelcore-scan-2026-04-29-addendum.md` — scan rerun result for core (2 FPs → 0).

**Modified:**
- `tools/TaintAnalyzer/Program.cs:91-126` — call `AsyncStateMachineResolver.Resolve` before `WalkWithSeed`; adjust bitmask + seedFields for async-redirected sources; emit `resolved_via` on the source hop.
- `tools/TaintAnalyzer/HopRecord.cs:33-66` — add optional `string? ResolvedVia { get; init; }` to `HopRecord`.
- `tools/TaintAnalyzer/TraceEmitter.cs:243-294` — propagate `ResolvedVia` through `PathNodeFromHop` (after a new field is added to `PathNode`).
- `tools/ValidateFixture/FixtureDocument.cs` — add optional `ResolvedVia` field on `PathNode` (round-trippable via YamlDotNet).
- `tools/TaintAnalyzer/SanitizerShapes.cs` — add `MatchValueClamp(Instruction, MethodDefinition)` static method that returns a clamp result for the join slot when matched.
- `tools/TaintAnalyzer/TaintWalker.cs:122` and around `:802` — invoke `MatchValueClamp` during the IL walk and untaint the join slot; recognise `Math.Min/Max/Clamp` in `HandleCall`.
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add `AsyncSourceFixtures`, `ClampFixtures` static classes.
- `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` — extend with `MatchValueClamp` tests.

**Untouched (verified untouched as part of the regression gate):**
- All fixtures under `fixtures/otelcontrib-{55m9,vc24}-*` and `fixtures/imagesharp-307{4,9}-*`.

---

## Session 1 — Async source resolution

### Task 1: AsyncSourceFixtures — fixture for resolver tests

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append a new static class).

- [ ] **Step 1: Add the fixture types**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (after the last existing class):

```csharp
// Fixtures for AsyncStateMachineResolver tests. Each method is intentionally minimal —
// the resolver only inspects custom attributes and the state-machine type structure.
public static class AsyncSourceFixtures
{
    // Sync method — no AsyncStateMachineAttribute. Resolver returns this method unchanged.
    public static int Sync(int x) => x + 1;

    // Plain async method. Compiler emits `[AsyncStateMachine(typeof(<AsyncSimple>d__N))]`
    // on the stub and lowers the body into the nested type's MoveNext.
    public static async System.Threading.Tasks.Task<int> AsyncSimple(int x)
    {
        await System.Threading.Tasks.Task.Yield();
        return x + 1;
    }

    // Generic async method — state machine type is generic (<AsyncGeneric>d__N`1).
    public static async System.Threading.Tasks.Task<T> AsyncGeneric<T>(T x)
    {
        await System.Threading.Tasks.Task.Yield();
        return x;
    }
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug`
Expected: build succeeds with 0 errors.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "$(cat <<'EOF'
test fixture: AsyncSourceFixtures for milestone-I resolver tests

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: AsyncStateMachineResolver — non-async pass-through

**Files:**
- Create: `tools/TaintAnalyzer/AsyncStateMachineResolver.cs`
- Create: `tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs`

- [ ] **Step 1: Write the failing test**

Create `tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;

namespace TaintAnalyzer.Tests;

public class AsyncStateMachineResolverTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition FindMethod(AssemblyContext ctx, string typeFullName, string name) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == typeFullName && m.Name == name);

    [Fact]
    public void Resolve_NonAsync_ReturnsSameMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var sync = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "Sync");

        var result = AsyncStateMachineResolver.Resolve(sync);

        result.Method.ShouldBeSameAs(sync);
        result.RedirectedFromAsync.ShouldBeFalse();
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~AsyncStateMachineResolverTests"`
Expected: FAIL — `AsyncStateMachineResolver` does not exist.

- [ ] **Step 3: Implement the minimal resolver (pass-through only)**

Create `tools/TaintAnalyzer/AsyncStateMachineResolver.cs`:

```csharp
using Mono.Cecil;

namespace TaintAnalyzer;

public static class AsyncStateMachineResolver
{
    private const string AttributeFullName =
        "System.Runtime.CompilerServices.AsyncStateMachineAttribute";

    public sealed record Resolution(MethodDefinition Method, bool RedirectedFromAsync);

    public static Resolution Resolve(MethodDefinition source)
    {
        foreach (var ca in source.CustomAttributes)
        {
            if (ca.AttributeType.FullName == AttributeFullName)
            {
                throw new NotImplementedException("async redirect — implemented in Task 3");
            }
        }
        return new Resolution(source, false);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~AsyncStateMachineResolverTests"`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/AsyncStateMachineResolver.cs tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs
git commit -m "$(cat <<'EOF'
analyzer: AsyncStateMachineResolver skeleton + non-async pass-through

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: AsyncStateMachineResolver — async redirect to MoveNext

**Files:**
- Modify: `tools/TaintAnalyzer/AsyncStateMachineResolver.cs`
- Modify: `tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs`

- [ ] **Step 1: Add the failing tests for async + generic redirect**

Append to `tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs` (inside the class):

```csharp
[Fact]
public void Resolve_AsyncMethod_RedirectsToMoveNext()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var asyncSimple = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "AsyncSimple");

    var result = AsyncStateMachineResolver.Resolve(asyncSimple);

    result.RedirectedFromAsync.ShouldBeTrue();
    result.Method.Name.ShouldBe("MoveNext");
    result.Method.DeclaringType.Name.ShouldStartWith("<AsyncSimple>d__");
}

[Fact]
public void Resolve_AsyncGenericMethod_RedirectsToMoveNextOnGenericInstance()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var asyncGeneric = FindMethod(ctx, "TaintAnalyzer.Tests.Fixtures.AsyncSourceFixtures", "AsyncGeneric");

    var result = AsyncStateMachineResolver.Resolve(asyncGeneric);

    result.RedirectedFromAsync.ShouldBeTrue();
    result.Method.Name.ShouldBe("MoveNext");
    // The Cecil type-reference resolves to the open-generic state machine.
    result.Method.DeclaringType.Name.ShouldStartWith("<AsyncGeneric>d__");
    result.Method.DeclaringType.HasGenericParameters.ShouldBeTrue();
}
```

- [ ] **Step 2: Run the tests to verify both fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~AsyncStateMachineResolverTests"`
Expected: 2 FAIL (NotImplementedException), 1 PASS (the pass-through from Task 2).

- [ ] **Step 3: Implement the async redirect**

Replace the body of `Resolve` in `tools/TaintAnalyzer/AsyncStateMachineResolver.cs`:

```csharp
public static Resolution Resolve(MethodDefinition source)
{
    foreach (var ca in source.CustomAttributes)
    {
        if (ca.AttributeType.FullName != AttributeFullName) continue;
        if (ca.ConstructorArguments.Count == 0) continue;

        var typeArg = ca.ConstructorArguments[0];
        if (typeArg.Value is not TypeReference smTypeRef) continue;

        var smType = smTypeRef.Resolve()
            ?? throw new InvalidOperationException(
                $"async state machine type unresolvable for {source.FullName}");

        var moveNext = smType.Methods.FirstOrDefault(m => m.Name == "MoveNext")
            ?? throw new InvalidOperationException(
                $"async state machine {smType.FullName} has no MoveNext");

        return new Resolution(moveNext, true);
    }
    return new Resolution(source, false);
}
```

- [ ] **Step 4: Run the tests to verify all three pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~AsyncStateMachineResolverTests"`
Expected: 3 PASS.

- [ ] **Step 5: Run the full test suite to verify no regression**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: all existing tests still pass; no analyzer behaviour change yet because nothing calls the resolver.

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/AsyncStateMachineResolver.cs tools/TaintAnalyzer.Tests/AsyncStateMachineResolverTests.cs
git commit -m "$(cat <<'EOF'
analyzer: AsyncStateMachineResolver redirects async sources to MoveNext

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: HopRecord.ResolvedVia + TraceEmitter wiring

**Files:**
- Modify: `tools/TaintAnalyzer/HopRecord.cs:33-66`
- Modify: `tools/ValidateFixture/FixtureDocument.cs`
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:243-294`

- [ ] **Step 1: Add ResolvedVia to HopRecord**

In `tools/TaintAnalyzer/HopRecord.cs`, add an optional field to `HopRecord` (after the `Note` field at line 44):

```csharp
public string? Note { get; init; }
public string? ResolvedVia { get; init; }
```

- [ ] **Step 2: Add ResolvedVia to PathNode (FixtureDocument)**

Read `tools/ValidateFixture/FixtureDocument.cs`. Locate the `PathNode` class (it's the YAML-serialisable record/class shared between emitter and validator). Add an optional field:

```csharp
[YamlMember(Alias = "resolved_via", DefaultValuesHandling = DefaultValuesHandling.OmitNull)]
public string? ResolvedVia { get; set; }
```

If the file uses `init`-only properties, mirror that style. The `OmitNull` handling is essential — every existing fixture trace must continue to round-trip identically.

- [ ] **Step 3: Wire ResolvedVia through PathNodeFromHop**

In `tools/TaintAnalyzer/TraceEmitter.cs:267-294`, inside `PathNodeFromHop`, add `ResolvedVia = h.ResolvedVia,` to the `PathNode` initializer (alongside `Note = h.Note,` etc.).

- [ ] **Step 4: Build + run all tests**

Run: `dotnet build TaintAnalyzer.sln -c Debug && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: build succeeds; all tests pass; existing fixtures unaffected because no hop sets `ResolvedVia` yet.

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/HopRecord.cs tools/ValidateFixture/FixtureDocument.cs tools/TaintAnalyzer/TraceEmitter.cs
git commit -m "$(cat <<'EOF'
analyzer: HopRecord.ResolvedVia + PathNode.resolved_via plumbing

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Wire AsyncStateMachineResolver into Program.cs

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs:91-126`

- [ ] **Step 1: Read the current source-loop**

Read `tools/TaintAnalyzer/Program.cs:89-126` and confirm the structure matches:

```csharp
foreach (var entry in rules.SourceMethods!)
{
    var source = context.FindMethod(entry.Signature);
    // ... null check ...
    int bitmask = (1 << source.Parameters.Count) - 1;
    var seedFields = entry.SeedThisFields ?? (IReadOnlyCollection<string>)Array.Empty<string>();
    walker.TaintFromExternalReturns = entry.TaintFromExternalReturns ?? Array.Empty<string>();
    var summary = walker.WalkWithSeed(source, bitmask, seedFields);

    var sp = source.Body is null ? null : context.GetSequencePoint(source, source.Body.Instructions.First());
    allHops.Add(new HopRecord
    {
        Hop = 0,
        Method = $"{source.DeclaringType.FullName}.{source.Name}",
        // ...
    });
    allHops.AddRange(summary.Hops);
}
```

- [ ] **Step 2: Insert resolver call + adjust seed for async-redirected sources**

Replace the body of the `foreach (var entry in rules.SourceMethods!)` loop with the following. Keep the null-check + suggestion-on-failure behaviour intact:

```csharp
foreach (var entry in rules.SourceMethods!)
{
    var source = context.FindMethod(entry.Signature);
    if (source is null)
    {
        var suggestion = SuggestNearest(context, entry.Signature);
        Console.Error.WriteLine($"error: source method not found: {entry.Signature}");
        if (suggestion is not null) Console.Error.WriteLine($"   closest in target: {suggestion}");
        return 1;
    }

    var resolution = AsyncStateMachineResolver.Resolve(source);
    walker.TaintFromExternalReturns = entry.TaintFromExternalReturns
        ?? (IReadOnlyList<string>)Array.Empty<string>();

    int bitmask;
    IReadOnlyCollection<string> seedFields;
    if (resolution.RedirectedFromAsync)
    {
        // MoveNext takes no parameters; captured arguments live as `this`-fields whose names
        // match the original method's parameter names. Seed those fields as tainted.
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

    // Source hop reflects the user-facing method (not MoveNext).
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
}
```

- [ ] **Step 3: Build + run all tests**

Run: `dotnet build TaintAnalyzer.sln -c Debug && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: build succeeds; all existing tests pass (no existing source rule names an async method, so existing fixtures take the non-async path unchanged).

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/Program.cs
git commit -m "$(cat <<'EOF'
analyzer: Program.cs uses AsyncStateMachineResolver for source resolution

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: End-to-end async-source walk test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/AsyncSourceWalkTests.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`

- [ ] **Step 1: Add a synthetic async source fixture that emits a MatchHttpRead sink**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
public static class AsyncSinkFixtures
{
    // An async method that posts to an HttpClient and reads the response body unbounded.
    // Mirrors the OpAmp PlainHttpTransport.SendAsync pre-fix shape exactly enough to drive
    // the analyzer's async-source resolution + MatchHttpRead sink end-to-end.
    public static async System.Threading.Tasks.Task<byte[]> AsyncReadResponse(
        System.Net.Http.HttpClient client, byte[] body, System.Threading.CancellationToken token)
    {
        using var content = new System.Net.Http.ByteArrayContent(body);
        var response = await client.PostAsync("https://example.invalid/", content, token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
    }
}
```

- [ ] **Step 2: Write the failing end-to-end test**

Create `tools/TaintAnalyzer.Tests/AsyncSourceWalkTests.cs`:

```csharp
using Shouldly;

namespace TaintAnalyzer.Tests;

public class AsyncSourceWalkTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void AnalyzeAsyncSource_EmitsMatchHttpReadSink_AndMarksResolvedViaAsyncStateMachine()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Find the user-facing async method by name.
        var source = ctx.AllMethods()
            .First(m => m.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.AsyncSinkFixtures"
                     && m.Name == "AsyncReadResponse");

        var resolution = AsyncStateMachineResolver.Resolve(source);
        resolution.RedirectedFromAsync.ShouldBeTrue();

        var walker = new TaintWalker(ctx)
        {
            TaintFromExternalReturns = new[] { "HttpClient::PostAsync" },
        };

        // MoveNext has no parameters; seed captured `this`-fields whose name matches a parameter.
        var smFieldNames = resolution.Method.DeclaringType.Fields
            .Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var seedFields = source.Parameters
            .Select(p => p.Name)
            .Where(name => smFieldNames.Contains(name))
            .ToList();

        var summary = walker.WalkWithSeed(resolution.Method, 0, seedFields);

        // The sink is a MatchHttpRead (HttpContentRead from ReadAsByteArrayAsync).
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.HttpContentRead);
    }
}
```

- [ ] **Step 3: Build + run the test**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~AsyncSourceWalkTests"`
Expected: PASS. (If FAIL, the seed-field set is empty — typical cause: the captured field names contain compiler-mangled prefixes like `<>` instead of matching the parameter name. Inspect Cecil's `resolution.Method.DeclaringType.Fields` to confirm.)

- [ ] **Step 4: Run the full test suite**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer.Tests/AsyncSourceWalkTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "$(cat <<'EOF'
test: end-to-end async-source walk emits MatchHttpRead sink

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Session 2 — Loop-guard sanitizer

### Task 7: Baseline regression — milestone-H prefix fixtures still fire

**Files:**
- Read-only check: `fixtures/otelcontrib-55m9-prefix/{rules,trace}.yaml`
- Read-only check: `artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll`

This is a no-op verification step before touching the sanitizer. Goal: have a known-good baseline so we can confirm Task 9-11 don't over-untaint the milestone-H pre-fix fixtures.

- [ ] **Step 1: Confirm the milestone-H artifact is present**

Run: `ls artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.{dll,pdb}`

Expected: both files exist (these are the gitignored Debug binaries built during milestone-H, kept under `artifacts/` per repo convention).

If MISSING (fresh checkout / lost local state): the milestone-H plan does not have a checked-in materialize script for these binaries. Build them by adapting the OpAmp materialize script (Task 12) — the prefix commit you need is the parent of `77dc5d14fcdf6c6b3aeba5f8bba5dfded90495c9` (PR #4117 merge) for `OpenTelemetry.Exporter.OneCollector.csproj`. Land the rebuild in `artifacts/otelcontrib-55m9-pre/`. Do NOT proceed with subsequent tasks until you have this binary — losing the milestone-H baseline check would mean we have no regression coverage for the sanitizer change.

- [ ] **Step 2: Re-run the analyzer against the prefix DLL**

Run:

```bash
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll \
    --rules fixtures/otelcontrib-55m9-prefix/rules.yaml \
    --output /tmp/55m9-prefix-baseline.yaml
```

Expected: produces a non-empty trace with at least one `http_content_read` sink.

- [ ] **Step 3: Compare against ground truth**

Run:

```bash
dotnet run --project tools/ValidateFixture -- --compare \
    fixtures/otelcontrib-55m9-prefix/trace.yaml \
    /tmp/55m9-prefix-baseline.yaml
```

Expected: exit code 0 (`--compare` non-strict passes).

- [ ] **Step 4: Record baseline in the task log**

No commit. Note the sink count and exit code in the task summary so the post-sanitizer rerun (Task 11 Step 5) has a clear comparison point.

---

### Task 8: ClampFixtures — IL fixtures for sanitizer tests

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`

- [ ] **Step 1: Add the clamp fixtures**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
// Fixtures for MatchValueClamp tests. Each method produces a specific IL diamond/call
// shape that the sanitizer matcher must recognise (or, for negative cases, must reject).
public static class ClampFixtures
{
    // Orientation A — the canonical OTel HttpClientHelpers.GetBufferLength shape.
    // C# emits this as `clt; brfalse LBL_K; ldarg.0; br LBL_join; LBL_K: ldarg.1; LBL_join:`
    public static int TernaryClamp_LessThan(int tainted, int limit)
        => tainted < limit ? tainted : limit;

    // Orientation B — flipped condition, same semantics.
    public static int TernaryClamp_GreaterThanOrEqual(int tainted, int limit)
        => tainted >= limit ? limit : tainted;

    // Negative — both operands tainted; the result is still bounded by the smaller of two
    // attacker-controlled values, which we conservatively treat as still tainted.
    public static int TernaryClamp_BothTainted(int x, int y) => x < y ? x : y;

    // Mirrors the GetBufferLength inner branch: `(int)stream.Length < limit ? (int)stream.Length : limit`.
    // We synthesise stream.Length via a parameter whose taint shape we control in the test.
    public static int StreamLengthVsLimit(long streamLength, int limit)
        => (int)streamLength < limit ? (int)streamLength : limit;

    // Math.Min / Max / Clamp shapes for the HandleCall recognizer.
    public static int MathMin_TaintedAndConstant(int tainted) => System.Math.Min(tainted, 4096);
    public static int MathMin_TwoTainted(int x, int y) => System.Math.Min(x, y);
    public static int MathMax_TaintedAndConstant(int tainted) => System.Math.Max(tainted, 0);
    public static int MathClamp_TaintedWithConstantBounds(int tainted) => System.Math.Clamp(tainted, 0, 4096);
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "$(cat <<'EOF'
test fixture: ClampFixtures for milestone-I sanitizer tests

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: MatchValueClamp — ternary-clamp diamond

**Files:**
- Modify: `tools/TaintAnalyzer/SanitizerShapes.cs` (append `MatchValueClamp` and supporting types)
- Modify: `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` (extend with ternary tests)

The matcher returns information about which slot to untaint at the post-join instruction. Wire-in to the walker happens in Task 11.

- [ ] **Step 1: Define the result type**

Add to `tools/TaintAnalyzer/SanitizerShapes.cs` (top of the file, near `BranchSides`):

```csharp
public sealed class ClampMatch
{
    /// <summary>IL offset of the comparison/branch that opened the diamond.</summary>
    public required int ComparisonIlOffset { get; init; }
    /// <summary>IL offset of the join instruction (where both arms converge).</summary>
    public required int JoinIlOffset { get; init; }
    /// <summary>Provenance string identifying the originally-tainted operand (e.g. "arg0", "stream.Length").</summary>
    public required string TaintedOperandProvenance { get; init; }
    /// <summary>Provenance string identifying the bounded operand (e.g. "ldc.i4 4096", "limit").</summary>
    public required string BoundedOperandProvenance { get; init; }
}
```

- [ ] **Step 2: Write the failing tests**

Append to `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` (inside the class):

```csharp
[Fact]
public void TernaryClamp_OrientationA_LessThan_Matches()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var m = ctx.AllMethods()
        .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                  && md.Name == "TernaryClamp_LessThan");

    var matches = SanitizerShapes.MatchValueClamps(m).ToList();
    matches.ShouldHaveSingleItem();
}

[Fact]
public void TernaryClamp_OrientationB_GreaterThanOrEqual_Matches()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var m = ctx.AllMethods()
        .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                  && md.Name == "TernaryClamp_GreaterThanOrEqual");

    var matches = SanitizerShapes.MatchValueClamps(m).ToList();
    matches.ShouldHaveSingleItem();
}

[Fact]
public void TernaryClamp_StreamLengthVsLimit_Matches()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var m = ctx.AllMethods()
        .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                  && md.Name == "StreamLengthVsLimit");

    var matches = SanitizerShapes.MatchValueClamps(m).ToList();
    matches.ShouldHaveSingleItem();
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapesTests.TernaryClamp"`
Expected: 3 FAIL — `MatchValueClamps` does not exist.

- [ ] **Step 4: Implement MatchValueClamps**

Append to `tools/TaintAnalyzer/SanitizerShapes.cs` (inside the static `SanitizerShapes` class):

```csharp
/// <summary>
/// Detects the C# ternary-clamp idiom `tainted <op> bound ? tainted : bound`
/// (and the symmetric `tainted <op> bound ? bound : tainted` form) emitted as a
/// branch diamond. Both arms must be a single straight-line load followed by a
/// converging unconditional `br`. Returns one match per matching diamond in the
/// method body.
/// </summary>
public static IEnumerable<ClampMatch> MatchValueClamps(MethodDefinition method)
{
    if (method.Body is null) yield break;

    // The pattern (orientation A — `<` / `clt`):
    //   ld<X>          ; load operand A   (the value the diamond ultimately picks IF A < B)
    //   ld<Y>          ; load operand B
    //   clt | bge      ; comparison + branch
    //   brfalse|brtrue LBL_pickB
    //   ld<X>          ; load A again (small-side)
    //   br LBL_join
    //   LBL_pickB:
    //   ld<Y>          ; load B (large-side)
    //   LBL_join:
    //
    // We walk every conditional branch and, for each one, structurally verify the
    // diamond. Single-load arms only — multi-instruction arms abort the match.

    foreach (var br in method.Body.Instructions)
    {
        if (br.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
        if (br.OpCode.Code == Code.Switch) continue;

        var fallthrough = br.Next;
        var jumpTarget  = br.Operand as Instruction;
        if (fallthrough is null || jumpTarget is null) continue;

        // Each arm: must be a single load instruction followed by an unconditional `br`
        // (or, for the second arm, the join itself).
        var armA = ClassifyArm(fallthrough);
        if (armA is null) continue;

        // The second arm starts at jumpTarget. It must end at the same join as armA.
        var armB = ClassifyArm(jumpTarget);
        if (armB is null) continue;
        if (armB.JoinAt != armA.JoinAt) continue;

        // Pre-branch operands: walk back two `Previous` instructions from `br` and
        // capture their provenance strings.
        var prev1 = br.Previous;            // operand B (top of stack)
        var prev2 = prev1?.Previous;        // operand A (under)
        if (prev1 is null || prev2 is null) continue;

        var provA = OperandProvenance(prev2, method);
        var provB = OperandProvenance(prev1, method);
        if (provA is null || provB is null) continue;

        // The matcher does not decide which side is tainted — that's a runtime walker
        // concern. We just report both provenances and let the walker decide untainting
        // when it has actual taint state for the operands.
        yield return new ClampMatch
        {
            ComparisonIlOffset = br.Offset,
            JoinIlOffset = armA.JoinAt,
            TaintedOperandProvenance = provA,
            BoundedOperandProvenance = provB,
        };
    }
}

private sealed record Arm(int JoinAt);

private static Arm? ClassifyArm(Instruction start)
{
    var cur = start;
    // Skip any leading nop emitted by Roslyn for sequence points.
    while (cur is not null && cur.OpCode.Code == Code.Nop) cur = cur.Next;
    if (cur is null) return null;

    // Single load instruction.
    if (!IsLoadInstruction(cur)) return null;
    var next = cur.Next;
    if (next is null) return null;

    // Either: an unconditional `br`/`br.s` (orientation A's first arm and the explicit-br
    // arm of orientation B), or the next instruction IS the join (orientation B's tail arm).
    if (next.OpCode.Code is Code.Br or Code.Br_S)
    {
        if (next.Operand is not Instruction join) return null;
        return new Arm(join.Offset);
    }
    // Implicit join: this arm's load is the last instruction before the join — the join is
    // wherever the OTHER arm jumped to, which the caller cross-checks. Use this arm's `next`
    // as the join offset.
    return new Arm(next.Offset);
}

private static bool IsLoadInstruction(Instruction ins) => ins.OpCode.Code switch
{
    Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1
        or Code.Ldarg_2 or Code.Ldarg_3 => true,
    Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1
        or Code.Ldloc_2 or Code.Ldloc_3 => true,
    Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2
        or Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6
        or Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I4_M1 => true,
    Code.Ldc_I8 or Code.Ldfld or Code.Ldsfld => true,
    _ => false,
};

private static string? OperandProvenance(Instruction ins, MethodDefinition method)
{
    return ins.OpCode.Code switch
    {
        Code.Ldarg_0 => method.HasThis ? "this" : ParamName(method, 0),
        Code.Ldarg_1 => ParamName(method, method.HasThis ? 0 : 1),
        Code.Ldarg_2 => ParamName(method, method.HasThis ? 1 : 2),
        Code.Ldarg_3 => ParamName(method, method.HasThis ? 2 : 3),
        Code.Ldarg or Code.Ldarg_S when ins.Operand is ParameterDefinition pd => pd.Name,
        Code.Ldloc_0 => $"loc{0}",
        Code.Ldloc_1 => $"loc{1}",
        Code.Ldloc_2 => $"loc{2}",
        Code.Ldloc_3 => $"loc{3}",
        Code.Ldloc or Code.Ldloc_S when ins.Operand is VariableDefinition vd
            => $"loc{vd.Index}",
        Code.Ldfld or Code.Ldsfld when ins.Operand is FieldReference fr => fr.Name,
        Code.Ldc_I4_0 => "0",
        Code.Ldc_I4_1 => "1",
        Code.Ldc_I4_2 => "2",
        Code.Ldc_I4_3 => "3",
        Code.Ldc_I4_4 => "4",
        Code.Ldc_I4_5 => "5",
        Code.Ldc_I4_6 => "6",
        Code.Ldc_I4_7 => "7",
        Code.Ldc_I4_8 => "8",
        Code.Ldc_I4_M1 => "-1",
        Code.Ldc_I4 or Code.Ldc_I4_S => ins.Operand?.ToString(),
        Code.Ldc_I8 => ins.Operand?.ToString(),
        _ => null,
    };
}

private static string? ParamName(MethodDefinition m, int index)
    => index >= 0 && index < m.Parameters.Count ? m.Parameters[index].Name : null;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapesTests.TernaryClamp"`
Expected: 3 PASS.

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs
git commit -m "$(cat <<'EOF'
analyzer: SanitizerShapes.MatchValueClamps recognises ternary-clamp diamond

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Math.Min / Max / Clamp recognizer in HandleCall

**Files:**
- Create: `tools/TaintAnalyzer.Tests/MathClampTests.cs`
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:802` (within `HandleCall`)

- [ ] **Step 1: Write the failing tests**

Create `tools/TaintAnalyzer.Tests/MathClampTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;

namespace TaintAnalyzer.Tests;

public class MathClampTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string name) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                                 && m.Name == name);

    [Fact]
    public void MathMin_TaintedAndConstant_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMin_TaintedAndConstant"), bitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void MathMin_TwoTainted_ReturnsTainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMin_TwoTainted"), bitmask: 0b11, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeTrue();
    }

    [Fact]
    public void MathMax_TaintedAndConstant_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathMax_TaintedAndConstant"), bitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }

    [Fact]
    public void MathClamp_TaintedWithConstantBounds_ReturnsUntainted()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);
        var summary = walker.WalkWithSeed(Find(ctx, "MathClamp_TaintedWithConstantBounds"), bitmask: 0b1, Array.Empty<string>());

        summary.ReturnsTainted.ShouldBeFalse();
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail (or, for the two-tainted case, possibly pass already)**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MathClampTests"`
Expected: at least 3 FAIL — the tainted-with-constant cases currently return tainted because the walker over-approximates external-call returns.

- [ ] **Step 3: Add the recognizer in HandleCall**

In `tools/TaintAnalyzer/TaintWalker.cs`, locate the external-call branch in `HandleCall` (around line 847–886, where `resolved is null || resolved.Module.Assembly != _context.Assembly` is true). Just before the `if (!IsVoidReturn(callee))` block (around line 858), insert:

```csharp
// Math.Min/Max/Clamp clamp recognizer. When at least one argument is bounded (untainted
// constant/parameter/field), the result is bounded too; the call is a value-clamping
// sanitizer at the call-site, regardless of input taint count.
if (IsMathClampCall(callee) && argSlots.Any(s => !s.Tainted))
{
    var taintedArgs = argSlots.Where(s => s.Tainted).Select(s => s.Provenance);
    var boundArgs   = argSlots.Where(s => !s.Tainted).Select(s => s.Provenance);
    var prov = $"clamped({string.Join(",", taintedArgs)}; bound={string.Join(",", boundArgs)})";
    state.Stack.Push(new StackSlot(false, prov));
    return false;
}
```

Then, also in `TaintWalker.cs`, add the helper method `IsMathClampCall` somewhere convenient (e.g., near `IsVoidReturn`):

```csharp
private static bool IsMathClampCall(MethodReference callee)
{
    if (callee.DeclaringType.FullName != "System.Math") return false;
    return callee.Name is "Min" or "Max" or "Clamp";
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MathClampTests"`
Expected: 4 PASS.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/MathClampTests.cs
git commit -m "$(cat <<'EOF'
analyzer: HandleCall recognises Math.Min/Max/Clamp as value-clamping sanitizer

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Wire MatchValueClamps into the walker IL loop

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` around lines 100-170 and `StoreLocal` / `Push` paths.

This is the load-bearing wiring step. The matcher from Task 9 returns metadata about each diamond; this task consumes it at the join offset and replaces the stack slot at the join with an untainted slot when one of the operands was tainted and the other was bounded.

- [ ] **Step 1: Pre-compute clamp matches alongside sanitizer matches**

In `tools/TaintAnalyzer/TaintWalker.cs:117-122`, alongside the `sanitizerByOffset` precomputation, add:

```csharp
// Pre-compute ternary-clamp matches keyed by JOIN IL offset. When the IL walker reaches
// the join, the symbolic stack contains the post-join value (already pushed by the loaded
// arm). If the comparison's two operands at ComparisonIlOffset were tainted vs bounded,
// replace the join slot with an untainted slot.
var clampMatchByJoinOffset = SanitizerShapes.MatchValueClamps(method)
    .GroupBy(c => c.JoinIlOffset)
    .ToDictionary(g => g.Key, g => g.First());
```

- [ ] **Step 2: Apply the clamp at the join offset**

Inside the `foreach (var ins in method.Body.Instructions)` loop, after `StepInstruction(...)` (around line 169), add:

```csharp
if (clampMatchByJoinOffset.TryGetValue(ins.Offset, out var clamp))
{
    // The arm just executed pushed an operand; if the join is exactly at the join point
    // the top of the stack is the joined value. Untaint it iff one operand is tainted
    // and the other is bounded.
    if (state.Stack.Depth > 0)
    {
        var top = state.Stack.Peek();
        if (top.Tainted)
        {
            state.Stack.Pop();
            var prov = $"clamped({clamp.TaintedOperandProvenance}; bound={clamp.BoundedOperandProvenance})";
            state.Stack.Push(new StackSlot(false, prov));
        }
    }
}
```

NOTE: The linear walker may have desynced from the real IL stack. If the top-of-stack at the join is not tainted, do nothing — over-approximating "we don't know" is the safe default.

- [ ] **Step 3: Add an integration test for the canonical OTel shape**

Append to `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`:

```csharp
[Fact]
public void TernaryClamp_StreamLengthVsLimit_WalkerUntaintsResult()
{
    using var ctx = AssemblyContext.Load(FixturePath);
    var m = ctx.AllMethods()
        .First(md => md.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.ClampFixtures"
                  && md.Name == "StreamLengthVsLimit");

    var walker = new TaintWalker(ctx);
    // Seed only `streamLength` (bit 0) as tainted; `limit` (bit 1) is bounded.
    var summary = walker.WalkWithSeed(m, bitmask: 0b01, Array.Empty<string>());

    summary.ReturnsTainted.ShouldBeFalse();
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapesTests.TernaryClamp_StreamLengthVsLimit_WalkerUntaintsResult"`
Expected: PASS.

- [ ] **Step 5: Run the full suite + the milestone-H baseline check from Task 7**

Run:
```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/otelcontrib-55m9-pre/OpenTelemetry.Exporter.OneCollector.dll \
    --rules fixtures/otelcontrib-55m9-prefix/rules.yaml \
    --output /tmp/55m9-prefix-after-clamp.yaml
dotnet run --project tools/ValidateFixture -- --compare \
    fixtures/otelcontrib-55m9-prefix/trace.yaml \
    /tmp/55m9-prefix-after-clamp.yaml

# And the same for vc24:
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/otelcontrib-vc24-pre/OpenTelemetry.Resources.Azure.dll \
    --rules fixtures/otelcontrib-vc24-prefix/rules.yaml \
    --output /tmp/vc24-prefix-after-clamp.yaml
dotnet run --project tools/ValidateFixture -- --compare \
    fixtures/otelcontrib-vc24-prefix/trace.yaml \
    /tmp/vc24-prefix-after-clamp.yaml
```
Expected: all unit tests pass; both `--compare` invocations exit 0 (the milestone-H pre-fix fixtures' sinks still fire; the clamp matcher does NOT untaint the genuinely unbounded reads).

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs
git commit -m "$(cat <<'EOF'
analyzer: walker applies MatchValueClamps to untaint ternary-clamp join slots

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Session 3 — OpAmp fixture pair + scan rerun

### Task 12: Materialize OpAmp pair + author rules

**Files:**
- Create: `scripts/materialize-otelcontrib-opamp.sh`
- Create: `fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml`
- Create: `fixtures/otelcontrib-opamp-w2jh-prefix/README.md`
- Create: `fixtures/otelcontrib-opamp-w2jh-postfix/rules.yaml`
- Create: `fixtures/otelcontrib-opamp-w2jh-postfix/README.md`

- [ ] **Step 1: Create the materialize script**

Create `scripts/materialize-otelcontrib-opamp.sh`:

```bash
#!/usr/bin/env bash
# Materialize OpenTelemetry.OpAmp.Client at pre-fix and post-fix commits for the
# GHSA-w2jh-77fq-7gp8 / CVE-2026-42348 fixture pair.
set -euo pipefail

REPO=/tmp/otel-contrib-opamp
PREFIX_SHA=d6e87d8af403554107671e98e1913a3b2dfe141a
POSTFIX_SHA=bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "$REPO/.git" ]]; then
    git clone https://github.com/open-telemetry/opentelemetry-dotnet-contrib.git "$REPO"
fi

build_at() {
    local sha=$1
    local dest="${ARTIFACTS}/${sha}"
    mkdir -p "$dest"
    git -C "$REPO" -c advice.detachedHead=false fetch --depth 1 origin "$sha" 2>/dev/null || true
    git -C "$REPO" -c advice.detachedHead=false checkout "$sha"
    DOTNET_NOLOGO=1 dotnet build "$REPO/src/OpenTelemetry.OpAmp.Client/OpenTelemetry.OpAmp.Client.csproj" \
        -c Debug --framework net10.0 \
        -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false
    cp "$REPO/artifacts/bin/OpenTelemetry.OpAmp.Client/debug_net10.0/OpenTelemetry.OpAmp.Client.dll" "$dest/"
    cp "$REPO/artifacts/bin/OpenTelemetry.OpAmp.Client/debug_net10.0/OpenTelemetry.OpAmp.Client.pdb" "$dest/"
}

build_at "$PREFIX_SHA"
build_at "$POSTFIX_SHA"

echo "[materialize] prefix DLL:  ${ARTIFACTS}/${PREFIX_SHA}/OpenTelemetry.OpAmp.Client.dll"
echo "[materialize] postfix DLL: ${ARTIFACTS}/${POSTFIX_SHA}/OpenTelemetry.OpAmp.Client.dll"
```

Then make it executable:

```bash
chmod +x scripts/materialize-otelcontrib-opamp.sh
```

- [ ] **Step 2: Run the script**

Run: `bash scripts/materialize-otelcontrib-opamp.sh`
Expected: prefix and postfix DLLs land under `artifacts/<sha>/`. The build can take 30–60 s per commit.

- [ ] **Step 3: Author the prefix rules.yaml**

Create `fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml`:

```yaml
vuln_id: otelcontrib-opamp-w2jh
source_methods:
  - signature: OpenTelemetry.OpAmp.Client.Internal.Transport.Http.PlainHttpTransport::SendAsync(T,System.Threading.CancellationToken)
    taint_from_external_returns:
      - HttpClient::Send
      - HttpClient::SendAsync
      - HttpClient::PostAsync
      - HttpClient::GetStringAsync
      - HttpClient::GetByteArrayAsync
```

- [ ] **Step 4: Copy rules to postfix**

Run: `cp fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml fixtures/otelcontrib-opamp-w2jh-postfix/rules.yaml`

- [ ] **Step 5: Author both READMEs**

Create `fixtures/otelcontrib-opamp-w2jh-prefix/README.md`:

```markdown
# otelcontrib-opamp-w2jh-prefix

Source: opentelemetry-dotnet-contrib @ commit `d6e87d8af403554107671e98e1913a3b2dfe141a`
(parent of fix `bf1fad4`).

Advisory: GHSA-w2jh-77fq-7gp8 / CVE-2026-42348.

Vulnerable code: `src/OpenTelemetry.OpAmp.Client/Internal/Transport/Http/PlainHttpTransport.cs:51`
— `ReadAsByteArrayAsync` on the HTTP response body with no size cap.

Materialize:

    bash scripts/materialize-otelcontrib-opamp.sh

Expected analyzer behaviour: `MatchHttpRead` fires (sink `http_content_read`).
The source rule names the user-facing async method; `AsyncStateMachineResolver`
redirects to `<SendAsync>d__7\`1::MoveNext`.
```

Create `fixtures/otelcontrib-opamp-w2jh-postfix/README.md`:

```markdown
# otelcontrib-opamp-w2jh-postfix

Source: opentelemetry-dotnet-contrib @ commit `bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a`
(fix commit "[OpAMP] Apply response size limits for oversized responses (#4116)").

Advisory: GHSA-w2jh-77fq-7gp8 / CVE-2026-42348.

Materialize:

    bash scripts/materialize-otelcontrib-opamp.sh

Expected analyzer behaviour: empty findings. The fix replaces unbounded
`ReadAsByteArrayAsync` with `ReadBoundedResponseAsync`, which uses
`ReadAsStreamAsync` + bounded `Stream.ReadAsync` into an `ArrayPool` rented
buffer sized by `TransportConstants.MaxMessageSize` (128 KiB constant).
```

- [ ] **Step 6: Commit**

```bash
git add scripts/materialize-otelcontrib-opamp.sh fixtures/otelcontrib-opamp-w2jh-prefix fixtures/otelcontrib-opamp-w2jh-postfix
git commit -m "$(cat <<'EOF'
fixture: otelcontrib-opamp-w2jh prefix/postfix rules + materialize script

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: Author OpAmp prefix and postfix trace.yaml from analyzer output

**Files:**
- Create: `fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml`
- Create: `fixtures/otelcontrib-opamp-w2jh-postfix/trace.yaml`

- [ ] **Step 1: Run the analyzer against the prefix DLL**

Run:

```bash
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/d6e87d8af403554107671e98e1913a3b2dfe141a/OpenTelemetry.OpAmp.Client.dll \
    --rules fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml \
    --output fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml
```

Expected: the file contains a single document with:
- `source.method: OpenTelemetry.OpAmp.Client.Internal.Transport.Http.PlainHttpTransport.SendAsync`
- `source.resolved_via: async_state_machine`
- `sink.kind: allocation`, `sink.api: http_content_read`, line 51
- A `sanitizer_absence` entry

- [ ] **Step 2: Validate the prefix trace round-trips**

Run:

```bash
dotnet run --project tools/ValidateFixture -- --compare \
    fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml \
    fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml
```

Expected: exit code 0 (a self-compare is the trivial pass).

- [ ] **Step 3: Run the analyzer against the postfix DLL**

Run:

```bash
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a/OpenTelemetry.OpAmp.Client.dll \
    --rules fixtures/otelcontrib-opamp-w2jh-postfix/rules.yaml \
    --output fixtures/otelcontrib-opamp-w2jh-postfix/trace.yaml
```

Expected: empty file (no sinks reached). If the file is non-empty, inspect why — possible cause: the postfix code's `ArrayPool<byte>.Shared.Rent(TransportConstants.MaxMessageSize)` call surfaces as `array_pool_rent` because `MaxMessageSize` was somehow seen as tainted. If so, that's a real bug in the new sanitizer or the seed; investigate before continuing.

- [ ] **Step 4: Commit**

```bash
git add fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml fixtures/otelcontrib-opamp-w2jh-postfix/trace.yaml
git commit -m "$(cat <<'EOF'
fixture: otelcontrib-opamp-w2jh prefix/postfix ground-truth trace.yaml

Prefix: MatchHttpRead fires at PlainHttpTransport.cs:51 with resolved_via marker.
Postfix: empty findings (bounded helper sanitizes the read path).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Scan rerun — confirm 4 known false-positives are gone

**Files:**
- Create: `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md`
- Create: `docs/otelcore-scan-2026-04-29-addendum.md`

- [ ] **Step 1: Locate the cached scan binaries and rules**

The 2026-04-29 scans built binaries and rules under `/tmp/otel-scan/` (contrib) and `/tmp/otel-core-scan/` (core). Check what's still present:

```bash
ls /tmp/otel-scan/  2>&1 | head
ls /tmp/otel-core-scan/  2>&1 | head
find /tmp/otel-scan /tmp/otel-core-scan -name '*.dll' -o -name '*.yaml' 2>/dev/null | head -30
```

If MISSING (fresh tmpfs / lost local state): the scan rules are reproducible from the methodology sections of the two scan reports (`docs/otelcontrib-phase2-scan-2026-04-29.md`, `docs/otelcore-scan-2026-04-29.md`). Each package's rule entry uses the same shape — vuln_id + one source_method signature + the same `taint_from_external_returns` list. Reconstruct any missing rule files from those reports' "Detailed finding notes" sections; rebuild any missing binaries by extending the OpAmp materialize script (Task 12) to the relevant SHAs and packages.

- [ ] **Step 2: Rerun analyzer for each of the 5 packages**

Run each command and capture the output. The 5 cases to check (4 contrib FPs + 2 core FPs):

```bash
mkdir -p /tmp/otel-rerun-2026-05-06

# Contrib — AWS (array_pool_rent FP)
dotnet run --project tools/TaintAnalyzer -- \
    /tmp/otel-scan/AWS/OpenTelemetry.Resources.AWS.dll \
    --rules /tmp/otel-scan/AWS/rules.yaml \
    --output /tmp/otel-rerun-2026-05-06/AWS.yaml

# Contrib — Azure (array_pool_rent FP)
dotnet run --project tools/TaintAnalyzer -- \
    /tmp/otel-scan/Azure/OpenTelemetry.Resources.Azure.dll \
    --rules /tmp/otel-scan/Azure/rules.yaml \
    --output /tmp/otel-rerun-2026-05-06/Azure.yaml

# Contrib — OneCollector (http_content_read FP)
dotnet run --project tools/TaintAnalyzer -- \
    /tmp/otel-scan/OneCollector/OpenTelemetry.Exporter.OneCollector.dll \
    --rules /tmp/otel-scan/OneCollector/rules.yaml \
    --output /tmp/otel-rerun-2026-05-06/OneCollector.yaml

# Core — OTLP/HTTP (array_pool_rent FP)
dotnet run --project tools/TaintAnalyzer -- \
    /tmp/otel-core-scan/OpenTelemetry.Exporter.OpenTelemetryProtocol.dll \
    --rules /tmp/otel-core-scan/rules-otlp-http.yaml \
    --output /tmp/otel-rerun-2026-05-06/OTLP-HTTP.yaml

# Core — OTLP/gRPC (array_pool_rent FP)
dotnet run --project tools/TaintAnalyzer -- \
    /tmp/otel-core-scan/OpenTelemetry.Exporter.OpenTelemetryProtocol.dll \
    --rules /tmp/otel-core-scan/rules-otlp-grpc.yaml \
    --output /tmp/otel-rerun-2026-05-06/OTLP-gRPC.yaml
```

For each output file, expected: empty file (no `sanitizer_absence`, no sink — the clamp recogniser sanitises the size value inside `HttpClientHelpers.GetBufferLength` and `array_pool_rent` no longer fires).

Verify with: `wc -l /tmp/otel-rerun-2026-05-06/*.yaml` — all should be 0.

If a file is non-empty, inspect the surviving finding. Possible causes:
- The clamp matcher missed the diamond (orientation drift between Roslyn versions).
- The Math.Min recognizer missed an overload (e.g. `(uint, uint)` not in the list).
- The seed propagated taint through a different path that doesn't touch `GetBufferLength`.
Investigate before declaring the gate met.

- [ ] **Step 3: Write the contrib addendum**

Create `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md`:

```markdown
# OpenTelemetry Contrib HTTP DoS Broad Scan — 2026-04-29 (milestone-I rerun)

**Rerun date:** 2026-05-06 (after milestone-I MatchValueClamps + Math.Min/Clamp recognizer landed).

## Methodology

Same DLLs and rules as the original 2026-04-29 scan
(`docs/otelcontrib-phase2-scan-2026-04-29.md`). Only the analyzer changed.

## Results (delta vs 2026-04-29)

| Package | 2026-04-29 finding | 2026-05-06 finding |
|---------|-------------------|--------------------|
| `OpenTelemetry.Resources.AWS` | `array_pool_rent` (false-positive in `HttpClientHelpers`) | empty (clamp recognised) |
| `OpenTelemetry.Resources.Azure` | `array_pool_rent` (false-positive in `HttpClientHelpers`) | empty (clamp recognised) |
| `OpenTelemetry.Exporter.OneCollector` | `http_content_read` (false-positive in `HttpClientHelpers`) | empty (clamp recognised) |
| `OpenTelemetry.Resources.Gcp` | no-sink | no-sink |
| `OpenTelemetry.Resources.Container` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.Http` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.AWS` | no-sink | no-sink |

## Summary

3 false-positives → 0. The new milestone-I `MatchValueClamps` matcher recognises
the `(int)stream.Length < limit ? (int)stream.Length : limit` ternary in
`Shared/HttpClientHelpers.GetBufferLength` and untaints the join slot, so
`array_pool_rent` no longer fires inside the bounded helper. No new
vulnerabilities surfaced.

The originally-disclosed CVEs (GHSA-55m9 / GHSA-vc24) remain confirmed-fixed on
main; the milestone-H fixture pair `otelcontrib-{55m9,vc24}-{prefix,postfix}`
continues to pass `--compare` non-strict (the pre-fix fixtures' genuine
unbounded reads still fire — the sanitizer correctly does NOT over-untaint).
```

- [ ] **Step 4: Write the core addendum**

Create `docs/otelcore-scan-2026-04-29-addendum.md`:

```markdown
# OpenTelemetry Core HTTP DoS Broad Scan — 2026-04-29 (milestone-I rerun)

**Rerun date:** 2026-05-06 (after milestone-I MatchValueClamps + Math.Min/Clamp recognizer landed).

## Methodology

Same DLLs and rules as the original 2026-04-29 scan
(`docs/otelcore-scan-2026-04-29.md`). Only the analyzer changed.

## Results (delta vs 2026-04-29)

| Package | 2026-04-29 finding | 2026-05-06 finding |
|---------|-------------------|--------------------|
| `OpenTelemetry.Exporter.Zipkin` | no-sink (analyzer-error on byref signature) | unchanged — rules-validator gap deferred |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/HTTP) | `array_pool_rent` (false-positive in `HttpClientHelpers`) | empty (clamp recognised) |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/gRPC) | `array_pool_rent` (false-positive in `HttpClientHelpers`) | empty (clamp recognised) |

## Summary

2 false-positives → 0. The shared `HttpClientHelpers.GetBufferLength` clamp is
now recognised. Zipkin remains unchanged (rules-format validator limitation
documented in the original report; deferred). No new vulnerabilities surfaced.
```

- [ ] **Step 5: Commit**

```bash
git add docs/otelcontrib-phase2-scan-2026-04-29-addendum.md docs/otelcore-scan-2026-04-29-addendum.md
git commit -m "$(cat <<'EOF'
docs: addenda — 2026-04-29 OTel scans rerun confirms 5 FPs eliminated

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15 (bonus): Strict gate calibration for OpAmp pair

Optional bonus aligning the OpAmp pair with the milestone-G/H `--compare --strict` precedent. Skip if not pursuing.

- [ ] **Step 1: Run --compare --strict against the prefix fixture**

Run:

```bash
dotnet run --project tools/ValidateFixture -- --compare --strict \
    fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml \
    fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml
```

Expected: exit 0 (self-compare).

- [ ] **Step 2: Run --compare --strict re-running analyzer fresh**

```bash
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/d6e87d8af403554107671e98e1913a3b2dfe141a/OpenTelemetry.OpAmp.Client.dll \
    --rules fixtures/otelcontrib-opamp-w2jh-prefix/rules.yaml \
    --output /tmp/opamp-prefix-fresh.yaml
dotnet run --project tools/ValidateFixture -- --compare --strict \
    fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml \
    /tmp/opamp-prefix-fresh.yaml
```

Expected: exit 0. If FAIL, calibrate the ground-truth `trace.yaml` to the fresh output (the milestone-G/H "verbatim post-fix output becomes baseline" pattern).

- [ ] **Step 3: Repeat for postfix**

Same procedure with the postfix DLL + fixture.

- [ ] **Step 4: Update or commit if calibration was needed**

Only commit if Step 2 or Step 3 required calibration:

```bash
git add fixtures/otelcontrib-opamp-w2jh-prefix/trace.yaml fixtures/otelcontrib-opamp-w2jh-postfix/trace.yaml
git commit -m "$(cat <<'EOF'
fixture: calibrate OpAmp pair trace.yaml to pass --compare --strict

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review — spec coverage

- **Goal 1** (`AsyncStateMachineResolver`) → Tasks 2 + 3.
- **Goal 2** (seed-fields adjustment for redirected sources) → Task 5 (Step 2).
- **Goal 3** (`resolved_via` trace marker) → Task 4 + Task 5 (Step 2).
- **Goal 4** (`MatchValueClamp` ternary-clamp diamond) → Task 9 (matcher) + Task 11 (walker wiring).
- **Goal 5** (`Math.Min`/`Max`/`Clamp` recognizer) → Task 10.
- **Goal 6** (OpAmp fixture pair) → Tasks 12 + 13.
- **Goal 7** (scan-validation rerun) → Task 14.
- **Acceptance gate 1** (existing tests green) → covered by every task that ends in "run the full suite".
- **Acceptance gate 2** (existing fixtures pass `--compare`) → Task 7 (baseline) + Task 11 Step 5 (post-sanitizer check).
- **Acceptance gate 3** (OpAmp pair passes `--compare`) → Task 13.
- **Acceptance gate 4** (5 known FPs — 3 contrib + 2 core — become empty) → Task 14.
- **Bonus gate 5** (strict for OpAmp pair) → Task 15.
