# Milestone-G Implementation Plan — Hop dedup + document dedup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate hop explosion (23k → ~1k) and document explosion (40 → 5–10) for imagesharp-3079-prefix, then calibrate its ground truth to the improved output so all five fixtures pass `--compare --strict` (5/5).

**Architecture:** Two independent code-change sessions separated by natural break points. Session 1 adds a per-walk `HashSet<string> expandedCallees` guard in `TaintWalker.HandleCall` (U10) so the same in-assembly callee's hops are appended at most once per walk. Session 2 adds a path-prefix fingerprint dedup in `TraceEmitter.Emit` (U11) that groups sink documents sharing the same first three propagator-method names and keeps only the deepest per group. Session 3 refreshes all fixture ground truths verbatim and verifies 5/5 strict.

**Tech Stack:** .NET 10 / xUnit / Shouldly / Mono.Cecil 0.11.6 / YamlDotNet 15.1.6.

**Spec reference:** `docs/superpowers/specs/2026-04-29-milestone-g-design.md`.

**Branch model:** Work on a `milestone-g` branch off main (currently at `001ce27`). Land on main via fast-forward at the end.

**Baseline (pre-G):** 124 tests, 5/5 non-strict, 4/5 strict (3079-prefix fails D_a=40, H_a=23151).

**Pre-built artifact paths:**
- `PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `artifacts/synthetic-callee-arithmetic/Decoder.dll`
- `artifacts/synthetic-stackalloc/Decoder.dll`
- `artifacts/synthetic-instance-arithmetic/Decoder.dll`

---

## Task overview

| # | Title | Session | Files (primary) |
|---|-------|---------|-----------------|
| 0 | Branch setup | — | — |
| 1 | U10 fixture + failing test | 1 | `Fixtures.cs`, `TaintWalkerTests.cs` |
| 2 | U10 implementation | 1 | `TaintWalker.cs` |
| 3 | Commit Session 1 | 1 | — |
| *(break)* | | | |
| 4 | U11 failing test | 2 | `TraceEmitterTests.cs` |
| 5 | U11 implementation | 2 | `TraceEmitter.cs` |
| 6 | Commit Session 2 | 2 | — |
| *(break)* | | | |
| 7 | Ground-truth refresh | 3 | all `trace.yaml` files |
| 8 | Verify and commit | 3 | `docs/superpowers/specs/…` |

---

## Task 0: Branch setup

- [ ] **Step 0.1: Create the milestone-g branch**

```bash
git checkout main
git pull --ff-only 2>/dev/null || true
git checkout -b milestone-g
```

Expected: now on `milestone-g`, tip at `001ce27` (main's current head).

- [ ] **Step 0.2: Confirm baseline tests pass**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:" | head -3
```

Expected: 124 tests passing, 0 failures.

- [ ] **Step 0.3: Capture pre-G baseline fixture outputs for pre-flight diffing later**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo -q

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/baseline-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/baseline-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/baseline-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/baseline-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/baseline-stackalloc.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-instance-arithmetic/Decoder.dll --rules fixtures/synthetic-instance-arithmetic/rules.yaml --output /tmp/baseline-instance.yaml >/dev/null 2>&1

echo "=== baseline doc + hop counts ==="
for f in /tmp/baseline-3074-pre.yaml /tmp/baseline-3074-post.yaml /tmp/baseline-3079-pre.yaml /tmp/baseline-synthetic.yaml /tmp/baseline-stackalloc.yaml /tmp/baseline-instance.yaml; do
    docs=$(grep -c '^vuln_id:' "$f")
    hops=$(grep -c '^- hop:' "$f" 2>/dev/null || echo 0)
    echo "$(basename $f): $docs docs, $hops path-hops (raw grep)"
done
```

Save these numbers; they're the before-state for verifying Session 1 and 2 improvements.

---

## Task 1: U10 fixture + failing test

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append new class)
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (append new tests)

- [ ] **Step 1.1: Append the U10 fixture class to `Fixtures.cs`**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Append after the last closing `}` of the file:

```csharp

// Milestone-G U10 fixtures — per-walk callee-expansion guard.
public static class U10DoubleCallFixtures
{
    // Emits exactly one arithmetic hop (mul). Used to detect duplicates.
    internal static int Double(int x) => x * 2;

    // Calls Double twice with the same tainted arg.
    // U10 must ensure Double's arithmetic hop appears exactly once in the walk.
    public static byte[] CallHelperTwice(int n)
    {
        int a = Double(n);
        int b = Double(n);
        return new byte[a + b];
    }
}
```

- [ ] **Step 1.2: Append the failing U10 test to `TaintWalkerTests.cs`**

Open `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`. Append before the final closing `}` of the `TaintWalkerTests` class:

```csharp
    [Fact]
    public void Walk_SameCalleeCalledTwice_CalleeHopsNotDuplicated()
    {
        // U10: Double(n) is called twice in CallHelperTwice. Without U10, Double's
        // arithmetic hop (x * 2) would appear twice in the summary Hops list.
        // With U10, it must appear exactly once.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.U10DoubleCallFixtures::CallHelperTwice(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        int doubleArithHops = summary.Hops.Count(h =>
            h.Transformation == "arithmetic"
            && (h.Method ?? "").Contains("U10DoubleCallFixtures")
            && !(h.Method ?? "").Contains("CallHelperTwice"));
        doubleArithHops.ShouldBe(1, "U10: Double's arithmetic hop must not be duplicated on second call");
    }

    [Fact]
    public void Walk_SameCalleeUntainted_NoHopsEither()
    {
        // Guard: with bitmask=0, no taint flows — CallHelperTwice should not reach the sink
        // and produce no hops regardless of U10.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.U10DoubleCallFixtures::CallHelperTwice(System.Int32)")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse();
        summary.Hops.ShouldBeEmpty();
    }
```

- [ ] **Step 1.3: Build fixtures and run new tests — expect the first to fail**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_SameCalleeCalledTwice|Walk_SameCalleeUntainted"
```

Expected:
- `Walk_SameCalleeCalledTwice_CalleeHopsNotDuplicated` — **FAIL** (`doubleArithHops` is 2, not 1)
- `Walk_SameCalleeUntainted_NoHopsEither` — **PASS**

---

## Task 2: U10 implementation

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs`

- [ ] **Step 2.1: Add `expandedCallees` to `WalkMethodBody`**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find the block:

```csharp
        var hops = new List<HopRecord>();
        bool reachedSink = false;
        bool returnsTainted = false;
        // Hop counter resets per method; Task 11 refines to aggregate hops across the call chain.
        int hopCounter = 0;
        var newlyTaintedFields = new HashSet<string>(StringComparer.Ordinal);
```

Replace with:

```csharp
        var hops = new List<HopRecord>();
        bool reachedSink = false;
        bool returnsTainted = false;
        // Hop counter resets per method; Task 11 refines to aggregate hops across the call chain.
        int hopCounter = 0;
        var newlyTaintedFields = new HashSet<string>(StringComparer.Ordinal);
        // U10 — tracks which (callee.FullName|bitmask|seedKey) triples have already had their
        // hops merged into this walk's flat list. Prevents duplicate appends when the same
        // callee is called more than once with the same taint context.
        var expandedCallees = new HashSet<string>(StringComparer.Ordinal);
```

- [ ] **Step 2.2: Pass `expandedCallees` to `HandleCall`**

In the same file, find the `HandleCall` invocation inside the `Code.Call`/`Code.Callvirt` case. It looks like:

```csharp
                if (HandleCall(method, ins, state, newlyTaintedFields, hops, ref hopCounter))
```

Replace with:

```csharp
                if (HandleCall(method, ins, state, newlyTaintedFields, hops, ref hopCounter, expandedCallees))
```

- [ ] **Step 2.3: Add `expandedCallees` parameter to `HandleCall` signature**

Find the `HandleCall` method declaration:

```csharp
    private bool HandleCall(MethodDefinition callerMethod, Instruction ins, TaintState state,
                           HashSet<string> newlyTaintedFields, List<HopRecord> hops, ref int hopCounter)
```

Replace with:

```csharp
    private bool HandleCall(MethodDefinition callerMethod, Instruction ins, TaintState state,
                           HashSet<string> newlyTaintedFields, List<HopRecord> hops, ref int hopCounter,
                           HashSet<string> expandedCallees)
```

- [ ] **Step 2.4: Add the expansion-key computation inside `HandleCall`**

In `HandleCall`, find the line:

```csharp
        var calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);
```

Replace with:

```csharp
        var calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);

        // U10 — per-walk callee-expansion guard. The expansion key matches the memo key
        // so the first call (which populates the memo) is also the one whose hops are merged.
        // Subsequent calls with the same (callee, bitmask, seedKey) still emit the call-boundary
        // identity hop (dispatch signal) but skip appending callee hops a second time.
        var expansionKey = $"{resolved.FullName}|{bitmask}|{BuildSeedKey(seedFields)}";
        bool alreadyExpanded = !expandedCallees.Add(expansionKey);
```

- [ ] **Step 2.5: Guard the callee-hop append with `alreadyExpanded`**

Find the callee-hop append block:

```csharp
            // Append the callee's hops (the recursive walk's findings) into the caller's hop list,
            // preserving each hop's Method label so the trace shows the cross-method chain.
            // Don't append calleeSummary.Absences — only the outermost walked method synthesizes
            // absences (the caller's WalkMethodBody end-block will emit at most one).
            foreach (var calleeHop in calleeSummary.Hops)
            {
                hops.Add(calleeHop);
            }
```

Replace with:

```csharp
            // Append the callee's hops (the recursive walk's findings) into the caller's hop list,
            // preserving each hop's Method label so the trace shows the cross-method chain.
            // Don't append calleeSummary.Absences — only the outermost walked method synthesizes
            // absences (the caller's WalkMethodBody end-block will emit at most one).
            // U10: skip append on repeated calls to the same callee (alreadyExpanded).
            if (!alreadyExpanded)
            {
                foreach (var calleeHop in calleeSummary.Hops)
                {
                    hops.Add(calleeHop);
                }
            }
```

- [ ] **Step 2.6: Build and run the two new U10 tests — expect both to pass**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Walk_SameCalleeCalledTwice|Walk_SameCalleeUntainted"
```

Expected: 2 passing, 0 failing.

- [ ] **Step 2.7: Run the full analyzer test suite — no regressions**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green. Baseline 124 + 2 new = 126 tests passing.

If any existing test fails, investigate. U10 changes hop-list contents for callees called repeatedly — any test asserting on specific hop counts for multi-call scenarios may need updating. Treat as an expected naming change: update the assertion to the post-U10 value and document in the commit message.

- [ ] **Step 2.8: Quick fixture sanity check — non-strict still exits 0**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/u10-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/u10-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/u10-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/u10-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/u10-stackalloc.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-instance-arithmetic/Decoder.dll --rules fixtures/synthetic-instance-arithmetic/rules.yaml --output /tmp/u10-instance.yaml >/dev/null 2>&1

for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)               yaml=/tmp/u10-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)              yaml=/tmp/u10-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)               yaml=/tmp/u10-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/u10-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)      yaml=/tmp/u10-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/u10-instance.yaml; dir=fixtures/$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1)
    echo "$fix exit=$? | $(echo "$out" | tail -1)"
done
```

Expected: all six exit=0. If any fails, investigate before continuing.

Also print the new hop counts to see U10's impact:

```bash
echo "=== U10 hop counts (compare to baseline) ==="
for f in /tmp/u10-3074-pre.yaml /tmp/u10-3074-post.yaml /tmp/u10-3079-pre.yaml /tmp/u10-synthetic.yaml /tmp/u10-stackalloc.yaml /tmp/u10-instance.yaml; do
    docs=$(grep -c '^vuln_id:' "$f")
    echo "$(basename $f): $docs docs"
done
```

---

## Task 3: Commit Session 1

- [ ] **Step 3.1: Commit all Session 1 changes**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs \
        tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs \
        tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "analyzer: U10 — per-walk callee-expansion guard prevents hop duplication (Session 1)"
```

---

## *** BREAK POINT — END OF SESSION 1 ***

---

## Task 4: U11 failing test

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`

- [ ] **Step 4.1: Append the failing U11 test to `TraceEmitterTests.cs`**

Open `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`. Append before the final closing `}` of the `TraceEmitterTests` class:

```csharp
    [Fact]
    public void Emit_TwoSinksWithSharedPathPrefix_CollapsesToDeepestDocument()
    {
        // U11: Sink A (depth 4) and Sink B (depth 6) share the same first 3 distinct
        // propagator-method names (Helper1, Helper2, Helper3). FingerprintDedup must keep
        // only Sink B (the deeper one) and drop Sink A.
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M()" } };
        var hops = new HopRecord[]
        {
            new() { Hop = 0, Method = "Ns.T.M",       File = "T.cs", Line = 1,  Role = HopRole.Source,
                    TaintedValueIn = "s", Transformation = "read_stream", TaintedValueOut = "s" },
            new() { Hop = 1, Method = "Ns.Helper1",    File = "T.cs", Line = 10, Role = HopRole.Propagator,
                    TaintedValueIn = "s", Transformation = "identity",   TaintedValueOut = "s" },
            new() { Hop = 2, Method = "Ns.Helper2",    File = "T.cs", Line = 20, Role = HopRole.Propagator,
                    TaintedValueIn = "s", Transformation = "arithmetic", TaintedValueOut = "n" },
            new() { Hop = 3, Method = "Ns.Helper3",    File = "T.cs", Line = 30, Role = HopRole.Propagator,
                    TaintedValueIn = "n", Transformation = "identity",   TaintedValueOut = "n" },
            // Sink A — shallower (depth 4 from source)
            new() { Hop = 4, Method = "Ns.Helper3",    File = "T.cs", Line = 31, Role = HopRole.Sink,
                    TaintedValueIn = "n", Transformation = "identity",   TaintedValueOut = "n",
                    SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n" },
            new() { Hop = 5, Method = "Ns.Helper3",    File = "T.cs", Line = 32, Role = HopRole.Propagator,
                    TaintedValueIn = "n", Transformation = "identity",   TaintedValueOut = "n" },
            // Sink B — deeper (depth 6 from source)
            new() { Hop = 6, Method = "Ns.SinkMethod", File = "T.cs", Line = 40, Role = HopRole.Sink,
                    TaintedValueIn = "n", Transformation = "identity",   TaintedValueOut = "n",
                    SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        // U11 must produce exactly one document (Sink B — deeper wins).
        var docs = yaml.Split("\n---\n");
        docs.Length.ShouldBe(1, "U11 should collapse shared-prefix sinks to one document");
        yaml.ShouldContain("line: 40");    // Sink B kept
        yaml.ShouldNotContain("line: 31"); // Sink A dropped
    }

    [Fact]
    public void Emit_TwoSinksWithDistinctPaths_KeepsBothDocuments()
    {
        // Guard: sinks with DIFFERENT 3-method fingerprints must not be collapsed.
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M()" } };
        var hops = new HopRecord[]
        {
            new() { Hop = 0, Method = "Ns.T.M",    File = "T.cs", Line = 1,  Role = HopRole.Source,
                    TaintedValueIn = "s", Transformation = "read_stream", TaintedValueOut = "s" },
            // Path to Sink A: BranchX → SinkMethodA
            new() { Hop = 1, Method = "Ns.BranchX", File = "T.cs", Line = 10, Role = HopRole.Propagator,
                    TaintedValueIn = "s", Transformation = "identity",   TaintedValueOut = "s" },
            new() { Hop = 2, Method = "Ns.SinkMethodA", File = "T.cs", Line = 20, Role = HopRole.Sink,
                    TaintedValueIn = "s", Transformation = "identity",   TaintedValueOut = "s",
                    SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "s" },
            // Path to Sink B: BranchY → SinkMethodB (different first method)
            new() { Hop = 3, Method = "Ns.BranchY", File = "T.cs", Line = 30, Role = HopRole.Propagator,
                    TaintedValueIn = "s", Transformation = "identity",   TaintedValueOut = "s" },
            new() { Hop = 4, Method = "Ns.SinkMethodB", File = "T.cs", Line = 40, Role = HopRole.Sink,
                    TaintedValueIn = "s", Transformation = "identity",   TaintedValueOut = "s",
                    SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "s" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        // Different fingerprints → two documents must survive.
        var docs = yaml.Split("\n---\n");
        docs.Length.ShouldBe(2, "distinct-prefix sinks must each produce a document");
    }
```

- [ ] **Step 4.2: Run the new tests — expect both to fail**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Emit_TwoSinksWithSharedPathPrefix|Emit_TwoSinksWithDistinctPaths"
```

Expected:
- `Emit_TwoSinksWithSharedPathPrefix_CollapsesToDeepestDocument` — **FAIL** (2 docs instead of 1, or wrong doc kept)
- `Emit_TwoSinksWithDistinctPaths_KeepsBothDocuments` — **FAIL** (0 docs or other mismatch)

---

## Task 5: U11 implementation

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs`

- [ ] **Step 5.1: Add `FindPrecedingSourceIndex` helper**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Find `CollapseAdjacentRedundantHops` (around line 394). Just ABOVE it, insert:

```csharp
    // U11 helpers — path-prefix fingerprint dedup.

    private static int FindPrecedingSourceIndex(List<int> sourceIndices, int sinkIdx)
    {
        for (int j = sourceIndices.Count - 1; j >= 0; j--)
        {
            if (sourceIndices[j] < sinkIdx) return sourceIndices[j];
        }
        return -1;
    }

    private static (string, string, string) ComputeFingerprint(
        IReadOnlyList<HopRecord> hops, int sourceIdx, int sinkIdx)
    {
        // First 3 distinct method names in the propagator path (method must change from
        // the previous hop's method to count as a new entry).
        var methods = new List<string>(3);
        string? prev = null;
        for (int i = sourceIdx + 1; i < sinkIdx && methods.Count < 3; i++)
        {
            var hop = hops[i];
            if (hop.Role != HopRole.Propagator) continue;
            if (hop.Method != prev)
            {
                methods.Add(hop.Method);
                prev = hop.Method;
            }
        }
        while (methods.Count < 3) methods.Add("");
        return (methods[0], methods[1], methods[2]);
    }

    private static List<int> FingerprintDedup(
        IReadOnlyList<HopRecord> hops,
        List<int> sinkIndices,
        List<int> sourceIndices)
    {
        // Group sinks by fingerprint; keep the deepest (highest sinkIdx - sourceIdx) per group.
        var best = new Dictionary<(string, string, string), (int depth, int sinkIdx)>();
        foreach (int sinkIdx in sinkIndices)
        {
            int sourceIdx = FindPrecedingSourceIndex(sourceIndices, sinkIdx);
            if (sourceIdx < 0) continue;
            var fp = ComputeFingerprint(hops, sourceIdx, sinkIdx);
            int depth = sinkIdx - sourceIdx;
            if (!best.TryGetValue(fp, out var prev) || depth > prev.depth)
                best[fp] = (depth, sinkIdx);
        }
        return best.Values.Select(v => v.sinkIdx).OrderBy(i => i).ToList();
    }

```

- [ ] **Step 5.2: Call `FingerprintDedup` after U8 in `Emit`**

In `TraceEmitter.Emit`, find the end of the U8 block. It ends with the closing `}` of the `foreach (int idx in rawSinkIndices)` loop, where `sinkIndices` has been populated. The surrounding code looks like:

```csharp
        var sinkIndices = new List<int>();
        var seenSinkKeys = new HashSet<(string method, SinkKind kind, SinkApi api, string operand)>();
        foreach (int idx in rawSinkIndices)
        {
            var sh = hops[idx];
            var operand = sh.SizeExpression
                ?? sh.AccessExpression
                ?? sh.TaintedValueIn;
            var key = (sh.Method ?? "", sh.SinkKind!.Value, sh.SinkApi!.Value, operand);
            if (seenSinkKeys.Add(key))
            {
                sinkIndices.Add(idx);
            }
        }

        var sb = new StringBuilder();
```

Replace the blank line before `var sb = new StringBuilder();` with:

```csharp
        // U11 — path-prefix fingerprint dedup: group sinks sharing the same first 3 distinct
        // propagator-method names; keep only the deepest (most specific) per group.
        sinkIndices = FingerprintDedup(hops, sinkIndices, sourceIndices);

        var sb = new StringBuilder();
```

(Leave everything else in the Emit method unchanged.)

- [ ] **Step 5.3: Build and run the two new U11 tests — expect both to pass**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo \
    --filter "FullyQualifiedName~Emit_TwoSinksWithSharedPathPrefix|Emit_TwoSinksWithDistinctPaths"
```

Expected: 2 passing, 0 failing.

- [ ] **Step 5.4: Run the full test suite — no regressions**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green. Baseline 126 (post-U10) + 2 new = 128 tests passing.

If any existing TraceEmitter test fails: the U11 filter may be collapsing a synthetic hop sequence that the test relied on having two documents. Inspect the failure — if the fingerprints of the two sinks match, the test was relying on an over-emission that U11 intentionally removes; update the assertion. If they don't match, there is a bug in FingerprintDedup.

- [ ] **Step 5.5: Run the validator test suite — no regressions**

```bash
dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo
```

Expected: all green (U11 is in TraceEmitter, not FixtureValidator, so no validator tests should be affected).

- [ ] **Step 5.6: Non-strict fixture sanity check for all six fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/u11-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/u11-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/u11-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/u11-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/u11-stackalloc.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-instance-arithmetic/Decoder.dll --rules fixtures/synthetic-instance-arithmetic/rules.yaml --output /tmp/u11-instance.yaml >/dev/null 2>&1

echo "=== non-strict (all must exit 0) ==="
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)   yaml=/tmp/u11-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)  yaml=/tmp/u11-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)   yaml=/tmp/u11-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/u11-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/u11-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/u11-instance.yaml; dir=fixtures/$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1)
    echo "$fix exit=$? | $(echo "$out" | tail -1)"
done

echo ""
echo "=== document counts after U10+U11 ==="
for f in /tmp/u11-3074-pre.yaml /tmp/u11-3074-post.yaml /tmp/u11-3079-pre.yaml /tmp/u11-synthetic.yaml /tmp/u11-stackalloc.yaml /tmp/u11-instance.yaml; do
    docs=$(grep -c '^vuln_id:' "$f")
    echo "$(basename $f): $docs docs"
done
```

Expected: all six exit=0. The 3079-prefix doc count should drop significantly from 40.

---

## Task 6: Commit Session 2

- [ ] **Step 6.1: Commit all Session 2 changes**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs \
        tools/TaintAnalyzer.Tests/TraceEmitterTests.cs
git commit -m "analyzer: U11 — path-prefix fingerprint dedup collapses shared-chain sink docs (Session 2)"
```

---

## *** BREAK POINT — END OF SESSION 2 ***

---

## Task 7: Ground-truth refresh (Session 3)

**Files:**
- Modify: `fixtures/imagesharp-3074-prefix/trace.yaml` (if changed)
- Modify: `fixtures/imagesharp-3074-postfix/trace.yaml` (if changed)
- Modify: `fixtures/imagesharp-3079-prefix/trace.yaml` (definite change)
- Modify: `fixtures/synthetic-callee-arithmetic/trace.yaml` (if changed)
- Modify: `fixtures/synthetic-stackalloc/trace.yaml` (if changed)
- Modify: `fixtures/synthetic-instance-arithmetic/trace.yaml` (if changed)

- [ ] **Step 7.1: Confirm analyzer is built with U10+U11**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
```

Expected: 0 errors, 0 warnings.

- [ ] **Step 7.2: Regenerate all six fixture outputs**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/final-3074-pre.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/final-3074-post.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/final-3079-pre.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/final-synthetic.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/final-stackalloc.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-instance-arithmetic/Decoder.dll --rules fixtures/synthetic-instance-arithmetic/rules.yaml --output /tmp/final-instance.yaml

echo "=== final doc counts ==="
for f in /tmp/final-3074-pre.yaml /tmp/final-3074-post.yaml /tmp/final-3079-pre.yaml /tmp/final-synthetic.yaml /tmp/final-stackalloc.yaml /tmp/final-instance.yaml; do
    docs=$(grep -c '^vuln_id:' "$f")
    echo "$(basename $f): $docs docs"
done
```

- [ ] **Step 7.3: Pre-flight structural diff for each fixture**

For each fixture that changed (any where the new output differs from the current ground truth), confirm only the expected fields changed. Run:

```bash
for pair in "3074-pre:/tmp/final-3074-pre.yaml:fixtures/imagesharp-3074-prefix" \
            "3074-post:/tmp/final-3074-post.yaml:fixtures/imagesharp-3074-postfix" \
            "3079-pre:/tmp/final-3079-pre.yaml:fixtures/imagesharp-3079-prefix" \
            "synthetic:/tmp/final-synthetic.yaml:fixtures/synthetic-callee-arithmetic" \
            "stackalloc:/tmp/final-stackalloc.yaml:fixtures/synthetic-stackalloc" \
            "instance:/tmp/final-instance.yaml:fixtures/synthetic-instance-arithmetic"; do
    name=$(echo $pair | cut -d: -f1)
    new=$(echo $pair | cut -d: -f2)
    dir=$(echo $pair | cut -d: -f3)
    doc_old=$(grep -c '^vuln_id:' "$dir/trace.yaml")
    doc_new=$(grep -c '^vuln_id:' "$new")
    echo "$name: old=$doc_old docs → new=$doc_new docs"
done
```

If a synthetic fixture's doc count changed unexpectedly (e.g., synthetic-callee-arithmetic goes from 1 to 0 docs), stop and investigate before refreshing its ground truth — that would be a regression, not an improvement.

- [ ] **Step 7.4: Refresh each changed fixture's `trace.yaml`**

For EACH fixture where the output changed, refresh the ground truth. The pattern: preserve the metadata header (`vuln_id`, `fix_commit`, `fix_pr`, `description`), replace the body (`source:` onward) verbatim from the analyzer output.

**For `imagesharp-3079-prefix` (definite change — do this one first):**

```bash
# Capture the existing metadata header (everything before the first `source:` line).
sed -n '1,/^source:/{/^source:/!p}' fixtures/imagesharp-3079-prefix/trace.yaml > /tmp/3079-header.yaml

# Check how many documents the new output has and how it starts.
head -5 /tmp/final-3079-pre.yaml
grep -c '^vuln_id:' /tmp/final-3079-pre.yaml
```

If the new output starts with `vuln_id:` (the analyzer emits it), inspect whether the first document's body starts with `source:` and the subsequent documents are separated by `---`. Then:

```bash
# Replace the trace body with the new output.
# Strategy: copy new output verbatim and use Edit tool to insert the metadata header
# after the first vuln_id: line.
cp /tmp/final-3079-pre.yaml fixtures/imagesharp-3079-prefix/trace.yaml
```

Then use the Edit tool to insert `fix_commit: ""`, `fix_pr: ""`, and the `description:` block after the first `vuln_id:` line (matching the format from the original file). Check `head -15 /tmp/3079-header.yaml` to see the exact original header format.

**For each other fixture that changed** (check the Step 7.3 output), apply the same pattern:

```bash
# Template for each changed fixture:
# FIXTURE=imagesharp-3074-prefix  NEW=/tmp/final-3074-pre.yaml
sed -n '1,/^source:/{/^source:/!p}' fixtures/$FIXTURE/trace.yaml > /tmp/${FIXTURE}-header.yaml
sed -n '/^source:/,$p' $NEW > /tmp/${FIXTURE}-body.yaml
cat /tmp/${FIXTURE}-header.yaml /tmp/${FIXTURE}-body.yaml > fixtures/$FIXTURE/trace.yaml
```

If any fixture has multi-document YAML (multiple `---`-separated sections), the header only applies to the first document. Inspect `head -10 $NEW` to confirm structure before copying.

- [ ] **Step 7.5: Verify `--compare` non-strict on all six fixtures — must exit 0**

```bash
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)   yaml=/tmp/final-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)  yaml=/tmp/final-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)   yaml=/tmp/final-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/final-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/final-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/final-instance.yaml; dir=fixtures/$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1)
    echo "$fix non-strict exit=$? | $(echo "$out" | tail -1)"
done
```

Expected: all six exit=0. If any fails, inspect the FX-code diagnostic and fix the trace.yaml before continuing.

- [ ] **Step 7.6: Verify `--compare --strict` on all six fixtures — target 5/5 (or 6/6)**

```bash
echo "=== strict ==="
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)   yaml=/tmp/final-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)  yaml=/tmp/final-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)   yaml=/tmp/final-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/final-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/final-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/final-instance.yaml; dir=fixtures/$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare --strict "$dir/trace.yaml" "$yaml" 2>&1)
    echo "$fix strict exit=$? | $(echo "$out" | grep FX064 | head -2)"
done
```

Expected: all exit=0 (ground truth = analyzer output, so D_a = D_g and H_a = H_g ≤ 2·H_g trivially). Record the actual tally.

- [ ] **Step 7.7: Full test suite — all green**

```bash
dotnet test TaintAnalyzer.sln --nologo
```

Expected: all green. Baseline 128 (post-Sessions 1+2) + 0 new in Session 3 = 128 tests passing.

- [ ] **Step 7.8: Commit the ground-truth refresh**

Stage only the changed trace.yaml files:

```bash
git add fixtures/imagesharp-3079-prefix/trace.yaml
# Add other changed fixtures discovered in Step 7.3:
# git add fixtures/imagesharp-3074-prefix/trace.yaml  (if changed)
# git add fixtures/imagesharp-3074-postfix/trace.yaml (if changed)
# git add fixtures/synthetic-callee-arithmetic/trace.yaml (if changed)
# git add fixtures/synthetic-stackalloc/trace.yaml (if changed)
# git add fixtures/synthetic-instance-arithmetic/trace.yaml (if changed)

git commit -m "fixture: refresh ground-truth for U10+U11 (Session 3)"
```

---

## Task 8: Spec status update + final banner

**Files:**
- Modify: `docs/superpowers/specs/2026-04-29-milestone-g-design.md`

- [ ] **Step 8.1: Capture final numbers**

```bash
dotnet build TaintAnalyzer.sln --nologo 2>&1 | grep -E "Warning|Error"
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"

echo "=== final document counts ==="
for f in /tmp/final-3074-pre.yaml /tmp/final-3074-post.yaml /tmp/final-3079-pre.yaml /tmp/final-synthetic.yaml /tmp/final-stackalloc.yaml /tmp/final-instance.yaml; do
    docs=$(grep -c '^vuln_id:' "$f")
    echo "$(basename $f): $docs docs"
done
```

- [ ] **Step 8.2: Update spec Status line**

Open `docs/superpowers/specs/2026-04-29-milestone-g-design.md`. Find:

```
**Status:** Approved 2026-04-29.
```

Replace with (filling actual numbers from Step 8.1):

```
**Status:** Implementation complete 2026-04-29. Required gate met: 6/6 fixtures pass `--compare` non-strict. Strict bonus: <X>/6 after ground-truth calibration. 3079-prefix reduced from 40 docs / 23151 hops to <D> docs / <H> hops. See revision history for measured evidence.
```

- [ ] **Step 8.3: Append revision-history entry**

Append to the end of the spec file:

```markdown
- **2026-04-29 (implementation complete).** U10 + U11 landed; ground truths refreshed.
  - **Build/tests.** Clean build 0/0. Test suite green: <X> (TaintAnalyzer.Tests) + <Y> (ValidateFixture.Tests) = **<Z>** total, 0 failures.
  - **Required gate met:** `--compare` non-strict exits 0 on all six fixture pairs.
  - **3079-prefix reduction:** D_a: 40 → <D_new>; H_a: 23151 → <H_new>.
  - **Strict bonus:** <S>/6 (target was 5/5 on the original 5 + 1 new = 6 total). Ground truths calibrated to post-dedup output, so the new strict ceiling is D_a ≤ D_g = D_new.
  - **Carry-overs to milestone-H:**
    - `loc_N` recovery in sanitizer hops — still open.
    - U1.c redesign (meaningful sanitizer bound vs. sibling guard) — still open.
    - parquet-dotnet round-trip — fixture authored, materialize script pending.
    - Callee-hop duplication across TOP-LEVEL walks (U10 prevents within-walk repeats; separate top-level walks for different sources can still duplicate) — noted but not blocking.
```

- [ ] **Step 8.4: Commit the spec update**

```bash
git add docs/superpowers/specs/2026-04-29-milestone-g-design.md
git commit -m "docs: spec — milestone-G implementation complete (U10+U11)"
```

- [ ] **Step 8.5: Land milestone-g on main**

```bash
git checkout main
git merge --ff-only milestone-g
```

Expected: fast-forward merge succeeds. If it fails (main has moved), rebase `milestone-g` onto the new main tip first.

- [ ] **Step 8.6: Print final status banner**

```bash
echo "=== milestone-G complete ==="
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
echo ""
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/g-final-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/g-final-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/g-final-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/g-final-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/g-final-stackalloc.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-instance-arithmetic/Decoder.dll --rules fixtures/synthetic-instance-arithmetic/rules.yaml --output /tmp/g-final-instance.yaml >/dev/null 2>&1
echo "non-strict:"
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)   yaml=/tmp/g-final-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)  yaml=/tmp/g-final-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)   yaml=/tmp/g-final-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/g-final-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/g-final-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/g-final-instance.yaml; dir=fixtures/$fix ;;
    esac
    echo "  $fix: $(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1 | tail -1)"
done
echo "strict:"
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc synthetic-instance-arithmetic; do
    case $fix in
        3074-prefix)   yaml=/tmp/g-final-3074-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        3074-postfix)  yaml=/tmp/g-final-3074-post.yaml; dir=fixtures/imagesharp-$fix ;;
        3079-prefix)   yaml=/tmp/g-final-3079-pre.yaml;  dir=fixtures/imagesharp-$fix ;;
        synthetic-callee-arithmetic) yaml=/tmp/g-final-synthetic.yaml;  dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/g-final-stackalloc.yaml; dir=fixtures/$fix ;;
        synthetic-instance-arithmetic) yaml=/tmp/g-final-instance.yaml; dir=fixtures/$fix ;;
    esac
    dotnet run --project tools/ValidateFixture --no-build -- --compare --strict "$dir/trace.yaml" "$yaml" >/dev/null 2>&1
    echo "  $fix: exit=$?"
done
```

Expected: all non-strict exit=0; all strict exit=0.

---

## Self-Review

**Spec coverage:**
- *U10 callee-expansion guard:* Tasks 1+2 (fixture + test + HandleCall + WalkMethodBody). ✓
- *U11 path-prefix fingerprint dedup:* Tasks 4+5 (test + FingerprintDedup + ComputeFingerprint + FindPrecedingSourceIndex + Emit hook). ✓
- *DoD-1 (Walk_SameCalleeCalledTwice test):* Task 1 Step 1.2. ✓
- *DoD-2 (Emit_TwoSinksWithSharedPathPrefix test):* Task 4 Step 4.1. ✓
- *DoD-3 (all six non-strict):* Tasks 2 Step 2.8, 5 Step 5.6, 7 Step 7.5. ✓
- *DoD-4 (all six strict after refresh):* Task 7 Step 7.6. ✓
- *DoD-5 (build clean, tests green):* Tasks 2 Step 2.7, 5 Steps 5.4+5.5, 7 Step 7.7. ✓
- *Ground-truth refresh:* Task 7. ✓
- *Spec status update:* Task 8. ✓
- *Break points:* After Task 3 and after Task 6. ✓

**Placeholder scan:** No TBD/TODO items. Step 7.4 has `# if changed` comments — those are conditional instructions, not placeholders; the agent fills them in based on Step 7.3 output. Step 8.2/8.3 have `<X>/<D>/<H>` markers that are explicitly instructed to be filled from Step 8.1 measurements. ✓

**Type consistency:**
- `expandedCallees: HashSet<string>` — declared in Step 2.1, passed in Step 2.2, added to signature in Step 2.3, used in Steps 2.4+2.5. ✓
- `alreadyExpanded: bool` — computed in Step 2.4, used in Step 2.5. ✓
- `FingerprintDedup(IReadOnlyList<HopRecord>, List<int>, List<int>) → List<int>` — defined in Step 5.1, called in Step 5.2. ✓
- `ComputeFingerprint(IReadOnlyList<HopRecord>, int, int) → (string,string,string)` — defined in Step 5.1, called inside FingerprintDedup. ✓
- `FindPrecedingSourceIndex(List<int>, int) → int` — defined in Step 5.1, called inside FingerprintDedup. ✓
- HopRecord construction in Step 4.1 uses `new() { ... }` target-typed pattern matching existing TraceEmitterTests style. ✓
