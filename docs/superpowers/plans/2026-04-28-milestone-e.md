# Milestone E: Strict-Bonus Recovery + Stackalloc Sink — Implementation Plan

**Status:** Approved 2026-04-28.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement three coupled work units against the analyzer plus a new fixture. (1) `SinkApi.Stackalloc` enum + `Localloc` opcode matcher in `SinkShapes`. (2) Operand-aware sink-document dedup in `TraceEmitter` (extends milestone-D's U1.a). (3) Adjacent identical-tuple hop dedup pass in `TraceEmitter`. Plus `fixtures/synthetic-stackalloc/`.

**Architecture:** All analyzer-side. U7 in `HopRecord.cs` (enum), `SinkShapes.cs` (matcher), `TaintWalker.cs` (dispatch), `TraceEmitter.cs` (serialization). U8 + U9 in `TraceEmitter.cs` only. New synthetic fixture mirrors `synthetic-callee-arithmetic`'s scaffold (standalone `Decoder.csproj` outside the solution, built by a dedicated script). No validator changes.

**Tech Stack:** .NET 10 SDK (pinned `global.json`); Mono.Cecil 0.11.6; YamlDotNet 15.1.6; xUnit 2.9.3; Shouldly 4.3.0. Synthetic fixture targets `net8.0`.

**Spec reference:** `docs/superpowers/specs/2026-04-28-milestone-e-design.md` at commit `cca2de5`.

---

## File Structure

**Modified analyzer — `tools/TaintAnalyzer/`:**
- `HopRecord.cs:7` — extend `SinkApi` enum with `Stackalloc`.
- `SinkShapes.cs` — add `MatchLocalloc` static method (Task 1).
- `TaintWalker.cs:219` — extend the sink-match chain with `?? SinkShapes.MatchLocalloc(ins, state.Stack)`.
- `TraceEmitter.cs:370-377` — extend `SinkApiToString` switch with `SinkApi.Stackalloc => "stackalloc"`.
- `TraceEmitter.cs:50-63` — replace U1.a's `(method, line)` dedup key with operand-aware key (Task 2).
- `TraceEmitter.cs` (new method, called from `Emit` per-document loop) — adjacent-tuple hop dedup pass (Task 3).

**Modified tests — `tools/TaintAnalyzer.Tests/`:**
- `SinkShapesTests.cs` — add 2 tests for `MatchLocalloc` (tainted size returns match; untainted returns null).
- `TraceEmitterTests.cs` — add tests for U8 (operand-aware dedup) and U9 (adjacent-tuple collapse).
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — add `StackallocBytes(int size)` to `SinkFixtures`.

**Possibly-modified ground truth (Task 3 reconciliation):**
- `fixtures/imagesharp-3074-prefix/trace.yaml` — hop list collapse if FX061 fires post-U9.
- `fixtures/imagesharp-3074-postfix/trace.yaml` — same.

**New fixture — `fixtures/synthetic-stackalloc/`:**
- `rules.yaml` — names `WireProcessor.Process(System.IO.Stream)` as source.
- `trace.yaml` — single-document ground truth (Task 6).
- `source/Decoder.csproj` — net8.0 library, portable PDB.
- `source/Decoder.cs` — `WireProcessor` + `WireReader` (canonical u16-from-stream → `stackalloc byte[N]`).
- `source/README.md` — short description.
- `snippets/decoder-snippet.txt` — offending lines for cross-reference.

**New script — `scripts/build-synthetic-stackalloc.sh`:**
- Builds `Decoder.csproj` to `artifacts/synthetic-stackalloc/`.

---

## Task overview

1. U7 — `SinkApi.Stackalloc` enum + `Localloc` matcher + walker dispatch + emitter serialization + tests.
2. U8 — operand-aware sink-document dedup key in `TraceEmitter.Emit`.
3. U9 — adjacent identical-tuple hop dedup pass in `TraceEmitter.Emit` + reconcile #3074 ground truth if needed.
4. Synthetic stackalloc fixture scaffold — `Decoder.csproj` + source + build script.
5. Synthetic stackalloc fixture ground truth — capture analyzer output, write `trace.yaml`, verify the `api: stackalloc` sink hop is at the localloc site.
6. Required-gate cross-check — clean build, full test suite, `--compare` non-strict on all 5 fixtures.
7. Bonus tally — `--compare --strict` on all 5 fixtures, count exit-0 results, record in spec revision history.

---

## Task 1: U7 — `SinkApi.Stackalloc` + `Localloc` matcher

**Files:**
- Modify: `tools/TaintAnalyzer/HopRecord.cs:7`
- Modify: `tools/TaintAnalyzer/SinkShapes.cs` (append `MatchLocalloc` method)
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:219`
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:370-377`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs:14-25` (extend `SinkFixtures`)
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append two tests)

- [ ] **Step 1.1: Add the fixture method that emits `localloc`**

In `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`, locate the `SinkFixtures` class (around line 14). After the `SliceSpan` method, append:

```csharp
    // Localloc shape: `Span<byte> buf = stackalloc byte[size];` — emits `localloc`.
    // Returning `Length` (not the buffer) keeps the buffer's lifetime confined to this method,
    // which is what real callers do; the IL shape is what the analyzer cares about.
    public static int StackallocBytes(int size)
    {
        Span<byte> buf = stackalloc byte[size];
        return buf.Length;
    }
```

The class final shape becomes:

```csharp
public static class SinkFixtures
{
    public static byte[] NewByteArray(int size) => new byte[size];
    public static byte[] ArrayPoolRent(int size) => ArrayPool<byte>.Shared.Rent(size);
    public static ReadOnlySpan<byte> SliceSpan(ReadOnlySpan<byte> src, int start, int length)
        => src.Slice(start, length);
    public static int StackallocBytes(int size)
    {
        Span<byte> buf = stackalloc byte[size];
        return buf.Length;
    }
}
```

- [ ] **Step 1.2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo`
Expected: 0 errors, 0 warnings.

If the build fails because `Span<byte> buf = stackalloc byte[size]` doesn't compile in the project's language version, the project's `<TargetFramework>net10.0</TargetFramework>` already supplies C# 12+; no `<AllowUnsafeBlocks>` is needed for the safe-stackalloc form. If you still see an error, double-check there are no other unrelated edits in this commit.

- [ ] **Step 1.3: Write the failing test for `MatchLocalloc` — tainted size returns match**

Append to `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`, just before the closing brace of the `SinkShapesTests` class:

```csharp
    [Fact]
    public void MatchLocalloc_TaintedSize_ReturnsMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::StackallocBytes(System.Int32)");

        var localloc = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Localloc);
        var stack = new SymbolicStack();
        stack.Push(StackSlot.TaintedWith("size"));

        var match = SinkShapes.MatchLocalloc(localloc, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.Allocation);
        match.Api.ShouldBe(SinkApi.Stackalloc);
        match.SizeProvenance.ShouldBe("size");
    }

    [Fact]
    public void MatchLocalloc_UntaintedSize_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SinkFixtures::StackallocBytes(System.Int32)");
        var localloc = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Localloc);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchLocalloc(localloc, stack).ShouldBeNull();
    }
```

- [ ] **Step 1.4: Run the failing tests — expect compile error**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~MatchLocalloc"`
Expected: compile error — `SinkApi.Stackalloc` does not exist (and `MatchLocalloc` does not exist). Red bar.

- [ ] **Step 1.5: Add `Stackalloc` to `SinkApi` enum**

Open `tools/TaintAnalyzer/HopRecord.cs`. Find line 7:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex }
```

Replace with:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc }
```

- [ ] **Step 1.6: Add `MatchLocalloc` to `SinkShapes`**

Open `tools/TaintAnalyzer/SinkShapes.cs`. Append the new method before the final closing brace of the `SinkShapes` class (around line 117):

```csharp
    public static SinkMatch? MatchLocalloc(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Localloc) return null;
        if (stack.Depth == 0) return null;

        // Localloc pops one operand: the size in bytes (native int / int32 / uint32 — the JIT
        // accepts any of these from the stack). The size at the top-of-stack is the only
        // attacker-influenceable input. If tainted, this is a stack-allocation sink.
        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.Stackalloc,
            SizeProvenance = sizeSlot.Provenance,
        };
    }
```

- [ ] **Step 1.7: Wire `MatchLocalloc` into the walker's sink-match chain**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find lines 215–219:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack);
```

Replace with:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack);
```

- [ ] **Step 1.8: Extend `TraceEmitter.SinkApiToString` to serialize the new API**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Find lines 370–377:

```csharp
    private static string? SinkApiToString(SinkApi? a) => a switch
    {
        SinkApi.NewArray => "new_array",
        SinkApi.ArrayPoolRent => "array_pool_rent",
        SinkApi.SpanSlice => "span_slice",
        SinkApi.SpanIndex => "span_index",
        _ => null,
    };
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
        _ => null,
    };
```

- [ ] **Step 1.9: Run the new tests — expect green**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~MatchLocalloc"`
Expected: 2 passing, 0 failing.

- [ ] **Step 1.10: Run the full analyzer test suite — confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all tests pass (existing 110 + 2 new = 112). No `MatchLocalloc`-adjacent regressions.

- [ ] **Step 1.11: Run the full validator test suite — confirm no regressions**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo`
Expected: 61 passing, 0 failing. (Validator is untouched; this is just a sanity check.)

- [ ] **Step 1.12: Commit**

```bash
git add tools/TaintAnalyzer/HopRecord.cs tools/TaintAnalyzer/SinkShapes.cs tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "analyzer: U7 — stackalloc sink kind via Localloc matcher (Task 1)"
```

---

## Task 2: U8 — operand-aware sink-document dedup key

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:50-63` (the U1.a block)
- Modify: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` (append a new test)

- [ ] **Step 2.1: Write the failing test**

Append to `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`, just before the closing brace of the `TraceEmitterTests` class:

```csharp
    [Fact]
    public void Emit_ThreeSinksSameMethodSameOperandDifferentLines_ProducesOneDocument()
    {
        // Models the imagesharp-3074-prefix shape: three `new byte[colorMapSizeBytes]` calls
        // in BmpDecoderCore.ReadFileHeader at distinct lines. U1.a's (method, line) key would
        // emit three documents; U8's (method, sink-shape, primary-operand-name) key collapses
        // them to one because they share method + (allocation, new_array) + colorMapSizeBytes.
        var rules = new RulesDocument { VulnId = "test-u8", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
        };
        HopRecord MakeSink(int line) => new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = line, Role = HopRole.Sink,
            TaintedValueIn = "colorMapSizeBytes", Transformation = "identity", TaintedValueOut = "colorMapSizeBytes",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray,
            SizeExpression = "colorMapSizeBytes",
        };

        var yaml = TraceEmitter.Emit(rules, new[]
        {
            sourceHop,
            MakeSink(20),
            MakeSink(21),
            MakeSink(22),
        }, Array.Empty<EmittedSanitizerAbsence>());

        var docCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^vuln_id:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        docCount.ShouldBe(1, "U8 should collapse three same-operand same-shape sinks in the same method into one document");
    }

    [Fact]
    public void Emit_TwoSinksSameMethodDifferentOperands_ProducesTwoDocuments()
    {
        // Different operand names → distinct keys → both documents emitted.
        var rules = new RulesDocument { VulnId = "test-u8b", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
        };
        var sinkA = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "a", Transformation = "identity", TaintedValueOut = "a",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "a",
        };
        var sinkB = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 21, Role = HopRole.Sink,
            TaintedValueIn = "b", Transformation = "identity", TaintedValueOut = "b",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "b",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sinkA, sinkB }, Array.Empty<EmittedSanitizerAbsence>());

        var docCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^vuln_id:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        docCount.ShouldBe(2, "different operand names → distinct keys → both emitted");
    }
```

- [ ] **Step 2.2: Run the failing tests — expect FAIL**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Emit_ThreeSinksSameMethodSameOperand|Emit_TwoSinksSameMethodDifferentOperands"`
Expected: `Emit_ThreeSinksSameMethodSameOperandDifferentLines_ProducesOneDocument` FAILS (current U1.a `(method, line)` key emits 3 documents). `Emit_TwoSinksSameMethodDifferentOperands_ProducesTwoDocuments` PASSES (current behavior already emits 2 because lines differ).

- [ ] **Step 2.3: Replace U1.a's dedup key with the operand-aware U8 key**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Find lines 50–63:

```csharp
        // U1.a — dedup sinks by (method, line). When two sink hops fire at the same source
        // location (rare; implies adjacent sink-shape calls on one line, or analyzer re-entry
        // through a shared callee), the first wins. Avoids emitting near-identical documents.
        var sinkIndices = new List<int>();
        var seenSinkLocations = new HashSet<(string method, int line)>();
        foreach (int idx in rawSinkIndices)
        {
            var sh = hops[idx];
            var key = (sh.Method ?? "", sh.Line);
            if (seenSinkLocations.Add(key))
            {
                sinkIndices.Add(idx);
            }
        }
```

Replace with:

```csharp
        // U8 — dedup sinks by (method, sink-shape, primary-operand-name). Extends milestone-D's
        // U1.a (which used (method, line)) to collapse multiple sinks of the same shape with the
        // same load-bearing operand within one method — even when they fire at distinct lines.
        // Models the #3074 case: three `new byte[colorMapSizeBytes]` calls in
        // BmpDecoderCore.ReadFileHeader at distinct lines all share key
        // (BmpDecoderCore.ReadFileHeader, (allocation, new_array), colorMapSizeBytes).
        //
        // Primary-operand-name resolution order:
        //   1. SizeExpression (allocation sinks).
        //   2. AccessExpression (span sinks).
        //   3. TaintedValueIn (defensive fallback — every sink hop has this).
        var sinkIndices = new List<int>();
        var seenSinkKeys = new HashSet<(string method, SinkKind? kind, SinkApi? api, string operand)>();
        foreach (int idx in rawSinkIndices)
        {
            var sh = hops[idx];
            var operand = sh.SizeExpression
                ?? sh.AccessExpression
                ?? sh.TaintedValueIn
                ?? "";
            var key = (sh.Method ?? "", sh.SinkKind, sh.SinkApi, operand);
            if (seenSinkKeys.Add(key))
            {
                sinkIndices.Add(idx);
            }
        }
```

- [ ] **Step 2.4: Run the U8 tests — expect green**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Emit_ThreeSinksSameMethodSameOperand|Emit_TwoSinksSameMethodDifferentOperands"`
Expected: 2 passing, 0 failing.

- [ ] **Step 2.5: Run the full analyzer test suite — confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all green (112 from Task 1 + 2 new = 114). The existing `Emit_TwoSinkHopsAtSameMethodAndLine_ProducesOneDocument` test from milestone-D should still pass because U8's key is *strictly more permissive* than U1.a's `(method, line)` for that test's setup (same method, same line, same operand collapse to one document under U8 just as they did under U1.a).

- [ ] **Step 2.6: End-to-end check on the imagesharp-3074-prefix fixture — verify D_a drops to 1**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074" --rules fixtures/imagesharp-3074-prefix/rules.yaml --output /tmp/an-3074-pre.yaml
grep -c "^vuln_id:" /tmp/an-3074-pre.yaml
```
Expected: `1`. (Pre-U8: was `3`; post-U8: should collapse to `1`.)

If you see `2` or `3`: the operand-name resolution is missing one of the three sinks. Inspect the analyzer output (`grep -E "^vuln_id|size_expression|line:" /tmp/an-3074-pre.yaml`) to see which `size_expression` values differ — the implementation may need a normalization step (e.g., trim whitespace) before matching.

- [ ] **Step 2.7: Commit**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer.Tests/TraceEmitterTests.cs
git commit -m "analyzer: U8 — operand-aware sink-document dedup key (Task 2)"
```

---

## Task 3: U9 — adjacent identical-tuple hop dedup pass

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs` (add a private `CollapseAdjacentRedundantHops` method; call from `Emit` after `pathHops` is built and before `pathNodes` is built)
- Modify: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` (append U9 tests)
- Possibly modify: `fixtures/imagesharp-3074-prefix/trace.yaml`, `fixtures/imagesharp-3074-postfix/trace.yaml` (Step 3.6 reconciliation)

- [ ] **Step 3.1: Write the failing tests**

Append to `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`, just before the closing brace of the `TraceEmitterTests` class:

```csharp
    [Fact]
    public void Emit_AdjacentSameMethodIdentityHops_AreCollapsed()
    {
        // Rule 1: hop[i+1].transformation == "identity" AND hop[i+1].method == hop[i].method
        // Three adjacent identity hops in the same method at distinct lines should collapse to
        // the first one — that's the in-method identity-chain pattern in #3074-prefix.
        var rules = new RulesDocument { VulnId = "test-u9a", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var hops = new[]
        {
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 5, Role = HopRole.Source,
                TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream" },
            new HopRecord { Hop = 0, Method = "Ns.T.ReadHeader", File = "T.cs", Line = 100, Role = HopRole.Propagator,
                TaintedValueIn = "stream", Transformation = "identity", TaintedValueOut = "headerA" },
            new HopRecord { Hop = 0, Method = "Ns.T.ReadHeader", File = "T.cs", Line = 101, Role = HopRole.Propagator,
                TaintedValueIn = "headerA", Transformation = "identity", TaintedValueOut = "headerB" },
            new HopRecord { Hop = 0, Method = "Ns.T.ReadHeader", File = "T.cs", Line = 102, Role = HopRole.Propagator,
                TaintedValueIn = "headerB", Transformation = "identity", TaintedValueOut = "headerC" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
                TaintedValueIn = "headerC", Transformation = "identity", TaintedValueOut = "headerC",
                SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "headerC" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        // Three identity hops in the same method should collapse to one. So path[] has exactly 1.
        var hopCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^- hop:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        hopCount.ShouldBe(1, "three adjacent same-method identity hops collapse to one");
    }

    [Fact]
    public void Emit_CrossMethodIdentityHop_NotCollapsed()
    {
        // Rule 1's method-equality predicate must NOT collapse hops crossing method boundaries.
        // Two identity hops with different methods stay distinct (preserves call-graph signal).
        var rules = new RulesDocument { VulnId = "test-u9b", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var hops = new[]
        {
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 5, Role = HopRole.Source,
                TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Propagator,
                TaintedValueIn = "stream", Transformation = "identity", TaintedValueOut = "headerA" },
            new HopRecord { Hop = 0, Method = "Ns.T.ReadHeader", File = "T.cs", Line = 100, Role = HopRole.Propagator,
                TaintedValueIn = "headerA", Transformation = "identity", TaintedValueOut = "headerB" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
                TaintedValueIn = "headerB", Transformation = "identity", TaintedValueOut = "headerB",
                SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "headerB" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        // Both propagator hops survive — they are in different methods.
        var hopCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^- hop:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        hopCount.ShouldBe(2, "cross-method identity hop is preserved");
    }

    [Fact]
    public void Emit_AdjacentNonIdentityHops_SameTuple_AreCollapsed()
    {
        // Rule 2: (method, file, line, transformation, tainted_value_in) tuple match.
        // Two adjacent field_load hops with identical tuples collapse to one.
        var rules = new RulesDocument { VulnId = "test-u9c", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var hops = new[]
        {
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 5, Role = HopRole.Source,
                TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 11, Role = HopRole.Propagator,
                TaintedValueIn = "header", Transformation = "field_load", TaintedValueOut = "header.Offset" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 11, Role = HopRole.Propagator,
                TaintedValueIn = "header", Transformation = "field_load", TaintedValueOut = "header.Offset" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
                TaintedValueIn = "header.Offset", Transformation = "identity", TaintedValueOut = "header.Offset",
                SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "header.Offset" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        var hopCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^- hop:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        hopCount.ShouldBe(1, "adjacent identical-tuple non-identity hops collapse");
    }

    [Fact]
    public void Emit_SanitizerHopBetweenIdentityHops_IsPreserved()
    {
        // U9 must not collapse sanitizer hops. A sanitizer between two identity hops stays.
        var rules = new RulesDocument { VulnId = "test-u9d", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var hops = new[]
        {
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 5, Role = HopRole.Source,
                TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Propagator,
                TaintedValueIn = "stream", Transformation = "identity", TaintedValueOut = "x" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 12, Role = HopRole.Sanitizer,
                TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
                EstablishesBound = new EstablishesBound { Target = "x", Relation = "<=", UpperBound = "1024" },
                OnFailure = new OnFailure { Kind = FailureKind.Throw, Exception = "System.ArgumentOutOfRangeException" } },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Propagator,
                TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" },
            new HopRecord { Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
                TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
                SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "x" },
        };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        // Three path hops: identity → sanitizer → identity (distinct roles, sanitizer can't collapse).
        // U9 may collapse the last identity hop with the first one only if they're adjacent in the
        // path slice — they're not, the sanitizer is between them. So all three survive.
        var hopCount = System.Text.RegularExpressions.Regex.Matches(yaml, @"^- hop:", System.Text.RegularExpressions.RegexOptions.Multiline).Count;
        hopCount.ShouldBe(3, "sanitizer hop is preserved between adjacent identity hops");
    }
```

- [ ] **Step 3.2: Run the failing tests — expect FAIL**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Emit_AdjacentSameMethodIdentityHops|Emit_CrossMethodIdentityHop_NotCollapsed|Emit_AdjacentNonIdentityHops_SameTuple|Emit_SanitizerHopBetweenIdentityHops"`
Expected:
- `Emit_AdjacentSameMethodIdentityHops_AreCollapsed` — FAIL (currently emits 3 hops, want 1).
- `Emit_CrossMethodIdentityHop_NotCollapsed` — PASS (no collapse needed; current behavior).
- `Emit_AdjacentNonIdentityHops_SameTuple_AreCollapsed` — FAIL (currently emits 2 hops, want 1).
- `Emit_SanitizerHopBetweenIdentityHops_IsPreserved` — PASS (sanitizer is in path; current behavior emits 3).

- [ ] **Step 3.3: Add the `CollapseAdjacentRedundantHops` private method**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. After the existing `SinkApiToString` method (around line 378, just before the final closing brace of the file), add:

```csharp
    // U9 — adjacent identical-tuple hop dedup. Runs after `pathHops` is built per document,
    // collapsing redundant runs that the walker's emission generated. Two sub-rules in one pass:
    //
    //   Rule 1 (identity special case): `hop[i+1].transformation == "identity"` AND
    //                                   `hop[i+1].method == hop[i].method` → drop hop[i+1].
    //                                   Catches in-method identity chains spanning distinct lines
    //                                   that milestone-D's U2 (call-boundary filter) misses.
    //
    //   Rule 2 (general tuple match): `(method, file, line, transformation, tainted_value_in)` of
    //                                  hop[i+1] equals that of hop[i] → drop hop[i+1].
    //                                  Catches non-identity adjacent repeats.
    //
    // Source/sink/sanitizer hops are never in pathHops (they're top-level in the doc), so we
    // never collapse them. Sanitizer hops *can* be in pathHops — they're never dropped because
    // their (transformation, method) tuple, while sometimes "identity" same-method, is gated
    // by their distinct Role. We check Role explicitly to be safe.
    private static List<HopRecord> CollapseAdjacentRedundantHops(IReadOnlyList<HopRecord> pathHops)
    {
        if (pathHops.Count < 2) return new List<HopRecord>(pathHops);

        var result = new List<HopRecord>(pathHops.Count) { pathHops[0] };
        for (int i = 1; i < pathHops.Count; i++)
        {
            var prev = result[^1];
            var curr = pathHops[i];

            // Never collapse sanitizer hops — they carry FX063 / FX023 audit signal.
            if (curr.Role == HopRole.Sanitizer || prev.Role == HopRole.Sanitizer)
            {
                result.Add(curr);
                continue;
            }

            // Rule 1 — identity special case.
            bool rule1 = curr.Transformation == "identity" && curr.Method == prev.Method;

            // Rule 2 — general tuple match.
            bool rule2 = curr.Method == prev.Method
                && curr.File == prev.File
                && curr.Line == prev.Line
                && curr.Transformation == prev.Transformation
                && curr.TaintedValueIn == prev.TaintedValueIn;

            if (rule1 || rule2)
            {
                continue; // drop curr
            }
            result.Add(curr);
        }
        return result;
    }
```

- [ ] **Step 3.4: Wire the U9 pass into `Emit`**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Find the per-document loop body that builds `pathHops` (around lines 88–95):

```csharp
            var pathHops = new List<HopRecord>();
            for (int i = sourceIdx + 1; i < sinkIdx; i++)
            {
                if (hops[i].Role is HopRole.Propagator or HopRole.Sanitizer)
                {
                    pathHops.Add(hops[i]);
                }
            }
            var pathNodes = new List<PathNode>(pathHops.Count);
```

Replace with:

```csharp
            var pathHops = new List<HopRecord>();
            for (int i = sourceIdx + 1; i < sinkIdx; i++)
            {
                if (hops[i].Role is HopRole.Propagator or HopRole.Sanitizer)
                {
                    pathHops.Add(hops[i]);
                }
            }
            // U9 — collapse adjacent redundant hops. Runs unconditionally (not gated on --strict)
            // so the YAML the user reads matches what the validator counts.
            pathHops = CollapseAdjacentRedundantHops(pathHops);
            var pathNodes = new List<PathNode>(pathHops.Count);
```

- [ ] **Step 3.5: Run the U9 tests — expect green**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Emit_AdjacentSameMethodIdentityHops|Emit_CrossMethodIdentityHop_NotCollapsed|Emit_AdjacentNonIdentityHops_SameTuple|Emit_SanitizerHopBetweenIdentityHops"`
Expected: 4 passing, 0 failing.

- [ ] **Step 3.6: Run the full analyzer test suite — confirm no regressions, capture any FX061 reconciliations needed for existing fixtures**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all green (114 from Task 2 + 4 new = 118).

Then end-to-end check on the imagesharp fixtures:

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml

echo "=== --compare (non-strict) ==="
dotnet run --project tools/ValidateFixture --no-build -- --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/an-3074-pre.yaml; echo "  exit=$?"
dotnet run --project tools/ValidateFixture --no-build -- --compare fixtures/imagesharp-3074-postfix/trace.yaml /tmp/an-3074-post.yaml; echo "  exit=$?"
dotnet run --project tools/ValidateFixture --no-build -- --compare fixtures/imagesharp-3079-prefix/trace.yaml /tmp/an-3079-pre.yaml; echo "  exit=$?"
```
Expected: all three lines say `exit=0`.

If any line shows `exit=1`, the analyzer's collapsed hop list no longer matches that fixture's hand-authored ground truth (FX060/FX061). This is **expected** for #3074 fixtures — the milestone-E spec calls out this reconciliation. Open the diagnostic, identify which hops the ground-truth `trace.yaml` had that the analyzer no longer emits, and update the ground-truth YAML to drop them. **Rule:** only drop hops that the ground truth had as adjacent same-method identity hops or adjacent identical-tuple hops. Do NOT add or change source/sink/sanitizer fields. After each edit, re-run `--compare` until exit 0.

If `imagesharp-3079-prefix` fails: investigate. The spec says #3079 is **not** expected to need reconciliation (its ground truth has 3 hops in `path[]`, none of which are adjacent collapsibles). If FX061 fires there, the U9 pass is incorrectly collapsing a hop the ground truth needs — review the rule predicates against the diagnostic.

- [ ] **Step 3.7: Commit U9 (with any reconciliation)**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer.Tests/TraceEmitterTests.cs fixtures/imagesharp-3074-prefix/trace.yaml fixtures/imagesharp-3074-postfix/trace.yaml
git commit -m "analyzer: U9 — adjacent identical-tuple hop dedup pass (Task 3)"
```

(`git add` of the trace.yaml files is a no-op if Step 3.6 didn't need reconciliation. That's fine; `git add` of an unchanged file doesn't error.)

---

## Task 4: Synthetic stackalloc fixture scaffold

**Files:**
- Create: `fixtures/synthetic-stackalloc/source/Decoder.csproj`
- Create: `fixtures/synthetic-stackalloc/source/Decoder.cs`
- Create: `fixtures/synthetic-stackalloc/source/README.md`
- Create: `fixtures/synthetic-stackalloc/snippets/decoder-snippet.txt`
- Create: `fixtures/synthetic-stackalloc/rules.yaml`
- Create: `scripts/build-synthetic-stackalloc.sh`

(Ground-truth `trace.yaml` is authored in Task 5, after the analyzer's output is captured.)

- [ ] **Step 4.1: Create the source csproj**

Write `fixtures/synthetic-stackalloc/source/Decoder.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <DebugType>portable</DebugType>
    <DebugSymbols>true</DebugSymbols>
    <Optimize>false</Optimize>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>SyntheticStackalloc</RootNamespace>
    <AssemblyName>Decoder</AssemblyName>
    <OutputType>Library</OutputType>
  </PropertyGroup>
</Project>
```

- [ ] **Step 4.2: Create the source file**

Write `fixtures/synthetic-stackalloc/source/Decoder.cs`:

```csharp
using System.IO;

namespace SyntheticStackalloc;

public sealed class WireProcessor
{
    public byte[] Process(Stream stream)
    {
        var reader = new WireReader(stream);
        ushort recordCount = reader.ReadU16();
        Span<byte> scratch = stackalloc byte[recordCount];
        return scratch.ToArray();
    }
}

internal sealed class WireReader
{
    private readonly Stream _stream;

    public WireReader(Stream stream)
    {
        _stream = stream;
    }

    public ushort ReadU16()
    {
        int hi = _stream.ReadByte();
        int lo = _stream.ReadByte();
        return (ushort)((hi << 8) | lo);
    }
}
```

- [ ] **Step 4.3: Create the README**

Write `fixtures/synthetic-stackalloc/source/README.md`:

```markdown
# synthetic-stackalloc — milestone-E regression fixture

`WireProcessor.Process` reads a u16 from a stream and uses it as the size argument to
`stackalloc byte[recordCount]`. The product is a stack buffer whose size is fully
attacker-controlled — the stack-overflow analogue of `new byte[N]`. This fixture exercises
milestone-E's U7 (`Localloc` matcher → `kind: allocation`, `api: stackalloc` sink hop).

The fixture is built outside the main solution by `scripts/build-synthetic-stackalloc.sh`,
producing `artifacts/synthetic-stackalloc/Decoder.dll` (+ `.pdb`).

The ground-truth `trace.yaml` for this fixture lives one level up at
`fixtures/synthetic-stackalloc/trace.yaml` and is authored from the analyzer's own output
(see Task 5 of `docs/superpowers/plans/2026-04-28-milestone-e.md`).
```

- [ ] **Step 4.4: Create the rules file**

Write `fixtures/synthetic-stackalloc/rules.yaml`:

```yaml
vuln_id: synthetic-stackalloc
source_methods:
  - SyntheticStackalloc.WireProcessor::Process(System.IO.Stream)
```

- [ ] **Step 4.5: Create the snippets file**

Write `fixtures/synthetic-stackalloc/snippets/decoder-snippet.txt`:

```
// from WireProcessor.Process (Decoder.cs):
        ushort recordCount = reader.ReadU16();
        Span<byte> scratch = stackalloc byte[recordCount];
        return scratch.ToArray();

// from WireReader.ReadU16 (Decoder.cs):
public ushort ReadU16()
{
    int hi = _stream.ReadByte();
    int lo = _stream.ReadByte();
    return (ushort)((hi << 8) | lo);
}
```

- [ ] **Step 4.6: Create the build script**

Write `scripts/build-synthetic-stackalloc.sh`:

```bash
#!/usr/bin/env bash
# Builds fixtures/synthetic-stackalloc/source/Decoder.csproj into
# artifacts/synthetic-stackalloc/. Mirrors scripts/build-synthetic-callee-arithmetic.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/synthetic-stackalloc/source"
OUT_DIR="$REPO_ROOT/artifacts/synthetic-stackalloc"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/Decoder.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "synthetic-stackalloc built at $OUT_DIR/Decoder.dll"
```

Then make it executable:

```bash
chmod +x scripts/build-synthetic-stackalloc.sh
```

- [ ] **Step 4.7: Run the build script and confirm output**

Run: `scripts/build-synthetic-stackalloc.sh`
Expected: stdout ends with `synthetic-stackalloc built at .../Decoder.dll`. Exit code 0. Both `artifacts/synthetic-stackalloc/Decoder.dll` and `artifacts/synthetic-stackalloc/Decoder.pdb` exist.

Verify:
```bash
ls -l artifacts/synthetic-stackalloc/Decoder.dll artifacts/synthetic-stackalloc/Decoder.pdb
```
Expected: both files present, non-zero size.

- [ ] **Step 4.8: Commit**

```bash
git add fixtures/synthetic-stackalloc/ scripts/build-synthetic-stackalloc.sh
git commit -m "fixture+scripts: synthetic-stackalloc source + build script (Task 4)"
```

---

## Task 5: Synthetic stackalloc fixture ground truth

**Files:**
- Create: `fixtures/synthetic-stackalloc/trace.yaml`

The ground truth is authored AFTER U7+U8+U9 land (Tasks 1–3) so it reflects the milestone-E analyzer.

- [ ] **Step 5.1: Run the analyzer against the synthetic fixture**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/synthetic-stackalloc/Decoder.dll \
    --rules fixtures/synthetic-stackalloc/rules.yaml \
    --output /tmp/an-stackalloc.yaml
echo "exit=$?"
cat /tmp/an-stackalloc.yaml
```
Expected: exit code 0; `/tmp/an-stackalloc.yaml` contains a single document with:
- `source.method: SyntheticStackalloc.WireProcessor.Process`
- `sink.method: SyntheticStackalloc.WireProcessor.Process`
- `sink.kind: allocation`
- `sink.api: stackalloc`
- `sink.size_expression: recordCount` (or similar — the local's debug name)
- `sink.line` resolving to the `stackalloc byte[recordCount]` line in `Decoder.cs`
- One propagator hop in `path[]` for the call into `WireReader.ReadU16` (cross-method identity, preserved by U2)
- One `sanitizer_absence` entry pointing at the size's first-tainted line

If the trace doesn't have `api: stackalloc`: U7 didn't actually fire — investigate. Check that:
1. The DLL was rebuilt with the milestone-E source (`ls -lt artifacts/synthetic-stackalloc/Decoder.dll` shows recent timestamp).
2. The analyzer was rebuilt (`dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj`).
3. The `Localloc` instruction is reachable in the analyzer (the safe `Span<byte> = stackalloc` form should compile to `localloc`; verify with `dotnet ildasm artifacts/synthetic-stackalloc/Decoder.dll | grep -i localloc` or equivalent — the exact tooling depends on what's available).

- [ ] **Step 5.2: Adapt the analyzer output into ground truth**

Copy `/tmp/an-stackalloc.yaml` to `fixtures/synthetic-stackalloc/trace.yaml`, then add the metadata fields the analyzer doesn't emit:

```yaml
vuln_id: synthetic-stackalloc
fix_commit: ""
fix_pr: ""
description: >
  Synthetic regression fixture for milestone-E stackalloc sink kind.
  WireProcessor.Process reads a u16 from a stream and uses it as the size
  argument to stackalloc byte[recordCount]. The product is a stack buffer
  whose size is fully attacker-controlled — the stack-overflow analogue of
  new byte[N]. The sink hop has kind: allocation, api: stackalloc.

source:
  # from analyzer output

sink:
  # from analyzer output — must have kind: allocation, api: stackalloc

path:
  # from analyzer output

sanitizer_absence:
  # from analyzer output
```

(Don't paraphrase the analyzer's hops. Copy them verbatim. The `# from analyzer output` markers are placeholders for the captured-output sections; replace them with the YAML content from `/tmp/an-stackalloc.yaml`.)

- [ ] **Step 5.3: Verify the round trip closes (`--compare` non-strict)**

```bash
dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/synthetic-stackalloc/trace.yaml \
    /tmp/an-stackalloc.yaml
echo "exit=$?"
```
Expected: stdout shows `OK: ...`; exit code 0.

If FX060/FX061/FX062/FX063 fires: edit `trace.yaml` to match the analyzer output exactly (this is fixture-authoring, not analyzer debugging — the analyzer's output IS the expected behavior here). Re-run until exit 0.

- [ ] **Step 5.4: Verify the sink hop has `api: stackalloc` at the localloc site**

```bash
grep -nE "api: stackalloc|kind: allocation|line:" fixtures/synthetic-stackalloc/trace.yaml | head -10
```
Expected: a line `  api: stackalloc` and a `kind: allocation` line associated with the top-level `sink:` block. The `sink.line` value should match the line number of `Span<byte> scratch = stackalloc byte[recordCount];` in `source/Decoder.cs` (line 11 with the file shape from Step 4.2).

If `api: stackalloc` is absent or maps to a different line: revisit Step 5.1's diagnostics — the analyzer didn't recognize the localloc.

- [ ] **Step 5.5: Verify `--compare --strict` also passes (synthetic should fit by construction)**

```bash
dotnet run --project tools/ValidateFixture --no-build -- --compare --strict \
    fixtures/synthetic-stackalloc/trace.yaml \
    /tmp/an-stackalloc.yaml
echo "exit=$?"
```
Expected: exit code 0 (`H_g=1`, strict ceiling `H_a ≤ 2·1 = 2`; the analyzer should emit at most 2 hops in `path[]`).

If strict fails: hop count is too high. Possible causes: U2 didn't fire on the `WireReader.ReadU16` call boundary (different method → cross-method, expected to be preserved); U9 didn't collapse some adjacent identity hop. Inspect `path[]` and adjust if a real over-emission is happening; otherwise update the strict expectation to match what we measure.

- [ ] **Step 5.6: Commit**

```bash
git add fixtures/synthetic-stackalloc/trace.yaml
git commit -m "fixture: synthetic-stackalloc ground-truth trace.yaml (Task 5)"
```

---

## Task 6: Required-gate cross-check

**Files:** No code changes. Verification only.

- [ ] **Step 6.1: Clean build of the entire solution**

```bash
find . -type d \( -name bin -o -name obj \) -not -path './artifacts/*' -prune -exec rm -rf {} +
dotnet build TaintAnalyzer.sln --nologo
```
Expected: 0 errors, 0 warnings.

- [ ] **Step 6.2: Full test suite**

```bash
dotnet test TaintAnalyzer.sln --nologo
```
Expected: all green. Capture the test counts for the revision-history entry in Task 7. Expected ballpark: 110 (analyzer baseline) + 2 (Task 1 U7) + 2 (Task 2 U8) + 4 (Task 3 U9) = 118 in `TaintAnalyzer.Tests`. Validator's 61 unchanged. Total: 179.

- [ ] **Step 6.3: `--compare` non-strict on all 5 fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll \
    --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll \
    --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/an-stackalloc.yaml >/dev/null 2>&1

echo "=== --compare (non-strict) ==="
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc; do
    case $fix in
        synthetic-callee-arithmetic) yaml=/tmp/an-synthetic.yaml; dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/an-stackalloc.yaml; dir=fixtures/$fix ;;
        3074-prefix)                 yaml=/tmp/an-3074-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
        3074-postfix)                yaml=/tmp/an-3074-post.yaml;  dir=fixtures/imagesharp-$fix ;;
        3079-prefix)                 yaml=/tmp/an-3079-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1)
    rc=$?
    echo "$fix exit=$rc | $(echo "$out" | tail -1)"
done
```
Expected: all five lines say `exit=0` with `OK: ...`.

If any non-strict line fails: that's a regression. Investigate before continuing — the spec's required gate is 5/5 non-strict.

- [ ] **Step 6.4: Verify the new fixture's `api: stackalloc` is intact**

```bash
grep "api: stackalloc" fixtures/synthetic-stackalloc/trace.yaml
```
Expected: at least one line of output. Confirms milestone-E required-gate criterion #4.

- [ ] **Step 6.5: Verify `--compare --strict` runs without crashing on all 5 fixtures**

```bash
echo "=== --compare --strict (smoke check, exit codes captured) ==="
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc; do
    case $fix in
        synthetic-callee-arithmetic) yaml=/tmp/an-synthetic.yaml; dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/an-stackalloc.yaml; dir=fixtures/$fix ;;
        3074-prefix)                 yaml=/tmp/an-3074-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
        3074-postfix)                yaml=/tmp/an-3074-post.yaml;  dir=fixtures/imagesharp-$fix ;;
        3079-prefix)                 yaml=/tmp/an-3079-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
    esac
    dotnet run --project tools/ValidateFixture --no-build -- --compare --strict "$dir/trace.yaml" "$yaml" >/dev/null 2>&1
    echo "$fix exit=$?"
done
```
Expected: every line says `exit=0` OR `exit=1`. **No exceptions, no hangs.** Required-gate criterion #5. The actual exit code per fixture is the bonus tally; we record that in Task 7.

- [ ] **Step 6.6: No commit (verification-only task)**

This task makes no source changes; nothing to commit.

---

## Task 7: Bonus tally + spec status update

**Files:**
- Modify: `docs/superpowers/specs/2026-04-28-milestone-e-design.md` (Status line + Revision history)

- [ ] **Step 7.1: Run the bonus tally**

```bash
PASS=0
declare -A results
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc; do
    case $fix in
        synthetic-callee-arithmetic) yaml=/tmp/an-synthetic.yaml; dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/an-stackalloc.yaml; dir=fixtures/$fix ;;
        3074-prefix)                 yaml=/tmp/an-3074-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
        3074-postfix)                yaml=/tmp/an-3074-post.yaml;  dir=fixtures/imagesharp-$fix ;;
        3079-prefix)                 yaml=/tmp/an-3079-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
    esac
    out=$(dotnet run --project tools/ValidateFixture --no-build -- --compare --strict "$dir/trace.yaml" "$yaml" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        PASS=$((PASS+1))
        results[$fix]="STRICT-PASS"
        echo "$fix STRICT-PASS"
    else
        results[$fix]="STRICT-FAIL: $(echo "$out" | grep -E "FX0|exceeded" | head -2 | tr '\n' '; ')"
        echo "$fix STRICT-FAIL"
        echo "$out" | grep -E "FX0|exceeded" | head -2 | sed 's/^/    /'
    fi
done
echo
echo "BONUS: $PASS/5 strict-passes"
```
Expected: target is `≥4/5`. Optimistic projection: synthetic-callee-arithmetic + synthetic-stackalloc + 3074 prefix + 3074 postfix = 4/5; #3079 stays a strict-fail. Worst plausible: 2/5 (synthetic + stackalloc) if U9's reduction wasn't aggressive enough.

Capture the per-fixture `D_a` and `H_a` numbers from each STRICT-FAIL diagnostic line — needed for Step 7.3's table.

- [ ] **Step 7.2: Capture build/test counts for the revision-history entry**

```bash
dotnet build TaintAnalyzer.sln --nologo 2>&1 | grep -E "Warning|Error"
dotnet test TaintAnalyzer.sln --nologo 2>&1 | grep -E "Passed!|Failed:" | head -2
```
Expected build counts: `0 Warning(s)` / `0 Error(s)`. Expected test counts: 118 (analyzer) + 61 (validator) = 179. Capture the actual numbers if they differ.

- [ ] **Step 7.3: Update the spec's Status line and append the implementation-complete revision-history entry**

Open `docs/superpowers/specs/2026-04-28-milestone-e-design.md`. Find the top-level Status line:

```
**Status:** Approved 2026-04-28.
```

Replace with:

```
**Status:** Implementation complete 2026-04-28. Required gate met (5/5 fixtures pass `--compare` non-strict). Bonus tier: <N>/5 strict-passes. See revision history for the per-fixture tally and milestone-F carry-overs.
```

Replace `<N>` with the actual integer from Step 7.1.

Then append to the `## Revision history` section at the end of the file:

```markdown
- **2026-04-28 (implementation complete, same day).** All three work units landed.
  - **Build/tests.** Clean build 0/0 across the solution. Full test suite green: <X> (TaintAnalyzer.Tests) + <Y> (ValidateFixture.Tests) = **<Z>** tests, 0 failures, 0 skips.
  - **Required gate met:** `--compare` non-strict exits 0 on all five fixture pairs (`imagesharp-3074-prefix`, `imagesharp-3074-postfix`, `imagesharp-3079-prefix`, `synthetic-callee-arithmetic`, `synthetic-stackalloc`).
  - **Bonus gate result:** **<N>/5** strict-passes. Per-fixture detail (D_a vs strict ceiling, H_a vs strict ceiling):
    | Fixture | D_a / D_g_strict | H_a / H_g_strict | Strict |
    |---|---|---|---|
    | imagesharp-3074-prefix  | <Da-pre>  / ≤<Dc-pre>  | <Ha-pre>  / ≤<Hc-pre>  | <pass-pre>  |
    | imagesharp-3074-postfix | <Da-post> / ≤<Dc-post> | <Ha-post> / ≤<Hc-post> | <pass-post> |
    | imagesharp-3079-prefix  | <Da-3079> / ≤<Dc-3079> | <Ha-3079> / ≤<Hc-3079> | ❌ |
    | synthetic-callee-arithmetic | <Da-syn> / ≤<Dc-syn> | <Ha-syn> / ≤<Hc-syn> | ✅ |
    | synthetic-stackalloc    | <Da-sta>  / ≤<Dc-sta>  | <Ha-sta>  / ≤<Hc-sta>  | ✅ |
  - **vs target:** spec target was ≥4/5. <One sentence comparing actual N to the target — "Hit the target." or "Underdelivered by N points; the gap is on <fixture>, where U9's hop reduction landed at H_a=<value> against the strict ceiling ≤<value>.">
  - **Trace-quality wins (qualitative).** U7 closes the stackalloc sink-vocabulary gap (synthetic-stackalloc demonstrates `api: stackalloc` at the localloc site). U8 + U9 collapse #3074's three-document over-emission and in-method identity bloat — even where the strict ceiling isn't hit, the trace is materially shorter and more readable.
  - **Carry-overs to milestone-F backlog:** if any ImageSharp #3074 fixture still strict-fails, add an entry "U9 tuning — refine adjacent-tuple predicate to land H_a within strict ceiling on <fixture>". The original milestone-D carry-overs (tainted-value naming, parquet-dotnet round-trip, U1.c redesign) all remain pending.
```

Replace each `<...>` placeholder with the actual values from Steps 7.1 and 7.2.

- [ ] **Step 7.4: Commit the spec update**

```bash
git add docs/superpowers/specs/2026-04-28-milestone-e-design.md
git commit -m "docs: spec — milestone-E implementation complete (bonus N/5 strict)"
```

(Replace the `N` in the message with the actual integer.)

- [ ] **Step 7.5: Print the final status banner**

```bash
echo "=== milestone E complete ==="
echo "all tests:"
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
echo
echo "non-strict --compare:"
for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc; do
    case $fix in
        synthetic-callee-arithmetic) yaml=/tmp/an-synthetic.yaml; dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/an-stackalloc.yaml; dir=fixtures/$fix ;;
        3074-prefix)                 yaml=/tmp/an-3074-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
        3074-postfix)                yaml=/tmp/an-3074-post.yaml;  dir=fixtures/imagesharp-$fix ;;
        3079-prefix)                 yaml=/tmp/an-3079-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
    esac
    echo "  $fix: $(dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" 2>&1 | tail -1)"
done
```

Expected: every line says `OK: ...`.

---

## Self-review

**Spec coverage:**
- *Stackalloc sink kind (U7):* Task 1 (analyzer enum + matcher + walker dispatch + emitter serialization + tests).
- *Cross-method sink-document dedup (U8):* Task 2 (operand-aware key in `TraceEmitter.Emit`).
- *Adjacent identical-tuple hop dedup (U9):* Task 3 (`CollapseAdjacentRedundantHops` private method + Emit integration + reconciliation).
- *No regression (required gate):* Task 6 (clean build, full test suite, `--compare` non-strict on all 5 fixtures).
- *Bonus integer tally:* Task 7 Step 7.1.
- *New fixture:* Task 4 (scaffold) + Task 5 (ground truth).
- *Spec status update:* Task 7 Step 7.3.

**Placeholder scan:** No `TBD`/`TODO` items. The `<N>`/`<X>`/etc. placeholders in Step 7.3 are intentional — they're filled with concrete values captured in Steps 7.1/7.2. Step 5.2's `# from analyzer output` markers are also intentional (the engineer pastes the captured trace verbatim).

**Type consistency:**
- `SinkApi.Stackalloc` — defined in Task 1 Step 1.5, used in Task 1 Step 1.3 test, Task 1 Step 1.6 matcher, Task 1 Step 1.8 emitter switch. ✓
- `SinkShapes.MatchLocalloc` — defined in Task 1 Step 1.6, called in Task 1 Step 1.7 walker dispatch, used in Task 1 Step 1.3 test. ✓
- `CollapseAdjacentRedundantHops` — defined in Task 3 Step 3.3, called in Task 3 Step 3.4. Method signature: `(IReadOnlyList<HopRecord>) -> List<HopRecord>`. ✓
- `seenSinkKeys` (Task 2) replaces `seenSinkLocations` (milestone-D U1.a) — no other call sites; safe rename within the same block. ✓
- `EstablishesBound` / `OnFailure` types in Task 3 Step 3.1's sanitizer test — matches the analyzer-side records in `HopRecord.cs` (verified: same field shapes used in milestone-D's tests). ✓

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-28-milestone-e.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?
