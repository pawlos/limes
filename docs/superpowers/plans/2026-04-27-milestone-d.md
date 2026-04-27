# Milestone D: Trace quality + over-emission budget — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement four work units against the analyzer + validator. (1) FX064 over-emission budget with `--strict` flag in the validator; (2) same-method identity-hop filter in `TaintWalker`; (3) opcode-aware operand-name rendering for arithmetic hops; (4) sink-document `(method, line)` dedup in `TraceEmitter` (U1.a). U1.c (sanitizer-suppressed-path pruning) was scoped here originally, attempted in Task 5, reverted, and deferred to milestone-E — see Task 5 status. Plus a new committed fixture `fixtures/synthetic-callee-arithmetic/`.

**Architecture:** All analyzer-side changes are localized: U2 in `TaintWalker.HandleCall` (around line 869), U3 in `TaintWalker.CombineProvenance`, U1.a in `TraceEmitter.Emit` (U1.c reverted). Validator-side: U4 adds a new `Comparator` method called once per `--compare` invocation from `Program.RunCompare`, plus a `--strict` CLI flag. New fixture lives outside the solution as a standalone csproj built by a dedicated script.

**Tech Stack:** .NET 10 SDK (pinned `global.json`); Mono.Cecil 0.11.6 (already referenced); YamlDotNet 15.1.6; xUnit 2.9.3; Shouldly 4.3.0. New fixture targets net8.0 (matches ImageSharp fixtures).

**Spec reference:** `docs/superpowers/specs/2026-04-27-milestone-d-design.md` at commits `cb00f92` → `e8e3333`.

---

## File Structure

**Modified analyzer — `tools/TaintAnalyzer/`:**
- `TaintWalker.cs`
  - `HandleCall` (around line 844-879) — add same-method identity filter (U2).
  - `CombineProvenance` (line 1152) — accept opcode, render operator-aware combined name (U3).
  - Pass opcode from arithmetic emission site (line 469) to `CombineProvenance`.
- `TraceEmitter.cs`
  - `Emit` (line 26 onwards) — add `(method, line)` sink dedup before main loop (U1.a). U1.c was reverted; see Task 5.

**Modified validator — `tools/ValidateFixture/`:**
- `Comparator.cs` — add `CompareBudget(...)` method that returns FX064 diagnostics.
- `Program.cs` — recognize `--strict` flag, call `Comparator.CompareBudget`, treat FX064 as warning (default) or failure (strict).

**Modified tests — `tools/TaintAnalyzer.Tests/` and `tools/ValidateFixture.Tests/`:**
- `TaintWalkerTests.cs` — add tests for U2 (same-method identity filter) and U3 (operator-aware operand names).
- `TraceEmitterTests.cs` — add tests for U1.a (dedup). U1.c tests reverted with Task 5.
- `ComparatorTests.cs` — add tests for FX064 (default warning, strict failure, equality at ceiling).
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — new test methods exercising U2/U3 IL shapes.

**New fixture — `fixtures/synthetic-callee-arithmetic/`:**
- `rules.yaml` — names `WireDecoder.Decode` as source.
- `trace.yaml` — ground-truth single document with arithmetic propagator hop.
- `source/Decoder.csproj` — net8.0 library, portable PDB.
- `source/Decoder.cs` — `WireDecoder` + `WireReader` + `PayloadSizer` (canonical u16×u16 → byte[N]).
- `source/README.md` — 5-line description.
- `snippets/decoder-snippet.txt` — offending lines for cross-reference.

**New script — `scripts/build-synthetic-callee-arithmetic.sh`:**
- Builds `Decoder.csproj` to `artifacts/synthetic-callee-arithmetic/`.

---

## Task overview

1. FX064 budget diagnostic + `--strict` flag (validator-only; preserves existing `--compare` behavior).
2. U2 — same-method identity hop filter in `TaintWalker.HandleCall`.
3. U3 — operator-aware `CombineProvenance` for arithmetic hop value-out names.
4. U1.a — sink-document dedup by `(method, line)` in `TraceEmitter.Emit`.
5. ~~U1.c — sanitizer-suppressed-path pruning in `TraceEmitter.Emit`~~ — **DEFERRED to milestone-E** (implemented, reviewed, reverted; see Task 5).
6. Synthetic fixture scaffold — `Decoder.csproj` + source + build script.
7. Synthetic fixture ground truth — capture analyzer output, write `trace.yaml`, verify arithmetic hop is present at `*` site.
8. Required-gate cross-check — clean build, full test suite, `--compare` non-strict on all 4 fixtures.
9. Bonus tally — `--compare --strict` on all 4 fixtures, count exit-0 results, record in spec revision history.

---

## Task 1: FX064 budget diagnostic + `--strict` flag

**Files:**
- Modify: `tools/ValidateFixture/Comparator.cs:16-60` (add `CompareBudget` method)
- Modify: `tools/ValidateFixture/Program.cs:71-144` (parse `--strict`, call `CompareBudget`, classify diagnostics)
- Test: `tools/ValidateFixture.Tests/ComparatorTests.cs` (new test class section)

- [ ] **Step 1.1: Write the failing test for default-mode within ceiling**

Add to `tools/ValidateFixture.Tests/ComparatorTests.cs`:

```csharp
[Fact]
public void CompareBudget_DefaultMode_AtCeiling_NoDiagnostic()
{
    // Default ceiling: D_a ≤ 3·D_g + 1, H_a ≤ 5·H_g + 10.
    // GT: 1 doc, 3 hops. Default ceiling: 4 docs, 25 hops.
    var gt = new[] { MakeDoc(numPathHops: 3) };
    var an = new[] { MakeDoc(numPathHops: 25), MakeDoc(numPathHops: 0), MakeDoc(numPathHops: 0), MakeDoc(numPathHops: 0) };
    var diags = new Comparator().CompareBudget(gt, an, strict: false);
    diags.ShouldBeEmpty();
}

private static FixtureDocument MakeDoc(int numPathHops)
{
    var path = new List<PathNode>();
    for (int i = 0; i < numPathHops; i++)
    {
        path.Add(new PathNode { Hop = i, Method = "M", File = "F.cs", Line = 1, Role = "propagator", TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x" });
    }
    return new FixtureDocument
    {
        VulnId = "test",
        Source = new PathNode { Method = "M", File = "F.cs", Line = 1, Role = "source", Kind = "decoder_entry", TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream" },
        Sink   = new PathNode { Method = "M", File = "F.cs", Line = 99, Role = "sink", Kind = "allocation", Api = "new_array", TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size", SizeExpression = "size" },
        Path = path,
        SanitizerAbsence = new List<SanitizerAbsence>(),
    };
}
```

- [ ] **Step 1.2: Run the test to verify it fails (compile error)**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo --filter FullyQualifiedName~CompareBudget_DefaultMode_AtCeiling_NoDiagnostic`
Expected: build error — `Comparator.CompareBudget` doesn't exist.

- [ ] **Step 1.3: Implement `CompareBudget` minimally to make the test pass**

Append to `tools/ValidateFixture/Comparator.cs` (inside the `Comparator` class, before the closing brace at line 351):

```csharp
// FX064: over-emission budget. Counts documents and total hops on each side.
// Default mode: D_a ≤ 3·D_g + 1, H_a ≤ 5·H_g + 10 (warnings only — exit code unchanged).
// Strict mode:  D_a ≤ D_g,        H_a ≤ 2·H_g       (failures — caller exits 1).
// `strict` only affects the diagnostic code returned; the caller decides exit code.
public IReadOnlyList<Diagnostic> CompareBudget(
    IReadOnlyList<FixtureDocument> groundTruth,
    IReadOnlyList<FixtureDocument> analyzer,
    bool strict)
{
    var diagnostics = new List<Diagnostic>();
    int dG = groundTruth.Count;
    int dA = analyzer.Count;
    int hG = groundTruth.Sum(d => d.Path?.Count ?? 0);
    int hA = analyzer.Sum(d => d.Path?.Count ?? 0);

    int dCeiling = strict ? dG : 3 * dG + 1;
    int hCeiling = strict ? 2 * hG : 5 * hG + 10;

    if (dA > dCeiling)
    {
        diagnostics.Add(new Diagnostic("FX064",
            $"budget exceeded: documents D_a={dA} (≤{dCeiling}) [{(strict ? "strict" : "default")} mode]"));
    }
    if (hA > hCeiling)
    {
        diagnostics.Add(new Diagnostic("FX064",
            $"budget exceeded: hops H_a={hA} (≤{hCeiling}) [{(strict ? "strict" : "default")} mode]"));
    }
    return diagnostics;
}
```

- [ ] **Step 1.4: Run the test to verify it passes**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo --filter FullyQualifiedName~CompareBudget_DefaultMode_AtCeiling_NoDiagnostic`
Expected: PASS.

- [ ] **Step 1.5: Add the remaining FX064 test cases**

Append after the `CompareBudget_DefaultMode_AtCeiling_NoDiagnostic` test:

```csharp
[Fact]
public void CompareBudget_DefaultMode_DocCountExceeds_ReportsFX064()
{
    var gt = new[] { MakeDoc(0) };
    var an = new[] { MakeDoc(0), MakeDoc(0), MakeDoc(0), MakeDoc(0), MakeDoc(0) }; // 5 > 4
    var diags = new Comparator().CompareBudget(gt, an, strict: false);
    diags.ShouldContain(d => d.Code == "FX064" && d.Message.Contains("documents"));
}

[Fact]
public void CompareBudget_DefaultMode_HopCountExceeds_ReportsFX064()
{
    var gt = new[] { MakeDoc(3) };
    var an = new[] { MakeDoc(26) }; // 26 > 25
    var diags = new Comparator().CompareBudget(gt, an, strict: false);
    diags.ShouldContain(d => d.Code == "FX064" && d.Message.Contains("hops"));
}

[Fact]
public void CompareBudget_StrictMode_DocCountStrictlyAboveGt_ReportsFX064()
{
    var gt = new[] { MakeDoc(0) };
    var an = new[] { MakeDoc(0), MakeDoc(0) }; // 2 > 1
    var diags = new Comparator().CompareBudget(gt, an, strict: true);
    diags.ShouldContain(d => d.Code == "FX064" && d.Message.Contains("strict"));
}

[Fact]
public void CompareBudget_StrictMode_AtCeiling_NoDiagnostic()
{
    var gt = new[] { MakeDoc(3) };
    var an = new[] { MakeDoc(6) }; // strict hop ceiling = 2·3 = 6
    var diags = new Comparator().CompareBudget(gt, an, strict: true);
    diags.ShouldBeEmpty();
}

[Fact]
public void CompareBudget_GroundTruthZeroHops_DefensiveCeiling()
{
    // H_g = 0 → default ceiling = 10, strict ceiling = 0.
    var gt = new[] { MakeDoc(0) };
    var an = new[] { MakeDoc(10) };
    var defaultDiags = new Comparator().CompareBudget(gt, an, strict: false);
    defaultDiags.ShouldBeEmpty();
    var strictDiags = new Comparator().CompareBudget(gt, an, strict: true);
    strictDiags.ShouldContain(d => d.Code == "FX064");
}
```

- [ ] **Step 1.6: Run all FX064 tests to verify they pass**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo --filter FullyQualifiedName~CompareBudget`
Expected: 5 tests pass.

- [ ] **Step 1.7: Wire `--strict` flag into `Program.RunCompare`**

In `tools/ValidateFixture/Program.cs`, replace the `RunCompare` method body (lines 71-144) so it accepts an optional `--strict` flag and calls `Comparator.CompareBudget`. Replace this block:

```csharp
private static int RunCompare(string[] args)
{
    if (args.Length != 3)
    {
        Console.Error.WriteLine("error: --compare requires exactly two paths");
        PrintUsage();
        return 2;
    }

    var groundTruthPath = args[1];
    var analyzerPath = args[2];
```

with:

```csharp
private static int RunCompare(string[] args)
{
    // Accepted forms:
    //   --compare <gt> <an>
    //   --compare <gt> <an> --strict
    //   --compare --strict <gt> <an>
    bool strict = false;
    var positional = new List<string>();
    for (int i = 1; i < args.Length; i++)
    {
        if (args[i] == "--strict") { strict = true; continue; }
        positional.Add(args[i]);
    }
    if (positional.Count != 2)
    {
        Console.Error.WriteLine("error: --compare requires exactly two paths");
        PrintUsage();
        return 2;
    }

    var groundTruthPath = positional[0];
    var analyzerPath = positional[1];
```

Then, AFTER the existing `foreach (var gt in gtDocs) { allDiagnostics.AddRange(...); }` loop and BEFORE the `foreach (var d in allDiagnostics)` print loop (currently line 130), add:

```csharp
    var budgetDiagnostics = comparator.CompareBudget(gtDocs, anDocs, strict);
```

Then change the `foreach (var d in allDiagnostics)` print block so budget diagnostics are printed alongside but counted separately for the exit code:

```csharp
    foreach (var d in allDiagnostics)
    {
        Console.Error.WriteLine($"{d.Code} {d.Message}");
    }
    foreach (var d in budgetDiagnostics)
    {
        // Default mode: print to stderr but don't fail. Strict mode: counts toward failures.
        Console.Error.WriteLine($"{d.Code} {d.Message}");
    }

    var failures = allDiagnostics.Count(d => d.Code != "FX-info");
    if (strict) failures += budgetDiagnostics.Count;
    if (failures == 0)
    {
        Console.WriteLine($"OK: {analyzerPath} matches {groundTruthPath}");
        return 0;
    }

    Console.Error.WriteLine($"FAIL: {failures} mismatch diagnostic(s)");
    return 1;
```

(Delete the old block that begins with `foreach (var d in allDiagnostics)` through the end of the existing `RunCompare` body — the replacement above subsumes it.)

Also update `PrintUsage`:

```csharp
private static void PrintUsage()
{
    Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
    Console.Error.WriteLine("       ValidateFixture --compare [--strict] <ground-truth.yaml> <analyzer-output.yaml>");
}
```

- [ ] **Step 1.8: Run the full validator test suite to confirm no regressions**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo`
Expected: all tests pass (existing FX060/FX061/FX062/FX063 tests + new FX064 tests).

- [ ] **Step 1.9: Smoke test the existing fixtures (non-strict — must still exit 0)**

Run from repo root:
```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
dotnet run --project tools/TaintAnalyzer -- "$PRE3074" --rules fixtures/imagesharp-3074-prefix/rules.yaml --output /tmp/an-3074-pre.yaml >/dev/null 2>&1
dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/an-3074-pre.yaml
echo "exit=$?"
```
Expected: stderr shows `FX064 budget exceeded: documents D_a=3 (≤4)` (or similar — the existing 3 docs and ~261 total hops likely exceed 5·H_g + 10 too); stdout shows `OK:`; exit code 0.

The FX064 warning IS expected — that's the whole point. Required-gate item: exit code stays 0 in default mode.

- [ ] **Step 1.10: Commit**

```bash
git add tools/ValidateFixture/Comparator.cs tools/ValidateFixture/Program.cs tools/ValidateFixture.Tests/ComparatorTests.cs
git commit -m "validator: FX064 over-emission budget + --strict flag (Task 1)"
```

---

## Task 2: U2 — same-method identity hop filter in `TaintWalker.HandleCall`

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:843-879` (the call-boundary hop emission block)
- Test: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (add U2 cases)
- Test fixture: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (add `IdentityFilterFixtures`)

- [ ] **Step 2.1: Author the test fixture**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
// Drives U2 (same-method identity-hop filter). The decoder body invokes two helper methods
// in sequence; both have tainted return values that the analyzer would otherwise emit as
// identity hops on the call boundary. After U2: only the cross-method boundaries are
// emitted (not the two consecutive same-method identity rebroadcasts).
public static class IdentityFilterFixtures
{
    public static int Decode(byte[] stream)
    {
        var lengthA = ReadLength(stream);
        var lengthB = ReadLength(stream);
        return new int[lengthA + lengthB][0];   // sink — array allocation with tainted size
    }

    public static int ReadLength(byte[] s) => s[0];
}
```

(Note: the `new int[…][0]` form forces an array allocation of tainted size that's also indexed; the analyzer should emit a `new_array` sink hop. The exact code shape can be adjusted at implementation time if the test fixture project doesn't compile with that syntax — the goal is "two consecutive same-method calls returning tainted values, leading to a sink".)

- [ ] **Step 2.2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo`
Expected: 0 errors.

- [ ] **Step 2.3: Write the failing test**

Append to `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`:

```csharp
[Fact]
public void Walk_SameMethodIdentityHops_AreFiltered()
{
    using var asmCtx = TestFixtureContext.Open();
    var method = asmCtx.FindMethod("TaintAnalyzer.Tests.Fixtures.IdentityFilterFixtures::Decode(System.Byte[])");
    var walker = new TaintWalker(asmCtx);
    var summary = walker.Walk(method, taintedParamBitmask: 0b1);

    // Hops in the same method (`Decode`) with role=propagator AND transformation=identity AND
    // method matching the previous emitted hop's method should not appear. Cross-method
    // identity hops (entries into ReadLength) ARE preserved.
    var sameMethodIdentityHops = summary.Hops
        .Where(h => h.Role == HopRole.Propagator
                 && h.Transformation == "identity"
                 && h.Method.EndsWith(".Decode"))
        .ToList();
    sameMethodIdentityHops.ShouldBeEmpty();

    // The cross-method call into ReadLength should still be present (it's an identity hop
    // attributed to ReadLength's method label, not Decode's — different method, preserved).
    summary.Hops.ShouldContain(h => h.Method.EndsWith(".ReadLength"));
}
```

(`TestFixtureContext.Open()` and `FindMethod` patterns — match the convention used by existing TaintWalkerTests; if they don't exist as helpers, inline the setup with `AssemblyContext.Load(...)` directly.)

- [ ] **Step 2.4: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Walk_SameMethodIdentityHops_AreFiltered`
Expected: FAIL — same-method identity hops are present.

- [ ] **Step 2.5: Implement the filter in `HandleCall`**

In `tools/TaintAnalyzer/TaintWalker.cs`, modify the block starting at line 843 (`// Emit a propagator hop for the call boundary if any taint flowed through ...`). Replace just the `EmitPropagatorHop` call (line 869) with a guarded version. Find:

```csharp
            EmitPropagatorHop(callerMethod, ins, "identity", valueIn, valueOut, dispatch, hops, ref hopCounter);
```

Replace with:

```csharp
            // U2: skip emitting an identity propagator hop when the previous emitted hop is in
            // the SAME method. Cross-method identity hops (call-boundary signal where method
            // changes) are preserved. The previous-hop check uses Method-string equality rather
            // than IL-region containment because hop labels mirror the user-facing trace.
            string callerMethodLabel = $"{callerMethod.DeclaringType.FullName}.{callerMethod.Name}";
            bool sameMethodAsPrev = hops.Count > 0 && hops[^1].Method == callerMethodLabel;
            if (!sameMethodAsPrev)
            {
                EmitPropagatorHop(callerMethod, ins, "identity", valueIn, valueOut, dispatch, hops, ref hopCounter);
            }
```

- [ ] **Step 2.6: Run the U2 test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Walk_SameMethodIdentityHops_AreFiltered`
Expected: PASS.

- [ ] **Step 2.7: Run the full analyzer test suite to confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all tests pass.

- [ ] **Step 2.8: Run all existing fixtures (non-strict `--compare`) to confirm no regression**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

for fix in 3074-prefix 3074-postfix 3079-prefix; do
    case $fix in
      3074-prefix)  dll="$PRE3074" ;;
      3074-postfix) dll="$POST3074" ;;
      3079-prefix)  dll="$PRE3079" ;;
    esac
    dotnet run --project tools/TaintAnalyzer -- "$dll" --rules fixtures/imagesharp-$fix/rules.yaml --output /tmp/an-$fix.yaml >/dev/null 2>&1
    dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-$fix/trace.yaml /tmp/an-$fix.yaml >/dev/null
    echo "$fix exit=$?"
done
```
Expected: all three lines say `exit=0` (FX064 warnings on stderr are OK; non-strict gate is exit-code only).

- [ ] **Step 2.9: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: U2 — same-method identity hop filter (Task 2)"
```

---

## Task 3: U3 — operator-aware operand-name rendering

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:447-479` (arithmetic emit site — pass opcode)
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:1152-1156` (`CombineProvenance` — opcode-aware operator)
- Test: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (new operator-rendering cases)
- Test fixture: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (add `ArithmeticOperatorFixtures`)

**Background.** The arithmetic-hop emission already works (line 472 — all opcodes Add through Mul_Ovf_Un already trigger emission). What's missing is the operator name in the combined operand-name string: `CombineProvenance` always renders `a+b` regardless of opcode. So `recordCount * recordStride` shows up as `recordCount+recordStride` in the trace.

- [ ] **Step 3.1: Author the test fixture**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
// Drives U3 (operator-aware operand-name rendering for arithmetic hops).
public static class ArithmeticOperatorFixtures
{
    public static int MulPath(int a, int b) => a * b;
    public static int DivPath(int a, int b) => a / b;
    public static int ShlPath(int a, int b) => a << b;
    public static int ShrPath(int a, int b) => a >> b;
}
```

- [ ] **Step 3.2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo`
Expected: 0 errors.

- [ ] **Step 3.3: Write the failing test**

Append to `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`:

```csharp
[Theory]
[InlineData("MulPath", "*")]
[InlineData("DivPath", "/")]
[InlineData("ShlPath", "<<")]
[InlineData("ShrPath", ">>")]
public void Walk_ArithmeticHop_UsesOperatorAwareOperandName(string methodName, string expectedOp)
{
    using var asmCtx = TestFixtureContext.Open();
    var method = asmCtx.FindMethod($"TaintAnalyzer.Tests.Fixtures.ArithmeticOperatorFixtures::{methodName}(System.Int32,System.Int32)");
    var walker = new TaintWalker(asmCtx);
    var summary = walker.Walk(method, taintedParamBitmask: 0b11);

    // Expect a propagator hop with transformation=arithmetic whose tainted_value_out
    // contains the operator (e.g., "a*b", "a+b", etc.).
    var arithHop = summary.Hops.FirstOrDefault(h => h.Transformation == "arithmetic");
    arithHop.ShouldNotBeNull();
    arithHop.TaintedValueOut.ShouldContain(expectedOp);
}
```

- [ ] **Step 3.4: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Walk_ArithmeticHop_UsesOperatorAwareOperandName`
Expected: FAIL — operand name uses `+` for all operators.

- [ ] **Step 3.5: Make `CombineProvenance` opcode-aware**

In `tools/TaintAnalyzer/TaintWalker.cs`, replace the existing `CombineProvenance` (lines 1152-1156):

```csharp
private static string CombineProvenance(StackSlot a, StackSlot b)
{
    if (a.Tainted && b.Tainted) return $"{a.Provenance}+{b.Provenance}";
    return a.Tainted ? a.Provenance : b.Provenance;
}
```

with:

```csharp
private static string CombineProvenance(StackSlot a, StackSlot b, OpCode? op = null)
{
    if (a.Tainted && b.Tainted)
    {
        var sep = op?.Code switch
        {
            Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un => "*",
            Code.Div or Code.Div_Un => "/",
            Code.Rem or Code.Rem_Un => "%",
            Code.Shl => "<<",
            Code.Shr or Code.Shr_Un => ">>",
            Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => "-",
            Code.And => "&",
            Code.Or => "|",
            Code.Xor => "^",
            _ => "+",
        };
        return $"{a.Provenance}{sep}{b.Provenance}";
    }
    return a.Tainted ? a.Provenance : b.Provenance;
}
```

- [ ] **Step 3.6: Pass opcode at the arithmetic-emit call site**

In `tools/TaintAnalyzer/TaintWalker.cs`, find the arithmetic-op block at lines 464-479. Replace the existing call:

```csharp
                    var prov = CombineProvenance(lhs, rhs);
```

with:

```csharp
                    var prov = CombineProvenance(lhs, rhs, ins.OpCode);
```

(Existing callers of `CombineProvenance` that don't pass an opcode continue to work via the optional default — search for any other call sites with `grep CombineProvenance tools/TaintAnalyzer/TaintWalker.cs` to confirm only the one call site exists.)

- [ ] **Step 3.7: Run the U3 test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Walk_ArithmeticHop_UsesOperatorAwareOperandName`
Expected: 4 theory rows pass.

- [ ] **Step 3.8: Run the full analyzer test suite to confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all tests pass.

- [ ] **Step 3.9: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "analyzer: U3 — operator-aware CombineProvenance for arithmetic hops (Task 3)"
```

---

## Task 4: U1.a — sink-document `(method, line)` dedup in `TraceEmitter.Emit`

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:33-49` (sink-index collection)
- Test: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` (new dedup case)

- [ ] **Step 4.1: Write the failing test**

Append to `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs`:

```csharp
[Fact]
public void Emit_TwoSinkHopsAtSameMethodAndLine_ProducesOneDocument()
{
    var rules = new RulesDocument { VulnId = "test-dedup", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
    var sourceHop = new HopRecord
    {
        Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
        TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
    };
    var sink1 = new HopRecord
    {
        Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
        TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size",
        SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size",
    };
    var sink2 = new HopRecord
    {
        // Same method + same line as sink1 — should be deduped.
        Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
        TaintedValueIn = "alt", Transformation = "identity", TaintedValueOut = "alt",
        SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "alt",
    };

    var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sink1, sink2 }, Array.Empty<EmittedSanitizerAbsence>());

    // One YAML document only — no `---` separator should appear since dedup collapses to a single doc.
    yaml.ShouldNotContain("---\n");
    // The first sink wins.
    yaml.ShouldContain("size_expression: size");
    yaml.ShouldNotContain("size_expression: alt");
}
```

- [ ] **Step 4.2: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Emit_TwoSinkHopsAtSameMethodAndLine_ProducesOneDocument`
Expected: FAIL — current emitter produces two documents separated by `---`.

- [ ] **Step 4.3: Implement dedup in `Emit`**

In `tools/TaintAnalyzer/TraceEmitter.cs`, replace the sink-collection block (lines 33-49). Find:

```csharp
        // Index source/sink hops by position in the flat list so we can pair each sink with the
        // most-recent preceding source.
        var sinkIndices = new List<int>();
        var sourceIndices = new List<int>();
        for (int i = 0; i < hops.Count; i++)
        {
            if (hops[i].Role == HopRole.Sink) sinkIndices.Add(i);
            else if (hops[i].Role == HopRole.Source) sourceIndices.Add(i);
        }

        if (sinkIndices.Count == 0)
        {
            // No sinks reached — emit empty output. Caller (Program.cs) writes nothing to stdout
            // / output file, indicating "analyzer found no tainted sink for these rules".
            return "";
        }
```

Replace with:

```csharp
        // Index source/sink hops by position in the flat list so we can pair each sink with the
        // most-recent preceding source.
        var rawSinkIndices = new List<int>();
        var sourceIndices = new List<int>();
        for (int i = 0; i < hops.Count; i++)
        {
            if (hops[i].Role == HopRole.Sink) rawSinkIndices.Add(i);
            else if (hops[i].Role == HopRole.Source) sourceIndices.Add(i);
        }

        if (rawSinkIndices.Count == 0)
        {
            // No sinks reached — emit empty output. Caller (Program.cs) writes nothing to stdout
            // / output file, indicating "analyzer found no tainted sink for these rules".
            return "";
        }

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

- [ ] **Step 4.4: Run the dedup test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter FullyQualifiedName~Emit_TwoSinkHopsAtSameMethodAndLine_ProducesOneDocument`
Expected: PASS.

- [ ] **Step 4.5: Run the full analyzer test suite to confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo`
Expected: all tests pass.

- [ ] **Step 4.6: Verify existing fixtures still `--compare` exit 0 (non-strict)**

```bash
for fix in 3074-prefix 3074-postfix 3079-prefix; do
    dll=$(case $fix in
        3074-prefix)  echo "artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll" ;;
        3074-postfix) echo "artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll" ;;
        3079-prefix)  echo "artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll" ;;
    esac)
    dotnet run --project tools/TaintAnalyzer -- "$dll" --rules fixtures/imagesharp-$fix/rules.yaml --output /tmp/an-$fix.yaml >/dev/null 2>&1
    dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-$fix/trace.yaml /tmp/an-$fix.yaml >/dev/null
    echo "$fix exit=$?"
done
```
Expected: all three lines say `exit=0`.

- [ ] **Step 4.7: Commit**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer.Tests/TraceEmitterTests.cs
git commit -m "analyzer: U1.a — sink-document (method, line) dedup (Task 4)"
```

---

## Task 5: U1.c — sanitizer-suppressed-path pruning in `TraceEmitter.Emit` — **DEFERRED to milestone-E**

Status: implemented in commit c916ea5, reviewed, **reverted in commit ac55e42** (`git revert c916ea5`).

Reason: U1.c reuses the existing chain-walker (`BuildTransitiveValueChainTokens`), which fires on the same shape that defines a *post-fix fixture's* sanitized sink. Suppressing those documents semantically breaks the post-fix fixtures' purpose ("demonstrate analyzer recognizes the fix"). To keep `--compare` exit 0 the implementer changed the post-fix ground truth to point at a different sink (`ProfileSize`), which papered over the conflict rather than resolving it. Meanwhile #3079 — the over-emission target U1.c was supposed to help — has mostly *sibling-guard* sanitizers (bounding `compressionFlag` while the sink uses `translatedKeywordLength`) that don't overlap the chain, so U1.c barely reduces noise there. Net-negative trade.

Deferred to milestone-E for redesign that distinguishes "fixture-author-meaningful sanitizer bound" from "noisy sibling-guard". See spec revision history dated 2026-04-27 (de-scope, same day) for detail.

Skip directly to Task 6.

---

## Task 6: Synthetic fixture scaffold — `Decoder.csproj` + source + build script

**Files:**
- Create: `fixtures/synthetic-callee-arithmetic/source/Decoder.csproj`
- Create: `fixtures/synthetic-callee-arithmetic/source/Decoder.cs`
- Create: `fixtures/synthetic-callee-arithmetic/source/README.md`
- Create: `fixtures/synthetic-callee-arithmetic/snippets/decoder-snippet.txt`
- Create: `fixtures/synthetic-callee-arithmetic/rules.yaml`
- Create: `scripts/build-synthetic-callee-arithmetic.sh`

(Ground truth `trace.yaml` is authored in Task 7 once the analyzer's output is captured.)

- [ ] **Step 6.1: Create the source csproj**

Write `fixtures/synthetic-callee-arithmetic/source/Decoder.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <DebugType>portable</DebugType>
    <DebugSymbols>true</DebugSymbols>
    <Optimize>false</Optimize>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>SyntheticCalleeArithmetic</RootNamespace>
    <AssemblyName>Decoder</AssemblyName>
    <OutputType>Library</OutputType>
  </PropertyGroup>
</Project>
```

- [ ] **Step 6.2: Create the source file**

Write `fixtures/synthetic-callee-arithmetic/source/Decoder.cs`:

```csharp
using System.IO;

namespace SyntheticCalleeArithmetic;

public sealed class WireDecoder
{
    private readonly Stream _stream;

    public WireDecoder(Stream stream)
    {
        _stream = stream;
    }

    public byte[] Decode()
    {
        var reader = new WireReader(_stream);
        ushort recordCount = reader.ReadU16();
        ushort recordStride = reader.ReadU16();
        int totalBytes = PayloadSizer.RecordsAreaBytes(recordCount, recordStride);
        return new byte[totalBytes];
    }
}

internal static class PayloadSizer
{
    internal static int RecordsAreaBytes(ushort count, ushort stride)
    {
        return (int)count * (int)stride;
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

- [ ] **Step 6.3: Create the README**

Write `fixtures/synthetic-callee-arithmetic/source/README.md`:

```markdown
# synthetic-callee-arithmetic — milestone-D regression fixture

`WireDecoder.Decode` reads two u16 fields from a stream and multiplies them via a helper
class (`PayloadSizer.RecordsAreaBytes`). The product is used as the size of a `new byte[N]`
allocation. The multiplication happens inside the helper's return path — a shape that
exposed the milestone-D arithmetic-attribution gap when run blind through the analyzer.

The fixture is built outside the main solution by `scripts/build-synthetic-callee-arithmetic.sh`,
producing `artifacts/synthetic-callee-arithmetic/Decoder.dll` (+ `.pdb`).
```

- [ ] **Step 6.4: Create the rules file**

Write `fixtures/synthetic-callee-arithmetic/rules.yaml`:

```yaml
vuln_id: synthetic-callee-arithmetic
source_methods:
  - signature: SyntheticCalleeArithmetic.WireDecoder::Decode()
```

- [ ] **Step 6.5: Create the snippets file**

Write `fixtures/synthetic-callee-arithmetic/snippets/decoder-snippet.txt`:

```
        ushort recordCount = reader.ReadU16();
        ushort recordStride = reader.ReadU16();
        int totalBytes = PayloadSizer.RecordsAreaBytes(recordCount, recordStride);
        return new byte[totalBytes];

internal static int RecordsAreaBytes(ushort count, ushort stride)
{
    return (int)count * (int)stride;
}
```

- [ ] **Step 6.6: Create the build script**

Write `scripts/build-synthetic-callee-arithmetic.sh`:

```bash
#!/usr/bin/env bash
# Builds fixtures/synthetic-callee-arithmetic/source/Decoder.csproj into
# artifacts/synthetic-callee-arithmetic/. Mirrors the materialize-imagesharp scripts
# but uses an in-tree source tree instead of a `git archive | tar -x` extraction.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/synthetic-callee-arithmetic/source"
OUT_DIR="$REPO_ROOT/artifacts/synthetic-callee-arithmetic"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/Decoder.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet \
    /p:GenerateDocumentationFile=false

echo "synthetic-callee-arithmetic built at $OUT_DIR/Decoder.dll"
```

Then make it executable:

```bash
chmod +x scripts/build-synthetic-callee-arithmetic.sh
```

- [ ] **Step 6.7: Run the build script and confirm output**

Run: `scripts/build-synthetic-callee-arithmetic.sh`
Expected: stdout ends with `synthetic-callee-arithmetic built at .../Decoder.dll`. Exit code 0. `artifacts/synthetic-callee-arithmetic/Decoder.dll` and `.pdb` exist.

- [ ] **Step 6.8: Commit**

```bash
git add fixtures/synthetic-callee-arithmetic/ scripts/build-synthetic-callee-arithmetic.sh
git commit -m "fixture+scripts: synthetic-callee-arithmetic source + build script (Task 6)"
```

---

## Task 7: Synthetic fixture ground truth — capture analyzer output, write `trace.yaml`

**Files:**
- Create: `fixtures/synthetic-callee-arithmetic/trace.yaml`

The ground truth is authored AFTER U1/U2/U3 land so it reflects the cleaned-up trace, per spec.

- [ ] **Step 7.1: Run the analyzer against the synthetic fixture**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet run --project tools/TaintAnalyzer -- \
    artifacts/synthetic-callee-arithmetic/Decoder.dll \
    --rules fixtures/synthetic-callee-arithmetic/rules.yaml \
    --output /tmp/an-synthetic.yaml
```
Expected: exit 0; `/tmp/an-synthetic.yaml` exists.

- [ ] **Step 7.2: Inspect the analyzer output**

Run: `cat /tmp/an-synthetic.yaml`
Expected: a single document with:
- `source.method: SyntheticCalleeArithmetic.WireDecoder.Decode`
- `sink.method: SyntheticCalleeArithmetic.WireDecoder.Decode`, `sink.api: new_array`, `sink.size_expression: totalBytes` (or similar)
- A propagator hop with `transformation: arithmetic`, `method: SyntheticCalleeArithmetic.PayloadSizer.RecordsAreaBytes`, value-out containing `*` (e.g. `count*stride`)

If no arithmetic hop is present at the `*` site, U3 didn't actually fix the gap — return to Task 3 and refine. If the trace has any `loc_N` names that should be readable, accept as-is for milestone-D (naming is non-goal).

- [ ] **Step 7.3: Adapt the analyzer output into ground truth**

Copy `/tmp/an-synthetic.yaml` to `fixtures/synthetic-callee-arithmetic/trace.yaml`, then add the metadata fields the analyzer doesn't emit (vuln-id stays; add `fix_commit`, `fix_pr`, `description`, plus FX008 `sanitizer_absence` if missing). Use this template — fill in the `# from analyzer output` placeholders verbatim from the captured file:

```yaml
vuln_id: synthetic-callee-arithmetic
fix_commit: ""
fix_pr: ""
description: >
  Synthetic regression fixture for milestone-D arithmetic-attribution gap.
  WireDecoder.Decode reads two u16 fields from a stream, multiplies them via
  PayloadSizer.RecordsAreaBytes (a helper-class return path), and uses the
  product to size a new byte[N] allocation. Models the canonical
  "u16×u16 multiply through a sizing helper" shape observed in real-world
  protocol parsers.

source:
  # from analyzer output

sink:
  # from analyzer output

path:
  # from analyzer output, with `hop:` indices renumbered if the dedup/filter
  # changes the hop count.

sanitizer_absence:
  # from analyzer output — should be one entry pointing at the arithmetic site.
```

(Note: don't paraphrase the analyzer's hops. Copy them verbatim, including `transformation`, `tainted_value_in`, `tainted_value_out`, etc. The whole point of the round-trip is byte-for-byte agreement on hop structure.)

- [ ] **Step 7.4: Run `--compare` to verify the round trip closes**

```bash
dotnet run --project tools/ValidateFixture -- --compare \
    fixtures/synthetic-callee-arithmetic/trace.yaml \
    /tmp/an-synthetic.yaml
echo "exit=$?"
```
Expected: stdout shows `OK: ...`; exit code 0.

If FX060/FX061/FX062/FX063 fires, edit `trace.yaml` to match the analyzer output exactly (this is a fixture-authoring step, not an analyzer-bug step — the ground truth IS the analyzer's expected behavior here). Re-run until exit 0.

- [ ] **Step 7.5: Verify the arithmetic hop is at the `*` site**

```bash
grep -n "transformation: arithmetic" fixtures/synthetic-callee-arithmetic/trace.yaml
grep -B1 "transformation: arithmetic" fixtures/synthetic-callee-arithmetic/trace.yaml | head -5
```

Expected: at least one `transformation: arithmetic` line, with the preceding `line:` value matching the line number of `(int)count * (int)stride` in `Decoder.cs:30` (the `*` operator).

- [ ] **Step 7.6: Commit**

```bash
git add fixtures/synthetic-callee-arithmetic/trace.yaml
git commit -m "fixture: synthetic-callee-arithmetic ground-truth trace.yaml (Task 7)"
```

---

## Task 8: Required-gate cross-check

**Files:** No code changes. Verification only.

- [ ] **Step 8.1: Clean build of the entire solution**

Run:
```bash
find . -type d \( -name bin -o -name obj \) -not -path './artifacts/*' -prune -exec rm -rf {} + 2>&1
dotnet build TaintAnalyzer.sln --nologo
```
Expected: 0 errors, 0 warnings.

- [ ] **Step 8.2: Full test suite**

Run: `dotnet test TaintAnalyzer.sln --nologo`
Expected: all green (current 159 + new tests added in Tasks 1–5). Capture the test counts for the revision-history entry in Task 9.

- [ ] **Step 8.3: `--compare` non-strict on all 4 fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- artifacts/synthetic-callee-arithmetic/Decoder.dll \
    --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic.yaml >/dev/null 2>&1

echo "  3074-prefix:  $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-prefix/trace.yaml  /tmp/an-3074-pre.yaml  2>&1 | tail -1)"
echo "  3074-postfix: $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-postfix/trace.yaml /tmp/an-3074-post.yaml 2>&1 | tail -1)"
echo "  3079-prefix:  $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3079-prefix/trace.yaml  /tmp/an-3079-pre.yaml  2>&1 | tail -1)"
echo "  synthetic:    $(dotnet run --project tools/ValidateFixture -- --compare fixtures/synthetic-callee-arithmetic/trace.yaml /tmp/an-synthetic.yaml 2>&1 | tail -1)"
```

Expected: all four lines say `OK:`. Each says exit 0 (the printed line is the OK message).

- [ ] **Step 8.4: Verify the synthetic fixture's arithmetic hop placement**

```bash
grep -B1 "transformation: arithmetic" fixtures/synthetic-callee-arithmetic/trace.yaml
```
Expected: the line immediately above each `transformation: arithmetic` is `line:` followed by the line number of `(int)count * (int)stride` in `Decoder.cs` (the `*` operator).

- [ ] **Step 8.5: Capture metric snapshot for revision history**

```bash
echo "Document counts (analyzer side):"
for fix in 3074-pre 3074-post 3079-pre synthetic; do
    case $fix in
        synthetic) tracefile="/tmp/an-synthetic.yaml" ;;
        *)         tracefile="/tmp/an-$fix.yaml" ;;
    esac
    docs=$(grep -c '^---' "$tracefile" || true)
    docs=$((docs + 1))    # n separators = n+1 documents
    hops=$(grep -c '^- hop:' "$tracefile" || true)
    echo "  $fix: docs=$docs hops=$hops"
done
```

Save the output for the revision-history entry — these are the post-milestone-D numbers for posterity.

- [ ] **Step 8.6: No commit (verification-only task)**

If any check failed, return to the relevant task and iterate. Once all checks pass, proceed to Task 9.

---

## Task 9: Bonus tally + spec status update

**Files:**
- Modify: `docs/superpowers/specs/2026-04-27-milestone-d-design.md` (status line + revision-history entry)

- [ ] **Step 9.1: Run `--compare --strict` on all 4 fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

# Re-run analyzer (in case Task 8's outputs were cleared).
dotnet run --project tools/TaintAnalyzer -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer -- artifacts/synthetic-callee-arithmetic/Decoder.dll \
    --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic.yaml >/dev/null 2>&1

PASS=0
for fix in "3074-prefix:fixtures/imagesharp-3074-prefix/trace.yaml:/tmp/an-3074-pre.yaml" \
           "3074-postfix:fixtures/imagesharp-3074-postfix/trace.yaml:/tmp/an-3074-post.yaml" \
           "3079-prefix:fixtures/imagesharp-3079-prefix/trace.yaml:/tmp/an-3079-pre.yaml" \
           "synthetic:fixtures/synthetic-callee-arithmetic/trace.yaml:/tmp/an-synthetic.yaml"; do
    name=$(echo "$fix" | cut -d: -f1)
    gt=$(echo "$fix" | cut -d: -f2)
    an=$(echo "$fix" | cut -d: -f3)
    if dotnet run --project tools/ValidateFixture -- --compare --strict "$gt" "$an" >/dev/null 2>&1; then
        echo "  $name: STRICT PASS"
        PASS=$((PASS + 1))
    else
        echo "  $name: STRICT FAIL"
    fi
done
echo "Strict-mode total: $PASS / 4"
```

Expected: `$PASS` is a number ≥ 3 (bonus criterion). Note the result for the revision-history entry.

- [ ] **Step 9.2: Update spec status line**

Edit `docs/superpowers/specs/2026-04-27-milestone-d-design.md`. Find the line:

```
**Status:** Approved 2026-04-27.
```

Replace with:

```
**Status:** Approved 2026-04-27. Implemented 2026-04-27 — required gate met; bonus tally <N>/4 strict-mode passes (see revision history for outcome).
```

Replace `<N>` with the integer from Step 9.1.

- [ ] **Step 9.3: Append revision-history entry**

At the end of the spec, append below the existing revision-history entries:

```markdown
- **2026-04-27 (implementation complete).** All four units landed.
  - **U1.a (`TraceEmitter.Emit`).** Sink documents deduped by `(method, line)`. Existing #3074-prefix dropped from 3 documents to <X>; #3079-prefix dropped from 115 to <Y>. (U1.c attempted then deferred to milestone-E — see Task 5.)
  - **U2 (`TaintWalker.HandleCall`).** Same-method identity hops at the call boundary suppressed. #3074-prefix's longest document hop count dropped from 113 to <Z>.
  - **U3 (`TaintWalker.CombineProvenance`).** Operator-aware operand-name rendering: arithmetic hop `tainted_value_out` reflects `*`/`/`/`<<` etc. instead of `+` for everything.
  - **U4 (`Comparator.CompareBudget`).** FX064 over-emission budget added; default mode emits a stderr warning, `--strict` promotes to failure.
  - **New fixture.** `fixtures/synthetic-callee-arithmetic/` committed with rules.yaml, trace.yaml, source/Decoder.csproj, and build script. The `*` site in `PayloadSizer.RecordsAreaBytes` is attributed as `transformation: arithmetic`.
  - **Required gate met:** clean build (0/0); full test suite green (159 + <T> new tests = <total>); `--compare` non-strict exits 0 on all 4 fixture pairs.
  - **Bonus gate:** `<N>/4` strict-mode passes. <Brief enumeration: which fixtures passed strict and which didn't.>
```

Replace each `<X>` / `<Y>` / `<Z>` / `<T>` / `<total>` / `<N>` with the actual values from Tasks 8 and 9.

- [ ] **Step 9.4: Commit the spec update**

```bash
git add docs/superpowers/specs/2026-04-27-milestone-d-design.md
git commit -m "docs: spec — milestone-D implementation complete (bonus N/4 strict)"
```

- [ ] **Step 9.5: Print the final status banner**

```bash
echo "=== milestone D complete ==="
echo "all tests:"
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
echo
echo "non-strict --compare:"
echo "  3074-pre:  $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/an-3074-pre.yaml 2>&1 | tail -1)"
echo "  3074-post: $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3074-postfix/trace.yaml /tmp/an-3074-post.yaml 2>&1 | tail -1)"
echo "  3079-pre:  $(dotnet run --project tools/ValidateFixture -- --compare fixtures/imagesharp-3079-prefix/trace.yaml /tmp/an-3079-pre.yaml 2>&1 | tail -1)"
echo "  synthetic: $(dotnet run --project tools/ValidateFixture -- --compare fixtures/synthetic-callee-arithmetic/trace.yaml /tmp/an-synthetic.yaml 2>&1 | tail -1)"
```

Expected: every line says `OK:`.

---

## Self-review

**Spec coverage:**
- *FX064 default-soft / strict-hard:* Task 1 (validator-side scaffolding + tests) + Task 9 (final tally).
- *Sink-document dedup:* Task 4 (U1.a). U1.c (sanitizer-suppressed-path pruning) attempted in Task 5, reverted, deferred to milestone-E.
- *Hop-list bloat reduction:* Task 2 (U2 same-method identity filter).
- *Arithmetic transform attribution:* Task 3 (U3 operator-aware operand names — emission was already in place from milestone-C).
- *No regression (required gate):* Task 8 (`--compare` non-strict on all 4 fixtures).
- *Bonus integer tally:* Task 9 Step 9.1.
- *New fixture:* Task 6 (scaffold) + Task 7 (ground truth).

**Placeholder scan:** No "TBD"/"TODO" items remain. The `<X>/<Y>/<Z>/<T>/<total>/<N>` placeholders in Step 9.3 are intentional — they're filled with concrete values captured in Steps 8.5 and 9.1. Step 7.3's `# from analyzer output` markers are also intentional (the engineer pastes the captured trace verbatim).

**Type consistency:**
- `Comparator.CompareBudget(...)` — defined in Task 1 Step 1.3, called in Task 1 Step 1.7 from `Program.RunCompare`.
- `CombineProvenance` signature change — Task 3 Step 3.5 widens to take optional `OpCode? op = null`; only call site (Task 3 Step 3.6) passes `ins.OpCode`. Other call sites (`CombineProvenanceArgs` is a different method, line 884) untouched.
- `BuildTransitiveValueChainTokens` and `SanitizerBoundMatchesSink` were reused in the reverted U1.c implementation (Task 5) from existing `TraceEmitter` private methods (lines 273-313); not used by remaining tasks.
- Test helpers (`MakeDoc`, `TestFixtureContext.Open`, `FindMethod`) — Task 1 inlines `MakeDoc`; Tasks 2/3 use `TestFixtureContext.Open`/`FindMethod` patterns already established by existing TaintWalkerTests.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-27-milestone-d.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
