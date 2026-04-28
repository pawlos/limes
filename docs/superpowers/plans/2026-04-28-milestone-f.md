# Milestone-F Implementation Plan — Tainted-value naming pass

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make analyzer-emitted traces readable for triage by replacing MethodReference-style synthetic names in `tainted_value_in` / `tainted_value_out` with PDB-resolved local names (N1) and stripping `get_` from property-getter call provenance (N2).

**Architecture:** Two co-located edits in `TaintWalker.cs`. N1 is a rename branch in `StoreLocal` that overwrites a tainted slot's `Provenance` with the local's PDB name when meaningful. N2 is a small `CleanCalleeName` helper that strips the `get_` prefix at provenance-composition sites. Ground-truth `trace.yaml` files for all five existing fixtures get regenerated verbatim from the post-fix analyzer output.

**Tech Stack:** .NET 8 / xUnit / Shouldly / Mono.Cecil 0.11.6 / YamlDotNet 15.1.6.

**Spec reference:** `docs/superpowers/specs/2026-04-28-milestone-f-design.md` (commit `dd68b31`).

**Branch model:** Work on a `milestone-f` branch off main (currently at `1f9690c`). Land on main via fast-forward at the end (per the milestone-D/E pattern).

**Pre-built artifact paths used in steps below:**
- `PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"`
- `artifacts/synthetic-callee-arithmetic/Decoder.dll`
- `artifacts/synthetic-stackalloc/Decoder.dll`

---

## Task overview

| # | Title | Files (primary) |
|---|---|---|
| 1 | N1 — stloc-return naming + tests | `tools/TaintAnalyzer/TaintWalker.cs`, `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`, `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` |
| 2 | N2 — property-getter naming + tests | `tools/TaintAnalyzer/TaintWalker.cs`, `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`, `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` |
| 3 | Ground-truth refresh: synthetic fixtures | `fixtures/synthetic-callee-arithmetic/trace.yaml`, `fixtures/synthetic-stackalloc/trace.yaml` |
| 4 | Ground-truth refresh: imagesharp-3074 fixtures | `fixtures/imagesharp-3074-prefix/trace.yaml`, `fixtures/imagesharp-3074-postfix/trace.yaml` |
| 5 | Ground-truth refresh: imagesharp-3079-prefix | `fixtures/imagesharp-3079-prefix/trace.yaml` |
| 6 | Required-gate cross-check | (verification only) |
| 7 | Spec status update + carry-overs | `docs/superpowers/specs/2026-04-28-milestone-f-design.md` |

---

## Task 0: Branch setup

- [ ] **Step 0.1: Create the milestone-f branch**

```bash
git checkout main
git pull --ff-only 2>/dev/null || true
git checkout -b milestone-f
```

Expected: now on `milestone-f`, branch tip at `1f9690c` (main's current head).

- [ ] **Step 0.2: Confirm baseline tests pass**

```bash
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:" | head -3
```

Expected: 117 (analyzer) + 61 (validator) = 178 tests passing, 0 failures. This is the baseline against which milestone-F adds tests.

- [ ] **Step 0.3: Confirm baseline `--compare` non-strict on all 5 fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/an-stackalloc.yaml >/dev/null 2>&1

for fix in 3074-prefix 3074-postfix 3079-prefix synthetic-callee-arithmetic synthetic-stackalloc; do
    case $fix in
        synthetic-callee-arithmetic) yaml=/tmp/an-synthetic.yaml; dir=fixtures/$fix ;;
        synthetic-stackalloc)        yaml=/tmp/an-stackalloc.yaml; dir=fixtures/$fix ;;
        3074-prefix)                 yaml=/tmp/an-3074-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
        3074-postfix)                yaml=/tmp/an-3074-post.yaml;  dir=fixtures/imagesharp-$fix ;;
        3079-prefix)                 yaml=/tmp/an-3079-pre.yaml;   dir=fixtures/imagesharp-$fix ;;
    esac
    dotnet run --project tools/ValidateFixture --no-build -- --compare "$dir/trace.yaml" "$yaml" >/dev/null 2>&1
    echo "$fix exit=$?"
done
```

Expected: every line says `exit=0`. This baseline must hold.

The captured `/tmp/an-*.yaml` files from this step are the **pre-N1 baselines** referenced in Task 3/4/5 pre-flight diffs.

---

## Task 1: N1 — stloc-return naming + tests

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:295-316` (`StoreLocal`)
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` (add `IsMeaningfulLocalName` private static near other helpers)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append to existing `WalkerFixtures` or `CrossMethodHost`; add `NamingFixtures` if cleaner)
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (append tests)

- [ ] **Step 1.1: Add a fixture method that exercises N1's renamed propagator hop**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Find the `CrossMethodHost` class (around line 238). Append after the `Echo` method (around line 267, before the closing brace of `CrossMethodHost`):

```csharp
    // Exercises milestone-F N1: tainted call-return is stloc'd to local `m`, then `m + 4`
    // produces an arithmetic propagator hop. Without N1, the arithmetic hop's
    // `tainted_value_in` is the synthetic call-return provenance (e.g. "CrossMethodHost.Echo(n)").
    // With N1, it should be the local name "m".
    public byte[] StlocReturnThenArithmetic(int n)
    {
        int m = Echo(n);
        int p = m + 4;
        return new byte[p];
    }
```

- [ ] **Step 1.2: Append the failing test for the rename**

Open `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`. Append before the closing brace of `TaintWalkerTests` class:

```csharp
    [Fact]
    public void Walk_StlocOfTaintedCallReturn_RenamesProvenanceToLocalDebugName()
    {
        // N1: the arithmetic propagator hop after `int m = Echo(n); int p = m + 4;`
        // should carry tainted_value_in = "m" (the local's PDB name), not the synthetic
        // call-return provenance.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::StlocReturnThenArithmetic(System.Int32)")!,
            taintedParamBitmask: 0b1);

        var arithmeticHop = summary.Hops.FirstOrDefault(h => h.Transformation == "arithmetic");
        arithmeticHop.ShouldNotBeNull("expected an arithmetic propagator hop for `m + 4`");
        arithmeticHop.TaintedValueIn.ShouldBe("m", "N1 should rename the tainted slot to the local's PDB name on stloc");
    }

    [Fact]
    public void Walk_StlocOfUntaintedValue_DoesNotInventName()
    {
        // N1 should only rename when the slot is tainted. Untainted stloc must not produce
        // a renamed slot (no tainted hops should emerge from this method at all).
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.WalkerFixtures::IntraMethodNoTaint()")!,
            taintedParamBitmask: 0b0);

        summary.ReachedSink.ShouldBeFalse("no tainted input → no sink");
        summary.Hops.ShouldBeEmpty("no tainted input → no hops at all");
    }
```

- [ ] **Step 1.3: Build the test fixtures DLL and run the new tests — expect FAIL**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Walk_StlocOfTaintedCallReturn|Walk_StlocOfUntaintedValue"
```

Expected:
- `Walk_StlocOfTaintedCallReturn_RenamesProvenanceToLocalDebugName` — FAIL (current behavior: `tainted_value_in` is the synthetic call-return provenance).
- `Walk_StlocOfUntaintedValue_DoesNotInventName` — PASS (the no-taint case is already correct).

- [ ] **Step 1.4: Add the `IsMeaningfulLocalName` helper**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find the `StoreLocal` method (around line 295). Just *above* `StoreLocal`, add:

```csharp
    // N1 — predicate for whether a PDB-resolved local name is suitable for use as a slot's
    // Provenance. Skip compiler-generated state-machine fields (`<…>` prefix), compiler-generated
    // temporaries (`CS$…` prefix), and the `loc_N` debug-info fallback that matches the
    // sanitizer-side noise we explicitly want out of trace fields.
    private static bool IsMeaningfulLocalName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.StartsWith("<", StringComparison.Ordinal)) return false;
        if (name.StartsWith("CS$", StringComparison.Ordinal)) return false;
        // loc_<digits> shape — debug-info fallback emitted by some toolchains.
        if (name.Length > 4 && name.StartsWith("loc_", StringComparison.Ordinal))
        {
            bool allDigits = true;
            for (int i = 4; i < name.Length; i++)
            {
                if (!char.IsDigit(name[i])) { allDigits = false; break; }
            }
            if (allDigits) return false;
        }
        return true;
    }
```

- [ ] **Step 1.5: Add the rename branch to `StoreLocal`**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find `StoreLocal` (line 295). Replace the body:

Current body:
```csharp
    private void StoreLocal(MethodDefinition method, Instruction ins, int idx, TaintState state)
    {
        // Defensive: real-world IL with try/catch/filter regions or compiler-generated state
        // machines can leave the linear walker's symbolic stack out-of-sync with the actual IL
        // stack at certain instructions. Treat underflow as "store untainted" rather than
        // crashing — the value isn't observable through this code path anyway.
        if (state.Stack.Depth == 0)
        {
            state.Locals[idx] = StackSlot.Untainted;
            return;
        }
        var value = state.Stack.Pop();
        state.Locals[idx] = value;
        if (value.Tainted && !state.FirstLocalTaintLine.ContainsKey(idx))
        {
            var sp = _context.GetSequencePoint(method, ins);
            if (sp is not null)
            {
                state.FirstLocalTaintLine[idx] = (sp.Document.Url, sp.StartLine, value.Provenance);
            }
        }
    }
```

Replace with:
```csharp
    private void StoreLocal(MethodDefinition method, Instruction ins, int idx, TaintState state)
    {
        // Defensive: real-world IL with try/catch/filter regions or compiler-generated state
        // machines can leave the linear walker's symbolic stack out-of-sync with the actual IL
        // stack at certain instructions. Treat underflow as "store untainted" rather than
        // crashing — the value isn't observable through this code path anyway.
        if (state.Stack.Depth == 0)
        {
            state.Locals[idx] = StackSlot.Untainted;
            return;
        }
        var value = state.Stack.Pop();

        // N1 — when storing a tainted value to a local with a meaningful PDB name, replace
        // the slot's Provenance with the local name. Subsequent ldloc of this local pushes
        // a slot carrying the local name, so downstream hops' tainted_value_* fields reflect
        // what a triager reads in source instead of synthetic call-return / arithmetic strings.
        var slotToStore = value;
        if (value.Tainted
            && method.Body?.Variables is { } vars && idx < vars.Count
            && method.DebugInformation?.TryGetName(vars[idx], out var dn) == true
            && IsMeaningfulLocalName(dn))
        {
            slotToStore = StackSlot.TaintedWith(dn);
        }
        state.Locals[idx] = slotToStore;

        if (slotToStore.Tainted && !state.FirstLocalTaintLine.ContainsKey(idx))
        {
            var sp = _context.GetSequencePoint(method, ins);
            if (sp is not null)
            {
                state.FirstLocalTaintLine[idx] = (sp.Document.Url, sp.StartLine, slotToStore.Provenance);
            }
        }
    }
```

- [ ] **Step 1.6: Run the new tests — expect both passing**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Walk_StlocOfTaintedCallReturn|Walk_StlocOfUntaintedValue"
```

Expected: 2 passing, 0 failing.

- [ ] **Step 1.7: Run the full analyzer test suite — confirm no regressions**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green. Baseline 117 + 2 new = 119 (rough — count may vary if any existing test was affected).

If any existing test fails: investigate whether the failure is an expected naming change (the test asserted on a synthetic provenance string that should now be a local name) or an actual regression. Document expected naming changes in the commit message; fix actual regressions before continuing.

- [ ] **Step 1.8: Commit Task 1**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "analyzer: N1 — rename tainted slot to PDB local name at stloc (Task 1)"
```

---

## Task 2: N2 — property-getter naming + tests

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` (add `CleanCalleeName` helper; apply at `:783`, `:788`, `:834`)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (add a fixture exercising the getter shape)
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` (append tests)

- [ ] **Step 2.1: Add a fixture method that exercises a tainted getter call**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Append a new class block at the bottom of the file (after the last existing class):

```csharp

// Milestone-F N2 fixtures — exercise property-getter naming.
public sealed class GetterNamingHost
{
    private int _value;

    public int Value => _value;

    // Uses a property getter on a tainted receiver. Without N2, the call's synthetic
    // provenance is "host.get_Value"; with N2, it should be "host.Value".
    public static byte[] AllocateFromTaintedHostValue(GetterNamingHost host)
    {
        return new byte[host.Value];
    }
}
```

- [ ] **Step 2.2: Append the failing tests for the getter rename**

Open `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs`. Append before the closing brace of `TaintWalkerTests` class:

```csharp
    [Fact]
    public void Walk_TaintedReceiverPropertyGetter_StripsGetUnderscorePrefix()
    {
        // N2: the sink hop's tainted_value_in for `host.Value` (a property getter on a
        // tainted receiver) should be "host.Value", not "host.get_Value".
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.GetterNamingHost::AllocateFromTaintedHostValue(TaintAnalyzer.Tests.Fixtures.GetterNamingHost)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        var sinkHop = summary.Hops.Last();
        sinkHop.Role.ShouldBe(HopRole.Sink);
        // The sink's tainted_value_in records the value flowing into newarr — i.e. the
        // result of `host.Value`. After N2 it should not contain "get_".
        sinkHop.TaintedValueIn.ShouldNotBeNull();
        sinkHop.TaintedValueIn!.ShouldNotContain("get_", "N2 should strip the get_ prefix from property-getter call provenance");
    }

    [Fact]
    public void Walk_NonGetterCall_NoTraceFieldStartsWithUnderscore()
    {
        // Defensive: confirm CleanCalleeName doesn't accidentally chop something it shouldn't.
        // CrossMethodTaintedReturn calls Echo (not a getter) — no `tainted_value_*` field across
        // any hop should start with `_` (which would be the result of mistakenly stripping `get`
        // from a name that wasn't actually `get_<X>`).
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.Walk(
            ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.CrossMethodHost::CrossMethodTaintedReturn(System.Int32)")!,
            taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        foreach (var hop in summary.Hops)
        {
            (hop.TaintedValueIn ?? "").ShouldNotStartWith("_");
            (hop.TaintedValueOut ?? "").ShouldNotStartWith("_");
        }
    }
```

- [ ] **Step 2.3: Build the test fixtures DLL and run the new tests — expect failure on the first**

```bash
dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj --nologo
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Walk_TaintedReceiverPropertyGetter|Walk_NonGetterCall"
```

Expected:
- `Walk_TaintedReceiverPropertyGetter_StripsGetUnderscorePrefix` — FAIL (current `tainted_value_in` contains `get_Value`).
- `Walk_NonGetterCall_NameIsUnchanged` — PASS (control test).

- [ ] **Step 2.4: Add the `CleanCalleeName` helper**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Place the helper just above `IsMeaningfulLocalName` (added in Task 1). Insert:

```csharp
    // N2 — strip the `get_` property-getter prefix when composing call-return provenance,
    // so synthetic strings render as "receiver.Property" instead of "receiver.get_Property".
    // Conservative: matches only the common-case getter prefix; other accessor patterns
    // (set_/add_/remove_/op_) don't compose into provenance the same way and are out of scope.
    private static string CleanCalleeName(MethodReference callee)
    {
        var name = callee.Name;
        if (name.StartsWith("get_", StringComparison.Ordinal) && name.Length > 4)
        {
            return name.Substring(4);
        }
        return name;
    }
```

- [ ] **Step 2.5: Apply `CleanCalleeName` at the three composition sites**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Find line 783 (inside the external-call return-handler block):

```csharp
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{callee.Name}";
                    }
                    else
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{callee.Name}({firstTainted.Provenance})";
                    }
```

Replace with:

```csharp
                    if (hasThisOnStack && receiverSlot.Tainted)
                    {
                        prov = $"{receiverSlot.Provenance}.{CleanCalleeName(callee)}";
                    }
                    else
                    {
                        var firstTainted = argSlots.First(s => s.Tainted);
                        prov = $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}({firstTainted.Provenance})";
                    }
```

Then find the in-assembly call-return provenance composition (line 834):

```csharp
            var provenance = callReturnIsTainted
                ? CombineProvenanceArgs(argSlots, $"{callee.DeclaringType.Name}.{callee.Name}")
                : "";
```

Replace with:

```csharp
            var provenance = callReturnIsTainted
                ? CombineProvenanceArgs(argSlots, $"{callee.DeclaringType.Name}.{CleanCalleeName(callee)}")
                : "";
```

- [ ] **Step 2.6: Run the new tests — expect both passing**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo --filter "FullyQualifiedName~Walk_TaintedReceiverPropertyGetter|Walk_NonGetterCall"
```

Expected: 2 passing.

- [ ] **Step 2.7: Run the full analyzer test suite**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo
```

Expected: all green. Baseline 119 (post-Task-1) + 2 new = 121 (rough; may vary).

Existing tests that previously asserted on `get_*` strings will now need updating. Likely candidates: any sink-hop or propagator-hop test that compared `tainted_value_*` to `Type.get_X` or `instance.get_X` literally. Update those assertions to the post-N2 shape (drop the `get_`) and treat as part of this commit.

- [ ] **Step 2.8: Commit Task 2**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "analyzer: N2 — strip get_ prefix from property-getter call provenance (Task 2)"
```

---

## Task 3: Ground-truth refresh — synthetic fixtures

**Files:**
- Modify: `fixtures/synthetic-callee-arithmetic/trace.yaml` (regenerate)
- Modify: `fixtures/synthetic-stackalloc/trace.yaml` (regenerate)

These are the simpler regenerations — single document each. Use them as warm-up for the imagesharp refreshes in Tasks 4/5.

- [ ] **Step 3.1: Build TaintAnalyzer with N1+N2**

```bash
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
```

Expected: 0 errors, 0 warnings.

- [ ] **Step 3.2: Regenerate analyzer outputs for both synthetic fixtures**

```bash
dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/synthetic-callee-arithmetic/Decoder.dll \
    --rules fixtures/synthetic-callee-arithmetic/rules.yaml \
    --output /tmp/an-synthetic.yaml

dotnet run --project tools/TaintAnalyzer --no-build -- \
    artifacts/synthetic-stackalloc/Decoder.dll \
    --rules fixtures/synthetic-stackalloc/rules.yaml \
    --output /tmp/an-stackalloc.yaml
```

Expected: both exit 0; output files exist.

- [ ] **Step 3.3: Pre-flight diff against pre-N1 baselines (captured in Step 0.3)**

For each fixture, compare the pre-N1 baseline `/tmp/an-*.yaml` (from Step 0.3, captured before Task 1) against the post-N1+N2 `/tmp/an-*.yaml`. Confirm only naming-related fields changed.

If the baselines were lost (terminal cleared), regenerate them by checking out main temporarily, capturing, and switching back:

```bash
git stash
git checkout main
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic-baseline.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/an-stackalloc-baseline.yaml
git checkout milestone-f
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj --nologo
git stash pop 2>/dev/null || true
```

Then diff:

```bash
diff /tmp/an-synthetic-baseline.yaml /tmp/an-synthetic.yaml | head -50
diff /tmp/an-stackalloc-baseline.yaml /tmp/an-stackalloc.yaml | head -50
```

Expected: only `tainted_value_in`, `tainted_value_out`, `size_expression`, `access_expression`, and (where present) `establishes_bound.target` strings differ. Hop counts, methods, files, lines, sink kinds, sink APIs, transformations, and document counts MUST be identical between baseline and post-N1+N2.

If you see structural drift (different hop counts, new/missing documents, different sink shapes): N1 or N2 has a behavior side-effect that wasn't expected. Stop and investigate before refreshing ground truth — refreshing in this state would mask the regression.

- [ ] **Step 3.4: Refresh `synthetic-callee-arithmetic/trace.yaml`**

Read the existing `fixtures/synthetic-callee-arithmetic/trace.yaml` to recover the metadata header (`vuln_id`, `fix_commit`, `fix_pr`, `description`). Then construct the new trace.yaml as: metadata header + the source/sink/path/sanitizer_absence content from `/tmp/an-synthetic.yaml` copied verbatim.

```bash
# Inspect the existing metadata header.
grep -E "^vuln_id:|^fix_commit:|^fix_pr:|^description:" fixtures/synthetic-callee-arithmetic/trace.yaml
sed -n '1,/^source:/{/^source:/!p}' fixtures/synthetic-callee-arithmetic/trace.yaml > /tmp/synthetic-header.yaml

# Inspect the analyzer output's body (everything from `source:` onward).
sed -n '/^source:/,$p' /tmp/an-synthetic.yaml > /tmp/synthetic-body.yaml

# Compose the new trace.yaml.
cat /tmp/synthetic-header.yaml /tmp/synthetic-body.yaml > fixtures/synthetic-callee-arithmetic/trace.yaml
```

(Adjust the sed boundary if the analyzer output starts with a leading `vuln_id:` line that duplicates the metadata header. In that case, drop the leading metadata from the analyzer body before concatenating. Inspect `head -5 /tmp/an-synthetic.yaml` first.)

- [ ] **Step 3.5: Verify `--compare` non-strict on `synthetic-callee-arithmetic`**

```bash
dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/synthetic-callee-arithmetic/trace.yaml \
    /tmp/an-synthetic.yaml
echo "exit=$?"
```

Expected: `OK: ...` and exit=0.

If FX060/FX061/FX062/FX063 fires: the trace.yaml composition picked up something the analyzer doesn't emit, or vice versa. Inspect the diagnostic line, fix the trace.yaml, and re-run. Common cause: the `description` field in the metadata header has different whitespace from what `--compare` expects; align it.

- [ ] **Step 3.6: Refresh `synthetic-stackalloc/trace.yaml` (mirror Steps 3.4 + 3.5)**

```bash
sed -n '1,/^source:/{/^source:/!p}' fixtures/synthetic-stackalloc/trace.yaml > /tmp/stackalloc-header.yaml
sed -n '/^source:/,$p' /tmp/an-stackalloc.yaml > /tmp/stackalloc-body.yaml
cat /tmp/stackalloc-header.yaml /tmp/stackalloc-body.yaml > fixtures/synthetic-stackalloc/trace.yaml

dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/synthetic-stackalloc/trace.yaml \
    /tmp/an-stackalloc.yaml
echo "exit=$?"
```

Expected: exit=0.

- [ ] **Step 3.7: Spot-check the renamed names**

```bash
grep -E "tainted_value_(in|out):|size_expression:" fixtures/synthetic-callee-arithmetic/trace.yaml | head
grep -E "tainted_value_(in|out):|size_expression:" fixtures/synthetic-stackalloc/trace.yaml | head
```

Expected: at least some hops show natural local names (`recordCount`, `totalBytes`, etc.) where pre-N1 they showed synthetic call-return forms (`WireReader.ReadU16`, `Echo`, etc.). The synthetic-stackalloc fixture in particular should show the local `recordCount` somewhere instead of `WireReader.ReadU16`.

- [ ] **Step 3.8: Commit Task 3**

```bash
git add fixtures/synthetic-callee-arithmetic/trace.yaml fixtures/synthetic-stackalloc/trace.yaml
git commit -m "fixture: refresh synthetic ground-truth for N1+N2 naming (Task 3)"
```

---

## Task 4: Ground-truth refresh — imagesharp-3074 fixtures

**Files:**
- Modify: `fixtures/imagesharp-3074-prefix/trace.yaml` (regenerate)
- Modify: `fixtures/imagesharp-3074-postfix/trace.yaml` (regenerate)

Three documents each. Same regeneration pattern as Task 3.

- [ ] **Step 4.1: Regenerate analyzer outputs**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml
```

Expected: both exit 0.

- [ ] **Step 4.2: Pre-flight diff (optional but strongly recommended)**

If `/tmp/an-3074-pre-baseline.yaml` and `/tmp/an-3074-post-baseline.yaml` exist from Step 0.3, diff them against the new captures:

```bash
diff <(grep -vE "tainted_value_(in|out):|size_expression:|access_expression:|establishes_bound:" /tmp/an-3074-pre-baseline.yaml) \
     <(grep -vE "tainted_value_(in|out):|size_expression:|access_expression:|establishes_bound:" /tmp/an-3074-pre.yaml) | head -30
```

Expected: empty diff (everything that's NOT a naming field is identical between baseline and post-N1+N2).

If the diff has lines: structural drift detected; investigate before refreshing.

- [ ] **Step 4.3: Refresh `imagesharp-3074-prefix/trace.yaml`**

```bash
sed -n '1,/^source:/{/^source:/!p}' fixtures/imagesharp-3074-prefix/trace.yaml > /tmp/3074-pre-header.yaml
sed -n '/^source:/,$p' /tmp/an-3074-pre.yaml > /tmp/3074-pre-body.yaml
cat /tmp/3074-pre-header.yaml /tmp/3074-pre-body.yaml > fixtures/imagesharp-3074-prefix/trace.yaml
```

If the analyzer-output has multi-document YAML (`---` separators between documents), the sed boundary may need adjustment. Inspect `grep -c "^---$" /tmp/an-3074-pre.yaml` — if >0, the first document starts with `vuln_id:` and the body extraction needs to start at `source:` *within* the first document. Use:

```bash
sed -n '/^vuln_id:/,/^---$/{/^---$/!p}' /tmp/an-3074-pre.yaml > /tmp/3074-pre-body-doc1.yaml
# Then for additional documents, take everything from the first `---` to EOF:
sed -n '/^---$/,$p' /tmp/an-3074-pre.yaml > /tmp/3074-pre-body-rest.yaml
```

Compose: header (without analyzer's own vuln_id) + body of doc1 (from `source:`) + `---\n` + remaining documents.

In practice, the simpler approach is: **read the analyzer output verbatim** and **edit the metadata header** in-place after the copy. Read `head -10 /tmp/an-3074-pre.yaml`; if it already has `vuln_id:` matching the existing fixture's, just copy the analyzer output and prepend the missing metadata lines (`fix_commit:`, `fix_pr:`, `description:` if any) using the Edit tool to surgically insert them.

- [ ] **Step 4.4: Verify `--compare` non-strict on `3074-prefix`**

```bash
dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/imagesharp-3074-prefix/trace.yaml \
    /tmp/an-3074-pre.yaml
echo "exit=$?"
```

Expected: exit=0.

If non-zero: investigate, fix, re-run.

- [ ] **Step 4.5: Refresh `imagesharp-3074-postfix/trace.yaml` (mirror 4.3 + 4.4)**

```bash
sed -n '1,/^source:/{/^source:/!p}' fixtures/imagesharp-3074-postfix/trace.yaml > /tmp/3074-post-header.yaml
sed -n '/^source:/,$p' /tmp/an-3074-post.yaml > /tmp/3074-post-body.yaml
cat /tmp/3074-post-header.yaml /tmp/3074-post-body.yaml > fixtures/imagesharp-3074-postfix/trace.yaml

dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/imagesharp-3074-postfix/trace.yaml \
    /tmp/an-3074-post.yaml
echo "exit=$?"
```

Expected: exit=0.

- [ ] **Step 4.6: Spot-check the renames**

```bash
grep -cE "\.get_[A-Z]" fixtures/imagesharp-3074-prefix/trace.yaml fixtures/imagesharp-3074-postfix/trace.yaml
```

Expected: zero matches in either file (N2 stripped all `get_` prefixes).

```bash
grep -cE "Span'1\.op_Implicit|StreamExtensions\.Read|BmpInfoHeader\.get_" fixtures/imagesharp-3074-prefix/trace.yaml
```

Expected: zero matches (N1 + N2 should have replaced these noisy synthetic names with meaningful local names).

If any of these patterns still appear: the fixture's IL has stloc patterns where the local name itself isn't useful (e.g., the local is named `<>e__34` or absent). That's expected and not a regression — but confirm by inspecting one or two of the surviving lines.

- [ ] **Step 4.7: Commit Task 4**

```bash
git add fixtures/imagesharp-3074-prefix/trace.yaml fixtures/imagesharp-3074-postfix/trace.yaml
git commit -m "fixture: refresh imagesharp-3074 ground-truth for N1+N2 naming (Task 4)"
```

---

## Task 5: Ground-truth refresh — imagesharp-3079-prefix

**Files:**
- Modify: `fixtures/imagesharp-3079-prefix/trace.yaml` (regenerate; 40 documents)

This fixture has the highest churn — 40 documents. Same regeneration pattern but with the multi-document YAML challenge magnified.

- [ ] **Step 5.1: Regenerate analyzer output**

```bash
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079" --rules fixtures/imagesharp-3079-prefix/rules.yaml --output /tmp/an-3079-pre.yaml
echo "doc_count=$(grep -c '^vuln_id:' /tmp/an-3079-pre.yaml)"
echo "size_kb=$(du -k /tmp/an-3079-pre.yaml | cut -f1)"
```

Expected: doc_count is in the 30-50 range (matches milestone-E observation of 40); size_kb in the hundreds (file is large).

- [ ] **Step 5.2: Pre-flight: confirm structural fields are unchanged**

If the Step 0.3 baseline was preserved at `/tmp/an-3079-pre-baseline.yaml`, diff non-naming fields:

```bash
diff <(grep -vE "tainted_value_(in|out):|size_expression:|access_expression:|establishes_bound:|target:" /tmp/an-3079-pre-baseline.yaml) \
     <(grep -vE "tainted_value_(in|out):|size_expression:|access_expression:|establishes_bound:|target:" /tmp/an-3079-pre.yaml) | wc -l
```

Expected: 0. If non-zero, investigate.

If the baseline doesn't exist, fall back to confirming hop and document counts:

```bash
diff <(grep -c "^- hop:" /tmp/an-3079-pre.yaml) <(echo $(git show main:fixtures/imagesharp-3079-prefix/trace.yaml | grep -c "^- hop:"))
diff <(grep -c "^vuln_id:" /tmp/an-3079-pre.yaml) <(echo $(git show main:fixtures/imagesharp-3079-prefix/trace.yaml | grep -c "^vuln_id:"))
```

Expected: both diffs empty (counts match baseline).

- [ ] **Step 5.3: Refresh `imagesharp-3079-prefix/trace.yaml`**

For a multi-document YAML this large, the simplest reliable approach: read the analyzer output verbatim into the fixture, then surgically restore the metadata header (`fix_commit`, `fix_pr`, `description`) at the top using the Edit tool.

```bash
# Backup the existing file in case rollback is needed.
cp fixtures/imagesharp-3079-prefix/trace.yaml /tmp/3079-pre-original.yaml

# Capture the metadata-header lines the existing fixture has but the analyzer doesn't emit.
grep -E "^fix_commit:|^fix_pr:|^description:" /tmp/3079-pre-original.yaml > /tmp/3079-pre-meta.txt
# (description: is a multi-line field; capture differently if needed.)
sed -n '/^description:/,/^source:/{/^source:/!p}' /tmp/3079-pre-original.yaml > /tmp/3079-pre-description.txt

# Copy the analyzer output verbatim.
cp /tmp/an-3079-pre.yaml fixtures/imagesharp-3079-prefix/trace.yaml
```

Then use the Edit tool to insert `fix_commit:`, `fix_pr:`, and `description:` lines after the first `vuln_id:` line in the fixture, matching the format of the original.

Verify by spot-reading the head:

```bash
head -15 fixtures/imagesharp-3079-prefix/trace.yaml
```

Expected: `vuln_id: ...`, `fix_commit: ...`, `fix_pr: ...`, `description: ...`, then the source/sink/path body.

- [ ] **Step 5.4: Verify `--compare` non-strict**

```bash
dotnet run --project tools/ValidateFixture --no-build -- --compare \
    fixtures/imagesharp-3079-prefix/trace.yaml \
    /tmp/an-3079-pre.yaml
echo "exit=$?"
```

Expected: exit=0.

If FX060/FX061/FX062/FX063 fires on a *specific document*, identify which and fix. The 40-document scale makes this tedious but mechanical.

- [ ] **Step 5.5: Spot-check renames at scale**

```bash
echo "=== get_ remaining (should be ~0) ==="
grep -cE "\.get_[A-Z]" fixtures/imagesharp-3079-prefix/trace.yaml
echo "=== old synthetic shapes (should be near-0) ==="
grep -cE "Span'1\.op_Implicit|MemoryExtensions\.IndexOf|PngDecoderCore\.TryReadChunk" fixtures/imagesharp-3079-prefix/trace.yaml
echo "=== meaningful local names (should be many) ==="
grep -cE "tainted_value_(in|out): [a-z][A-Za-z0-9_]*$" fixtures/imagesharp-3079-prefix/trace.yaml
```

The third grep checks for `tainted_value_in/out` whose value is a simple identifier (typical for a local name like `data`, `length`, `header`). Expect this count to be much higher than the corresponding count on `main`'s pre-N1 baseline, and the first two counts to be near zero (or zero).

- [ ] **Step 5.6: Commit Task 5**

```bash
git add fixtures/imagesharp-3079-prefix/trace.yaml
git commit -m "fixture: refresh imagesharp-3079-prefix ground-truth for N1+N2 naming (Task 5)"
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

Expected: all green. Capture the test counts; expected ballpark: 117 (analyzer baseline) + 2 (Task 1) + 2 (Task 2) = 121 in `TaintAnalyzer.Tests`. Validator's 61 unchanged. Total: ~182.

- [ ] **Step 6.3: `--compare` non-strict on all 5 fixtures**

```bash
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"

dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3074"  --rules fixtures/imagesharp-3074-prefix/rules.yaml  --output /tmp/an-3074-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$POST3074" --rules fixtures/imagesharp-3074-postfix/rules.yaml --output /tmp/an-3074-post.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- "$PRE3079"  --rules fixtures/imagesharp-3079-prefix/rules.yaml  --output /tmp/an-3079-pre.yaml  >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-callee-arithmetic/Decoder.dll --rules fixtures/synthetic-callee-arithmetic/rules.yaml --output /tmp/an-synthetic.yaml >/dev/null 2>&1
dotnet run --project tools/TaintAnalyzer --no-build -- artifacts/synthetic-stackalloc/Decoder.dll --rules fixtures/synthetic-stackalloc/rules.yaml --output /tmp/an-stackalloc.yaml >/dev/null 2>&1

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

- [ ] **Step 6.4: DoD #2 — confirm imagesharp-3074-prefix has no MethodRef-style names where locals exist**

```bash
echo "=== get_ prefix surviving in 3074-prefix (should be 0) ==="
grep -cE "\.get_[A-Z]" fixtures/imagesharp-3074-prefix/trace.yaml
echo "=== synthetic Type.method shapes that suggest unrenamed call returns ==="
grep -E "tainted_value_(in|out): [A-Z][A-Za-z0-9'_]+\.[a-z][A-Za-z0-9_]*" fixtures/imagesharp-3074-prefix/trace.yaml | head
```

Expected: first count is 0. Second grep may return some hits (cases where the local-storage-on-same-line heuristic doesn't apply, e.g., a method-call return passed directly to another call without stloc) — manually inspect a few and confirm they're legitimate (no stloc to a named local available), not bugs. Document which (if any) survive in the Task 7 spec status update.

- [ ] **Step 6.5: DoD #3 — confirm property-getter calls render as `{receiver}.{Property}`**

```bash
echo "=== Specific named getters from the spec's DoD ==="
grep -E "infoHeader\.ProfileSize|fileHeader\.[A-Z]" fixtures/imagesharp-3074-prefix/trace.yaml | head
```

Expected: at least one match showing a clean `{receiver}.{Property}` shape. (Exact name depends on the IL; the point is a getter call composed without `get_`.)

- [ ] **Step 6.6: `--compare --strict` smoke check (bonus tally only)**

```bash
echo "=== --compare --strict (bonus tally) ==="
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

Expected: synthetic-callee-arithmetic and synthetic-stackalloc exit 0; the three imagesharp fixtures exit 1 (consistent with milestone-E baseline of 2/5). Naming changes don't affect strict tally; if anything *did* change the count, that's noted but not a regression.

- [ ] **Step 6.7: No commit (verification-only task)**

This task makes no source changes; nothing to commit.

---

## Task 7: Spec status update + carry-overs

**Files:**
- Modify: `docs/superpowers/specs/2026-04-28-milestone-f-design.md` (Status line + Revision history append)

- [ ] **Step 7.1: Capture build/test counts and DoD evidence**

Re-run from a clean shell to capture the final numbers:

```bash
dotnet build TaintAnalyzer.sln --nologo 2>&1 | grep -E "Warning|Error"
dotnet test TaintAnalyzer.sln --nologo 2>&1 | grep -E "Passed!|Failed:" | head -2

echo "=== get_ surviving across all fixtures ==="
for f in fixtures/imagesharp-3074-prefix/trace.yaml fixtures/imagesharp-3074-postfix/trace.yaml fixtures/imagesharp-3079-prefix/trace.yaml fixtures/synthetic-callee-arithmetic/trace.yaml fixtures/synthetic-stackalloc/trace.yaml; do
    echo "$f: $(grep -cE '\.get_[A-Z]' "$f")"
done
```

Expected: 0 build warnings/errors; tests passing; 0 `get_` matches across all five fixtures.

- [ ] **Step 7.2: Update the spec's Status line**

Open `docs/superpowers/specs/2026-04-28-milestone-f-design.md`. Find:

```
**Status:** Approved 2026-04-28.
```

Replace with (filling actual values):

```
**Status:** Implementation complete 2026-04-28. Required gate met: 5/5 fixtures pass `--compare` non-strict; all `get_` prefixes stripped; tainted-value names resolve to PDB locals where meaningful. See revision history for measured DoD evidence and milestone-G carry-overs.
```

- [ ] **Step 7.3: Append the implementation-complete revision-history entry**

Append to the end of the spec file (after the existing 2026-04-28 entry):

```markdown
- **2026-04-28 (implementation complete, same day).** N1 + N2 landed.
  - **Build/tests.** Clean build 0/0. Test suite green: <X> (TaintAnalyzer.Tests) + 61 (ValidateFixture.Tests) = **<Z>** tests, 0 failures, 0 skips.
  - **Required gate met:** `--compare` non-strict exits 0 on all five fixture pairs (`imagesharp-3074-prefix`, `imagesharp-3074-postfix`, `imagesharp-3079-prefix`, `synthetic-callee-arithmetic`, `synthetic-stackalloc`).
  - **DoD evidence (tainted-value naming):**
    - `\.get_[A-Z]` matches across all five fixture trace.yaml files: **0** (DoD #2 + DoD #3 satisfied).
    - Spot-checked (examples): `<receiver>.<Property>` forms now appear in `imagesharp-3074-prefix/trace.yaml` where `<receiver>.get_<Property>` previously did. Synthetic call-return shapes (`Span'1.op_Implicit`, `StreamExtensions.Read`) replaced by named locals in most contexts.
  - **Surviving synthetic shapes (expected):** Some hops still carry `<Type>.<method>` forms where the value isn't `stloc`'d to a named local on the same line — e.g., method-call returns passed directly into another call. This is the conservative scope: N1 only fires at `stloc`. Surviving shapes are not regressions; they're outside N1's heuristic boundary.
  - **Strict bonus tally (observational):** **2/5** (synthetic-callee-arithmetic + synthetic-stackalloc), unchanged from milestone-E. Naming changes don't affect document/hop counts; the strict tally couldn't move on this milestone by design.
  - **Carry-overs to milestone-G:**
    - **Sub-problem (iii) `loc_N` recovery in sanitizer hops** — `SanitizerShapes.OperandName` deferred from milestone-F's A2 sub-scope.
    - **Arithmetic attribution / blind-test gap** — investigation-shaped; needs a Pmsg-like fixture authored, then trace inspection to identify why the multiply hop is missing or visually masked.
    - **U9 tuning + cross-method sink-document dedup** — strict-bonus recovery work; structural.
    - **U1.c redesign** — meaningful sanitizer bound vs sibling guard.
    - **parquet-dotnet round-trip** — fixture authored, materialize script + analyzer run pending.
  - **Plan defects observed during execution (if any):** <fill in>. Use this slot to note any divergence between plan-prescribed step output and actual measurement (test counts, regenerate-vs-edit decisions, fixture-specific quirks). Empty if no defects.
```

Replace `<X>` with the actual TaintAnalyzer.Tests count from Step 7.1, `<Z>` with the total, and `<fill in>` with any plan-defect notes (or remove that bullet if none).

- [ ] **Step 7.4: Commit the spec update**

```bash
git add docs/superpowers/specs/2026-04-28-milestone-f-design.md
git commit -m "docs: spec — milestone-F implementation complete (N1+N2 naming)"
```

- [ ] **Step 7.5: Print the final status banner**

```bash
echo "=== milestone F complete ==="
echo "all tests:"
dotnet test TaintAnalyzer.sln --nologo --verbosity quiet 2>&1 | grep -E "Passed!|Failed:"
echo
echo "non-strict --compare:"
PRE3074="artifacts/67bac23cff7c32743d0c8e166e9cccbf567837e0/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
POST3074="artifacts/461c021608802370374afabd5d3c2720b3e46f04/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
PRE3079="artifacts/533ed51d3acc313bfcdadf120de316fdada52a72/artifacts/bin/src/ImageSharp/Debug/net8.0/SixLabors.ImageSharp.dll"
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
- *N1 stloc-return naming:* Task 1 (TaintWalker.StoreLocal rename + IsMeaningfulLocalName helper + tests).
- *N2 property-getter naming:* Task 2 (CleanCalleeName helper + applications at :783/:788/:834 + tests).
- *Ground-truth refresh on 5 existing fixtures:* Tasks 3 (synthetics) + 4 (3074 prefix/postfix) + 5 (3079).
- *No new fixture (waived):* aligned with spec premise.
- *Required gate (--compare 5/5 non-strict):* Task 6 Step 6.3.
- *DoD #2 (no MethodRef-style names where locals exist):* Task 6 Step 6.4.
- *DoD #3 (property-getter form):* Task 6 Step 6.5.
- *DoD #4 (build clean, tests green):* Task 6 Steps 6.1 + 6.2.
- *Bonus observational:* Task 6 Step 6.6 (strict tally) + Task 7 Step 7.3 (recorded).
- *Spec status update:* Task 7.

**Placeholder scan:** No `TBD`/`TODO` items. The `<X>`/`<Z>`/`<fill in>` markers in Step 7.3 are intentional output-substitution slots filled at execution time from Step 7.1 measurements. Step 5.3's "use the Edit tool to insert" instruction is action-prescriptive (engineer-facing), not a placeholder.

**Type consistency:**
- `IsMeaningfulLocalName(string?) -> bool` — defined in Task 1 Step 1.4, used in Task 1 Step 1.5. ✓
- `CleanCalleeName(MethodReference) -> string` — defined in Task 2 Step 2.4, used in Task 2 Step 2.5 (three sites). ✓
- `StackSlot.TaintedWith(string)` — used in Task 1 Step 1.5; matches existing factory at `StackSlot` (e.g. `TaintWalker.cs:471`). ✓
- `method.DebugInformation?.TryGetName(VariableDefinition, out string)` — pattern matches existing usage at `TaintWalker.cs:262`. ✓

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-28-milestone-f.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?
