# Milestone-T2: Marten SQLi prefix lock + DefaultInterpolatedStringHandler walker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect the real Marten 8.36 SQL-injection advisory (GHSA-vmw2-qwm8-x84c) by teaching the walker to propagate taint through `$"..."` string interpolation, anchored by a synthetic fixture in Phase 1 and the real Marten binary in Phase 2.

**Architecture:** Phase 1 adds a targeted `SinkShapes.TryHandleInterpolatedStringAppend` recognizer that fires on `call DefaultInterpolatedStringHandler::AppendFormatted` with a tainted value arg and taints the receiver-pointed-to local in `TaintState`. The recognizer is wired into `TaintWalker.HandleCall` as an early branch. Phase 2 materializes Marten 8.36 from NuGet and locks a real fixture proving end-to-end detection.

**Tech Stack:** .NET 10, Mono.Cecil, xUnit, Shouldly. Spec: `docs/superpowers/specs/2026-05-16-milestone-t2-marten-prefix-design.md`.

**Anchor discipline:** All existing fixtures (imagesharp / otelcontrib / nbmp / parquet / synthetic / scan-protobuf-net / scan-nbmp / sqli-synthetic-prefix) must remain green. The recognizer fires on a narrow IL shape (`call DefaultInterpolatedStringHandler::AppendFormatted`) that doesn't appear in any current anchor's call graph; expected delta is zero new findings on existing fixtures.

**Worktree:** This plan is intended to be executed in a git worktree `worktree-milestone-t2-marten-prefix`. The spec commit (`f02229b`) must be on `origin/main` before the worktree is created so it lands in the worktree base. Use `EnterWorktree` with `name: "milestone-t2-marten-prefix"`. Every subagent must `cd <worktree-absolute-path>` as Step 0 of its prompt — see memory `feedback_subagent_worktree_cd.md`.

---

## Phase 1 — Walker recognizer + synthetic anchor

### Task 1: Add InterpolatedStringFixtures and FakeFormatter to test-fixtures

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append two new classes near the existing fixture classes)

- [ ] **Step 1: Append new classes**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. At the end of the file (after the last existing fixture class but before the file's closing `}` if applicable — note: the file may have classes at top level with no enclosing wrapper, follow existing convention), insert:

```csharp
public static class InterpolatedStringFixtures
{
    // Lowers to: handler.ctor + AppendLiteral("prefix") + AppendFormatted(x)
    // + AppendLiteral("suffix") + ToStringAndClear. The recognizer targets the
    // AppendFormatted call; the AppendLiteral guard test targets one of the
    // AppendLiteral calls in the same body.
    public static string DoFormat(string x) => $"prefix{x}suffix";
}

// Negative-case fixture: a class with an `AppendFormatted(string)` method on a
// type that is NOT DefaultInterpolatedStringHandler. The recognizer must NOT
// fire here.
public sealed class FakeFormatter
{
    public void AppendFormatted(string value) { /* no-op */ }
}

public static class FakeFormatterFixtures
{
    public static void DoFakeFormat(FakeFormatter f, string s) => f.AppendFormatted(s);
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug`
Expected: build succeeds. Fixture DLL is rebuilt.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "test-fixtures: InterpolatedStringFixtures + FakeFormatter for handler-recognizer tests"
```

---

### Task 2: Failing test — TryHandleInterpolatedStringAppend taints handler local

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append before the class's closing brace)

- [ ] **Step 1: Append the failing test**

```csharp
    [Fact]
    public void TryHandleInterpolatedStringAppend_TaintedValue_TaintsHandlerLocal()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.InterpolatedStringFixtures::DoFormat(System.String)");

        var call = m.Body.Instructions.Single(i =>
            i.OpCode == Mono.Cecil.Cil.OpCodes.Call &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendFormatted" &&
            mr.DeclaringType.FullName == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.TaintedWith("x") };
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeTrue();
        // The handler local is V_0 (first local in the synthesized method body).
        state.Locals.ShouldContainKey(0);
        state.Locals[0].Tainted.ShouldBeTrue();
        state.Locals[0].Provenance.ShouldBe("InterpolatedString(x)");
    }
```

- [ ] **Step 2: Run; verify build fails**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TryHandleInterpolatedStringAppend_TaintedValue" -- xunit.parallelizeTestCollections=false`
Expected: build FAILS with `CS0117: 'SinkShapes' does not contain a definition for 'TryHandleInterpolatedStringAppend'`. This is the red state.

**Do NOT commit.** Task 3 will commit the test together with the implementation.

---

### Task 3: Implement TryHandleInterpolatedStringAppend

**Files:**
- Modify: `tools/TaintAnalyzer/SinkShapes.cs` (append the new method before the class's closing brace)

- [ ] **Step 1: Add the recognizer method**

Inside `public static class SinkShapes { ... }`, before the closing `}`:

```csharp
    // Phase 1 walker primitive: tainted value flowing into
    // DefaultInterpolatedStringHandler.AppendFormatted taints the handler local.
    // Subsequent ToStringAndClear() on that local picks up taint via the existing
    // HandleCall over-approximation (the byref-receiver lands in the call's bitmask).
    //
    // Returns true if the call was handled here; the caller (TaintWalker.HandleCall)
    // should early-return after a true result, skipping default external-call
    // dispatch (which would no-op for this call anyway, but avoids redundant work).
    public static bool TryHandleInterpolatedStringAppend(
        MethodReference callee,
        Instruction call,
        StackSlot[] argSlots,
        TaintState state)
    {
        if (callee.DeclaringType.FullName != "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler") return false;
        if (callee.Name != "AppendFormatted") return false;
        if (argSlots.Length == 0) return false;

        // The value-arg is argSlots[0]. If it's untainted, nothing to propagate.
        var valueSlot = argSlots[0];
        if (!valueSlot.Tainted) return false;

        // Walk back from the call site to find the receiver's pusher. The receiver
        // is the FIRST pushed of (totalPushers = paramCount + 1 for HasThis). Walk
        // back paramCount steps past the value/extra-arg pushers; the next non-nop
        // is the receiver pusher.
        int totalPushers = callee.Parameters.Count + (callee.HasThis ? 1 : 0);
        var cur = call.Previous;
        Instruction? receiverPusher = null;

        for (int slot = totalPushers - 1; slot >= 0 && cur is not null; slot--)
        {
            while (cur is not null && cur.OpCode.Code == Code.Nop) cur = cur.Previous;
            if (cur is null) break;
            if (slot == 0) receiverPusher = cur;
            cur = cur.Previous;
        }

        if (receiverPusher is null) return false;
        if (receiverPusher.OpCode.Code != Code.Ldloca && receiverPusher.OpCode.Code != Code.Ldloca_S) return false;
        if (receiverPusher.Operand is not VariableDefinition vd) return false;

        var prov = $"InterpolatedString({valueSlot.Provenance})";
        state.Locals[vd.Index] = StackSlot.TaintedWith(prov);
        return true;
    }
```

- [ ] **Step 2: Run the Task 2 test; verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TryHandleInterpolatedStringAppend_TaintedValue" -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test).

- [ ] **Step 3: Run full SinkShapesTests to confirm no regression**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SinkShapesTests" -- xunit.parallelizeTestCollections=false`
Expected: all 17 prior tests + the new one pass (18 total).

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/SinkShapes.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "analyzer: SinkShapes.TryHandleInterpolatedStringAppend recognizer for $\"...\" taint propagation"
```

---

### Task 4: Untainted-value guard test

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Append the test**

```csharp
    [Fact]
    public void TryHandleInterpolatedStringAppend_UntaintedValue_NoStateChange()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.InterpolatedStringFixtures::DoFormat(System.String)");

        var call = m.Body.Instructions.Single(i =>
            i.OpCode == Mono.Cecil.Cil.OpCodes.Call &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendFormatted" &&
            mr.DeclaringType.FullName == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.Untainted };
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeFalse();
        state.Locals.ShouldBeEmpty();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TryHandleInterpolatedStringAppend_UntaintedValue" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: TryHandleInterpolatedStringAppend rejects untainted value"
```

---

### Task 5: AppendLiteral guard test

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Append the test**

```csharp
    [Fact]
    public void TryHandleInterpolatedStringAppend_AppendLiteral_ReturnsFalse()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.InterpolatedStringFixtures::DoFormat(System.String)");

        // Pick any AppendLiteral call from the same method body — the recognizer
        // must return false because the method name is AppendLiteral, not AppendFormatted.
        var call = m.Body.Instructions.First(i =>
            i.OpCode == Mono.Cecil.Cil.OpCodes.Call &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendLiteral" &&
            mr.DeclaringType.FullName == "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.TaintedWith("literal") };  // even if "tainted", must not fire
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeFalse();
        state.Locals.ShouldBeEmpty();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TryHandleInterpolatedStringAppend_AppendLiteral" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: TryHandleInterpolatedStringAppend rejects AppendLiteral calls"
```

---

### Task 6: Non-handler-type guard test

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Append the test**

```csharp
    [Fact]
    public void TryHandleInterpolatedStringAppend_NonHandlerType_ReturnsFalse()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.FakeFormatterFixtures::DoFakeFormat(TaintAnalyzer.Tests.Fixtures.FakeFormatter,System.String)");

        // The call here is on FakeFormatter.AppendFormatted — same method name as the
        // recognizer targets, but the declaring type is not the BCL handler.
        var call = m.Body.Instructions.First(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "AppendFormatted");

        var callee = (Mono.Cecil.MethodReference)call.Operand;
        var argSlots = new[] { StackSlot.TaintedWith("s") };
        var state = new TaintState();

        var handled = SinkShapes.TryHandleInterpolatedStringAppend(callee, call, argSlots, state);

        handled.ShouldBeFalse();
        state.Locals.ShouldBeEmpty();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TryHandleInterpolatedStringAppend_NonHandlerType" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: TryHandleInterpolatedStringAppend rejects non-handler declaring types"
```

---

### Task 7: Wire-up into TaintWalker.HandleCall

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:870-895` (insert early branch after the stack pops)

- [ ] **Step 1: Add the early branch**

In `tools/TaintAnalyzer/TaintWalker.cs`, locate the `HandleCall` method (starts around line 870). Find this block:

```csharp
        var argSlots = new StackSlot[paramCount];
        for (int i = paramCount - 1; i >= 0; i--)
        {
            argSlots[i] = state.Stack.Pop();
        }
        var receiverSlot = hasThisOnStack ? state.Stack.Pop() : default;

        int bitmask = 0;
```

Immediately after the `var receiverSlot = ...` line and BEFORE `int bitmask = 0;`, insert:

```csharp
        // DefaultInterpolatedStringHandler.AppendFormatted recognizer (milestone-T2 Phase 1).
        // Propagates taint from a tainted value arg into the handler local, so subsequent
        // ToStringAndClear() picks up taint via the standard byref-receiver-in-bitmask path.
        // AppendFormatted returns void, so no stack push is needed after the early return.
        if (SinkShapes.TryHandleInterpolatedStringAppend(callee, ins, argSlots, state))
        {
            return false;
        }

```

- [ ] **Step 2: Run all TaintAnalyzer.Tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: all 281 tests pass (277 baseline + 4 new from Tasks 2-6).

- [ ] **Step 3: Run full test suite (regression sweep)**

Run: `dotnet test --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 281 + 63 = 344 tests pass. No anchor regression.

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs
git commit -m "analyzer: TaintWalker.HandleCall consults TryHandleInterpolatedStringAppend"
```

---

### Task 8: Synthetic source project + build script

**Files:**
- Create: `fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.cs`
- Create: `fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.csproj`
- Create: `scripts/build-sqli-interpolated.sh`

- [ ] **Step 1: Create directories**

```bash
mkdir -p fixtures/sqli-interpolated-prefix/source
mkdir -p artifacts/sqli-interpolated-prefix
```

- [ ] **Step 2: Create the source file**

Write `fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.cs`:

```csharp
using System.Data.Common;

namespace InterpolatedSqliPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    // Tainted parameter flows through $"..." interpolation into DbCommand.CommandText.
    // Compiler lowers to DefaultInterpolatedStringHandler.ctor + AppendLiteral / AppendFormatted
    // chain + ToStringAndClear. The T2 Phase-1 walker recognizer taints the handler local on
    // AppendFormatted(regConfig); ToStringAndClear's byref receiver carries that taint to its
    // string return; the T1 set_CommandText matcher then fires the SqlInjection sink.
    public void Search(string regConfig)
    {
        _cmd.CommandText = $"to_tsvector('{regConfig}'::regconfig, body)";
        _cmd.ExecuteNonQuery();
    }
}
```

- [ ] **Step 3: Create the csproj**

Write `fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>InterpolatedSqliDemo</AssemblyName>
    <RootNamespace>InterpolatedSqliPoc</RootNamespace>
  </PropertyGroup>
</Project>
```

- [ ] **Step 4: Create the build script**

Write `scripts/build-sqli-interpolated.sh`:

```bash
#!/usr/bin/env bash
# Builds fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.csproj into
# artifacts/sqli-interpolated-prefix/. Mirrors scripts/build-sqli-synthetic.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-interpolated-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-interpolated-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/InterpolatedSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-interpolated-prefix built at $OUT_DIR/InterpolatedSqliDemo.dll"
```

- [ ] **Step 5: Make it executable and run it**

```bash
chmod +x scripts/build-sqli-interpolated.sh
scripts/build-sqli-interpolated.sh
ls -la artifacts/sqli-interpolated-prefix/InterpolatedSqliDemo.dll
```

Expected: build succeeds, DLL appears at the listed path.

- [ ] **Step 6: Commit**

```bash
git add fixtures/sqli-interpolated-prefix/source/ scripts/build-sqli-interpolated.sh
git commit -m "fixture: sqli-interpolated-prefix source project + build script"
```

---

### Task 9: Generate rules.yaml and lock trace.yaml

**Files:**
- Create: `fixtures/sqli-interpolated-prefix/rules.yaml`
- Create: `fixtures/sqli-interpolated-prefix/trace.yaml`

- [ ] **Step 1: Create rules.yaml**

Write `fixtures/sqli-interpolated-prefix/rules.yaml`:

```yaml
vuln_id: sqli-interpolated-prefix
source_methods:
  - InterpolatedSqliPoc.SearchService::Search(System.String)
```

- [ ] **Step 2: Build analyzer in Release**

Run: `dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release --nologo /v:quiet`
Expected: success.

- [ ] **Step 3: Run analyzer; capture trace**

```bash
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/sqli-interpolated-prefix/InterpolatedSqliDemo.dll \
    --rules fixtures/sqli-interpolated-prefix/rules.yaml \
    --output fixtures/sqli-interpolated-prefix/trace.yaml
echo "EXIT=$?"
cat fixtures/sqli-interpolated-prefix/trace.yaml
```

Expected: exit code 0, non-empty trace.yaml containing `kind: sql_injection` and `api: sql_command_text`.

If the trace is empty (analyzer found no sink), this is a Phase-1 failure — the recognizer or wire-up is wrong. Debug before continuing:
- Confirm the recognizer fires: temporarily add `Console.Error.WriteLine("HANDLED")` in `TryHandleInterpolatedStringAppend` after the receiver-taint line; re-run; remove the debug print before committing.
- Confirm the handler local index matches what's actually emitted: dump IL of the artifact with the inspect-IL technique from milestone-T1 (`/tmp/inspect-il.csx` pattern).

- [ ] **Step 4: Add description block**

Edit `fixtures/sqli-interpolated-prefix/trace.yaml`. Find the first line (`vuln_id: sqli-interpolated-prefix`) and add the following block after it (before `source:`):

```yaml
fix_commit: ""
fix_pr: ""
description: >
  Synthetic regression fixture for milestone-T2 Phase 1: $"..." interpolation
  flowing into IDbCommand.CommandText. SearchService.Search interpolates a
  tainted regConfig parameter via DefaultInterpolatedStringHandler.AppendFormatted
  into a SQL fragment, then assigns to System.Data.Common.DbCommand.CommandText.
  The sink hop has kind: sql_injection, api: sql_command_text. Locked at
  milestone-T2 Phase 1; do not regenerate without re-locking.
```

- [ ] **Step 5: Verify ValidateFixture schema still passes**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 63 tests pass.

- [ ] **Step 6: Commit**

```bash
git add fixtures/sqli-interpolated-prefix/rules.yaml fixtures/sqli-interpolated-prefix/trace.yaml
git commit -m "fixture: sqli-interpolated-prefix rules + locked trace.yaml"
```

---

### Task 10: End-to-end fixture test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/SqliInterpolatedFixtureTests.cs`

- [ ] **Step 1: Write the test**

Write `tools/TaintAnalyzer.Tests/SqliInterpolatedFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class SqliInterpolatedFixtureTests
{
    private static string RepoRoot
    {
        get
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 5 && d?.Parent is not null; i++) d = d.Parent;
            return d!.FullName;
        }
    }

    [Fact]
    public void SqliInterpolatedPrefix_TraceContainsSqlInjectionSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-interpolated-prefix", "InterpolatedSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-interpolated-prefix", "rules.yaml");

        if (!File.Exists(dllPath))
        {
            // Build artifact not materialized in this checkout. Skip silently.
            return;
        }

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-interp-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(
                new[] { dllPath, "--rules", rulesPath, "--output", outPath },
                stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_text");
            trace.ShouldContain("InterpolatedSqliPoc.SearchService");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 2: Run targeted test**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SqliInterpolatedFixtureTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test).

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SqliInterpolatedFixtureTests.cs
git commit -m "test: end-to-end fixture run for sqli-interpolated-prefix"
```

---

## Phase 1 checkpoint

At this point Phase 1 is complete. State summary expected:
- Test count: 277 → 282 (4 unit + 1 e2e in TaintAnalyzer.Tests), 63 ValidateFixture.Tests unchanged. Total **345**.
- Anchors: all existing fixtures green; new `sqli-interpolated-prefix` anchored.
- No walker changes other than the recognizer wire-up.

If any of the above is not true, stop and investigate before starting Phase 2.

---

## Phase 2 — Marten real-world lock

### Task 11: materialize-marten-8.36 script

**Files:**
- Create: `scripts/materialize-marten-8.36.sh`

- [ ] **Step 1: Write the script**

Write `scripts/materialize-marten-8.36.sh`:

```bash
#!/usr/bin/env bash
# Materializes Marten 8.36.0 from NuGet into artifacts/marten-8.36/.
# Mirrors the structure of scripts/materialize-imagesharp-3074.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARTEN_VERSION=8.36.0
OUT_DIR="$REPO_ROOT/artifacts/marten-8.36"
TFM="net9.0"

mkdir -p "$OUT_DIR"

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

cat > "$SCRATCH/scratch.csproj" << EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>$TFM</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Marten" Version="$MARTEN_VERSION" />
  </ItemGroup>
</Project>
EOF

dotnet restore "$SCRATCH/scratch.csproj" --nologo /v:quiet

PKG_DIR="$HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/$TFM"
if [ ! -f "$PKG_DIR/Marten.dll" ]; then
    # Fall back to net8.0 if net9.0 isn't shipped in this version.
    TFM_FALLBACK="net8.0"
    PKG_DIR="$HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/$TFM_FALLBACK"
    if [ ! -f "$PKG_DIR/Marten.dll" ]; then
        echo "error: Marten.dll not found in $HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/{$TFM,$TFM_FALLBACK}/" >&2
        exit 1
    fi
    TFM="$TFM_FALLBACK"
fi

cp "$PKG_DIR/Marten.dll" "$OUT_DIR/Marten.dll"

if [ -f "$PKG_DIR/Marten.pdb" ]; then
    cp "$PKG_DIR/Marten.pdb" "$OUT_DIR/Marten.pdb"
    rm -f "$OUT_DIR/.nopdb-marker"
else
    touch "$OUT_DIR/.nopdb-marker"
fi

echo "marten-8.36 materialized at $OUT_DIR (TFM=$TFM)"
sha256sum "$OUT_DIR/Marten.dll"
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x scripts/materialize-marten-8.36.sh
scripts/materialize-marten-8.36.sh
ls -la artifacts/marten-8.36/
```

Expected: `Marten.dll` (and possibly `Marten.pdb`) at the listed path; SHA256 hash printed. If the script fails because the package can't be restored (network), STOP and report — this needs to be debugged manually before continuing.

- [ ] **Step 3: Verify .gitignore covers artifacts/**

Run: `git check-ignore -v artifacts/marten-8.36/Marten.dll && echo IGNORED || echo NOT_IGNORED`

If `IGNORED`: continue.

If `NOT_IGNORED`: edit `.gitignore` and add a line `artifacts/` (or `artifacts/marten-*/` if the existing convention is more specific). Stage the .gitignore change and include it in the commit below.

- [ ] **Step 4: Commit**

```bash
git add scripts/materialize-marten-8.36.sh
# Also stage .gitignore if it was modified in Step 3.
git commit -m "script: materialize Marten 8.36.0 from NuGet into artifacts/"
```

---

### Task 12: Discover Marten's IQuerySession.SearchAsync signature

**Files:**
- (Temporary, removed after task) `tools/TaintAnalyzer.Tests/_DumpMartenIl.cs`

- [ ] **Step 1: Create a one-shot IL dump test**

Write `tools/TaintAnalyzer.Tests/_DumpMartenIl.cs`:

```csharp
using System;
using System.IO;
using System.Linq;
using Mono.Cecil;
using Xunit;
using Xunit.Abstractions;

namespace TaintAnalyzer.Tests;

public class _DumpMartenIl
{
    private readonly ITestOutputHelper _out;
    public _DumpMartenIl(ITestOutputHelper output) { _out = output; }

    [Fact]
    public void DumpSearchAsyncSignatures()
    {
        var path = Path.Combine(
            new DirectoryInfo(AppContext.BaseDirectory).Parent!.Parent!.Parent!.Parent!.Parent!.FullName,
            "artifacts", "marten-8.36", "Marten.dll");
        if (!File.Exists(path))
        {
            _out.WriteLine($"Marten.dll not found at {path} — run scripts/materialize-marten-8.36.sh first");
            return;
        }

        var asm = AssemblyDefinition.ReadAssembly(path);
        foreach (var t in asm.MainModule.Types)
        {
            if (t.Name != "IQuerySession") continue;
            _out.WriteLine($"Type: {t.FullName}");
            foreach (var m in t.Methods)
            {
                if (!m.Name.Contains("Search", StringComparison.Ordinal)) continue;
                _out.WriteLine($"  Method: {m.FullName}");
                _out.WriteLine($"    HasThis={m.HasThis} IsAbstract={m.IsAbstract}");
                _out.WriteLine($"    Params: {string.Join(", ", m.Parameters.Select(p => $"{p.ParameterType.FullName} {p.Name}"))}");
                if (m.HasGenericParameters)
                {
                    _out.WriteLine($"    Generic params: {string.Join(", ", m.GenericParameters.Select(g => g.Name))}");
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run and capture the signatures**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~_DumpMartenIl" --logger "console;verbosity=detailed" -- xunit.parallelizeTestCollections=false 2>&1 | grep -E "Type:|  Method:|    Params:|    Generic"
```

Expected: console output listing each `SearchAsync*` method on `Marten.IQuerySession` with the exact full signature (`Marten.IQuerySession::SearchAsync<...>(...)`). Save this output — you'll paste the exact form into Task 13's rules.yaml.

- [ ] **Step 3: Remove the temporary file (do not commit)**

```bash
rm tools/TaintAnalyzer.Tests/_DumpMartenIl.cs
```

Do not commit anything for this task. The discovery output is captured in your task log; the rules.yaml in Task 13 uses it.

---

### Task 13: Marten rules.yaml + first lock attempt

**Files:**
- Create: `fixtures/marten-vmw2-prefix/rules.yaml`
- Create: `fixtures/marten-vmw2-prefix/trace.yaml`

- [ ] **Step 1: Create rules.yaml**

Based on Task 12's signature output, write `fixtures/marten-vmw2-prefix/rules.yaml`. The placeholder below shows the expected shape; replace the signature with the exact form discovered in Task 12:

```yaml
vuln_id: marten-vmw2-prefix
source_methods:
  - <exact-signature-from-task-12>
```

Example (the actual line depends on Task 12 output):
```yaml
  - Marten.IQuerySession::SearchAsync(System.String,System.String,System.Threading.CancellationToken)
```

- [ ] **Step 2: First lock attempt — run analyzer**

Determine whether Marten has a PDB:

```bash
NO_SYMBOLS_FLAG=""
if [ -f artifacts/marten-8.36/.nopdb-marker ]; then NO_SYMBOLS_FLAG="--no-symbols"; fi
echo "no-symbols flag: $NO_SYMBOLS_FLAG"
```

Run the analyzer:

```bash
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/marten-8.36/Marten.dll \
    --rules fixtures/marten-vmw2-prefix/rules.yaml \
    --output fixtures/marten-vmw2-prefix/trace.yaml \
    $NO_SYMBOLS_FLAG
echo "EXIT=$?"
cat fixtures/marten-vmw2-prefix/trace.yaml
```

- [ ] **Step 3: Triage the result**

There are three possible outcomes:

**Outcome A — Trace is empty (zero findings):** The walker did not reach a `set_CommandText` site from the source. Likely cause is one of the spec's "known unknowns":

a. Cross-method field-taint seeding for `_regConfig` requires `--include-this-field`. Try re-running with the flag added:
```bash
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/marten-8.36/Marten.dll \
    --rules fixtures/marten-vmw2-prefix/rules.yaml \
    --output fixtures/marten-vmw2-prefix/trace.yaml \
    --include-this-field $NO_SYMBOLS_FLAG
```

If this produces a finding: include `--include-this-field` in the fixture's run pattern going forward. Document the requirement in the rules.yaml header comment.

b. Marten's call graph crosses an interface or virtual dispatch that needs `--include-virtual-overrides`. Try adding that flag too. If `--include-virtual-overrides` requires `--scan` (which is documented in the analyzer's CLI), this won't work directly — STOP and escalate to the controller: this is a walker gap and the spec's escape valve applies (split into T2.1 walker fix + T2.2 lock).

c. The source signature in rules.yaml doesn't match what Cecil sees. Re-check Task 12's output and update rules.yaml.

**Outcome B — Trace fires but with unexpected sink:** the matcher fired on something other than `set_CommandText`. Inspect the trace, note the actual sink, and decide whether the lock is still valuable. If the trace fires on, say, an `Allocation` sink elsewhere in Marten, this is interesting but not the target — note as a separate finding and continue debugging the SQLi path.

**Outcome C — Trace fires with expected sink (`kind: sql_injection`, `api: sql_command_text`):** Lock is good. Proceed to Step 4.

- [ ] **Step 4: Add the description block**

Edit `fixtures/marten-vmw2-prefix/trace.yaml`. After the `vuln_id:` line, add:

```yaml
fix_commit: ""
fix_pr: https://github.com/JasperFx/marten/pull/4343
description: >
  Real-world advisory fixture for GHSA-vmw2-qwm8-x84c (Marten <= 8.36 SQL
  injection via FullTextWhereFragment.Sql interpolating user-controlled
  regConfig). Tainted regConfig parameter flows from IQuerySession.SearchAsync
  through FullTextWhereFragment's constructor + $"..."-built Sql property
  into NpgsqlCommand.CommandText. The sink hop has kind: sql_injection,
  api: sql_command_text (matched via the namespace-prefix fallback in
  MatchesDbProviderHeuristic since Npgsql.dll is not loaded). Locked at
  milestone-T2 Phase 2; do not regenerate without re-locking.
```

- [ ] **Step 5: Verify schema validator passes**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 63 tests pass.

- [ ] **Step 6: Commit**

```bash
git add fixtures/marten-vmw2-prefix/rules.yaml fixtures/marten-vmw2-prefix/trace.yaml
git commit -m "fixture: marten-vmw2-prefix rules + locked trace.yaml (GHSA-vmw2-qwm8-x84c)"
```

If Step 3 required `--include-this-field`, mention it in the commit message: `... (requires --include-this-field)`.

---

### Task 14: Marten end-to-end fixture test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/MartenVmw2FixtureTests.cs`

- [ ] **Step 1: Write the test**

Write `tools/TaintAnalyzer.Tests/MartenVmw2FixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class MartenVmw2FixtureTests
{
    private static string RepoRoot
    {
        get
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 5 && d?.Parent is not null; i++) d = d.Parent;
            return d!.FullName;
        }
    }

    [Fact]
    public void MartenVmw2Prefix_TraceContainsSqlInjectionSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "marten-8.36", "Marten.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "marten-vmw2-prefix", "rules.yaml");

        if (!File.Exists(dllPath))
        {
            // Marten artifact not materialized in this checkout. Skip silently.
            return;
        }

        var noPdbMarker = Path.Combine(RepoRoot, "artifacts", "marten-8.36", ".nopdb-marker");
        var noSymbols = File.Exists(noPdbMarker);

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"marten-vmw2-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--rules", rulesPath, "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");
            // If Task 13 required --include-this-field, add it here:
            // args.Add("--include-this-field");

            var rc = Program.Run(args.ToArray(), stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_text");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

If Task 13 required `--include-this-field` to produce the trace, uncomment the `args.Add("--include-this-field");` line in the test above.

- [ ] **Step 2: Run targeted test**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MartenVmw2FixtureTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test). If `artifacts/marten-8.36/Marten.dll` is present in your checkout, the test runs and asserts the trace markers. If absent, it skips silently.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/MartenVmw2FixtureTests.cs
git commit -m "test: end-to-end fixture run for marten-vmw2-prefix"
```

---

### Task 15: Full regression sweep and milestone close

**Files:**
- None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `dotnet test --nologo /v:quiet -- xunit.parallelizeTestCollections=false`

Expected:
- `TaintAnalyzer.Tests`: 277 + 6 (4 unit + 1 sqli-interp e2e + 1 marten e2e) = **283 passed**.
- `ValidateFixture.Tests`: 63 passed.
- **Total: 346 passed, 0 failed.**

If any prior test failed, the recognizer is firing where it shouldn't or the wire-up has a side effect. Investigate before continuing.

- [ ] **Step 2: Run scan-fixture lock scripts**

```bash
bash fixtures/scan-protobuf-net/run
bash fixtures/scan-nbmp-1.1.25/run
```

Expected: each prints either `match` (artifact materialized + lock matches) or `skip: ... DLL not at ...`. Anything else is a regression.

- [ ] **Step 3: Run T1's synthetic lock check**

The T1 synthetic fixture doesn't have a `run` script (per the milestone-T1 convention). It runs via the fixture-runner test which is included in Step 1. Confirm `SqliSyntheticFixtureTests` passed in Step 1's output.

- [ ] **Step 4: Final clean tree check**

```bash
git status
```

Expected: clean working tree. All milestone-T2 work committed.

- [ ] **Step 5: Summarize for user**

Report:
- 15 tasks completed across Phase 1 + Phase 2.
- Test count: 277 → 283 TaintAnalyzer.Tests (+6); 63 ValidateFixture.Tests unchanged; **total 346**.
- New files: walker recognizer (`SinkShapes.TryHandleInterpolatedStringAppend`), Phase 1 synthetic fixture, Phase 2 Marten fixture, two new fixture-runner test files, two new build/materialize scripts.
- Anchor regressions: none.
- Awaiting: user push to origin/main of the worktree branch via fast-forward to main.
- Next milestones: T3 (Marten postfix lock — regex-guard sanitizer extension).
