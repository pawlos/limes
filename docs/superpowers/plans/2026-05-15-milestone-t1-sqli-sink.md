# Milestone-T1: SQLi sink (CommandText setter) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Limes's first non-DoS sink class — detect a tainted string flowing into `IDbCommand.CommandText`, locked by a synthetic prefix fixture.

**Architecture:** Two new enum values (`SinkKind.SqlInjection`, `SinkApi.SqlCommandText`), one new matcher (`SinkShapes.MatchCommandTextSetter`) wired into `TaintWalker.HandleSinkMatch`, one new synthetic fixture under `fixtures/sqli-synthetic-prefix/`. No walker semantic changes; no changes to `EntryPointEnumerator`, `ReverseCallGraph`, or `SanitizerShapes`.

**Tech Stack:** .NET 10, Mono.Cecil, xUnit, Shouldly. Spec: `docs/superpowers/specs/2026-05-15-milestone-t-sqli-design.md`.

**Anchor discipline:** Before merge, every existing fixture (imagesharp / otelcontrib / nbmp / parquet / synthetic / scan-protobuf-net / scan-nbmp) must remain green. The new matcher fires only on `set_CommandText`-shaped instructions, which don't appear in any current fixture's call graph, so zero new findings is the expected delta.

---

### Task 1: Add new enum values

**Files:**
- Modify: `tools/TaintAnalyzer/HopRecord.cs:5-7`

- [ ] **Step 1: Modify SinkKind enum**

In `tools/TaintAnalyzer/HopRecord.cs`, change line 5 from:

```csharp
public enum SinkKind { Allocation, SpanAccess }
```

to:

```csharp
public enum SinkKind { Allocation, SpanAccess, SqlInjection }
```

- [ ] **Step 2: Modify SinkApi enum**

In the same file, change line 7 from:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc, HttpContentRead, HttpClientRead }
```

to:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc, HttpContentRead, HttpClientRead, SqlCommandText }
```

- [ ] **Step 3: Build to confirm enum addition is clean**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Debug`
Expected: build succeeds. (No call site consumes the new values yet, so adding them is non-breaking.)

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/HopRecord.cs
git commit -m "analyzer: add SinkKind.SqlInjection + SinkApi.SqlCommandText enum values"
```

---

### Task 2: Add SQLi sink fixture method to test-fixtures assembly

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (insert new fixture class)

- [ ] **Step 1: Add SqlSinkFixtures class**

Open `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`. Insert this class after the existing `SinkFixtures` class (which ends around line 60; find the closing brace of `public static class SinkFixtures { ... }` and insert below it):

```csharp
public static class SqlSinkFixtures
{
    // Single-line setter — lowers to: ldarg.0, ldarg.1, callvirt set_CommandText.
    // Used by SinkShapesTests.MatchCommandTextSetter_* to extract the callvirt
    // instruction at a known offset.
    public static void AssignCommandText(System.Data.Common.DbCommand cmd, string sql)
    {
        cmd.CommandText = sql;
    }

    // Setter via the interface — lowers to callvirt on System.Data.IDbCommand::set_CommandText.
    public static void AssignViaInterface(System.Data.IDbCommand cmd, string sql)
    {
        cmd.CommandText = sql;
    }

    public static void AssignUnrelatedCommandText(UnrelatedCommandTextHolder obj, string value)
    {
        obj.CommandText = value;
    }
}

// Negative-case fixture: an unrelated class with a CommandText member.
// The matcher must NOT fire on this type — kept as a sibling top-level class
// (not nested) so Cecil's short-sig format is straightforward in the test below.
public sealed class UnrelatedCommandTextHolder
{
    public string CommandText { get; set; } = "";
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug`
Expected: build succeeds. Fixture DLL is rebuilt; test bin gets the updated DLL on next test build.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "test-fixtures: SqlSinkFixtures with DbCommand / IDbCommand / unrelated-type setters"
```

---

### Task 3: Failing test — MatchCommandTextSetter on DbCommand-typed receiver

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append to end of class)

- [ ] **Step 1: Write the failing test**

Append to `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`, inside `public class SinkShapesTests { ... }`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_DbCommandSubtype_Tainted_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignCommandText(System.Data.Common.DbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver (the DbCommand)
        stack.Push(StackSlot.TaintedWith("sql"));              // value (Peek(0))

        var match = SinkShapes.MatchCommandTextSetter(setter, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }
```

- [ ] **Step 2: Build and run; verify it fails**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchCommandTextSetter_DbCommandSubtype_Tainted_Matches" -- xunit.parallelizeTestCollections=false`
Expected: build FAILS with `CS0117: 'SinkShapes' does not contain a definition for 'MatchCommandTextSetter'`. This is the failing red state.

---

### Task 4: Implement minimal MatchCommandTextSetter (BCL-resolved path only)

**Files:**
- Modify: `tools/TaintAnalyzer/SinkShapes.cs` (append new method before closing brace)

- [ ] **Step 1: Add the matcher method**

Append to `tools/TaintAnalyzer/SinkShapes.cs`, inside `public static class SinkShapes { ... }`, before the closing `}`:

```csharp
    // SQL injection sink: tainted string assigned to IDbCommand.CommandText.
    // Matches `callvirt System.Data.IDbCommand::set_CommandText(string)` OR a setter
    // on a class that implements IDbCommand. Resolve-failure fallback (Task 8) accepts
    // declaring types under known DB-provider namespaces whose names end in `Command`.
    public static SinkMatch? MatchCommandTextSetter(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "set_CommandText") return null;
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return null;

        var declaring = mr.DeclaringType;
        var resolved = declaring.Resolve();
        if (resolved is null) return null;   // Task 8 extends this with the fallback heuristic.

        if (!ImplementsIDbCommand(resolved)) return null;

        if (stack.Depth < 2) return null;    // receiver + value
        var valueSlot = stack.Peek(0);
        if (!valueSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SqlInjection,
            Api = SinkApi.SqlCommandText,
            SizeProvenance = valueSlot.Provenance,
        };
    }

    private static bool ImplementsIDbCommand(TypeDefinition td)
    {
        const string Target = "System.Data.IDbCommand";

        // Walk the base chain and check interface implementations on each.
        var current = td;
        while (current is not null)
        {
            if (current.FullName == Target) return true;
            foreach (var iface in current.Interfaces)
            {
                var ir = iface.InterfaceType;
                if (ir.FullName == Target) return true;
                // Interface inheritance — resolve and check transitively.
                var iresolved = ir.Resolve();
                if (iresolved is not null && ImplementsIDbCommandViaInterface(iresolved, Target)) return true;
            }
            var baseType = current.BaseType;
            current = baseType?.Resolve();
        }
        return false;
    }

    private static bool ImplementsIDbCommandViaInterface(TypeDefinition iface, string target)
    {
        if (iface.FullName == target) return true;
        foreach (var parent in iface.Interfaces)
        {
            var pr = parent.InterfaceType;
            if (pr.FullName == target) return true;
            var presolved = pr.Resolve();
            if (presolved is not null && ImplementsIDbCommandViaInterface(presolved, target)) return true;
        }
        return false;
    }
```

- [ ] **Step 2: Run the test from Task 3 again; verify it passes**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchCommandTextSetter_DbCommandSubtype_Tainted_Matches" -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test).

- [ ] **Step 3: Run full SinkShapesTests to confirm no regression**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SinkShapesTests" -- xunit.parallelizeTestCollections=false`
Expected: all prior SinkShapesTests pass + the new one. No regressions.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/SinkShapes.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "analyzer: SinkShapes.MatchCommandTextSetter for IDbCommand-subtype receivers"
```

---

### Task 5: Test for direct-IDbCommand-typed receiver

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

This case (interface-typed receiver) goes through the `current.FullName == Target` short-circuit at the very top of `ImplementsIDbCommand`. It's the simpler path and should already pass — this test is a regression guard.

- [ ] **Step 1: Write the test**

Append inside `SinkShapesTests`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_DirectIDbCommand_Tainted_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignViaInterface(System.Data.IDbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("sql"));              // value

        var match = SinkShapes.MatchCommandTextSetter(setter, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchCommandTextSetter_DirectIDbCommand" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: MatchCommandTextSetter accepts IDbCommand-typed receiver"
```

---

### Task 6: Test for untainted-value rejection

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Write the test**

Append inside `SinkShapesTests`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_Untainted_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignCommandText(System.Data.Common.DbCommand,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.Untainted);                       // value — untainted

        SinkShapes.MatchCommandTextSetter(setter, stack).ShouldBeNull();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchCommandTextSetter_Untainted" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: MatchCommandTextSetter rejects untainted value"
```

---

### Task 7: Test for non-DbType rejection

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Write the test**

Append inside `SinkShapesTests`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_NonDbType_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.SqlSinkFixtures::AssignUnrelatedCommandText(TaintAnalyzer.Tests.Fixtures.UnrelatedCommandTextHolder,System.String)");

        var setter = m.Body.Instructions.Single(i =>
            (i.OpCode == Mono.Cecil.Cil.OpCodes.Call || i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt) &&
            i.Operand is Mono.Cecil.MethodReference mr &&
            mr.Name == "set_CommandText");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("value"));            // value tainted, but type isn't DB

        SinkShapes.MatchCommandTextSetter(setter, stack).ShouldBeNull();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchCommandTextSetter_NonDbType" -- xunit.parallelizeTestCollections=false`
Expected: PASS. `UnrelatedCommandText` does not implement `IDbCommand`, so the matcher returns null even though the value is tainted.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: MatchCommandTextSetter rejects unrelated type with CommandText property"
```

---

### Task 8: Resolve-failure fallback heuristic

**Files:**
- Modify: `tools/TaintAnalyzer/SinkShapes.cs:MatchCommandTextSetter` (replace null-return on resolve failure with fallback)
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Write the failing test**

Append inside `SinkShapesTests`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_ResolveFailure_FallbackHeuristic_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Synthesize a MethodReference whose declaring type is in the Npgsql namespace
        // and ends with "Command" but cannot be resolved (no Npgsql assembly loaded).
        var module = ctx.Assembly.MainModule;
        var stringType = module.TypeSystem.String;
        var voidType = module.TypeSystem.Void;
        var declaringType = new Mono.Cecil.TypeReference("Npgsql", "NpgsqlCommand", module, module);
        var setter = new Mono.Cecil.MethodReference("set_CommandText", voidType, declaringType)
        {
            HasThis = true,
        };
        setter.Parameters.Add(new Mono.Cecil.ParameterDefinition(stringType));
        var ins = Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Callvirt, setter);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("sql"));              // value

        var match = SinkShapes.MatchCommandTextSetter(ins, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandText);
        match.SizeProvenance.ShouldBe("sql");
    }
```

- [ ] **Step 2: Run and verify it fails**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~ResolveFailure_FallbackHeuristic" -- xunit.parallelizeTestCollections=false`
Expected: FAIL — current matcher returns null on resolve failure, but the test expects a match.

- [ ] **Step 3: Add the fallback heuristic**

In `tools/TaintAnalyzer/SinkShapes.cs`, locate this block inside `MatchCommandTextSetter`:

```csharp
        var declaring = mr.DeclaringType;
        var resolved = declaring.Resolve();
        if (resolved is null) return null;   // Task 8 extends this with the fallback heuristic.

        if (!ImplementsIDbCommand(resolved)) return null;
```

Replace it with:

```csharp
        var declaring = mr.DeclaringType;
        var resolved = declaring.Resolve();
        if (resolved is not null)
        {
            if (!ImplementsIDbCommand(resolved)) return null;
        }
        else
        {
            if (!MatchesDbProviderHeuristic(declaring)) return null;
        }
```

Then add this helper method below `ImplementsIDbCommandViaInterface`:

```csharp
    // Fallback when MethodReference.Resolve() returns null (declaring type's assembly
    // not loaded). Accepts known ADO.NET provider namespaces with type names ending
    // in "Command". Trades a small FP risk for the ability to scan apps that reference
    // DB providers without us loading the provider assembly.
    private static bool MatchesDbProviderHeuristic(TypeReference tr)
    {
        var typeName = tr.Name ?? "";
        if (!typeName.EndsWith("Command", StringComparison.Ordinal)) return false;

        var ns = tr.Namespace ?? "";
        return ns.StartsWith("System.Data.", StringComparison.Ordinal)
            || ns.StartsWith("Npgsql", StringComparison.Ordinal)
            || ns.StartsWith("MySql", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.Data.", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.EntityFrameworkCore.", StringComparison.Ordinal);
    }
```

- [ ] **Step 4: Run the test again; verify it passes**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~ResolveFailure_FallbackHeuristic" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 5: Run all SinkShapesTests to confirm no regression**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SinkShapesTests" -- xunit.parallelizeTestCollections=false`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/SinkShapes.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "analyzer: MatchCommandTextSetter fallback heuristic for unresolved DB-provider types"
```

---

### Task 9: Negative test for fallback heuristic

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` (append test)

- [ ] **Step 1: Write the test**

Append inside `SinkShapesTests`:

```csharp
    [Fact]
    public void MatchCommandTextSetter_ResolveFailure_NoFallback_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Unresolvable declaring type with namespace NOT in the DB-provider list.
        // Type name ends in "Command" so the name half of the heuristic passes,
        // but namespace doesn't qualify — overall fallback must reject.
        var module = ctx.Assembly.MainModule;
        var stringType = module.TypeSystem.String;
        var voidType = module.TypeSystem.Void;
        var declaringType = new Mono.Cecil.TypeReference("Acme.Logging", "LogCommand", module, module);
        var setter = new Mono.Cecil.MethodReference("set_CommandText", voidType, declaringType)
        {
            HasThis = true,
        };
        setter.Parameters.Add(new Mono.Cecil.ParameterDefinition(stringType));
        var ins = Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Callvirt, setter);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.TaintedWith("value"));

        SinkShapes.MatchCommandTextSetter(ins, stack).ShouldBeNull();
    }
```

- [ ] **Step 2: Run and verify pass**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~ResolveFailure_NoFallback" -- xunit.parallelizeTestCollections=false`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/SinkShapesTests.cs
git commit -m "test: MatchCommandTextSetter fallback rejects non-DB namespaces"
```

---

### Task 10: Wire matcher into TaintWalker

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:270-277`

- [ ] **Step 1: Add the matcher to the sink sweep**

Open `tools/TaintAnalyzer/TaintWalker.cs`. Locate this block at lines 270-277:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchBinaryReaderReadBytes(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack)
            ?? SinkShapes.MatchHttpRead(ins, state.Stack);
```

Append the new matcher to the chain:

```csharp
        var m =
            SinkShapes.MatchNewArr(ins, state.Stack)
            ?? SinkShapes.MatchArrayPoolRent(ins, state.Stack)
            ?? SinkShapes.MatchBinaryReaderReadBytes(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanSlice(ins, state.Stack)
            ?? SinkShapes.MatchReadOnlySpanIndex(ins, state.Stack)
            ?? SinkShapes.MatchLocalloc(ins, state.Stack)
            ?? SinkShapes.MatchHttpRead(ins, state.Stack)
            ?? SinkShapes.MatchCommandTextSetter(ins, state.Stack);
```

- [ ] **Step 2: Run all TaintAnalyzer.Tests**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj -- xunit.parallelizeTestCollections=false`
Expected: all existing tests pass. Wiring is a no-op for them because none of the existing fixtures contain `set_CommandText`-shaped instructions.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/TaintWalker.cs
git commit -m "analyzer: TaintWalker.HandleSinkMatch consults MatchCommandTextSetter"
```

---

### Task 11: TraceEmitter string mappings

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:385-401`

- [ ] **Step 1: Add SinkKind.SqlInjection to SinkKindToString**

Open `tools/TaintAnalyzer/TraceEmitter.cs`. Locate `SinkKindToString` (around line 385):

```csharp
    private static string? SinkKindToString(SinkKind? k) => k switch
    {
        SinkKind.Allocation => "allocation",
        SinkKind.SpanAccess => "span_access",
        _ => null,
    };
```

Add the new case:

```csharp
    private static string? SinkKindToString(SinkKind? k) => k switch
    {
        SinkKind.Allocation => "allocation",
        SinkKind.SpanAccess => "span_access",
        SinkKind.SqlInjection => "sql_injection",
        _ => null,
    };
```

- [ ] **Step 2: Add SinkApi.SqlCommandText to SinkApiToString**

Locate `SinkApiToString` (around line 392):

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
        _ => null,
    };
```

Add the new case:

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
        SinkApi.SqlCommandText => "sql_command_text",
        _ => null,
    };
```

- [ ] **Step 3: Build and run all TaintAnalyzer.Tests**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj -- xunit.parallelizeTestCollections=false`
Expected: all pass. No call-site consumer fires the new strings yet (synthetic fixture comes in Task 12).

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/TraceEmitter.cs
git commit -m "analyzer: TraceEmitter serializes sql_injection / sql_command_text"
```

---

### Task 12: Synthetic source project + build script

**Files:**
- Create: `fixtures/sqli-synthetic-prefix/source/SqliDemo.cs`
- Create: `fixtures/sqli-synthetic-prefix/source/SqliDemo.csproj`
- Create: `scripts/build-sqli-synthetic.sh`

- [ ] **Step 1: Create the source directory and class**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
mkdir -p fixtures/sqli-synthetic-prefix/source
mkdir -p artifacts/sqli-synthetic-prefix
```

Create `fixtures/sqli-synthetic-prefix/source/SqliDemo.cs` with:

```csharp
using System.Data.Common;

namespace SqliSyntheticPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    public void Search(string regConfig, string term)
    {
        var sql = "SELECT * FROM docs WHERE to_tsvector('"
                  + regConfig
                  + "'::regconfig, body) @@ to_tsquery('"
                  + term
                  + "')";
        _cmd.CommandText = sql;
        _cmd.ExecuteNonQuery();
    }
}
```

- [ ] **Step 2: Create the csproj**

Create `fixtures/sqli-synthetic-prefix/source/SqliDemo.csproj` with:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>SqliDemo</AssemblyName>
    <RootNamespace>SqliSyntheticPoc</RootNamespace>
  </PropertyGroup>
</Project>
```

- [ ] **Step 3: Create the build script**

Create `scripts/build-sqli-synthetic.sh` with:

```bash
#!/usr/bin/env bash
# Builds fixtures/sqli-synthetic-prefix/source/SqliDemo.csproj into
# artifacts/sqli-synthetic-prefix/. Mirrors scripts/build-synthetic-stackalloc.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-synthetic-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-synthetic-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/SqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-synthetic-prefix built at $OUT_DIR/SqliDemo.dll"
```

- [ ] **Step 4: Make it executable and run it**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
chmod +x scripts/build-sqli-synthetic.sh
scripts/build-sqli-synthetic.sh
```

Expected output: `sqli-synthetic-prefix built at /mnt/c/work/dotnet-taint-analyzer/artifacts/sqli-synthetic-prefix/SqliDemo.dll`. Verify with:

```bash
ls -la /mnt/c/work/dotnet-taint-analyzer/artifacts/sqli-synthetic-prefix/SqliDemo.dll
```

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add fixtures/sqli-synthetic-prefix/source/ scripts/build-sqli-synthetic.sh
git commit -m "fixture: sqli-synthetic-prefix source project + build script"
```

---

### Task 13: Generate the rules.yaml and trace.yaml lock

**Files:**
- Create: `fixtures/sqli-synthetic-prefix/rules.yaml`
- Create: `fixtures/sqli-synthetic-prefix/trace.yaml`

- [ ] **Step 1: Create rules.yaml**

Create `fixtures/sqli-synthetic-prefix/rules.yaml` with:

```yaml
vuln_id: sqli-synthetic-prefix
source_methods:
  - SqliSyntheticPoc.SearchService::Search(System.String,System.String)
```

- [ ] **Step 2: Build the analyzer in Release**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release --nologo /v:quiet`
Expected: success. Analyzer DLL at `tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll`.

- [ ] **Step 3: Run the analyzer and capture output**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/sqli-synthetic-prefix/SqliDemo.dll \
    --rules fixtures/sqli-synthetic-prefix/rules.yaml \
    --output fixtures/sqli-synthetic-prefix/trace.yaml
```

Expected: exit code 0, file written. Inspect the output:

```bash
cat fixtures/sqli-synthetic-prefix/trace.yaml
```

Expected content shape (header values may differ — sink line/file numbers depend on the C# compiler's sequence points; lock whatever the analyzer emits):

```yaml
vuln_id: sqli-synthetic-prefix
fix_commit: ""
fix_pr: ""
description: ""
source:
  method: SqliSyntheticPoc.SearchService.Search
  ...
sink:
  method: SqliSyntheticPoc.SearchService.Search
  ...
  kind: sql_injection
  api: sql_command_text
  ...
```

The critical assertions for the lock: `kind: sql_injection` and `api: sql_command_text` must appear in the sink hop. If they don't, the matcher isn't firing — return to Task 10 to debug the wiring.

- [ ] **Step 4: Manually fill in description / fix_commit fields**

The analyzer leaves header fields empty when not in rules.yaml. Edit `fixtures/sqli-synthetic-prefix/trace.yaml` and add a description block at the top (mirror `synthetic-stackalloc/trace.yaml`):

Find the `description: >` line (or empty `description:`) and replace it with:

```yaml
description: >
  Synthetic regression fixture for milestone-T1 SQL-injection sink kind.
  SqliSyntheticPoc.SearchService.Search concatenates two tainted string
  parameters into a SQL fragment and assigns to System.Data.Common.DbCommand
  CommandText. The sink hop has kind: sql_injection, api: sql_command_text.
  Locked at milestone-T1; do not regenerate without re-locking.
```

Leave `fix_commit` and `fix_pr` as empty strings — there is no upstream fix (this is a synthetic). 

- [ ] **Step 5: Verify trace.yaml passes the fixture schema validator**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj -- xunit.parallelizeTestCollections=false`
Expected: all FixtureValidator tests still pass (this test suite validates the schema constants — adding new files won't break it, but confirm nothing regresses).

- [ ] **Step 6: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add fixtures/sqli-synthetic-prefix/rules.yaml fixtures/sqli-synthetic-prefix/trace.yaml
git commit -m "fixture: sqli-synthetic-prefix rules + locked trace.yaml"
```

---

### Task 14: End-to-end integration test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/SqliSyntheticFixtureTests.cs`

- [ ] **Step 1: Write the failing test**

Create `tools/TaintAnalyzer.Tests/SqliSyntheticFixtureTests.cs` with:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class SqliSyntheticFixtureTests
{
    private static string RepoRoot
    {
        get
        {
            // Test bin is at tools/TaintAnalyzer.Tests/bin/<config>/net10.0/.
            // Walk up four levels to repo root.
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 5 && d?.Parent is not null; i++) d = d.Parent;
            return d!.FullName;
        }
    }

    [Fact]
    public void SqliSyntheticPrefix_TraceContainsSqlInjectionSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-synthetic-prefix", "SqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-synthetic-prefix", "rules.yaml");

        if (!File.Exists(dllPath))
        {
            // Build artifact not materialized in this checkout. Skip silently —
            // mirrors the pattern used by scan-protobuf-net's run script.
            return;
        }

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-synth-{Guid.NewGuid()}.yaml");
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
            trace.ShouldContain("SqliSyntheticPoc.SearchService");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 2: Run; verify build + test pass**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SqliSyntheticFixtureTests" -- xunit.parallelizeTestCollections=false`

Expected: PASS (1 test). If the artifact directory doesn't exist (fresh clone), the test silently no-ops — same pattern as scan fixtures.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/SqliSyntheticFixtureTests.cs
git commit -m "test: end-to-end fixture run for sqli-synthetic-prefix"
```

---

### Task 15: Full regression sweep and milestone close

**Files:**
- None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test -- xunit.parallelizeTestCollections=false`

Expected output (test counts):
- `TaintAnalyzer.Tests`: 270 + 7 new (Tasks 3, 5, 6, 7, 8, 9, 14) = 277 passed.
- `ValidateFixture.Tests`: 63 passed.
- **Total: 340 passed, 0 failed.**

If any prior test fails, the matcher is firing somewhere it shouldn't. Investigate before continuing.

- [ ] **Step 2: Run the scan-fixture lock scripts**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
fixtures/scan-protobuf-net/run
fixtures/scan-nbmp-1.1.25/run
```

Expected for each: either `match` output OR `skip: ... DLL not at ...` if the artifact isn't materialized. Anything else (a `diff -u` output) is a regression — investigate before continuing.

- [ ] **Step 3: Final commit (milestone marker)**

If there are no outstanding changes, skip. Otherwise:

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git status
```

Expected: clean working tree. All milestone-T1 work committed.

- [ ] **Step 4: Summarize for user**

Report back:
- Task count: 15 tasks completed.
- Test count: 270 → 277 (+7 unit tests for `MatchCommandTextSetter`) plus 1 fixture-runner test.
- New files: `tools/TaintAnalyzer/SinkShapes.cs` (matcher methods appended), `fixtures/sqli-synthetic-prefix/{source,rules.yaml,trace.yaml}`, `scripts/build-sqli-synthetic.sh`, `tools/TaintAnalyzer.Tests/SqliSyntheticFixtureTests.cs`.
- Modified files: `HopRecord.cs`, `SinkShapes.cs`, `TaintWalker.cs`, `TraceEmitter.cs`, `Fixtures.cs`, `SinkShapesTests.cs`.
- Anchor regressions: none.
- Awaiting: user push to origin/main (per memory rule).
- Next milestones: T2 (Marten prefix lock — needs `DefaultInterpolatedStringHandler` byref modeling), T3 (Marten postfix lock — needs regex-guard throw-shape sanitizer).
