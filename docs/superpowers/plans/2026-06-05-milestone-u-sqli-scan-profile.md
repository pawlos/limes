# Milestone-U: SQLi `--scan` Profile — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--scan-profile sqli` that cold-rediscovers SQL-injection entry points (CWE-89) by enumerating string-typed sources gated on transitive reach to a SQL sink, proven by re-finding the Marten `FullTextWhereFragment` path with no hand-written rules.

**Architecture:** A `ScanProfile` (default `dos`, unchanged) selects the source-type set, candidate gate, and reported sink kinds. The new `sqli` profile uses `System.String` sources, turns the this-field path on, and gates every candidate on a new `SqlSinkReachability` pass (transitive reach to a SQL-sink call site). The SQL-sink call-site recognition is extracted from `SinkShapes` into one shared predicate (`IsSqlSinkCall`) so the static gate and the runtime walker cannot drift. `Program` filters reported findings to the profile's sink kind.

**Tech Stack:** C# / .NET 10, Mono.Cecil (IL inspection), xUnit + Shouldly. Tests run non-parallel: `dotnet test ... -- xunit.parallelizeTestCollections=false`.

---

## File Structure

**Create:**
- `tools/TaintAnalyzer/ScanProfile.cs` — `enum ScanProfile { Dos, Sqli }`.
- `tools/TaintAnalyzer/SqlSinkReachability.cs` — transitive "reaches a SQL sink" set over call edges.
- `tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs` — synthetic types for the reachability + sqli-enumeration tests.
- `tools/TaintAnalyzer.Tests/SqlSinkReachabilityTests.cs` — unit tests for the reachability pass.
- `tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs` — unit tests for the sqli enumeration paths.
- `tools/TaintAnalyzer.Tests/ScanMartenVmw2FixtureTests.cs` — the milestone anchor (cold rediscovery).

**Modify:**
- `tools/TaintAnalyzer/SinkShapes.cs` — extract `IsSqlSinkCall` + two private signature predicates; `MatchCommandTextSetter` / `MatchCommandBuilderAppend` delegate to them (behavior-preserving).
- `tools/TaintAnalyzer/EnumeratorConfig.cs` — add `StringSourceTypes` (default `{ "System.String" }`).
- `tools/TaintAnalyzer/EntryPointEnumerator.cs` — add a profile+gate `Enumerate` overload and the sqli this-field seeding helper.
- `tools/TaintAnalyzer/Program.cs` — `--scan-profile` flag + validation + wiring + sink-kind post-filter + usage text.
- `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs` — CLI flag tests.

**Note on existing behavior to preserve:** the 3-argument `EntryPointEnumerator.Enumerate(context, config, graph)` overload stays and keeps meaning "dos profile" — all existing enumerator tests call it unchanged. The `dos` path must stay byte-for-byte identical (the `scan-protobuf-net` / `scan-nbmp` locks are the proof).

---

### Task 1: Extract shared SQL-sink-call predicate (`SinkShapes` refactor)

Behavior-preserving refactor. The safety net is the existing sink + Marten suite — no new test asserts the refactor directly; Task 2 exercises the new predicate through the reachability pass.

**Files:**
- Modify: `tools/TaintAnalyzer/SinkShapes.cs`

- [ ] **Step 1: Add the shared predicates.** Insert these three methods into the `SinkShapes` class (e.g. just above `MatchCommandTextSetter` at line 200). They encode exactly the signature/declaring-type checks the two existing matchers already perform — no stack inspection.

```csharp
// Shared signature-level recognition of a SQL-sink call site (no stack inspection).
// Used by BOTH the runtime sink matchers below AND SqlSinkReachability's static gate,
// so the two cannot drift. A "SQL sink" is either IDbCommand.set_CommandText(string)
// or ICommandBuilder.AppendWithParameters(string, ...).
public static bool IsSqlSinkCall(MethodReference mr)
    => IsCommandTextSetterCall(mr) || IsCommandBuilderAppendCall(mr);

private static bool IsCommandTextSetterCall(MethodReference mr)
{
    if (mr.Name != "set_CommandText") return false;
    if (mr.Parameters.Count != 1) return false;
    if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;

    var declaring = mr.DeclaringType;
    var resolved = declaring.Resolve();
    return resolved is not null
        ? ImplementsIDbCommand(resolved)
        : MatchesDbProviderHeuristic(declaring);
}

private static bool IsCommandBuilderAppendCall(MethodReference mr)
{
    if (mr.Name != "AppendWithParameters") return false;
    if (mr.Parameters.Count < 1) return false;
    if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;

    var declaring = mr.DeclaringType;
    TypeDefinition? resolved;
    try { resolved = declaring.Resolve(); }
    catch (AssemblyResolutionException) { resolved = null; }
    return resolved is not null
        ? ImplementsCommandBuilder(resolved)
        : MatchesCommandBuilderHeuristic(declaring);
}
```

- [ ] **Step 2: Make `MatchCommandTextSetter` delegate.** Replace the body of `MatchCommandTextSetter` (lines 200-229) with:

```csharp
public static SinkMatch? MatchCommandTextSetter(Instruction instruction, SymbolicStack stack)
{
    if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
    if (instruction.Operand is not MethodReference mr) return null;
    if (!IsCommandTextSetterCall(mr)) return null;

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
```

- [ ] **Step 3: Make `MatchCommandBuilderAppend` delegate.** Replace the body of `MatchCommandBuilderAppend` (lines 397-432) with:

```csharp
public static SinkMatch? MatchCommandBuilderAppend(Instruction instruction, SymbolicStack stack)
{
    if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
    if (instruction.Operand is not MethodReference mr) return null;
    if (!IsCommandBuilderAppendCall(mr)) return null;

    // Stack layout: [receiver, arg0, arg1, …, argN-1] with argN-1 at Peek(0).
    // The SQL string (arg0) is at Peek(paramCount - 1).
    int paramCount = mr.Parameters.Count;
    int peekOffset = paramCount - 1;
    if (stack.Depth < paramCount + 1) return null;
    var sqlSlot = stack.Peek(peekOffset);
    if (!sqlSlot.Tainted) return null;

    return new SinkMatch
    {
        Kind = SinkKind.SqlInjection,
        Api = SinkApi.SqlCommandBuilderAppend,
        SizeProvenance = sqlSlot.Provenance,
    };
}
```

- [ ] **Step 4: Build and run the existing SQL/Marten suite to prove no behavior change.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo -- xunit.parallelizeTestCollections=false`
Expected: PASS, 299 passed (unchanged count).

- [ ] **Step 5: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/SinkShapes.cs
git commit -m "$(printf 'analyzer: extract shared IsSqlSinkCall predicate from SinkShapes\n\nBehaviour-preserving: MatchCommandTextSetter/MatchCommandBuilderAppend\ndelegate signature recognition to IsSqlSinkCall so the static SQLi gate\n(SqlSinkReachability, next) cannot drift from the runtime matchers.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: `SqlSinkReachability` pass + synthetic fixtures

**Files:**
- Create: `tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs`
- Create: `tools/TaintAnalyzer/SqlSinkReachability.cs`
- Create: `tools/TaintAnalyzer.Tests/SqlSinkReachabilityTests.cs`

- [ ] **Step 1: Add synthetic fixtures.** Create `tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs`. `IFakeCommandBuilder` already exists in `WeaselFixtures.cs` and is recognized by `ImplementsCommandBuilder` (its `TargetFake` constant).

```csharp
using Weasel.Postgresql;

namespace TaintAnalyzer.Tests.Fixtures.SqlReach;

// Calls AppendWithParameters directly -> a DIRECT sink caller.
public class DirectSink
{
    private readonly IFakeCommandBuilder _b;
    public DirectSink(IFakeCommandBuilder b) { _b = b; }
    public void Emit(string sql) { _b.AppendWithParameters(sql); }
}

// Calls DirectSink.Emit -> reaches a sink TRANSITIVELY (one hop).
public class TransitiveSink
{
    private readonly DirectSink _d;
    public TransitiveSink(DirectSink d) { _d = d; }
    public void Run(string sql) { _d.Emit(sql); }
}

// No path to any SQL sink.
public class NoSink
{
    public void Compute(string s) { _ = s.Length; }
}
```

- [ ] **Step 2: Write the failing test.** Create `tools/TaintAnalyzer.Tests/SqlSinkReachabilityTests.cs`.

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqlSinkReachabilityTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName)
        => ctx.Assembly.MainModule.GetTypes()
            .First(t => t.Name == typeName)
            .Methods.First(m => m.Name == methodName);

    [Fact]
    public void DirectCaller_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "DirectSink", "Emit")).ShouldBeTrue();
    }

    [Fact]
    public void TransitiveCaller_ReachesSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "TransitiveSink", "Run")).ShouldBeTrue();
    }

    [Fact]
    public void NonReachingMethod_DoesNotReachSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var reach = new SqlSinkReachability(ctx.Assembly);
        reach.ReachesSqlSink(Find(ctx, "NoSink", "Compute")).ShouldBeFalse();
    }
}
```

- [ ] **Step 2b: Run to verify it fails to compile (type missing).**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer.Tests -c Release --nologo`
Expected: FAIL — `The type or namespace name 'SqlSinkReachability' could not be found`.

- [ ] **Step 3: Implement `SqlSinkReachability`.** Create `tools/TaintAnalyzer/SqlSinkReachability.cs`. Edge-resolution policy mirrors `ReverseCallGraph` exactly (call/callvirt/newobj, same-assembly only, callvirt expanded via `VirtualOverrideIndex.EnumerateOverrides`).

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Computes the set of methods in this assembly that can transitively reach a SQL sink —
// a call site recognized by SinkShapes.IsSqlSinkCall. The SQLi scan profile gates string
// source candidates on membership: only methods that can actually reach a SQL sink are
// worth emitting. Edge policy mirrors ReverseCallGraph (call/callvirt/newobj, in-assembly
// only, callvirt expanded via VirtualOverrideIndex).
public sealed class SqlSinkReachability
{
    private readonly HashSet<MethodDefinition> _reachesSink = new();

    public SqlSinkReachability(AssemblyDefinition assembly)
    {
        var overrides = new VirtualOverrideIndex(assembly);
        var callees = new Dictionary<MethodDefinition, List<MethodDefinition>>();
        var directCallers = new List<MethodDefinition>();

        foreach (var m in AllMethods(assembly))
        {
            if (m.Body is null) continue;
            var outgoing = new List<MethodDefinition>();
            bool isDirect = false;

            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;

                if (SinkShapes.IsSqlSinkCall(mr)) isDirect = true;

                if (ins.OpCode == OpCodes.Callvirt)
                {
                    foreach (var target in overrides.EnumerateOverrides(mr))
                    {
                        if (target.Module.Assembly != assembly) continue;
                        outgoing.Add(target);
                    }
                    continue;
                }

                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null || callee.Module.Assembly != assembly) continue;
                outgoing.Add(callee);
            }

            if (outgoing.Count > 0) callees[m] = outgoing;
            if (isDirect) directCallers.Add(m);
        }

        // Invert caller->callee edges into callee->callers for reverse BFS.
        var callers = new Dictionary<MethodDefinition, List<MethodDefinition>>();
        foreach (var (caller, outs) in callees)
            foreach (var callee in outs)
            {
                if (!callers.TryGetValue(callee, out var list)) { list = new(); callers[callee] = list; }
                list.Add(caller);
            }

        var queue = new Queue<MethodDefinition>();
        foreach (var d in directCallers)
            if (_reachesSink.Add(d)) queue.Enqueue(d);

        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            if (!callers.TryGetValue(m, out var preds)) continue;
            foreach (var p in preds)
                if (_reachesSink.Add(p)) queue.Enqueue(p);
        }
    }

    public bool ReachesSqlSink(MethodDefinition method) => _reachesSink.Contains(method);

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

- [ ] **Step 4: Run the tests to verify they pass.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~SqlSinkReachabilityTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/SqlSinkReachability.cs tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs tools/TaintAnalyzer.Tests/SqlSinkReachabilityTests.cs
git commit -m "$(printf 'analyzer: SqlSinkReachability — transitive reach-to-SQL-sink set\n\nReverse-BFS over call/callvirt/newobj edges (mirrors ReverseCallGraph) from\nmethods whose body contains an IsSqlSinkCall site. Gates SQLi scan candidates.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: `StringSourceTypes` in `EnumeratorConfig`

**Files:**
- Modify: `tools/TaintAnalyzer/EnumeratorConfig.cs`
- Test: `tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs` (created here, extended in Task 4)

- [ ] **Step 1: Write the failing test.** Create `tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs`.

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliScanProfileTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Default_StringSourceTypes_ContainsString()
    {
        EnumeratorConfig.Default.StringSourceTypes.ShouldContain("System.String");
    }
}
```

- [ ] **Step 2: Run to verify it fails to compile.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer.Tests -c Release --nologo`
Expected: FAIL — `'EnumeratorConfig' does not contain a definition for 'StringSourceTypes'`.

- [ ] **Step 3: Add the property and default.** In `tools/TaintAnalyzer/EnumeratorConfig.cs`, add the property after line 9 (`ByteSourceTypes`):

```csharp
    public IReadOnlyList<string> StringSourceTypes { get; init; } = s_defaultStringSourceTypes;
```

And add the backing default array after the `s_defaultByteSourceTypes` block (after line 26):

```csharp
    // SQLi scan profile sources: attacker-controllable text. Kept minimal (just String)
    // so the sink-reachability gate, not type breadth, controls candidate volume.
    private static readonly string[] s_defaultStringSourceTypes = { "System.String" };
```

- [ ] **Step 4: Run the test to verify it passes.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~SqliScanProfileTests.Default_StringSourceTypes_ContainsString" -- xunit.parallelizeTestCollections=false`
Expected: PASS — 1 passed.

- [ ] **Step 5: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/EnumeratorConfig.cs tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs
git commit -m "$(printf 'analyzer: EnumeratorConfig.StringSourceTypes default { System.String }\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: `ScanProfile` + SQLi enumeration paths

**Files:**
- Create: `tools/TaintAnalyzer/ScanProfile.cs`
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs`
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs` (append sqli-enumeration fixtures)
- Modify: `tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs` (append enumeration tests)

- [ ] **Step 1: Append enumeration fixtures.** Add to `tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs` (same file, below the existing types):

```csharp
namespace TaintAnalyzer.Tests.Fixtures.SqliEnum
{
    using Weasel.Postgresql;

    // string PARAMETER path: public string-param method that reaches a SQL sink.
    public class StringParamQuery
    {
        private readonly IFakeCommandBuilder _b;
        public StringParamQuery(IFakeCommandBuilder b) { _b = b; }
        public void Where(string clause) { _b.AppendWithParameters(clause); }
    }

    // this-FIELD path: string field set in ctor, read by a sink-reaching method that
    // takes NO string parameter (mirrors Marten's FullTextWhereFragment.Apply).
    public class FieldFragment
    {
        private readonly string _regConfig;
        private readonly IFakeCommandBuilder _b;
        public FieldFragment(string regConfig, IFakeCommandBuilder b) { _regConfig = regConfig; _b = b; }
        public void Apply() { _b.AppendWithParameters(_regConfig); }
    }

    // string method that does NOT reach a SQL sink — must be gated out.
    public class StringNoSink
    {
        public void Log(string msg) { _ = msg.Trim(); }
    }
}
```

- [ ] **Step 2: Write the failing tests.** Append to `tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs` (inside the class), and add `using System.Linq;` at the top if not already present (it is implicit via global usings in this project — verify build):

```csharp
    private static System.Collections.Generic.List<SourceMethodEntry> SqliEnumerate()
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var reach = new SqlSinkReachability(ctx.Assembly);
        return EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph, ScanProfile.Sqli, reach)
            .ToList();
    }

    [Fact]
    public void Sqli_MatchesStringParamReachingSink()
    {
        SqliEnumerate().ShouldContain(e =>
            e.Signature.Contains("StringParamQuery::Where(System.String)"));
    }

    [Fact]
    public void Sqli_MatchesThisFieldFragment_WithStringSeed()
    {
        var apply = SqliEnumerate()
            .FirstOrDefault(e => e.Signature.Contains("FieldFragment::Apply("));
        apply.ShouldNotBeNull();
        apply!.SeedThisFields.ShouldNotBeNull();
        apply.SeedThisFields!.ShouldContain("_regConfig");
    }

    [Fact]
    public void Sqli_GatesOutNonSinkStringMethod()
    {
        SqliEnumerate().ShouldNotContain(e => e.Signature.Contains("StringNoSink::Log"));
    }

    [Fact]
    public void DosProfile_DoesNotEnumerateStringSources()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        // 3-arg overload == dos profile == today's behaviour.
        var entries = EntryPointEnumerator.Enumerate(ctx, EnumeratorConfig.Default, graph).ToList();
        entries.ShouldNotContain(e => e.Signature.Contains("StringParamQuery::Where"));
    }
```

- [ ] **Step 3: Run to verify the tests fail to compile (missing overload / enum).**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build tools/TaintAnalyzer.Tests -c Release --nologo`
Expected: FAIL — `'ScanProfile' could not be found` and no 5-arg `Enumerate` overload.

- [ ] **Step 4: Create the `ScanProfile` enum.** Create `tools/TaintAnalyzer/ScanProfile.cs`:

```csharp
namespace TaintAnalyzer;

// Selects what a --scan run enumerates and reports.
//   Dos  — byte-source DoS shapes (today's default behaviour, unchanged).
//   Sqli — string sources gated on transitive reach to a SQL sink (CWE-89).
public enum ScanProfile { Dos, Sqli }
```

- [ ] **Step 5: Add the profile-aware `Enumerate` overload.** In `tools/TaintAnalyzer/EntryPointEnumerator.cs`, replace the existing `Enumerate` method (lines 8-59) with the original kept as a 3-arg shim plus a new 5-arg overload, and add the `StringSeedFields` helper. Full replacement for the method:

```csharp
    public static IEnumerable<SourceMethodEntry> Enumerate(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph)
        => Enumerate(context, config, callGraph, ScanProfile.Dos, null);

    public static IEnumerable<SourceMethodEntry> Enumerate(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph,
        ScanProfile profile,
        SqlSinkReachability? sinkReachability)
    {
        var sourceTypes = profile == ScanProfile.Sqli ? config.StringSourceTypes : config.ByteSourceTypes;
        var sourceSet = new HashSet<string>(sourceTypes, StringComparer.Ordinal);
        // The SQLi profile always uses the this-field path (its sink-reachability gate, not a
        // user flag, scopes candidates). The byte path keeps its opt-in flag.
        bool includeThisField = profile == ScanProfile.Sqli || config.IncludeThisField;
        var thisFieldCache = new Dictionary<TypeDefinition, IReadOnlyList<string>?>();

        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;
                if (VisibilityReject(method, callGraph)) continue;
                if (ExclusionReject(method, config)) continue;

                // SQLi profile: a candidate must be able to reach a SQL sink.
                if (profile == ScanProfile.Sqli
                    && sinkReachability is not null
                    && !sinkReachability.ReachesSqlSink(method))
                {
                    continue;
                }

                if (MatchesParameterShape(method, sourceSet))
                {
                    yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                    continue;
                }

                if (includeThisField && !method.IsStatic)
                {
                    IReadOnlyList<string>? seedFields;
                    if (profile == ScanProfile.Sqli)
                    {
                        // No decoder-name gate for SQLi: any string field of a sink-reaching
                        // type is a candidate seed (sink-reachability already scoped us).
                        seedFields = StringSeedFields(type, sourceSet);
                    }
                    else if (!thisFieldCache.TryGetValue(type, out seedFields))
                    {
                        seedFields = MatchThisFieldShape(type, config, sourceSet);
                        thisFieldCache[type] = seedFields;
                    }

                    if (seedFields is not null)
                    {
                        yield return new SourceMethodEntry
                        {
                            Signature = BuildShortSignature(method),
                            SeedThisFields = seedFields.ToList(),
                        };
                        continue;
                    }
                }

                if (config.IncludeVirtualOverrides &&
                    IsOverrideOfReachableAbstract(method, context.VirtualOverrides, callGraph))
                {
                    yield return new SourceMethodEntry { Signature = BuildShortSignature(method) };
                    continue;
                }
            }
        }
    }

    // SQLi this-field seeding: every field of `type` whose type is in the source set
    // (i.e. System.String). No type-name gate — sink-reachability already constrained
    // which methods we reach here. Reuses FieldTypeMatchesByteSource as a set-membership
    // check (the set holds string types under the sqli profile).
    private static IReadOnlyList<string>? StringSeedFields(TypeDefinition type, HashSet<string> sourceTypes)
    {
        var fields = type.Fields
            .Where(f => FieldTypeMatchesByteSource(f, sourceTypes))
            .Select(f => f.Name)
            .ToList();
        return fields.Count > 0 ? fields : null;
    }
```

- [ ] **Step 6: Run the tests to verify they pass.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~SqliScanProfileTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS — 5 passed (the 4 new + the Task 3 default test).

- [ ] **Step 7: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/ScanProfile.cs tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests.Fixtures/SqlReachFixtures.cs tools/TaintAnalyzer.Tests/SqliScanProfileTests.cs
git commit -m "$(printf 'analyzer: ScanProfile.Sqli enumeration — string param + this-field paths\n\nNew 5-arg EntryPointEnumerator.Enumerate(profile, sinkReachability). Sqli\nprofile uses StringSourceTypes, forces the this-field path, gates every\ncandidate on SqlSinkReachability, and seeds all string fields of sink-reaching\ntypes. 3-arg overload preserved as dos default.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: `--scan-profile` CLI flag, wiring, and sink-kind post-filter

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs`
- Modify: `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs`

- [ ] **Step 1: Write the failing CLI tests.** Append to `tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs` (inside the class):

```csharp
    [Fact]
    public void ScanProfile_RequiresScan()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var rc = Program.Run(
            new[] { FixturePath, "--rules", "x.yaml", "--scan-profile", "sqli" }, stdout, stderr);
        rc.ShouldBe(2);
        stderr.ToString().ShouldContain("--scan-profile");
    }

    [Fact]
    public void ScanProfile_UnknownValue_Rejected()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var rc = Program.Run(
            new[] { FixturePath, "--scan", "--scan-profile", "bogus" }, stdout, stderr);
        rc.ShouldBe(2);
        stderr.ToString().ShouldContain("unknown scan profile");
    }

    [Fact]
    public void ScanProfile_Sqli_RunsClean()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var rc = Program.Run(
            new[] { FixturePath, "--scan", "--scan-profile", "sqli" }, stdout, stderr);
        rc.ShouldBe(0, $"stderr: {stderr}");
        stdout.ToString().ShouldContain("vuln_id");
    }
```

- [ ] **Step 2: Run to verify they fail.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~ProgramScanFlagTests.ScanProfile" -- xunit.parallelizeTestCollections=false`
Expected: FAIL — `--scan-profile` is an unknown flag (rc 2 but stderr says "unknown flag") for the `RunsClean` test; `RequiresScan` fails because the flag isn't recognized.

- [ ] **Step 3: Add the flag parse.** In `tools/TaintAnalyzer/Program.cs`, add a declaration alongside the other flag locals (after line 26, `enumeratorConfigPath`):

```csharp
        ScanProfile scanProfile = ScanProfile.Dos;
        bool scanProfileProvided = false;
```

Add a parse branch in the arg loop, just before the `--emit-rules` branch (before line 66):

```csharp
            else if (a == "--scan-profile")
            {
                if (++i >= args.Length) { stderr.WriteLine("error: --scan-profile requires a value (dos|sqli)"); return 2; }
                scanProfileProvided = true;
                switch (args[i])
                {
                    case "dos": scanProfile = ScanProfile.Dos; break;
                    case "sqli": scanProfile = ScanProfile.Sqli; break;
                    default:
                        stderr.WriteLine($"error: unknown scan profile '{args[i]}' (expected dos|sqli)");
                        return 2;
                }
            }
```

- [ ] **Step 4: Add the requires-scan guard.** In the validation block, after the `--emit-rules requires --scan` check (after line 116), add:

```csharp
        if (!scan && scanProfileProvided)
        {
            stderr.WriteLine("error: --scan-profile requires --scan");
            return 2;
        }
```

- [ ] **Step 5: Wire the profile + reachability into enumeration.** In the `if (scan)` block, replace the enumerate call (line 191):

```csharp
                var sources = EntryPointEnumerator.Enumerate(context, cfg, graph).ToList();
```

with:

```csharp
                SqlSinkReachability? sinkReachability =
                    scanProfile == ScanProfile.Sqli ? new SqlSinkReachability(context.Assembly) : null;
                var sources = EntryPointEnumerator
                    .Enumerate(context, cfg, graph, scanProfile, sinkReachability)
                    .ToList();
```

- [ ] **Step 6: Add the sink-kind post-filter.** Replace the per-source hop append (line 281, `allHops.AddRange(summary.Hops);`) with:

```csharp
                // SQLi scans report only SQL sinks; drop any incidental non-SQL sink hops
                // so a string-source scan never surfaces an allocation finding. The dos
                // profile (default, including all --rules runs) is unaffected.
                var summaryHops = scanProfile == ScanProfile.Sqli
                    ? summary.Hops.Where(h => h.Role != HopRole.Sink || h.SinkKind == SinkKind.SqlInjection)
                    : summary.Hops;
                allHops.AddRange(summaryHops);
```

- [ ] **Step 7: Update usage text.** Replace `PrintUsage` body (line 340):

```csharp
        stderr.WriteLine("usage: TaintAnalyzer <target.dll> [--rules <rules.yaml> | --scan [--scan-profile dos|sqli]] [--output <trace.yaml>] [--no-symbols]");
```

- [ ] **Step 8: Run the CLI tests to verify they pass.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~ProgramScanFlagTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS — all ProgramScanFlagTests pass (existing + 3 new).

- [ ] **Step 9: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramScanFlagTests.cs
git commit -m "$(printf 'analyzer: --scan-profile dos|sqli CLI + sink-kind reporting filter\n\nWires ScanProfile + SqlSinkReachability into the scan path; sqli runs report\nonly SqlInjection sinks. Requires --scan; unknown value rejected.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 6: Marten cold-rediscovery anchor (the milestone proof)

**Files:**
- Create: `tools/TaintAnalyzer.Tests/ScanMartenVmw2FixtureTests.cs`

This test skips silently when the Marten artifact isn't materialized (matching `MartenVmw2FixtureTests`), so it's safe in fresh checkouts and CI without the artifact.

- [ ] **Step 1: Write the anchor test.** Create `tools/TaintAnalyzer.Tests/ScanMartenVmw2FixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ScanMartenVmw2FixtureTests
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
    public void ScanSqli_RediscoversFullTextWhereFragment_Cold()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "marten-8.36", "Marten.dll");
        if (!File.Exists(dllPath)) return;  // artifact not materialized in this checkout

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", "marten-8.36", ".nopdb-marker"));

        // (1) --emit-rules: the candidate set contains Apply with its string seed fields,
        //     discovered cold — no hand-written source entry.
        var emitPath = Path.Combine(Path.GetTempPath(), $"scan-marten-emit-{Guid.NewGuid()}.yaml");
        var outPath = Path.Combine(Path.GetTempPath(), $"scan-marten-trace-{Guid.NewGuid()}.yaml");
        try
        {
            var stderr1 = new StringWriter();
            var emitArgs = new List<string>
                { dllPath, "--scan", "--scan-profile", "sqli", "--emit-rules", emitPath };
            if (noSymbols) emitArgs.Add("--no-symbols");
            Program.Run(emitArgs.ToArray(), new StringWriter(), stderr1)
                .ShouldBe(0, $"emit-rules stderr: {stderr1}");

            var emitted = File.ReadAllText(emitPath);
            emitted.ShouldContain(
                "Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::Apply(Weasel.Postgresql.ICommandBuilder)");
            emitted.ShouldContain("_regConfig");

            // (2) end-to-end scan produces the SQL sink finding cold.
            var stderr2 = new StringWriter();
            var scanArgs = new List<string>
                { dllPath, "--scan", "--scan-profile", "sqli", "--output", outPath };
            if (noSymbols) scanArgs.Add("--no-symbols");
            Program.Run(scanArgs.ToArray(), new StringWriter(), stderr2)
                .ShouldBe(0, $"scan stderr: {stderr2}");

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("api: sql_command_builder_append");
            trace.ShouldContain("FullTextWhereFragment");
        }
        finally
        {
            if (File.Exists(emitPath)) File.Delete(emitPath);
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 2: Run the anchor test.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet build TaintAnalyzer.sln -c Release --nologo && dotnet test tools/TaintAnalyzer.Tests -c Release --no-build --nologo --filter "FullyQualifiedName~ScanMartenVmw2FixtureTests" -- xunit.parallelizeTestCollections=false`
Expected: PASS — 1 passed. (If the Marten artifact is absent the test still PASSES via the early return; confirm presence with `ls artifacts/marten-8.36/Marten.dll`. If absent, materialize it the same way the `marten-vmw2-prefix` fixture was created before asserting the milestone is proven.)

- [ ] **Step 3: Full suite regression — prove nothing else broke.**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && dotnet test TaintAnalyzer.sln -c Release --no-build --nologo -- xunit.parallelizeTestCollections=false`
Expected: PASS — `ValidateFixture.Tests` 63 passed; `TaintAnalyzer.Tests` 299 + 11 new = **310 passed** (3 reachability + 1 config + 4 sqli-enum + 3 CLI). Total 373.

- [ ] **Step 4: Run the dos-profile regression locks (artifact-gated, prove byte-for-byte unchanged).**

Run: `cd /mnt/c/work/dotnet-taint-analyzer && bash fixtures/scan-protobuf-net/run && bash fixtures/scan-nbmp-1.1.25/run 2>/dev/null || true`
Expected: each prints either its "both locks match" success line or a "skip:" line if the artifact isn't present. Any "drifted" output is a FAIL — the dos path must be unchanged.

- [ ] **Step 5: Commit.**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
git add tools/TaintAnalyzer.Tests/ScanMartenVmw2FixtureTests.cs
git commit -m "$(printf 'test: milestone-U anchor — cold-rediscover Marten FullTextWhereFragment SQLi\n\n--scan --scan-profile sqli emits Apply with string seed fields and produces\nthe sql_command_builder_append finding without a hand-written source.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**1. Spec coverage:**
- Scan profiles (dos/sqli) → Task 4 (`ScanProfile`), Task 5 (CLI). ✓
- String source types → Task 3. ✓
- String this-field path (Marten anchor) → Task 4 (`StringSeedFields`). ✓
- String parameter-shape path → Task 4 (reuses `MatchesParameterShape` with string set). ✓
- Sink-reachability gate (Approach B) → Task 2. ✓
- Shared sink-signature predicate (no drift) → Task 1. ✓
- Active-sink-kind filtering → Task 5 Step 6. ✓
- `--scan-profile` flag + requires-scan guard + unknown-value reject → Task 5. ✓
- Anchor: `--emit-rules` contains Apply+seed AND end-to-end SQL finding → Task 6. ✓
- dos profile unchanged proof → Task 4 Step 2 test + Task 6 Step 4 locks. ✓
- Unit tests (reachability direct/transitive/unreachable; param; this-field+seed; profile filtering; dos-unchanged; CLI) → Tasks 2,4,5. ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code; every run step shows the command and expected result. ✓

**3. Type/name consistency:**
- `IsSqlSinkCall` (public) used in Task 1 and Task 2 — consistent. ✓
- `SqlSinkReachability.ReachesSqlSink(MethodDefinition)` defined Task 2, called Task 4 & 5 — consistent. ✓
- `EntryPointEnumerator.Enumerate(context, config, callGraph, ScanProfile, SqlSinkReachability?)` defined Task 4, called Task 4 test & Task 5 — consistent. ✓
- `ScanProfile { Dos, Sqli }` defined Task 4, used Tasks 4/5 — consistent. ✓
- `EnumeratorConfig.StringSourceTypes` defined Task 3, used Task 4 — consistent. ✓
- `VirtualOverrideIndex.EnumerateOverrides` / `HopRecord.SinkKind` / `SinkKind.SqlInjection` — pre-existing, matched against current code. ✓

**Coverage note (intentional, not a gap):** the spec mentioned an optional full-diff `--emit-rules` lock fixture (`fixtures/scan-marten-vmw2/`) analogous to `scan-protobuf-net`. This plan instead asserts the meaningful property via the `Contains`-based anchor test (Task 6), avoiding a generated-from-actual circular lock. The full-diff lock can be added later if desired; it is listed as out-of-scope-for-now, not forgotten.
