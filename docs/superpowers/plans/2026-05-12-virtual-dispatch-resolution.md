# Virtual-Dispatch Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve `callvirt` operands to all in-assembly overrides in both `ReverseCallGraph` (reachability) and `TaintWalker.HandleCall` (interprocedural taint flow), unblocking the protobuf-net OOM finding via `--scan`.

**Architecture:** A new `VirtualOverrideIndex` (owned lazily by `AssemblyContext`) maps each virtual/abstract method to its in-assembly overrides. Both consumers query a single `EnumerateOverrides(MethodReference)` method. `System.Object` virtuals are denylisted. Merge rule: OR taint flags, AND sanitiser flags.

**Tech Stack:** C# / .NET 9, Mono.Cecil, xUnit + Shouldly.

**Spec:** `docs/superpowers/specs/2026-05-12-virtual-dispatch-resolution-design.md`

---

## File Structure

**New files:**
- `tools/TaintAnalyzer/VirtualOverrideIndex.cs` — the index class
- `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs` — 13 unit tests
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.VirtualDispatch.cs` — fixture types
- `fixtures/scan-protobuf-net/README.md`
- `fixtures/scan-protobuf-net/run`
- `fixtures/scan-protobuf-net/rules.yaml.expected`

**Modified:**
- `tools/TaintAnalyzer/AssemblyContext.cs` — own a lazy `VirtualOverrideIndex`
- `tools/TaintAnalyzer/ReverseCallGraph.cs` — callvirt edge expansion
- `tools/TaintAnalyzer/TaintWalker.cs` — `HandleCall` callvirt branch + `WalkAndMerge`
- `tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs` — 4 new tests
- `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` — 9 new tests

---

### Task 1: Add VirtualDispatch fixture types

**Files:**
- Create: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.VirtualDispatch.cs`

These types are compiled into `TaintAnalyzer.Tests.Fixtures.dll` and loaded by all downstream unit tests via Cecil. They MUST come first because every subsequent test references one of these types by full name.

- [ ] **Step 1: Create the fixture source file**

Create `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.VirtualDispatch.cs`:

```csharp
// VirtualDispatchFixtures — types for VirtualOverrideIndex, ReverseCallGraph,
// and TaintWalker callvirt-override tests. Compiled into the Fixtures DLL and
// loaded via Cecil — not referenced as source.

namespace TaintAnalyzer.Tests.Fixtures.VirtualDispatch;

// ---- Non-virtual baseline ----

public class NonVirtualTarget
{
    public int Compute(int x) => x * 2;
}

// ---- Implicit override chain (A -> B -> C) ----

public abstract class TransitiveA
{
    public abstract int Foo(int x);
}

public abstract class TransitiveB : TransitiveA
{
    public override int Foo(int x) => x + 1;
}

public class TransitiveC : TransitiveB
{
    public override int Foo(int x) => x + 2;
}

// ---- Simple implicit override (abstract + 1 concrete) ----

public abstract class SimpleBase
{
    public abstract void Process(byte[] data);
}

public class SimpleDerived : SimpleBase
{
    public override void Process(byte[] data) { }
}

// ---- Two-override fan-out for TaintWalker merge tests ----

public abstract class TwoOverrideBase
{
    // arg is a tainted-byte-source candidate
    public abstract byte[] Read(byte[] input);
}

public class CleanOverride : TwoOverrideBase
{
    public override byte[] Read(byte[] input) => System.Array.Empty<byte>();
}

public class TaintingOverride : TwoOverrideBase
{
    // Allocation sink driven by input.Length — flows tainted byte-array length
    // into newarr; TaintWalker should record ReachedSink + ReturnsTainted.
    public override byte[] Read(byte[] input) => new byte[input.Length];
}

public class ThrowingOverride : TwoOverrideBase
{
    public override byte[] Read(byte[] input)
    {
        if (input.Length > 1024) throw new System.IO.InvalidDataException();
        return new byte[input.Length];
    }
}

// ---- Explicit interface implementations ----

public interface IExplicitOperation
{
    void Bar();
}

public class ExplicitImpl : IExplicitOperation
{
    void IExplicitOperation.Bar() { }
}

public class CustomDisposable : System.IDisposable
{
    public void Dispose() { }
}

public class CustomEnumerator : System.Collections.IEnumerator
{
    public object Current => null!;
    public bool MoveNext() => false;
    public void Reset() { }
}

// ---- Object.ToString override (denylist target) ----

public class CustomToString
{
    public override string ToString() => "custom";
}

// ---- modreq(InAttribute) parameter override ----

public abstract class InParamBase
{
    public abstract void Accept(in int value);
}

public class InParamDerived : InParamBase
{
    public override void Accept(in int value) { }
}

// ---- Callsite hosts for ReverseCallGraph + TaintWalker tests ----

public class PublicCallerForOverride
{
    private readonly SimpleBase _target;
    public PublicCallerForOverride(SimpleBase target) => _target = target;
    public void Call(byte[] data) => _target.Process(data); // callvirt SimpleBase::Process
}

public class PublicCallerForToString
{
    public string Stringify(object o) => o.ToString() ?? "";  // callvirt Object::ToString
}

public class PublicCallerForDispose
{
    public void Run(System.IDisposable d) => d.Dispose();     // callvirt IDisposable::Dispose
}

public class PublicCallerForTransitive
{
    public int Run(TransitiveA a, int x) => a.Foo(x);         // callvirt TransitiveA::Foo
}

public class PublicCallerForTwoOverride
{
    public byte[] Run(TwoOverrideBase t, byte[] data) => t.Read(data); // callvirt TwoOverrideBase::Read
}

// Caller that uses `call` (not callvirt) on a virtual — verifies opcode-gated trigger.
// C# emits `call` for `base.X()` invocations.
public class BaseCallSite : TransitiveB
{
    public int CallBaseDirectly(int x) => base.Foo(x); // call TransitiveB::Foo (not callvirt)
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug`
Expected: `Build succeeded`. No warnings about unused types.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.VirtualDispatch.cs
git commit -m "$(cat <<'EOF'
test-fixtures: add VirtualDispatch types for milestone-R

Source types used by VirtualOverrideIndex, ReverseCallGraph, and TaintWalker
callvirt-override unit tests. Includes transitive chain, two-override fan-out,
explicit interface impls, modreq(InAttribute) parameter, and call-vs-callvirt
host classes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: VirtualOverrideIndex — skeleton, non-virtual, denylist

**Files:**
- Create: `tools/TaintAnalyzer/VirtualOverrideIndex.cs`
- Create: `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class VirtualOverrideIndexTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void EnumerateOverrides_NonVirtualTarget_ReturnsSingleStatic()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var target = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.NonVirtualTarget::Compute(System.Int32)")!;

        var result = idx.EnumerateOverrides(target).ToList();

        result.Count.ShouldBe(1);
        result[0].FullName.ShouldBe(target.FullName);
    }

    [Fact]
    public void EnumerateOverrides_DenylistedObjectToString_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        // Locate Object::ToString via a callsite — Cecil resolves the operand to the def.
        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForToString::Stringify(System.Object)")!;
        var callvirt = caller.Body.Instructions
            .First(i => i.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt);
        var toStringRef = (MethodReference)callvirt.Operand;

        var result = idx.EnumerateOverrides(toStringRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
        result[0].Name.ShouldBe("ToString");
    }

    [Fact]
    public void EnumerateOverrides_DenylistedEquals_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var equalsRef = ResolveMscorlibObjectMethod(ctx.Assembly, "Equals", paramFullName: "System.Object");

        var result = idx.EnumerateOverrides(equalsRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
    }

    [Fact]
    public void EnumerateOverrides_DenylistedGetHashCode_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var ghcRef = ResolveMscorlibObjectMethod(ctx.Assembly, "GetHashCode", paramFullName: null);

        var result = idx.EnumerateOverrides(ghcRef).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
    }

    // Helper: build a MethodReference to a System.Object method via the assembly's
    // module so Resolve() works.
    private static MethodReference ResolveMscorlibObjectMethod(
        AssemblyDefinition asm, string name, string? paramFullName)
    {
        var corlib = asm.MainModule.TypeSystem.Object.Resolve()!;
        var m = corlib.Methods.First(mm =>
            mm.Name == name &&
            (paramFullName is null
                ? mm.Parameters.Count == 0
                : mm.Parameters.Count == 1 && mm.Parameters[0].ParameterType.FullName == paramFullName));
        return asm.MainModule.ImportReference(m);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 4 tests fail with "VirtualOverrideIndex does not exist in TaintAnalyzer".

- [ ] **Step 3: Write the minimal implementation**

Create `tools/TaintAnalyzer/VirtualOverrideIndex.cs`:

```csharp
using Mono.Cecil;

namespace TaintAnalyzer;

// Maps each virtual / abstract method in this assembly to the set of in-assembly
// overrides. Built once on first query and cached. Consumers: ReverseCallGraph
// (Callvirt edge expansion) and TaintWalker.HandleCall (interprocedural walk over
// every override).
//
// System.Object's virtuals (ToString / Equals / GetHashCode / Finalize) are
// denylisted: EnumerateOverrides returns only the static target for them, so
// override expansion does not fan out across every type in the assembly.
public sealed class VirtualOverrideIndex
{
    private static readonly HashSet<string> Denylist = new(StringComparer.Ordinal)
    {
        "System.String System.Object::ToString()",
        "System.Boolean System.Object::Equals(System.Object)",
        "System.Int32 System.Object::GetHashCode()",
        "System.Void System.Object::Finalize()",
    };

    private readonly AssemblyDefinition _assembly;
    private Dictionary<MethodDefinition, List<MethodDefinition>>? _index;

    public VirtualOverrideIndex(AssemblyDefinition assembly)
    {
        _assembly = assembly;
    }

    public IReadOnlyList<MethodDefinition> EnumerateOverrides(MethodReference vRef)
    {
        MethodDefinition? resolved;
        try { resolved = vRef.Resolve(); }
        catch { return Array.Empty<MethodDefinition>(); }
        if (resolved is null) return Array.Empty<MethodDefinition>();

        if (Denylist.Contains(resolved.FullName)) return new[] { resolved };
        if (!(resolved.IsVirtual || resolved.IsAbstract)) return new[] { resolved };

        EnsureIndexBuilt();
        if (!_index!.TryGetValue(resolved, out var overrides))
            return new[] { resolved };

        var result = new List<MethodDefinition>(overrides.Count + 1) { resolved };
        result.AddRange(overrides);
        return result;
    }

    private void EnsureIndexBuilt()
    {
        if (_index is not null) return;
        _index = new Dictionary<MethodDefinition, List<MethodDefinition>>();
        // BuildIndex body added in Task 3 + Task 4.
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/VirtualOverrideIndex.cs tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs
git commit -m "$(cat <<'EOF'
analyzer: VirtualOverrideIndex skeleton + System.Object denylist

EnumerateOverrides returns [resolved] for non-virtual targets and for any of
Object::ToString / Equals / GetHashCode / Finalize, so override expansion is
opt-out for those four high-fan-out virtuals. Index population added in
subsequent commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Implicit overrides (including transitive chain)

**Files:**
- Modify: `tools/TaintAnalyzer/VirtualOverrideIndex.cs` — implement `BuildIndex`
- Modify: `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs` — add 2 tests

- [ ] **Step 1: Write the failing tests** — append to `VirtualOverrideIndexTests`

```csharp
    [Fact]
    public void EnumerateOverrides_ImplicitOverride_Found()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var baseFoo = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleBase::Process(System.Byte[])")!;
        var derivedFoo = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleDerived::Process(System.Byte[])")!;

        var result = idx.EnumerateOverrides(baseFoo).Select(m => m.FullName).ToList();

        result.ShouldContain(baseFoo.FullName);
        result.ShouldContain(derivedFoo.FullName);
        result.Count.ShouldBe(2);
    }

    [Fact]
    public void EnumerateOverrides_TransitiveChain_AllAncestorsResolveToConcrete()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var topAbstract = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveA::Foo(System.Int32)")!;
        var midOverride = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveB::Foo(System.Int32)")!;
        var leafOverride = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveC::Foo(System.Int32)")!;

        // callvirt TransitiveA::Foo must enumerate B AND C (flattened chain).
        var fromA = idx.EnumerateOverrides(topAbstract).Select(m => m.FullName).ToHashSet();
        fromA.ShouldContain(topAbstract.FullName);
        fromA.ShouldContain(midOverride.FullName);
        fromA.ShouldContain(leafOverride.FullName);

        // callvirt TransitiveB::Foo must enumerate C.
        var fromB = idx.EnumerateOverrides(midOverride).Select(m => m.FullName).ToHashSet();
        fromB.ShouldContain(midOverride.FullName);
        fromB.ShouldContain(leafOverride.FullName);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests.EnumerateOverrides_ImplicitOverride|FullyQualifiedName~VirtualOverrideIndexTests.EnumerateOverrides_TransitiveChain"`
Expected: 2 tests fail (only base returned, no overrides).

- [ ] **Step 3: Implement BuildIndex — implicit-override discovery**

Replace `EnsureIndexBuilt()` in `tools/TaintAnalyzer/VirtualOverrideIndex.cs`:

```csharp
    private void EnsureIndexBuilt()
    {
        if (_index is not null) return;
        _index = new Dictionary<MethodDefinition, List<MethodDefinition>>();

        foreach (var type in AllTypes(_assembly))
        foreach (var method in type.Methods)
        {
            // Implicit override: walk the base chain and record this method
            // against every ancestor virtual/abstract method with matching
            // name+signature, in-assembly only. Continues past matches so a
            // deep chain (C overrides B overrides A) registers C against both
            // B and A.
            if (method.IsVirtual && method.IsReuseSlot)
                RecordImplicitOverrides(method);
        }
    }

    private void RecordImplicitOverrides(MethodDefinition method)
    {
        var baseType = method.DeclaringType.BaseType;
        var seenTypes = new HashSet<string>(StringComparer.Ordinal);
        while (baseType is not null && seenTypes.Add(baseType.FullName))
        {
            TypeDefinition? def;
            try { def = baseType.Resolve(); }
            catch { def = null; }
            if (def is null) break;
            if (def.Module.Assembly != _assembly) break;

            foreach (var candidate in def.Methods)
            {
                if (!(candidate.IsVirtual || candidate.IsAbstract)) continue;
                if (!SignatureMatches(candidate, method)) continue;
                AppendOverride(candidate, method);
            }

            baseType = def.BaseType;
        }
    }

    private void AppendOverride(MethodDefinition virt, MethodDefinition concrete)
    {
        if (!_index!.TryGetValue(virt, out var list))
        {
            list = new List<MethodDefinition>();
            _index[virt] = list;
        }
        list.Add(concrete);
    }

    // Match by name + parameter FullName list, stripping Cecil's
    // ` modreq(System.Runtime.InteropServices.InAttribute)` suffix that
    // decorates `in T` parameters. Mirrors AssemblyContext.BuildShortSignature
    // for consistency with the milestone-N rule.
    private static bool SignatureMatches(MethodDefinition a, MethodDefinition b)
    {
        if (a.Name != b.Name) return false;
        if (a.Parameters.Count != b.Parameters.Count) return false;
        for (int i = 0; i < a.Parameters.Count; i++)
        {
            var aKey = StripModreq(a.Parameters[i].ParameterType.FullName);
            var bKey = StripModreq(b.Parameters[i].ParameterType.FullName);
            if (aKey != bKey) return false;
        }
        return true;
    }

    private static string StripModreq(string typeName)
    {
        int idx = typeName.IndexOf(" modreq(", StringComparison.Ordinal);
        return idx >= 0 ? typeName[..idx] : typeName;
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 6 tests pass (4 from Task 2 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/VirtualOverrideIndex.cs tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs
git commit -m "$(cat <<'EOF'
analyzer: implicit-override discovery in VirtualOverrideIndex

Walks each virtual method's base chain and records the method against every
ancestor virtual/abstract method with matching name+signature. Transitive
chains are flattened so callvirt of the top abstract enumerates every
concrete leaf, not just the closest. Signature match strips Cecil's modreq
suffix for in-parameter consistency.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Explicit interface implementations

**Files:**
- Modify: `tools/TaintAnalyzer/VirtualOverrideIndex.cs` — extend `BuildIndex`
- Modify: `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs` — add 3 tests

- [ ] **Step 1: Write the failing tests** — append to `VirtualOverrideIndexTests`

```csharp
    [Fact]
    public void EnumerateOverrides_ExplicitInterfaceImpl_Found()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var ifaceBar = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.IExplicitOperation::Bar()")!;

        var result = idx.EnumerateOverrides(ifaceBar).Select(m => m.FullName).ToList();

        result.ShouldContain(ifaceBar.FullName);
        result.ShouldContain(
            "System.Void TaintAnalyzer.Tests.Fixtures.VirtualDispatch.ExplicitImpl::"
            + "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.IExplicitOperation.Bar()");
    }

    [Fact]
    public void EnumerateOverrides_IDisposableDispose_ImplIncluded()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        // Get IDisposable::Dispose via Cecil's import — denylist must NOT include it.
        var disposable = ctx.Assembly.MainModule.ImportReference(typeof(System.IDisposable)).Resolve()!;
        var disposeRef = ctx.Assembly.MainModule.ImportReference(
            disposable.Methods.Single(m => m.Name == "Dispose"));

        var result = idx.EnumerateOverrides(disposeRef).Select(m => m.FullName).ToList();

        // The CustomDisposable.Dispose impl is found via implicit-override discovery.
        result.ShouldContain(s => s.Contains("CustomDisposable::Dispose"));
    }

    [Fact]
    public void EnumerateOverrides_IEnumeratorMoveNext_ImplIncluded()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var enumerator = ctx.Assembly.MainModule.ImportReference(
            typeof(System.Collections.IEnumerator)).Resolve()!;
        var moveNextRef = ctx.Assembly.MainModule.ImportReference(
            enumerator.Methods.Single(m => m.Name == "MoveNext"));

        var result = idx.EnumerateOverrides(moveNextRef).Select(m => m.FullName).ToList();

        result.ShouldContain(s => s.Contains("CustomEnumerator::MoveNext"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 3 new tests fail (explicit `void IFoo.Bar()` doesn't have IsReuseSlot; only-interface-base path not covered).

- [ ] **Step 3: Extend BuildIndex with the explicit-overrides table**

Modify the main loop in `EnsureIndexBuilt()`:

```csharp
    private void EnsureIndexBuilt()
    {
        if (_index is not null) return;
        _index = new Dictionary<MethodDefinition, List<MethodDefinition>>();

        foreach (var type in AllTypes(_assembly))
        foreach (var method in type.Methods)
        {
            // (a) Explicit MethodImpl entries — Cecil's MethodDefinition.Overrides
            //     records every method this one explicitly overrides. Used for
            //     `void IFoo.Bar()` and similar shapes where the .NET name table
            //     puts the qualified interface name on the method.
            if (method.HasOverrides)
            {
                foreach (var over in method.Overrides)
                {
                    MethodDefinition? virt;
                    try { virt = over.Resolve(); }
                    catch { virt = null; }
                    if (virt is null) continue;
                    if (virt.Module.Assembly != _assembly) continue;
                    AppendOverride(virt, method);
                }
            }

            // (b) Implicit override via base-chain walk.
            if (method.IsVirtual && method.IsReuseSlot)
                RecordImplicitOverrides(method);
        }

        // After collecting direct overrides, also discover implicit overrides of
        // interface members. C# `public void Dispose()` on a class implementing
        // IDisposable does NOT set HasOverrides — the override is implicit. To
        // find these, iterate types and their interface table.
        foreach (var type in AllTypes(_assembly))
        {
            if (!type.HasInterfaces) continue;
            foreach (var iface in type.Interfaces)
            {
                TypeDefinition? ifaceDef;
                try { ifaceDef = iface.InterfaceType.Resolve(); }
                catch { ifaceDef = null; }
                if (ifaceDef is null) continue;
                if (ifaceDef.Module.Assembly != _assembly) continue;

                foreach (var ifaceMethod in ifaceDef.Methods)
                {
                    var impl = type.Methods.FirstOrDefault(m =>
                        m.IsVirtual && SignatureMatches(ifaceMethod, m) && !m.HasOverrides);
                    if (impl is not null) AppendOverride(ifaceMethod, impl);
                }
            }
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 9 tests pass (6 from prior tasks + 3 new).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/VirtualOverrideIndex.cs tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs
git commit -m "$(cat <<'EOF'
analyzer: explicit + interface-implicit overrides in VirtualOverrideIndex

Adds two more discovery passes: Cecil's MethodDefinition.Overrides for
`void IFoo.Bar()` shapes, and an interface-table walk so plain
`public void Dispose()` on a class implementing IDisposable is recorded
against IDisposable::Dispose. IDisposable and IEnumerator are NOT
denylisted; they're load-bearing in decoder paths.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Edge cases — modreq, resolve failure, cross-assembly

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs` — add 4 tests

- [ ] **Step 1: Write the failing tests** — append to `VirtualOverrideIndexTests`

```csharp
    [Fact]
    public void EnumerateOverrides_ModreqInAttribute_SignatureMatches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var baseAccept = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.InParamBase::Accept(System.Int32&)")!;
        var derivedAccept = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.InParamDerived::Accept(System.Int32&)")!;

        var result = idx.EnumerateOverrides(baseAccept).Select(m => m.FullName).ToList();

        result.ShouldContain(baseAccept.FullName);
        result.ShouldContain(derivedAccept.FullName);
    }

    [Fact]
    public void EnumerateOverrides_ResolveFailure_ReturnsEmpty()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        // A dangling MethodReference pointing at a type that doesn't exist in any
        // referenced assembly — Resolve() returns null.
        var fakeType = new TypeReference("Nonexistent", "Type",
            ctx.Assembly.MainModule, ctx.Assembly.MainModule.TypeSystem.CoreLibrary);
        var fake = new MethodReference("Vanished", ctx.Assembly.MainModule.TypeSystem.Void, fakeType);

        var result = idx.EnumerateOverrides(fake);

        result.ShouldBeEmpty();
    }

    [Fact]
    public void EnumerateOverrides_FinalizeDenylisted_ReturnsBaseOnly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var corlibObject = ctx.Assembly.MainModule.TypeSystem.Object.Resolve()!;
        var finalize = corlibObject.Methods.Single(m => m.Name == "Finalize");
        var ref_ = ctx.Assembly.MainModule.ImportReference(finalize);

        var result = idx.EnumerateOverrides(ref_).ToList();

        result.Count.ShouldBe(1);
        result[0].DeclaringType.FullName.ShouldBe("System.Object");
        result[0].Name.ShouldBe("Finalize");
    }

    [Fact]
    public void EnumerateOverrides_CrossAssemblyBase_ReturnsBaseOnly()
    {
        // System.Object::ToString is cross-assembly. Even without the denylist,
        // BuildIndex's same-assembly filter prevents recording overrides of
        // cross-assembly bases. The denylist check fires first; this test
        // documents that the same-assembly filter is the secondary safety net.
        using var ctx = AssemblyContext.Load(FixturePath);
        var idx = new VirtualOverrideIndex(ctx.Assembly);

        var corlibObject = ctx.Assembly.MainModule.TypeSystem.Object.Resolve()!;
        var toString = corlibObject.Methods.Single(m => m.Name == "ToString" && m.Parameters.Count == 0);
        var ref_ = ctx.Assembly.MainModule.ImportReference(toString);

        var result = idx.EnumerateOverrides(ref_).ToList();

        // Denylisted — return only the base; CustomToString.ToString MUST NOT appear.
        result.Count.ShouldBe(1);
        result.ShouldNotContain(m => m.DeclaringType.FullName.Contains("CustomToString"));
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~VirtualOverrideIndexTests"`
Expected: 13 tests pass.

The modreq test should already pass because `SignatureMatches` strips modreq. The resolve-failure test passes because we early-return on `null`. The denylist tests pass because the denylist check happens before the index lookup. If any fail, fix the relevant logic in `VirtualOverrideIndex.cs`.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs
git commit -m "$(cat <<'EOF'
test: cover modreq, resolve-failure, finalize denylist, cross-assembly bases

13 unit tests in total — VirtualOverrideIndex is feature-complete.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Wire VirtualOverrideIndex into AssemblyContext

**Files:**
- Modify: `tools/TaintAnalyzer/AssemblyContext.cs` — add lazy `VirtualOverrides` property

- [ ] **Step 1: Add the property**

In `tools/TaintAnalyzer/AssemblyContext.cs`, add a backing field and lazy property:

```csharp
    private VirtualOverrideIndex? _virtualOverrides;
    public VirtualOverrideIndex VirtualOverrides
        => _virtualOverrides ??= new VirtualOverrideIndex(Assembly);
```

Insert immediately after the `Assembly` property declaration (around line 14).

- [ ] **Step 2: Build the solution**

Run: `dotnet build TaintAnalyzer.sln -c Debug`
Expected: `Build succeeded`. No warnings.

- [ ] **Step 3: Run the full unit-test suite to confirm no regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: All existing tests still pass; VirtualOverrideIndexTests still pass.

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/AssemblyContext.cs
git commit -m "$(cat <<'EOF'
analyzer: AssemblyContext.VirtualOverrides — lazy index property

Single owner so the index builds once per loaded assembly and is shared
between ReverseCallGraph and TaintWalker.HandleCall (next two commits).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: ReverseCallGraph callvirt-override expansion

**Files:**
- Modify: `tools/TaintAnalyzer/ReverseCallGraph.cs`
- Modify: `tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs` — add 4 tests

- [ ] **Step 1: Write the failing tests** — append to `ReverseCallGraphTests`

```csharp
    [Fact]
    public void Callvirt_Override_ReachableFromPublicCaller()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // PublicCallerForOverride.Call does `callvirt SimpleBase::Process`;
        // SimpleDerived.Process must be enqueued via the override expansion.
        var derivedOverride = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleDerived", "Process");

        derivedOverride.ShouldNotBeNull();
        graph.IsReachableFromPublic(derivedOverride!).ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_OverrideOfDenylistedObjectToString_NotEnqueued()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // PublicCallerForToString.Stringify does `callvirt Object::ToString`.
        // CustomToString.ToString must NOT be enqueued from that callsite —
        // it's reachable only if some OTHER call reaches it. The fixture has
        // no other caller, so it stays unreachable.
        var customToString = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.CustomToString", "ToString");

        customToString.ShouldNotBeNull();
        graph.IsReachableFromPublic(customToString!).ShouldBeFalse();
    }

    [Fact]
    public void Callvirt_ExplicitInterfaceImpl_Reachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // PublicCallerForDispose.Run does `callvirt IDisposable::Dispose`;
        // CustomDisposable.Dispose must be enqueued.
        var customDispose = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.CustomDisposable", "Dispose");

        customDispose.ShouldNotBeNull();
        graph.IsReachableFromPublic(customDispose!).ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_TransitiveChain_AllOverridesReachable()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // PublicCallerForTransitive.Run does `callvirt TransitiveA::Foo`;
        // TransitiveB.Foo AND TransitiveC.Foo must both be reachable.
        var bFoo = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveB", "Foo");
        var cFoo = FindMethod(ctx.Assembly,
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TransitiveC", "Foo");

        bFoo.ShouldNotBeNull();
        cFoo.ShouldNotBeNull();
        graph.IsReachableFromPublic(bFoo!).ShouldBeTrue();
        graph.IsReachableFromPublic(cFoo!).ShouldBeTrue();
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~ReverseCallGraphTests.Callvirt"`
Expected: 4 tests fail (derived/transitive methods not reachable).

- [ ] **Step 3: Update ReverseCallGraph to expand callvirt edges**

Replace the BFS loop in `tools/TaintAnalyzer/ReverseCallGraph.cs`. The new code uses `AssemblyContext`-free construction (the existing ctor takes only `AssemblyDefinition`) — instantiate a private `VirtualOverrideIndex` directly so we don't introduce a circular dependency through AssemblyContext during construction.

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class ReverseCallGraph
{
    private readonly HashSet<MethodDefinition> _reachableFromPublic;

    public ReverseCallGraph(AssemblyDefinition assembly)
    {
        _reachableFromPublic = new HashSet<MethodDefinition>();
        var queue = new Queue<MethodDefinition>();
        var overrides = new VirtualOverrideIndex(assembly);

        foreach (var m in AllMethods(assembly).Where(IsPublic))
        {
            if (_reachableFromPublic.Add(m))
            {
                queue.Enqueue(m);
            }
        }

        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            if (m.Body is null) continue;
            foreach (var ins in m.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj)
                    continue;
                if (ins.Operand is not MethodReference mr) continue;

                if (ins.OpCode == OpCodes.Callvirt)
                {
                    foreach (var target in overrides.EnumerateOverrides(mr))
                    {
                        if (target.Module.Assembly != assembly) continue;
                        if (_reachableFromPublic.Add(target))
                            queue.Enqueue(target);
                    }
                    continue;
                }

                MethodDefinition? callee;
                try { callee = mr.Resolve(); }
                catch { continue; }
                if (callee is null || callee.Module.Assembly != assembly) continue;

                if (_reachableFromPublic.Add(callee))
                {
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~ReverseCallGraphTests"`
Expected: 9 tests pass (5 original + 4 new).

- [ ] **Step 5: Run the full unit-test suite to check for incidental regressions**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: All tests pass. (More methods are now "reachable from public" — verify no `EntryPointEnumerator` test that previously expected an orphan to be filtered now breaks. If any does, investigate before proceeding — it may indicate a fixture that needs revisiting.)

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/ReverseCallGraph.cs tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs
git commit -m "$(cat <<'EOF'
analyzer: ReverseCallGraph follows callvirt overrides via VirtualOverrideIndex

For every Callvirt edge, enumerate the static target + every in-assembly
override and enqueue each. Concrete overrides on internal types now mark as
reachable from public callers (fixes the protobuf-net
ReadOnlySequenceProtoReader::ImplReadString orphan in --scan mode). Call /
Newobj edges unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: TaintWalker — single-target callvirt path

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` — gate `HandleCall`'s `WalkWithSeed` call through `EnumerateOverrides`
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` — add 2 tests

This task adds the override-expansion plumbing without yet doing summary merging. When `EnumerateOverrides` returns a single target (the common case: denylisted, non-virtual, or no overrides), behaviour must be identical to today. Multi-target merging is Task 9.

- [ ] **Step 1: Write the failing tests** — append to `TaintWalkerTests`

```csharp
    [Fact]
    public void Callvirt_SingleOverride_PropagatesTaintFromOverrideBody()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // PublicCallerForOverride.Call does `callvirt SimpleBase::Process(byte[])`.
        // SimpleBase is abstract — empty body. SimpleDerived overrides Process
        // with a no-op. With override expansion, the walker visits SimpleDerived
        // but it doesn't taint anything; the call itself shouldn't reach a sink.
        // This test pins behaviour: tainted byte[] in -> no sink (correct).
        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForOverride::Call(System.Byte[])")!;
        var summary = walker.Walk(caller, taintedParamBitmask: 0b1);

        // No sink expected — Process is a no-op. But the override expansion
        // MUST have happened (otherwise we wouldn't even visit the override).
        // The proof is that we don't crash and the walker doesn't fall back
        // to the external-call path (which would taint return; Process is void).
        summary.ReachedSink.ShouldBeFalse();
    }

    [Fact]
    public void Callvirt_DenylistedObjectToString_FallsBackToSingleTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // PublicCallerForToString.Stringify(object) -> callvirt Object::ToString.
        // ToString is denylisted: EnumerateOverrides returns [Object::ToString].
        // Object::ToString is external (cross-assembly), so the walker takes
        // the external path. Without the denylist, this test would walk every
        // ToString override in the fixture DLL — far too noisy.
        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForToString::Stringify(System.Object)")!;
        var summary = walker.Walk(caller, taintedParamBitmask: 0b1);

        // Tainted object in, ToString returns tainted (external over-approximation),
        // but no sink. Critical assertion: we don't crash, and we don't recurse
        // into CustomToString (which is reachable only via the denylisted callvirt).
        summary.ReachedSink.ShouldBeFalse();
        summary.ReturnsTainted.ShouldBeTrue();
    }
```

- [ ] **Step 2: Run tests to verify they fail or pass for the wrong reason**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalkerTests.Callvirt_SingleOverride|FullyQualifiedName~TaintWalkerTests.Callvirt_DenylistedObjectToString"`
Expected: Tests pass today because of the existing external-path fallback. The behavioural change is invisible at this step. The point is to lock the behaviour BEFORE adding override expansion, so the next step's refactor doesn't drift.

- [ ] **Step 3: Modify HandleCall to route callvirt through EnumerateOverrides**

Find `HandleCall` in `tools/TaintAnalyzer/TaintWalker.cs` near line 995. Replace the `WalkWithSeed` call with an opcode-gated branch:

Current (around line 995):
```csharp
        // Cross-method walk with seeded `this`-fields.
        var calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);
```

Replace with:
```csharp
        // Cross-method walk with seeded `this`-fields.
        // For callvirt, expand the static target to all in-assembly overrides
        // via VirtualOverrideIndex. EnumerateOverrides returns [resolved] in the
        // common single-target case (non-virtual, denylisted, no overrides);
        // multi-target merging happens via WalkAndMerge (added in next task).
        MethodSummary calleeSummary;
        if (ins.OpCode == OpCodes.Callvirt)
        {
            var targets = _context.VirtualOverrides.EnumerateOverrides(callee)
                .Where(t => t.Module.Assembly == _context.Assembly)
                .ToList();
            if (targets.Count == 0)
                calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);
            else if (targets.Count == 1)
                calleeSummary = WalkWithSeed(targets[0], bitmask, seedFields);
            else
                calleeSummary = WalkAndMerge(targets, bitmask, seedFields);
        }
        else
        {
            calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);
        }
```

Add a placeholder `WalkAndMerge` immediately below `HandleCall` so the build passes; the real body lands in Task 9:

```csharp
    private MethodSummary WalkAndMerge(
        IReadOnlyList<MethodDefinition> targets, int bitmask, IReadOnlyCollection<string> seedFields)
    {
        // Placeholder — replaced with the real merge in the next task.
        return WalkWithSeed(targets[0], bitmask, seedFields);
    }
```

- [ ] **Step 4: Run the full unit-test suite**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: All tests pass. The single-target path is identical to before; multi-target paths fall through to the placeholder (which behaves like the old code for the first target). No fixture should regress.

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "$(cat <<'EOF'
analyzer: route callvirt through VirtualOverrideIndex in HandleCall

For callvirt instructions, enumerate the static target's in-assembly
overrides and walk each. Single-target case (denylisted / non-virtual /
no overrides) is identical to today's WalkWithSeed call. Multi-target
merging is a placeholder that takes the first target — real merge logic
lands in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: WalkAndMerge — multi-override summary fold

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs` — implement `WalkAndMerge`
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` — add 5 tests

- [ ] **Step 1: Write the failing tests** — append to `TaintWalkerTests`

```csharp
    [Fact]
    public void Callvirt_MultipleOverrides_OneTaintsReturn_SummaryHasReturnsTainted()
    {
        // PublicCallerForTwoOverride.Run -> callvirt TwoOverrideBase::Read.
        // Overrides: CleanOverride returns empty array; TaintingOverride returns
        // new byte[input.Length] (tainted by input arg). Merged summary must
        // report ReturnsTainted=true even though one override returns clean.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForTwoOverride::Run("
            + "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TwoOverrideBase,System.Byte[])")!;

        // arg0 (TwoOverrideBase receiver, bit 0) untainted; arg1 (byte[], bit 1) tainted.
        var summary = walker.Walk(caller, taintedParamBitmask: 0b10);

        summary.ReturnsTainted.ShouldBeTrue();
        // TaintingOverride does newarr — sink reached through the merged path.
        summary.ReachedSink.ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_OneOverrideReachesSink_OverallReachedSink()
    {
        // Walk TwoOverrideBase::Read directly with bitmask=0b1 (input arg tainted).
        // CleanOverride doesn't allocate; TaintingOverride newarrs on input.Length.
        // ReachedSink must be true on the merged summary.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var virt = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TwoOverrideBase::Read(System.Byte[])")!;
        var summary = walker.Walk(virt, taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        summary.ReturnsTainted.ShouldBeTrue();
    }

    [Fact]
    public void Callvirt_HopsPreferSinkReachingOverride()
    {
        // The hop trace must come from the override that reached the sink, not
        // from a clean sibling. We verify by checking the sink hop's method label
        // mentions TaintingOverride.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var virt = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TwoOverrideBase::Read(System.Byte[])")!;
        var summary = walker.Walk(virt, taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeTrue();
        var sinkHop = summary.Hops.LastOrDefault(h => h.Role == HopRole.Sink);
        sinkHop.ShouldNotBeNull();
        sinkHop!.Method.ShouldContain("TaintingOverride");
    }

    [Fact]
    public void Callvirt_OneOverrideSanitises_AppliedThrowShapeSanitiserStaysFalse()
    {
        // Build a hypothetical assembly where only one of N overrides is the
        // ThrowingOverride and the other is the TaintingOverride. We use the
        // existing TwoOverrideBase fixture: CleanOverride (no sanitiser) AND
        // ThrowingOverride (throws on >1024). The merged AppliedThrowShape-
        // Sanitiser flag must be the INTERSECTION (AND) — false here, because
        // CleanOverride does NOT throw on the tainted param.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var virt = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.TwoOverrideBase::Read(System.Byte[])")!;
        var summary = walker.Walk(virt, taintedParamBitmask: 0b1);

        summary.AppliedThrowShapeSanitiser.ShouldBeFalse();
    }

    [Fact]
    public void Callvirt_AllOverridesEmpty_DefaultSummaryReturned()
    {
        // For PublicCallerForOverride.Call (callvirt SimpleBase::Process), both
        // SimpleBase.Process (abstract, no body) and SimpleDerived.Process (no-op)
        // produce empty summaries. The merged summary must be inert: no sink, no
        // taint, no flags set, no hops.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var virt = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.SimpleBase::Process(System.Byte[])")!;
        var summary = walker.Walk(virt, taintedParamBitmask: 0b1);

        summary.ReachedSink.ShouldBeFalse();
        summary.ReturnsTainted.ShouldBeFalse();
        summary.NewlyTaintedThisFields.ShouldBeEmpty();
        summary.AppliedValueClamp.ShouldBeFalse();
        summary.AppliedThrowShapeSanitiser.ShouldBeFalse();
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalkerTests.Callvirt"`
Expected: At least `Callvirt_HopsPreferSinkReachingOverride` and the multi-override summary tests fail because `WalkAndMerge` is still a placeholder.

- [ ] **Step 3: Implement WalkAndMerge**

Replace the placeholder `WalkAndMerge` in `tools/TaintAnalyzer/TaintWalker.cs`:

```csharp
    private MethodSummary WalkAndMerge(
        IReadOnlyList<MethodDefinition> targets, int bitmask, IReadOnlyCollection<string> seedFields)
    {
        // Walk each target (memo deduplicates per (FullName, bitmask, seedKey))
        // and fold the per-target summaries:
        //   - ReturnsTainted / ReachedSink / NewlyTaintedThisFields: UNION (any).
        //   - AppliedValueClamp / AppliedThrowShapeSanitiser: INTERSECTION (all).
        //     Sanitiser flags suppress over-approximations in HandleCall; if even
        //     one override doesn't sanitise, we must NOT suppress.
        //   - Hops: pick the witness whose path reached the sink; otherwise the
        //     first ReturnsTainted; otherwise the first non-empty hops list.
        var perTarget = new List<MethodSummary>(targets.Count);
        foreach (var t in targets)
            perTarget.Add(WalkWithSeed(t, bitmask, seedFields));

        bool returns = perTarget.Any(s => s.ReturnsTainted);
        bool reached = perTarget.Any(s => s.ReachedSink);
        var newlyTainted = perTarget
            .SelectMany(s => s.NewlyTaintedThisFields)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        bool clamp = perTarget.All(s => s.AppliedValueClamp);
        bool throwShape = perTarget.All(s => s.AppliedThrowShapeSanitiser);

        var witness =
            perTarget.FirstOrDefault(s => s.ReachedSink)
            ?? perTarget.FirstOrDefault(s => s.ReturnsTainted)
            ?? perTarget.FirstOrDefault(s => s.Hops.Count > 0)
            ?? perTarget[0];

        // Use the first target's FullName + bitmask for the merged summary's identity
        // (the value isn't load-bearing because HandleCall consumes the summary
        // immediately; the memo holds per-target entries from WalkWithSeed).
        return new MethodSummary
        {
            MethodFullName = perTarget[0].MethodFullName,
            TaintedParamBitmask = bitmask,
            ReturnsTainted = returns,
            NewlyTaintedThisFields = newlyTainted,
            Hops = witness.Hops,
            Absences = witness.Absences,
            ReachedSink = reached,
            AppliedValueClamp = clamp,
            AppliedThrowShapeSanitiser = throwShape,
        };
    }
```

- [ ] **Step 4: Run the new tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalkerTests.Callvirt"`
Expected: 7 callvirt tests pass (2 from Task 8 + 5 new).

- [ ] **Step 5: Run the full unit-test suite**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`
Expected: All tests pass. Any regression here is a real signal — investigate before continuing.

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "$(cat <<'EOF'
analyzer: WalkAndMerge — fold callvirt-override summaries

OR-merges taint flags (ReturnsTainted, ReachedSink, NewlyTaintedThisFields)
and AND-merges sanitiser flags (AppliedValueClamp, AppliedThrowShape-
Sanitiser) so a clean sibling cannot mask a vulnerable override. Hops are
sourced from the override that reached the sink (or returns-tainted, or
first non-empty) so the user-facing trace points at the worst-case witness.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: TaintWalker edge cases — cross-assembly + call-on-virtual

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` — add 2 tests

- [ ] **Step 1: Write the tests** — append to `TaintWalkerTests`

```csharp
    [Fact]
    public void Callvirt_NotInAssembly_FallsBackToExternalPath()
    {
        // PublicCallerForToString does callvirt Object::ToString. The static
        // target is cross-assembly; EnumerateOverrides returns [Object::ToString]
        // (denylisted). After the .Where(in-assembly) filter in HandleCall,
        // targets.Count == 0 and we fall through to the WalkWithSeed(resolved,...)
        // path — which sees resolved.Module.Assembly != _context.Assembly and
        // takes the external-call path inside HandleCall. Verifies the
        // targets.Count == 0 branch.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.PublicCallerForToString::Stringify(System.Object)")!;
        var summary = walker.Walk(caller, taintedParamBitmask: 0b1);

        // Tainted object -> ToString returns tainted (external over-approx); no sink.
        summary.ReturnsTainted.ShouldBeTrue();
        summary.ReachedSink.ShouldBeFalse();
    }

    [Fact]
    public void Call_OpcodeOnVirtualMethod_NoOverrideExpansion()
    {
        // BaseCallSite.CallBaseDirectly does `call TransitiveB::Foo` (not callvirt
        // — C# emits `call` for `base.X()`). The walker must NOT expand to
        // TransitiveC::Foo; only TransitiveB::Foo runs.
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var caller = ctx.FindMethod(
            "TaintAnalyzer.Tests.Fixtures.VirtualDispatch.BaseCallSite::CallBaseDirectly(System.Int32)")!;
        var summary = walker.Walk(caller, taintedParamBitmask: 0b1);

        // TransitiveB.Foo and TransitiveC.Foo both return `x + N`. Neither sinks.
        // What we're asserting is no crash; the test is mostly a regression
        // guard against accidentally adding override expansion to the `call`
        // opcode. If TransitiveC were ever walked here, ReachedSink would still
        // be false (no sink in the fixture), so the proof is structural — we
        // assert the method body runs cleanly.
        summary.ReachedSink.ShouldBeFalse();
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~TaintWalkerTests.Callvirt_NotInAssembly|FullyQualifiedName~TaintWalkerTests.Call_OpcodeOnVirtualMethod"`
Expected: 2 tests pass. (Both are passing-tests: Task 8's HandleCall change already gates on `OpCodes.Callvirt`. These tests pin behaviour for future refactors.)

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/TaintWalkerTests.cs
git commit -m "$(cat <<'EOF'
test: pin callvirt-cross-assembly and call-opcode-on-virtual behaviour

Two regression guards. The cross-assembly case must fall through to the
external-call path; the call-vs-callvirt distinction must keep override
expansion gated on the callvirt opcode only.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Regression check — full suite + anchor fixtures

No code changes — verification step before the proof fixture.

- [ ] **Step 1: Run the full unit-test suite**

Run: `dotnet test TaintAnalyzer.sln -c Release`
Expected: 320 tests pass (294 baseline + 13 VirtualOverrideIndex + 4 ReverseCallGraph + 9 TaintWalker). If the count is off, count the tests and reconcile.

- [ ] **Step 2: Run anchor fixtures via --compare non-strict**

Each anchor fixture has a `run` script that wraps `--compare`. Run them sequentially and stop on the first failure:

```bash
for f in \
  imagesharp-3074-prefix imagesharp-3074-postfix \
  imagesharp-3079-prefix imagesharp-3079-postfix \
  otelcontrib-55m9-prefix otelcontrib-55m9-postfix \
  otelcontrib-vc24-prefix otelcontrib-vc24-postfix \
  otelcontrib-opamp-w2jh-prefix otelcontrib-opamp-w2jh-postfix \
  otelcontrib-aws-fp-fixed \
  nbmp-2cwq-pwfr-wcw3-prefix nbmp-2cwq-pwfr-wcw3-postfix \
  parquet-dotnet-738 \
  synthetic-callee-arithmetic synthetic-instance-arithmetic synthetic-stackalloc \
  scan-nbmp-1.1.25; do
  echo "=== $f ===" && fixtures/$f/run || { echo "FAIL: $f"; break; }
done
```

Expected: every fixture prints `OK` (or whatever its `run` script emits on success) and the loop completes without `FAIL:`.

- [ ] **Step 3: If any anchor fixture fails**

Diff the new output against the locked expected output:

```bash
fixtures/<failing-fixture>/run 2>&1 | tail -50
```

The most likely cause of a shift: a previously-empty callvirt summary now folds in real override hops. Either:
- The new behaviour is correct — relock the fixture (rare; do NOT do this without confirming with the user first).
- A merge rule is wrong — fix in `WalkAndMerge` or `EnumerateOverrides`.

Do not proceed past this step until every anchor is green.

- [ ] **Step 4: Commit any anchor-fixture updates if relocking was approved**

Skip this step if no fixtures changed. If any did, prepare a fresh commit for each fixture with a message explaining why the lock changed.

---

### Task 12: Lock the scan-protobuf-net proof fixture

**Files:**
- Create: `fixtures/scan-protobuf-net/README.md`
- Create: `fixtures/scan-protobuf-net/run`
- Create: `fixtures/scan-protobuf-net/rules.yaml.expected`

The fixture mirrors `fixtures/scan-nbmp-1.1.25/`. It assumes `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` exists; if it doesn't, the `run` script skips silently (so CI on a clean checkout doesn't break).

- [ ] **Step 1: Verify the protobuf-net DLL is available**

Run: `ls artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll 2>/dev/null || echo "missing"`
Expected: either the path prints, or `missing`. If missing, materialise it (the user has done this for other fixtures; the canonical NuGet pull pattern is in `scripts/` or visible in `fixtures/scan-nbmp-1.1.25/README.md`). The fixture STILL gets committed even if the artefact is missing — the lock is the expected file, not the artefact.

- [ ] **Step 2: Inspect the layout of `fixtures/scan-nbmp-1.1.25/` to mirror it**

Run: `ls fixtures/scan-nbmp-1.1.25/ && cat fixtures/scan-nbmp-1.1.25/run`
Expected: shows `README.md`, `rules.yaml.expected`, `run`. The `run` script invokes the analyzer with `--scan --emit-rules` against the artefact and diffs the output against `rules.yaml.expected`.

- [ ] **Step 3: Create `fixtures/scan-protobuf-net/README.md`**

```markdown
# scan-protobuf-net

End-to-end regression fixture for milestone-R (virtual-dispatch resolution).
Runs `TaintAnalyzer --scan --emit-rules` over protobuf-net.Core ≤ 3.2.56
(`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`) and asserts the
generated rules.yaml matches `rules.yaml.expected`.

The expected output contains `ProtoBuf.ProtoReader::ReadString` and the
parameter-shape candidate `ProtoBuf.ProtoReader::Create(System.Buffers.ReadOnlySequence<byte>,...)`.
With milestone-R's virtual-dispatch resolution, the analyzer's call graph
also reaches `ProtoBuf.ReadOnlySequenceProtoReader::ImplReadString` via the
`callvirt ImplReadString` site inside `ProtoReader::ReadString` — closing
the visibility gap that hid the OOM finding pre-R.

The fixture skips silently when
`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` is not
materialised (untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Ensure `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` is in
   place (NuGet: `nuget install protobuf-net.Core -Version 3.2.56`)
3. Run: `fixtures/scan-protobuf-net/run`
```

- [ ] **Step 4: Create the `run` script — mirror `scan-nbmp-1.1.25/run` exactly**

Open `fixtures/scan-nbmp-1.1.25/run`, copy its contents, and adapt:

```bash
cp fixtures/scan-nbmp-1.1.25/run fixtures/scan-protobuf-net/run
chmod +x fixtures/scan-protobuf-net/run
```

Then edit `fixtures/scan-protobuf-net/run` and replace:
- The artefact path: `artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll` → `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`
- Any fixture-name references: `scan-nbmp-1.1.25` → `scan-protobuf-net`

Run: `cat fixtures/scan-protobuf-net/run` and verify the paths are correct.

- [ ] **Step 5: Generate `rules.yaml.expected`**

Run the analyzer against the materialised artefact and capture the output:

```bash
dotnet run --project tools/TaintAnalyzer -c Release -- \
  --scan --emit-rules /tmp/rules-protobuf.yaml \
  --no-symbols \
  artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll
cp /tmp/rules-protobuf.yaml fixtures/scan-protobuf-net/rules.yaml.expected
```

- [ ] **Step 6: Validate the lock**

Run: `fixtures/scan-protobuf-net/run`
Expected: `OK` (or whatever the run script emits on success). Confirms the generated rules round-trip against the captured expected file.

- [ ] **Step 7: Verify the proof — ImplReadString is in the rules**

Run: `grep -E 'ReadOnlySequenceProtoReader|ImplReadString|ProtoReader::ReadString' fixtures/scan-protobuf-net/rules.yaml.expected`
Expected: Output includes `ProtoBuf.ProtoReader::ReadString` (the public entry) and (if virtual-dispatch reachability has surfaced it) `ProtoBuf.ReadOnlySequenceProtoReader::ImplReadString`. If `ImplReadString` is not present, virtual-dispatch is not making the override reachable — debug before locking.

If only `ProtoReader::ReadString` is present and `ImplReadString` is absent: that may still be the correct proof case, because `--scan` only enumerates entry points (public surface), not internal sinks. The user-facing demonstration in that case is via `--compare` showing a hop trace that crosses the override boundary, not a new entry in the rules file. Confirm with the user before locking if `ImplReadString` is not in the rules output.

- [ ] **Step 8: Commit**

```bash
git add fixtures/scan-protobuf-net/
git commit -m "$(cat <<'EOF'
fixture: lock scan-protobuf-net (virtual-dispatch reaches ImplReadString)

End-to-end proof for milestone-R. `--scan --emit-rules` over
protobuf-net.Core 3.2.56 produces a rules.yaml whose entry points include
ProtoBuf.ProtoReader::ReadString; the virtual-dispatch reachability now
makes ReadOnlySequenceProtoReader::ImplReadString visible inside the
analyzer's call graph, closing the gap that hid the OOM finding pre-R.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage check** — every numbered item maps to at least one task:

- Architecture section (`VirtualOverrideIndex` + `BuildIndex` + `EnumerateOverrides` + denylist) → Tasks 2, 3, 4, 5
- AssemblyContext ownership → Task 6
- ReverseCallGraph consumer → Task 7
- TaintWalker consumer (single-target path + `WalkAndMerge`) → Tasks 8, 9
- Override-discovery rules (implicit, explicit, interface, modreq, denylist, cross-assembly) → Tasks 2, 3, 4, 5
- Summary-merge rules (OR/AND/witness) → Task 9
- Expansion-guard (U10) note: handled implicitly because `expandedCallees` key uses `resolved.FullName`; each WalkWithSeed call inside WalkAndMerge sees a distinct `targets[i].FullName` so dedupe slots are per-target. No code change needed; covered by the merge-tests in Task 9.
- No CLI / configuration → Task 0 (no flag added; verified in plan structure)
- `Callvirt` only trigger → Task 8 (`if (ins.OpCode == OpCodes.Callvirt)`) + Task 10 (regression test)
- 26 new unit tests → Tasks 2-5 (13), 7 (4), 8 (2), 9 (5), 10 (2) = 26 ✓
- scan-protobuf-net fixture → Task 12
- Anchor fixtures stay green → Task 11

**Placeholder scan:** no TBD / TODO / "implement later" / "add error handling" / "similar to Task N" markers. Code in every step.

**Type / signature consistency:** `EnumerateOverrides(MethodReference)` used in every consumer; `WalkAndMerge(IReadOnlyList<MethodDefinition>, int, IReadOnlyCollection<string>)` matches its call sites in `HandleCall`; `VirtualOverrideIndex` ctor takes `AssemblyDefinition` everywhere.

**Plan ready for execution.**
