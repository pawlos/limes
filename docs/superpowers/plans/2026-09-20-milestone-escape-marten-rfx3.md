# Milestone-Escape Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Limes detect Marten GHSA-rfx3-98h7-v3xp (CVE-2026-75513) on Marten 8.37.0 and report it clean on the patched 9.13.0, by adding a raw `ICommandBuilder.Append(string)` SQL sink and the analyzer's first value-transforming sanitizer (quote-doubling `String.Replace("'", "''")`).

**Architecture:** Three independent pieces land in order. (1) `SinkShapes` gains a raw-append predicate with its own `SinkApi`, plus `Weasel.Core` recognition. (2) `SanitizerShapes` gains a pure IL pattern, `MatchSqlQuoteEscapes`, returning the IL offsets of quote-doubling `Replace` calls. (3) `TaintWalker` untaints the `Replace` result at those offsets — after `StepInstruction`, because the external-call over-approximation pushes a tainted return — and emits a sanitizer hop that carries a `transformation` instead of a bound. Fixtures then lock both directions, synthetically and against real Marten binaries.

**Tech Stack:** C#, .NET 10 SDK, Mono.Cecil 0.11.6, xUnit + Shouldly, YamlDotNet. Fixture assemblies are built by shell scripts into the gitignored `artifacts/` directory.

**Spec:** `docs/superpowers/specs/2026-09-19-milestone-escape-marten-rfx3-design.md`

## Global Constraints

- **Never run `git push`.** Commit locally; the user pushes.
- **Run tests serially:** `dotnet test <proj> -- xunit.parallelizeTestCollections=false`. Parallel runs flake on YamlDotNet serialization in `Program.Run` paths. This is pre-existing.
- **No existing fixture `trace.yaml` may change.** The only intentionally inverted lock is the unit test in Task 1, Step 1.
- **`artifacts/` is gitignored.** Fixture assemblies are materialized by scripts and never committed. Every fixture test returns early when its artifact is missing.
- **Marten versions:** prefix is **8.37.0** (`artifacts/marten-8.37`, already materialized by `scripts/materialize-marten-8.37.sh`), postfix is **9.13.0** (`artifacts/marten-9.13`, new script in Task 6). 8.37.0 is the GHSA-vmw2-*patched* build, which is the point of the pair.
- **Trace vocabulary added by this milestone:** api `sql_command_builder_append_raw`, transformation `sql_quote_escape`, provenance form `sql_quote_escaped(<orig>)`.
- **Commit messages** end with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Test project paths:** analyzer `tools/TaintAnalyzer/TaintAnalyzer.csproj`, tests `tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj`, IL fixtures `tools/TaintAnalyzer.Tests.Fixtures/`, validator `tools/ValidateFixture/`, validator tests `tools/ValidateFixture.Tests/`.

---

## File Structure

**Modified:**
- `tools/TaintAnalyzer/HopRecord.cs` — one new `SinkApi` member.
- `tools/TaintAnalyzer/SinkShapes.cs` — split append predicates, `Weasel.Core`, widened heuristic.
- `tools/TaintAnalyzer/SanitizerShapes.cs` — new `QuoteEscapeMatch` + `MatchSqlQuoteEscapes`.
- `tools/TaintAnalyzer/TaintWalker.cs` — precompute offsets, post-step untaint, sanitizer hop.
- `tools/TaintAnalyzer/TraceEmitter.cs` — api string mapping; bound-less sanitizer matching.
- `tools/ValidateFixture/Vocabularies.cs` — SQLi vocabulary + value-transforming set.
- `tools/ValidateFixture/FixtureValidator.cs` — FX023 exemption.
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` — new IL fixture methods.
- `tools/TaintAnalyzer.Tests/SinkShapesTests.cs` — inverted lock + new cases.
- `README.md` — findings table, sink list, sanitizer description.

**Created:**
- `tools/TaintAnalyzer.Tests/SanitizerShapesQuoteEscapeTests.cs`
- `tools/TaintAnalyzer.Tests/QuoteEscapeWalkTests.cs`
- `tools/TaintAnalyzer.Tests/SqliRawAppendFixtureTests.cs`
- `tools/TaintAnalyzer.Tests/SqliQuoteEscapeFixtureTests.cs`
- `tools/TaintAnalyzer.Tests/MartenRfx3FixtureTests.cs`
- `tools/TaintAnalyzer.Tests/ScanMartenRfx3FixtureTests.cs`
- `fixtures/sqli-raw-append-prefix/{source/,rules.yaml,trace.yaml}`
- `fixtures/sqli-quote-escape-postfix/{source/,rules.yaml,trace.yaml}`
- `fixtures/marten-rfx3-prefix/{rules.yaml,trace.yaml}`
- `fixtures/marten-rfx3-postfix/{rules.yaml,trace.yaml}`
- `scripts/build-sqli-raw-append.sh`, `scripts/build-sqli-quote-escape.sh`, `scripts/materialize-marten-9.13.sh`

---

### Task 1: Raw `Append(string)` sink with its own api label

**Files:**
- Modify: `tools/TaintAnalyzer/HopRecord.cs:7`
- Modify: `tools/TaintAnalyzer/SinkShapes.cs:216-229` (predicate), `:419-439` (matcher), `:441-473` (type checks)
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:447-459` (api mapping)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs:901-908`
- Test: `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `SinkApi.SqlCommandBuilderAppendRaw`; `SinkShapes.MatchCommandBuilderAppend(Instruction, SymbolicStack) → SinkMatch?` now returns either api; `SinkShapes.IsSqlSinkCall(MethodReference) → bool` now also accepts raw appends (used by `SqlSinkReachability`).

- [ ] **Step 1: Invert the stale lock and add the new sink tests**

In `tools/TaintAnalyzer.Tests/SinkShapesTests.cs`, **replace** the existing `MatchCommandBuilderAppend_WrongName_ReturnsNull` test (around line 509) with the four tests below. The old test asserted that `Append(string)` is not a sink; GHSA-rfx3 shows that was wrong, and inverting it is intentional.

```csharp
    [Fact]
    public void MatchCommandBuilderAppend_RawAppend_MatchesRawApi()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CommandBuilderFixtures::DoAppend(Weasel.Postgresql.IFakeCommandBuilder,System.String)");

        var call = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Append");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);                       // receiver
        stack.Push(StackSlot.TaintedWith("sql"));              // SQL — tainted

        var match = SinkShapes.MatchCommandBuilderAppend(call, stack);

        match.ShouldNotBeNull();
        match!.Kind.ShouldBe(SinkKind.SqlInjection);
        match.Api.ShouldBe(SinkApi.SqlCommandBuilderAppendRaw);
        match.SizeProvenance.ShouldBe("sql");
    }

    [Fact]
    public void MatchCommandBuilderAppend_RawAppend_Untainted_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CommandBuilderFixtures::DoAppend(Weasel.Postgresql.IFakeCommandBuilder,System.String)");

        var call = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Append");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.Untainted);

        SinkShapes.MatchCommandBuilderAppend(call, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchCommandBuilderAppend_CharOverload_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CommandBuilderFixtures::DoAppendChar(Weasel.Postgresql.IFakeCommandBuilder,System.Char)");

        var call = m.Body.Instructions.Single(i =>
            (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) &&
            i.Operand is MethodReference mr &&
            mr.Name == "Append");

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.TaintedWith("c"));

        SinkShapes.MatchCommandBuilderAppend(call, stack).ShouldBeNull();
    }

    [Fact]
    public void MatchCommandBuilderAppend_WeaselCoreNamespace_ResolveFailure_MatchesRawApi()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Weasel 9.x moved ICommandBuilder from Weasel.Postgresql to Weasel.Core.
        var module = ctx.Assembly.MainModule;
        var stringType = module.TypeSystem.String;
        var voidType = module.TypeSystem.Void;
        var declaringType = new TypeReference("Weasel.Core", "ICommandBuilder", module, module);
        var append = new MethodReference("Append", voidType, declaringType) { HasThis = true };
        append.Parameters.Add(new ParameterDefinition(stringType));
        var ins = Instruction.Create(OpCodes.Callvirt, append);

        var stack = new SymbolicStack();
        stack.Push(StackSlot.Untainted);
        stack.Push(StackSlot.TaintedWith("sql"));

        var match = SinkShapes.MatchCommandBuilderAppend(ins, stack);

        match.ShouldNotBeNull();
        match!.Api.ShouldBe(SinkApi.SqlCommandBuilderAppendRaw);
    }
```

Add the `Append(char)` members the third test needs. In `tools/TaintAnalyzer.Tests.Fixtures/WeaselFixtures.cs`, extend the interface:

```csharp
namespace Weasel.Postgresql;

public interface IFakeCommandBuilder
{
    void AppendWithParameters(string sql);
    void Append(string sql);
    void Append(char c);
}
```

And in `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`, extend `CommandBuilderFixtures` (around line 901):

```csharp
public static class CommandBuilderFixtures
{
    public static void DoAppendWithParameters(Weasel.Postgresql.IFakeCommandBuilder b, string sql)
        => b.AppendWithParameters(sql);

    public static void DoAppend(Weasel.Postgresql.IFakeCommandBuilder b, string sql)
        => b.Append(sql);

    public static void DoAppendChar(Weasel.Postgresql.IFakeCommandBuilder b, char c)
        => b.Append(c);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~SinkShapesTests.MatchCommandBuilderAppend" \
  -- xunit.parallelizeTestCollections=false
```

Expected: a compile error on `SinkApi.SqlCommandBuilderAppendRaw` (it doesn't exist yet). That counts as red. Once the enum member lands in Step 3, the raw-append tests fail on a null match.

- [ ] **Step 3: Add the enum member and the api string**

In `tools/TaintAnalyzer/HopRecord.cs` line 7:

```csharp
public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc, HttpContentRead, HttpClientRead, SqlCommandText, SqlCommandBuilderAppend, SqlCommandBuilderAppendRaw }
```

In `tools/TaintAnalyzer/TraceEmitter.cs`, in `SinkApiToString`, add below the `SqlCommandBuilderAppend` line:

```csharp
        SinkApi.SqlCommandBuilderAppendRaw => "sql_command_builder_append_raw",
```

- [ ] **Step 4: Split the append predicates in SinkShapes**

In `tools/TaintAnalyzer/SinkShapes.cs`, replace `IsCommandBuilderAppendCall` (lines 216-229) with:

```csharp
    // A "command-builder append" is either the parameterizing overload
    // (`AppendWithParameters(string, …)`, which binds `?` placeholders) or the RAW overload
    // (`Append(string)`, which concatenates SQL text verbatim). Both are injection sinks when
    // the string argument is attacker-controlled; the raw one is the more dangerous of the two
    // because nothing is bound. They are reported under distinct SinkApi values so traces stay
    // triageable (milestone-Escape / Marten GHSA-rfx3-98h7-v3xp).
    private static bool IsCommandBuilderAppendCall(MethodReference mr)
        => IsCommandBuilderParameterizedAppend(mr) || IsCommandBuilderRawAppend(mr);

    private static bool IsCommandBuilderParameterizedAppend(MethodReference mr)
    {
        if (mr.Name != "AppendWithParameters") return false;
        if (mr.Parameters.Count < 1) return false;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;
        return DeclaringTypeIsCommandBuilder(mr.DeclaringType);
    }

    // `Append(char)` is deliberately excluded: a single char cannot carry an injection payload.
    private static bool IsCommandBuilderRawAppend(MethodReference mr)
    {
        if (mr.Name != "Append") return false;
        if (mr.Parameters.Count != 1) return false;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;
        return DeclaringTypeIsCommandBuilder(mr.DeclaringType);
    }

    private static bool DeclaringTypeIsCommandBuilder(TypeReference declaring)
    {
        TypeDefinition? resolved;
        try { resolved = declaring.Resolve(); }
        catch (AssemblyResolutionException) { resolved = null; }
        return resolved is not null
            ? ImplementsCommandBuilder(resolved)
            : MatchesCommandBuilderHeuristic(declaring);
    }
```

Replace the body of `MatchCommandBuilderAppend` (lines 419-439) with:

```csharp
    public static SinkMatch? MatchCommandBuilderAppend(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;

        SinkApi api;
        if (IsCommandBuilderParameterizedAppend(mr)) api = SinkApi.SqlCommandBuilderAppend;
        else if (IsCommandBuilderRawAppend(mr)) api = SinkApi.SqlCommandBuilderAppendRaw;
        else return null;

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
            Api = api,
            SizeProvenance = sqlSlot.Provenance,
        };
    }
```

- [ ] **Step 5: Teach the type checks about Weasel 9.x**

In the same file, replace `ImplementsCommandBuilder` and `MatchesCommandBuilderHeuristic` (lines 441-473) with:

```csharp
    private static bool ImplementsCommandBuilder(TypeDefinition td)
    {
        // Weasel 9.x (Marten 9.x) moved ICommandBuilder from Weasel.Postgresql to Weasel.Core.
        static bool IsTarget(string fullName) =>
            fullName == "Weasel.Postgresql.ICommandBuilder"
            || fullName == "Weasel.Core.ICommandBuilder"
            || fullName == "Weasel.Postgresql.IFakeCommandBuilder";   // test fixture

        var current = td;
        while (current is not null)
        {
            if (IsTarget(current.FullName)) return true;
            foreach (var iface in current.Interfaces)
            {
                var ir = iface.InterfaceType;
                if (IsTarget(ir.FullName)) return true;
                TypeDefinition? iresolved;
                try { iresolved = ir.Resolve(); }
                catch (AssemblyResolutionException) { iresolved = null; }
                if (iresolved is not null && IsTarget(iresolved.FullName)) return true;
            }
            var baseType = current.BaseType;
            try { current = baseType?.Resolve(); }
            catch (AssemblyResolutionException) { current = null; }
        }
        return false;
    }

    private static bool MatchesCommandBuilderHeuristic(TypeReference tr)
    {
        // Widened from `Weasel.Postgresql` to any `Weasel.*` namespace so the 9.x Weasel.Core
        // move is covered when the Weasel assembly isn't resolvable next to the target.
        var ns = tr.Namespace ?? "";
        if (!ns.StartsWith("Weasel.", StringComparison.Ordinal)) return false;

        var typeName = tr.Name ?? "";
        return typeName.Contains("Command", StringComparison.Ordinal);
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~SinkShapesTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: PASS, with no other `SinkShapesTests` case regressing.

- [ ] **Step 7: Verify no existing fixture trace moved**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  -- xunit.parallelizeTestCollections=false
git status --short fixtures/
```

Expected: the full suite is green and `git status` shows no modified fixture. If a SQLi anchor did move, stop and report it — the spec's byte-identity invariant is the contract, and a real change there needs a decision, not a silent lock update.

- [ ] **Step 8: Commit**

```bash
git add tools/TaintAnalyzer/HopRecord.cs tools/TaintAnalyzer/SinkShapes.cs \
        tools/TaintAnalyzer/TraceEmitter.cs tools/TaintAnalyzer.Tests/SinkShapesTests.cs \
        tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs tools/TaintAnalyzer.Tests.Fixtures/WeaselFixtures.cs
git commit -m "analyzer: raw ICommandBuilder.Append(string) SQL sink + Weasel.Core recognition

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `MatchSqlQuoteEscapes` IL pattern

**Files:**
- Modify: `tools/TaintAnalyzer/SanitizerShapes.cs` (add `QuoteEscapeMatch` next to `ClampMatch` around line 20; add the matcher after `MatchRegexIsMatchAndThrow`, which ends near line 1500)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append a new fixture class at the end)
- Test: `tools/TaintAnalyzer.Tests/SanitizerShapesQuoteEscapeTests.cs` (create)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `SanitizerShapes.MatchSqlQuoteEscapes(MethodDefinition) → IEnumerable<QuoteEscapeMatch>`, where `QuoteEscapeMatch` has one property, `int CallIlOffset`. Task 3 consumes both.

- [ ] **Step 1: Add the IL fixture methods**

Append to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`:

```csharp
// milestone-Escape: quote-doubling escape recognizer fixtures.
// Marten 9.13.0 fixes GHSA-rfx3-98h7-v3xp with exactly the `Escape` shape below.
public static class QuoteEscapeFixtures
{
    public static string Escape(string s) => s.Replace("'", "''");

    // Negative: escapes double quotes, not single quotes.
    public static string DoubleQuoteEscape(string s) => s.Replace("\"", "\"\"");

    // Negative: strips the quote instead of doubling it.
    public static string StripQuote(string s) => s.Replace("'", "");

    // Negative: char overload cannot double a quote.
    public static string CharOverload(string s) => s.Replace('\'', '"');

    // Negative (documented limitation): literals routed through locals are not recognized.
    public static string EscapeViaLocals(string s)
    {
        var from = "'";
        var to = "''";
        return s.Replace(from, to);
    }
}

// Instance shape used by the walker tests in Task 3: a `this`-field flows into a fake
// command builder, with and without the escape.
public sealed class QuoteEscapeFragment
{
    private readonly string _key;

    public QuoteEscapeFragment(string key) => _key = key;

    public void ApplyEscaped(Weasel.Postgresql.IFakeCommandBuilder b)
    {
        b.Append("d.data #> '{");
        b.Append(_key.Replace("'", "''"));
        b.Append("}' is not null");
    }

    public void ApplyRaw(Weasel.Postgresql.IFakeCommandBuilder b)
    {
        b.Append("d.data #> '{");
        b.Append(_key);
        b.Append("}' is not null");
    }
}
```

- [ ] **Step 2: Write the failing pattern tests**

Create `tools/TaintAnalyzer.Tests/SanitizerShapesQuoteEscapeTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SanitizerShapesQuoteEscapeTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == $"TaintAnalyzer.Tests.Fixtures.{typeName}"
                                 && m.Name == methodName);

    [Fact]
    public void Escape_QuoteDoubling_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFixtures", "Escape");

        var matches = SanitizerShapes.MatchSqlQuoteEscapes(m).ToList();

        matches.Count.ShouldBe(1);
        var callOffsets = m.Body.Instructions
            .Where(i => i.Operand is MethodReference mr && mr.Name == "Replace")
            .Select(i => i.Offset)
            .ToList();
        callOffsets.ShouldContain(matches[0].CallIlOffset);
    }

    [Theory]
    [InlineData("DoubleQuoteEscape")]
    [InlineData("StripQuote")]
    [InlineData("CharOverload")]
    [InlineData("EscapeViaLocals")]
    public void NonQuoteDoublingShapes_DoNotMatch(string methodName)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFixtures", methodName);

        SanitizerShapes.MatchSqlQuoteEscapes(m).ShouldBeEmpty();
    }

    [Fact]
    public void MethodWithoutReplace_DoesNotMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFragment", "ApplyRaw");

        SanitizerShapes.MatchSqlQuoteEscapes(m).ShouldBeEmpty();
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~SanitizerShapesQuoteEscapeTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: compile error, `MatchSqlQuoteEscapes` does not exist.

- [ ] **Step 4: Implement the matcher**

In `tools/TaintAnalyzer/SanitizerShapes.cs`, add next to `ClampMatch` (after line 30):

```csharp
/// <summary>
/// A quote-doubling escape call — `s.Replace("'", "''")` — the standard PostgreSQL
/// single-quoted-literal escape. Unlike every other sanitizer shape here, it establishes no
/// bound and has no failure branch: it rewrites the value and execution continues. The walker
/// consumes the offset and untaints the call's result.
/// </summary>
public sealed class QuoteEscapeMatch
{
    /// <summary>IL offset of the `String::Replace` call that performs the doubling.</summary>
    public required int CallIlOffset { get; init; }
}
```

Add the matcher at the end of the `SanitizerShapes` class, after `MatchRegexIsMatchAndThrow`:

```csharp
    // Recognizes `<tainted>.Replace("'", "''")` by IL shape alone (no stack inspection), so it
    // is unit-testable without the walker. Both argument literals must be inline `ldstr`s —
    // which is what Roslyn emits for literal arguments in Debug and Release alike. Escape
    // arguments routed through locals or fields are NOT recognized (documented limitation).
    //
    // Excluded on purpose: `Replace(char, char)` (cannot double a quote) and the
    // StringComparison/culture overloads (no advisory has needed them yet).
    public static IEnumerable<QuoteEscapeMatch> MatchSqlQuoteEscapes(MethodDefinition method)
    {
        if (method.Body is null) yield break;

        foreach (var ins in method.Body.Instructions)
        {
            if (ins.OpCode.Code is not (Code.Call or Code.Callvirt)) continue;
            if (ins.Operand is not MethodReference mr) continue;
            if (mr.Name != "Replace") continue;
            if (mr.DeclaringType.FullName != "System.String") continue;
            if (mr.Parameters.Count != 2) continue;
            if (mr.Parameters[0].ParameterType.FullName != "System.String") continue;
            if (mr.Parameters[1].ParameterType.FullName != "System.String") continue;

            // Stack at the call: [receiver, oldValue, newValue]. Walk the two pushers back.
            var newValuePusher = PrevSkippingNops(ins);
            if (newValuePusher is null || newValuePusher.OpCode.Code != Code.Ldstr) continue;
            if (newValuePusher.Operand as string != "''") continue;

            var oldValuePusher = PrevSkippingNops(newValuePusher);
            if (oldValuePusher is null || oldValuePusher.OpCode.Code != Code.Ldstr) continue;
            if (oldValuePusher.Operand as string != "'") continue;

            yield return new QuoteEscapeMatch { CallIlOffset = ins.Offset };
        }
    }

    private static Instruction? PrevSkippingNops(Instruction ins)
    {
        var p = ins.Previous;
        while (p is not null && p.OpCode.Code == Code.Nop) p = p.Previous;
        return p;
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~SanitizerShapesQuoteEscapeTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: PASS (6 cases).

If `EscapeViaLocals` matches instead of being empty, the compiler folded the locals into inline `ldstr`s. Don't weaken the matcher: change the fixture so the locals are genuinely non-constant, e.g. `var from = "'" + string.Empty;`, and re-run.

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs \
        tools/TaintAnalyzer.Tests/SanitizerShapesQuoteEscapeTests.cs
git commit -m "analyzer: MatchSqlQuoteEscapes IL pattern for Replace(\"'\", \"''\")

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Walker untaint and the `sql_quote_escape` hop

**Files:**
- Modify: `tools/TaintAnalyzer/TaintWalker.cs:126-210` (precompute + main loop)
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:364-372` (`SanitizerBoundMatchesSink`)
- Test: `tools/TaintAnalyzer.Tests/QuoteEscapeWalkTests.cs` (create)

**Interfaces:**
- Consumes: `SanitizerShapes.MatchSqlQuoteEscapes` (Task 2), `SinkApi.SqlCommandBuilderAppendRaw` (Task 1).
- Produces: a `HopRecord` with `Role = HopRole.Sanitizer`, `Transformation = "sql_quote_escape"`, `TaintedValueOut = "sql_quote_escaped(<prov>)"`, and both `EstablishesBound` and `OnFailure` null. Tasks 4-6 lock this shape.

- [ ] **Step 1: Write the failing walker tests**

Create `tools/TaintAnalyzer.Tests/QuoteEscapeWalkTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class QuoteEscapeWalkTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == $"TaintAnalyzer.Tests.Fixtures.{typeName}"
                                 && m.Name == methodName);

    [Fact]
    public void RawAppendOfTaintedField_ReachesRawSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFragment", "ApplyRaw"), 0, new[] { "_key" });

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.SqlCommandBuilderAppendRaw);
    }

    [Fact]
    public void QuoteEscapedAppend_EmitsSanitizerHopAndNoSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFragment", "ApplyEscaped"), 0, new[] { "_key" });

        summary.ReachedSink.ShouldBeFalse();

        var sanitizers = summary.Hops.Where(h => h.Role == HopRole.Sanitizer).ToList();
        sanitizers.Count.ShouldBe(1);
        sanitizers[0].Transformation.ShouldBe("sql_quote_escape");
        sanitizers[0].TaintedValueIn.ShouldBe("_key");
        sanitizers[0].TaintedValueOut.ShouldBe("sql_quote_escaped(_key)");
        sanitizers[0].EstablishesBound.ShouldBeNull();
        sanitizers[0].OnFailure.ShouldBeNull();
    }

    [Fact]
    public void UntaintedEscape_EmitsNoSanitizerHop()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // No seed: `s` is untainted, so the Replace result is untainted and nothing is reported.
        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFixtures", "Escape"), 0, Array.Empty<string>());

        summary.Hops.ShouldNotContain(h => h.Role == HopRole.Sanitizer);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~QuoteEscapeWalkTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: `RawAppendOfTaintedField_ReachesRawSink` passes already (Task 1 delivered it); the other two fail — `ReachedSink` is true and no sanitizer hop exists, because the external `Replace` propagates taint.

- [ ] **Step 3: Precompute the escape offsets**

In `tools/TaintAnalyzer/TaintWalker.cs`, in `WalkMethodBody`, directly after the `clampMatchByJoinOffset` assignment (around line 134):

```csharp
        // milestone-Escape: IL offsets of quote-doubling `Replace("'", "''")` calls. The call is
        // stepped as an ordinary external call — which over-approximates and pushes a tainted
        // result — so the untaint is applied AFTER StepInstruction, below.
        var quoteEscapeOffsets = SanitizerShapes.MatchSqlQuoteEscapes(method)
            .Select(q => q.CallIlOffset)
            .ToHashSet();
```

- [ ] **Step 4: Untaint and emit the hop after the step**

In the same method's `foreach (var ins in method.Body.Instructions)` loop, insert this block immediately **after** the `StepInstruction(...)` call and **before** the `ins.OpCode.Code == Code.Ret` check (around line 202):

```csharp
            // Value-transforming sanitizer: the escaped result replaces the tainted one. Runs
            // post-step because StepInstruction pushes the (over-approximated tainted) return of
            // the external String.Replace call.
            if (quoteEscapeOffsets.Contains(ins.Offset)
                && state.Stack.Depth > 0
                && state.Stack.Peek().Tainted)
            {
                var escapedFrom = state.Stack.Pop();
                var escapedProvenance = $"sql_quote_escaped({escapedFrom.Provenance})";
                state.Stack.Push(new StackSlot(false, escapedProvenance));

                var escSp = _context.GetSequencePoint(method, ins);
                hops.Add(new HopRecord
                {
                    Hop = hopCounter++,
                    Method = $"{method.DeclaringType.FullName}.{method.Name}",
                    File = escSp is null ? "" : Path.GetFileName(escSp.Document.Url),
                    Line = escSp?.StartLine ?? 0,
                    Role = HopRole.Sanitizer,
                    TaintedValueIn = escapedFrom.Provenance,
                    Transformation = "sql_quote_escape",
                    TaintedValueOut = escapedProvenance,
                    Dispatch = new ResolvedDispatch
                    {
                        Kind = "direct",
                        StaticType = method.DeclaringType.FullName,
                        ResolvedTargets = Array.Empty<string>(),
                        ClosureBoundary = false,
                    },
                });
            }
```

- [ ] **Step 5: Make bound-less sanitizers match on the value they consumed**

The spec called for "a null guard" in `TraceEmitter.SanitizerBoundMatchesSink`. Reading the code, it is already null-safe — but it returns `true` for a bound-less hop, which would let an escape hop suppress `sanitizer_absence` for an unrelated tainted value in the same method. Match on `TaintedValueIn` instead. In `tools/TaintAnalyzer/TraceEmitter.cs`, replace `SanitizerBoundMatchesSink` (line 364):

```csharp
    private static bool SanitizerBoundMatchesSink(HopRecord sanitizer, HashSet<string> chainTokens)
    {
        if (chainTokens.Count == 0) return true;
        var target = sanitizer.EstablishesBound?.Target;
        // Value-transforming sanitizers (sql_quote_escape) carry no bound. Match on the value
        // they consumed, so they suppress absence only for their own chain.
        if (string.IsNullOrEmpty(target)) target = sanitizer.TaintedValueIn;
        if (string.IsNullOrEmpty(target)) return true;
        var tgtTokens = TokenizeForMatch(target);
        if (tgtTokens.Count == 0) tgtTokens = ShortTokens(target);
        return tgtTokens.Overlaps(chainTokens);
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~QuoteEscapeWalkTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: PASS (3 cases).

- [ ] **Step 7: Run the whole suite and check the fixtures again**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  -- xunit.parallelizeTestCollections=false
git status --short fixtures/
```

Expected: green, no fixture modified. Step 5 touches absence synthesis, which every DoS anchor depends on, so this check is the one that matters most in this task.

- [ ] **Step 8: Commit**

```bash
git add tools/TaintAnalyzer/TaintWalker.cs tools/TaintAnalyzer/TraceEmitter.cs \
        tools/TaintAnalyzer.Tests/QuoteEscapeWalkTests.cs
git commit -m "analyzer: untaint quote-escaped values + sql_quote_escape sanitizer hop

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: ValidateFixture vocabulary and the FX023 exemption

**Files:**
- Modify: `tools/ValidateFixture/Vocabularies.cs`
- Modify: `tools/ValidateFixture/FixtureValidator.cs:109-141`
- Test: `tools/ValidateFixture.Tests/FixtureValidatorTests.cs`

**Interfaces:**
- Consumes: the hop shape from Task 3 (`transformation: sql_quote_escape`, no bound, no failure).
- Produces: `Vocabularies.ValueTransformingSanitizers` (a `FrozenSet<string>`); FX023 no longer fires for those nodes.

- [ ] **Step 1: Write the failing validator tests**

`BuildYaml` at the bottom of `tools/ValidateFixture.Tests/FixtureValidatorTests.cs` emits a single path node with configurable role and transformation, and no `establishes_bound`/`on_failure`. That's exactly the shape needed. Add:

```csharp
    [Fact]
    public void SanitizerNode_QuoteEscapeTransformation_IsExemptFromFX023()
    {
        // Value-transforming sanitizers carry no bound and no failure branch.
        var yaml = BuildYaml(pathRole: "sanitizer", pathTransformation: "sql_quote_escape");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);

        diagnostics.ShouldNotContain(d => d.Code == "FX023");
        diagnostics.ShouldNotContain(d => d.Code == "FX011");
    }

    [Fact]
    public void SanitizerNode_IdentityTransformationWithoutBound_StillReportsFX023()
    {
        // Negative control: the exemption must not blanket-disable FX023 for sanitizers.
        var yaml = BuildYaml(pathRole: "sanitizer", pathTransformation: "identity");
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir: null);

        diagnostics.ShouldContain(d => d.Code == "FX023" && d.Message.Contains("establishes_bound"));
        diagnostics.ShouldContain(d => d.Code == "FX023" && d.Message.Contains("on_failure"));
    }
```

- [ ] **Step 2: Run them to verify they fail**

```bash
dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj \
  --filter "FullyQualifiedName~FixtureValidatorTests.SanitizerNode" \
  -- xunit.parallelizeTestCollections=false
```

Expected: the first test fails (FX023 and FX011 both fire — `sql_quote_escape` is not in the transformation vocabulary and the node has no bound). The second passes already.

- [ ] **Step 3: Extend the vocabularies**

In `tools/ValidateFixture/Vocabularies.cs`, update `Transformations`, `Relations`, `SinkKinds` and `SinkApis`, and add the new set:

```csharp
    public static readonly FrozenSet<string> Transformations = new HashSet<string>(StringComparer.Ordinal)
    {
        "identity", "read_stream", "field_load", "arithmetic",
        "cast", "array_index", "stream_offset", "sql_quote_escape",
    }.ToFrozenSet(StringComparer.Ordinal);

    // Sanitizers that rewrite the value instead of bounding it. They carry no establishes_bound
    // and no on_failure, so FX023's required-field check does not apply to them.
    public static readonly FrozenSet<string> ValueTransformingSanitizers = new HashSet<string>(StringComparer.Ordinal)
    {
        "sql_quote_escape",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> Relations = new HashSet<string>(StringComparer.Ordinal)
    {
        "<", "<=", "==", "!=", ">=", ">", "regex_match",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "allocation", "span_access", "sql_injection",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static readonly FrozenSet<string> SinkApis = new HashSet<string>(StringComparer.Ordinal)
    {
        "new_array", "array_pool_rent", "alloc_hglobal",
        "memory_pool_rent", "stackalloc",
        "span_index", "span_slice",
        "http_content_read", "http_client_read",
        "sql_command_text", "sql_command_builder_append", "sql_command_builder_append_raw",
    }.ToFrozenSet(StringComparer.Ordinal);
```

The `regex_match`, `sql_injection` and `sql_command_*` entries close a pre-existing gap: no SQLi fixture has ever been validatable, because those tokens were missing.

- [ ] **Step 4: Apply the FX023 exemption**

In `tools/ValidateFixture/FixtureValidator.cs`, change the sanitizer branch (line 109) from

```csharp
                if (string.Equals(node.Role, "sanitizer", StringComparison.Ordinal))
```

to

```csharp
                bool valueTransforming = node.Transformation is { } tf
                    && Vocabularies.ValueTransformingSanitizers.Contains(tf);
                if (string.Equals(node.Role, "sanitizer", StringComparison.Ordinal) && !valueTransforming)
```

Leave the body unchanged.

- [ ] **Step 5: Run the validator tests to verify they pass**

```bash
dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj \
  -- xunit.parallelizeTestCollections=false
```

Expected: the whole validator suite is green (63 tests plus the 2 added here).

- [ ] **Step 6: Commit**

```bash
git add tools/ValidateFixture/Vocabularies.cs tools/ValidateFixture/FixtureValidator.cs \
        tools/ValidateFixture.Tests/FixtureValidatorTests.cs
git commit -m "validate-fixture: sql_quote_escape exemption + SQLi vocabulary

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Synthetic prefix/postfix anchors

**Files:**
- Create: `fixtures/sqli-raw-append-prefix/source/RawAppendSqliDemo.cs`, `.../RawAppendSqliDemo.csproj`, `fixtures/sqli-raw-append-prefix/rules.yaml`, `.../trace.yaml`
- Create: `fixtures/sqli-quote-escape-postfix/source/QuoteEscapeSqliDemo.cs`, `.../QuoteEscapeSqliDemo.csproj`, `fixtures/sqli-quote-escape-postfix/rules.yaml`, `.../trace.yaml`
- Create: `scripts/build-sqli-raw-append.sh`, `scripts/build-sqli-quote-escape.sh`
- Test: `tools/TaintAnalyzer.Tests/SqliRawAppendFixtureTests.cs`, `tools/TaintAnalyzer.Tests/SqliQuoteEscapeFixtureTests.cs`

**Interfaces:**
- Consumes: the raw sink api from Task 1, the hop from Task 3.
- Produces: two locked fixture directories. Task 7's regression sweep includes them.

- [ ] **Step 1: Write the prefix fixture source and build script**

`fixtures/sqli-raw-append-prefix/source/RawAppendSqliDemo.cs` — this mirrors Marten's `DictionaryContainsKeyFilter.Apply`:

```csharp
namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void Append(string sql);
    }
}

namespace RawAppendSqliPoc
{
    // Mirrors Marten's DictionaryContainsKeyFilter.Apply (GHSA-rfx3-98h7-v3xp): a
    // attacker-controlled dictionary key is appended raw inside a single-quoted literal.
    public sealed class DictionaryKeyFragment
    {
        private readonly string _key;

        public DictionaryKeyFragment(string key) => _key = key;

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            builder.Append("d.data #> '{");
            builder.Append(_key);
            builder.Append("}' is not null");
        }
    }
}
```

`fixtures/sqli-raw-append-prefix/source/RawAppendSqliDemo.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>RawAppendSqliDemo</AssemblyName>
    <RootNamespace>RawAppendSqliPoc</RootNamespace>
  </PropertyGroup>
</Project>
```

`scripts/build-sqli-raw-append.sh` (mark executable with `chmod +x`):

```bash
#!/usr/bin/env bash
# Builds fixtures/sqli-raw-append-prefix/source/RawAppendSqliDemo.csproj into
# artifacts/sqli-raw-append-prefix/. Mirrors scripts/build-sqli-command-builder.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-raw-append-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-raw-append-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/RawAppendSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-raw-append-prefix built at $OUT_DIR/RawAppendSqliDemo.dll"
```

`fixtures/sqli-raw-append-prefix/rules.yaml`:

```yaml
vuln_id: sqli-raw-append-prefix
source_methods:
  - signature: RawAppendSqliPoc.DictionaryKeyFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _key
```

- [ ] **Step 2: Build it and generate the locked trace**

```bash
chmod +x scripts/build-sqli-raw-append.sh
./scripts/build-sqli-raw-append.sh
dotnet run --project tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release -- \
  artifacts/sqli-raw-append-prefix/RawAppendSqliDemo.dll \
  --rules fixtures/sqli-raw-append-prefix/rules.yaml \
  --output fixtures/sqli-raw-append-prefix/trace.yaml
cat fixtures/sqli-raw-append-prefix/trace.yaml
```

Inspect before committing. The trace must contain `kind: sql_injection`, `api: sql_command_builder_append_raw`, a `field_load` propagator for `_key`, and a populated `sanitizer_absence` (nothing guards the value). If the api says `sql_command_builder_append` instead, Task 1 misfired — stop and fix it there.

- [ ] **Step 3: Write the postfix fixture source, script and rules**

`fixtures/sqli-quote-escape-postfix/source/QuoteEscapeSqliDemo.cs` — identical but for the escape, mirroring Marten 9.13.0:

```csharp
namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void Append(string sql);
    }
}

namespace QuoteEscapeSqliPoc
{
    // The patched shape: the key is quote-doubled before it reaches the builder, which is
    // exactly what Marten 9.13.0 added to DictionaryContainsKeyFilter.Apply.
    public sealed class DictionaryKeyFragment
    {
        private readonly string _key;

        public DictionaryKeyFragment(string key) => _key = key;

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            builder.Append("d.data #> '{");
            builder.Append(_key.Replace("'", "''"));
            builder.Append("}' is not null");
        }
    }
}
```

`fixtures/sqli-quote-escape-postfix/source/QuoteEscapeSqliDemo.csproj`: the same as the prefix csproj with `<AssemblyName>QuoteEscapeSqliDemo</AssemblyName>` and `<RootNamespace>QuoteEscapeSqliPoc</RootNamespace>`.

`scripts/build-sqli-quote-escape.sh`: the same as the prefix script with `sqli-quote-escape-postfix`, `QuoteEscapeSqliDemo.csproj` and `artifacts/sqli-quote-escape-postfix`.

`fixtures/sqli-quote-escape-postfix/rules.yaml`:

```yaml
vuln_id: sqli-quote-escape-postfix
source_methods:
  - signature: QuoteEscapeSqliPoc.DictionaryKeyFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _key
```

- [ ] **Step 4: Build it and generate the locked trace**

```bash
chmod +x scripts/build-sqli-quote-escape.sh
./scripts/build-sqli-quote-escape.sh
dotnet run --project tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release -- \
  artifacts/sqli-quote-escape-postfix/QuoteEscapeSqliDemo.dll \
  --rules fixtures/sqli-quote-escape-postfix/rules.yaml \
  --output fixtures/sqli-quote-escape-postfix/trace.yaml
cat fixtures/sqli-quote-escape-postfix/trace.yaml
```

The trace must contain `transformation: sql_quote_escape` and `sql_quote_escaped(_key)`, must **not** contain `kind: sql_injection` or a `sink:` block, and `sanitizer_absence` must be empty (no `expected_check:`).

- [ ] **Step 5: Write the fixture-runner tests**

Create `tools/TaintAnalyzer.Tests/SqliRawAppendFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliRawAppendFixtureTests
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
    public void SqliRawAppendPrefix_TraceContainsRawSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-raw-append-prefix", "RawAppendSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-raw-append-prefix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-raw-append-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(new[] { dllPath, "--rules", rulesPath, "--output", outPath }, stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_builder_append_raw");
            trace.ShouldContain("RawAppendSqliPoc.DictionaryKeyFragment");
            trace.ShouldContain("expected_check:");   // nothing guards the value
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

Create `tools/TaintAnalyzer.Tests/SqliQuoteEscapeFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliQuoteEscapeFixtureTests
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
    public void SqliQuoteEscapePostfix_TraceContainsEscapeSanitizerNoSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-quote-escape-postfix", "QuoteEscapeSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-quote-escape-postfix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-quote-escape-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(new[] { dllPath, "--rules", rulesPath, "--output", outPath }, stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("transformation: sql_quote_escape");
            trace.ShouldContain("sql_quote_escaped(_key)");
            trace.ShouldContain("QuoteEscapeSqliPoc.DictionaryKeyFragment");
            trace.ShouldNotContain("kind: sql_injection");
            trace.ShouldNotContain("\nsink:");
            trace.ShouldNotContain("expected_check:");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 6: Run both fixture tests**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~SqliRawAppendFixtureTests|FullyQualifiedName~SqliQuoteEscapeFixtureTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: PASS (2 cases).

- [ ] **Step 7: Commit**

```bash
git add fixtures/sqli-raw-append-prefix fixtures/sqli-quote-escape-postfix \
        scripts/build-sqli-raw-append.sh scripts/build-sqli-quote-escape.sh \
        tools/TaintAnalyzer.Tests/SqliRawAppendFixtureTests.cs \
        tools/TaintAnalyzer.Tests/SqliQuoteEscapeFixtureTests.cs
git commit -m "fixture: synthetic raw-append prefix + quote-escape postfix anchors

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Marten 8.37.0 / 9.13.0 real-world anchors and the cold-scan lock

**Files:**
- Create: `scripts/materialize-marten-9.13.sh`
- Create: `fixtures/marten-rfx3-prefix/rules.yaml`, `.../trace.yaml`
- Create: `fixtures/marten-rfx3-postfix/rules.yaml`, `.../trace.yaml`
- Test: `tools/TaintAnalyzer.Tests/MartenRfx3FixtureTests.cs`, `tools/TaintAnalyzer.Tests/ScanMartenRfx3FixtureTests.cs`

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: the milestone's headline result — the same rules file yields a sink on 8.37.0 and a sanitizer-only trace on 9.13.0.

- [ ] **Step 1: Write the 9.13 materialization script**

Create `scripts/materialize-marten-9.13.sh`:

```bash
#!/usr/bin/env bash
# Materializes Marten 9.13.0 from NuGet into artifacts/marten-9.13/.
# 9.13.0 is the first release patched against GHSA-rfx3-98h7-v3xp (CVE-2026-75513).
# Mirrors the structure of scripts/materialize-marten-8.37.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARTEN_VERSION=9.13.0
OUT_DIR="$REPO_ROOT/artifacts/marten-9.13"
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

echo "marten-9.13 materialized at $OUT_DIR (TFM=$TFM)"
sha256sum "$OUT_DIR/Marten.dll"
```

```bash
chmod +x scripts/materialize-marten-9.13.sh
./scripts/materialize-marten-9.13.sh
ls artifacts/marten-9.13
```

`dotnet restore` prints NU1904 for Marten 8.37.0 (it is a known-vulnerable package — that is the point of the fixture). 9.13.0 restores clean.

- [ ] **Step 2: Write both rules files**

`fixtures/marten-rfx3-prefix/rules.yaml`:

```yaml
vuln_id: marten-rfx3-prefix
source_methods:
  - signature: Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _keyText
```

`fixtures/marten-rfx3-postfix/rules.yaml` is identical except `vuln_id: marten-rfx3-postfix`. The `Apply` signature still declares `Weasel.Postgresql.ICommandBuilder` in 9.13.0 — only the call targets inside the body moved to `Weasel.Core` — so the same signature resolves in both assemblies.

- [ ] **Step 3: Generate and inspect the prefix trace**

```bash
dotnet run --project tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release -- \
  artifacts/marten-8.37/Marten.dll \
  --rules fixtures/marten-rfx3-prefix/rules.yaml \
  --no-symbols \
  --output fixtures/marten-rfx3-prefix/trace.yaml
cat fixtures/marten-rfx3-prefix/trace.yaml
```

Expected: a source hop on `DictionaryContainsKeyFilter.Apply`, a `field_load` propagator for `_keyText`, and a sink with `kind: sql_injection` / `api: sql_command_builder_append_raw`.

Drop `--no-symbols` if `artifacts/marten-8.37/.nopdb-marker` does not exist. The NuGet package ships no PDB, so the marker is normally present.

- [ ] **Step 4: Generate and inspect the postfix trace**

```bash
dotnet run --project tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release -- \
  artifacts/marten-9.13/Marten.dll \
  --rules fixtures/marten-rfx3-postfix/rules.yaml \
  --no-symbols \
  --output fixtures/marten-rfx3-postfix/trace.yaml
cat fixtures/marten-rfx3-postfix/trace.yaml
diff -u fixtures/marten-rfx3-prefix/trace.yaml fixtures/marten-rfx3-postfix/trace.yaml || true
```

Expected: source, `field_load`, and a `sql_quote_escape` sanitizer, with no `sink:` block and an empty `sanitizer_absence`. The diff is the milestone's headline artifact.

If the postfix still reports a sink, the escape recognizer didn't fire on the real IL. The expected shape (verified during triage on 9.13.0) is:

```
IL_004d: ldfld  System.String ...DictionaryContainsKeyFilter::_keyText
IL_0052: ldstr  "'"
IL_0057: ldstr  "''"
IL_005c: callvirt System.String System.String::Replace(System.String,System.String)
IL_0061: callvirt System.Void Weasel.Core.ICommandBuilder::Append(System.String)
```

Compare the real IL against that before touching the matcher — a throwaway Cecil dumper (`AssemblyDefinition.ReadAssembly`, then print `method.Body.Instructions`) is the quickest way, and it belongs in the scratchpad, not the repo. Note `Replace` is `callvirt` here, which is why the matcher accepts both `call` and `callvirt`.

- [ ] **Step 5: Write the fixture-runner tests**

Create `tools/TaintAnalyzer.Tests/MartenRfx3FixtureTests.cs`, modelled on `MartenVmw2PostfixFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class MartenRfx3FixtureTests
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

    private static string RunTrace(string artifactDir, string fixtureDir)
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", artifactDir, "Marten.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", fixtureDir, "rules.yaml");
        if (!File.Exists(dllPath)) return "";   // artifact not materialized in fresh checkouts

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", artifactDir, ".nopdb-marker"));
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"{fixtureDir}-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--rules", rulesPath, "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            Program.Run(args.ToArray(), new StringWriter(), stderr).ShouldBe(0, $"stderr: {stderr}");
            return File.ReadAllText(outPath);
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }

    [Fact]
    public void MartenRfx3Prefix_837_ReportsRawAppendSink()
    {
        var trace = RunTrace("marten-8.37", "marten-rfx3-prefix");
        if (trace.Length == 0) return;

        trace.ShouldContain("kind: sql_injection");
        trace.ShouldContain("api: sql_command_builder_append_raw");
        trace.ShouldContain("DictionaryContainsKeyFilter");
        trace.ShouldContain("_keyText");
    }

    [Fact]
    public void MartenRfx3Postfix_913_ReportsEscapeSanitizerNoSink()
    {
        var trace = RunTrace("marten-9.13", "marten-rfx3-postfix");
        if (trace.Length == 0) return;

        trace.ShouldContain("transformation: sql_quote_escape");
        trace.ShouldContain("sql_quote_escaped(_keyText)");
        trace.ShouldContain("DictionaryContainsKeyFilter");
        trace.ShouldNotContain("kind: sql_injection");
        trace.ShouldNotContain("\nsink:");
        trace.ShouldNotContain("expected_check:");
    }
}
```

- [ ] **Step 6: Write the cold-scan lock**

Create `tools/TaintAnalyzer.Tests/ScanMartenRfx3FixtureTests.cs`, modelled on `ScanMartenVmw2FixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ScanMartenRfx3FixtureTests
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

    private static string ColdScan(string artifactDir)
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", artifactDir, "Marten.dll");
        if (!File.Exists(dllPath)) return "";

        var noSymbols = File.Exists(Path.Combine(RepoRoot, "artifacts", artifactDir, ".nopdb-marker"));
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"scan-rfx3-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--scan", "--scan-profile", "sqli", "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            Program.Run(args.ToArray(), new StringWriter(), stderr).ShouldBe(0, $"scan stderr: {stderr}");
            return File.ReadAllText(outPath);
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }

    // Returns the single YAML document whose source method is DictionaryContainsKeyFilter.Apply,
    // or "" when the scan produced none.
    private static string DictionaryFilterDocument(string trace)
        => trace.Split("\n---\n")
                .FirstOrDefault(d => d.Contains("method: Marten.Linq.Members.Dictionaries.DictionaryContainsKeyFilter.Apply")
                                  && d.Contains("role: source"))
           ?? "";

    [Fact]
    public void ScanSqli_837_RediscoversDictionaryContainsKeyFilter_Cold()
    {
        var trace = ColdScan("marten-8.37");
        if (trace.Length == 0) return;

        var doc = DictionaryFilterDocument(trace);
        doc.ShouldNotBeEmpty("cold sqli scan of Marten 8.37 must surface DictionaryContainsKeyFilter.Apply");
        doc.ShouldContain("api: sql_command_builder_append_raw");
        doc.ShouldContain("_keyText");
    }

    [Fact]
    public void ScanSqli_913_DoesNotFlagDictionaryContainsKeyFilter()
    {
        var trace = ColdScan("marten-9.13");
        if (trace.Length == 0) return;

        // The method may still be enumerated (it is sink-reachable), but the quote-escape
        // sanitizer must stop it short of a sink.
        var doc = DictionaryFilterDocument(trace);
        if (doc.Length == 0) return;   // not enumerated at all is also a pass
        doc.ShouldNotContain("kind: sql_injection");
    }
}
```

- [ ] **Step 7: Run both test classes**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj \
  --filter "FullyQualifiedName~MartenRfx3FixtureTests|FullyQualifiedName~ScanMartenRfx3FixtureTests" \
  -- xunit.parallelizeTestCollections=false
```

Expected: PASS (4 cases). The two cold scans walk the whole Marten assembly and take a few minutes each; that matches the existing `ScanMartenVmw2FixtureTests` cost.

- [ ] **Step 8: Commit**

```bash
git add scripts/materialize-marten-9.13.sh fixtures/marten-rfx3-prefix fixtures/marten-rfx3-postfix \
        tools/TaintAnalyzer.Tests/MartenRfx3FixtureTests.cs \
        tools/TaintAnalyzer.Tests/ScanMartenRfx3FixtureTests.cs
git commit -m "fixture: Marten GHSA-rfx3 prefix (8.37.0) / postfix (9.13.0) + cold-scan lock

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: README and the full regression sweep

**Files:**
- Modify: `README.md` (findings table, CWE-89 bullet, supported sink kinds, sanitizer description)
- Test: the full suites, both projects

**Interfaces:**
- Consumes: everything above.
- Produces: the milestone's documented state.

- [ ] **Step 1: Update the README findings table**

Add a row under the existing Marten row:

```markdown
| **Marten** | `DictionaryContainsKeyFilter` LINQ dictionary-key SQL injection (GHSA-rfx3-98h7-v3xp, CVE-2026-75513, ≤ 9.12.0) | CWE-89 |
```

- [ ] **Step 2: Update the sink and sanitizer prose**

In the CWE-89 bullet, change the sink list to name both append forms:

```markdown
- **CWE-89 — SQL injection.** A string value reaches a SQL command sink
  (`DbCommand.CommandText`, a parameterizing command-builder append, or a **raw**
  `ICommandBuilder.Append(string)` that concatenates SQL text verbatim) without passing a
  recognized sanitizer.
```

In the "Supported sink kinds" paragraph, change the `SqlInjection` list to:

```markdown
`SqlInjection` (`sql_command_text`, `sql_command_builder_append`, `sql_command_builder_append_raw`).
```

In the "How it works" step 4, extend the sanitizer sentence:

```markdown
4. **Match** — `SinkShapes` recognizes sink call patterns; `SanitizerShapes` recognizes
   bound checks, regex guards, and value-transforming sanitizers such as quote-doubling
   (`Replace("'", "''")`), which clear taint.
```

- [ ] **Step 3: Run both suites in full**

```bash
dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj -- xunit.parallelizeTestCollections=false
dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj -- xunit.parallelizeTestCollections=false
```

Expected: both green. Record the two test counts; they go in the completion note.

- [ ] **Step 4: Prove the byte-identity invariant**

```bash
git status --short fixtures/
git diff --stat HEAD -- fixtures/
```

Expected: the only fixture paths that appear are the four created in Tasks 5 and 6. If any pre-existing `trace.yaml` shows as modified, stop and report it rather than re-locking it.

- [ ] **Step 5: Show the headline diff**

```bash
diff -u fixtures/marten-rfx3-prefix/trace.yaml fixtures/marten-rfx3-postfix/trace.yaml || true
```

Expected: the sink block with `api: sql_command_builder_append_raw` on the left, and a `transformation: sql_quote_escape` hop with no sink on the right.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: README rows for Marten GHSA-rfx3 + raw append sink and escape sanitizer

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the executor

- **The walker is a linear IL walk**, not a CFG traversal. It visits every instruction in order, including both arms of a branch and the bodies of exception handlers. That's why the untaint in Task 3 is a simple offset check, and it's why the Marten `Apply` method works despite its `try/finally` enumerator block.
- **Under `--scan-profile sqli` every string is a potential source**, so the raw-append sink adds roughly 47 benign trace documents on a cold Marten 8.37 scan (19 → 66). That's expected and recorded in the spec. Only the `DictionaryContainsKeyFilter` document is asserted on.
- **Don't widen the escape recognizer** to make a stubborn case pass. The narrow claim is the design. If real IL needs something else, report it rather than loosening the pattern.
