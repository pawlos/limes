# Milestone-T3: Marten SQLi postfix lock via Regex.IsMatch sanitizer recognizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lock Marten 8.37's fix of GHSA-vmw2-qwm8-x84c by adding a `SanitizerShapes.MatchRegexIsMatchAndThrow` recognizer + a `TraceEmitter` change that emits source+sanitizer traces when no sink is reached. Two locks: synthetic (inline guard in Apply) + real Marten 8.37 (source the ctor).

**Architecture:** Phase 1 adds the recognizer + emitter change + synthetic anchor proving the full `source + sanitizer + sink` shape. Phase 2 materializes Marten 8.37 and sources `FullTextWhereFragment::.ctor` with parameter-bitmask seeding; trace shows source + sanitizer hop, no sink — proves Limes distinguishes vulnerable (T2.1's `marten-vmw2-prefix`) from patched (T3's `marten-vmw2-postfix`) on the same advisory.

**Tech Stack:** .NET 10, Mono.Cecil, xUnit, Shouldly. Spec: `docs/superpowers/specs/2026-05-16-milestone-t3-marten-postfix-design.md`.

**Anchor discipline:** All existing anchors must remain green: `analyzer_gap_backlog.md`'s list + `sqli-synthetic-prefix` (T1) + `sqli-interpolated-prefix` (T2 Phase 1) + `sqli-command-builder-prefix` (T2.1 Phase 1) + `marten-vmw2-prefix` (T2.1 Phase 2). The new recognizer fires only on `Regex::IsMatch` IL; the new emitter behavior only changes outputs when source + sanitizer exist without sink. Neither condition occurs in any prior anchor.

**Worktree note:** Per `[[feedback push spec+plan before worktree]]`, execute in a fresh worktree created from origin/main AFTER the plan commit is pushed. The controller will execute in-controller per `[[feedback prefer controller execution for milestones]]` — no subagent dispatches.

---

## Phase 1 — Sanitizer recognizer + emitter change + synthetic anchor

### Task 1: Add RegexGuardFixtures to test-fixtures

**Files:**
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs` (append at end of file)

- [ ] **Step 1: Append the fixture class**

At the end of `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`, append:

```csharp
public static class RegexGuardFixtures
{
    // Pattern field used by the instance-form tests. Static-readonly so the recognizer's
    // pattern extraction walks the .cctor.
    private static readonly System.Text.RegularExpressions.Regex _staticPattern =
        new(@"^[a-zA-Z_][a-zA-Z0-9_]*$", System.Text.RegularExpressions.RegexOptions.Compiled);

    // Shape 1: instance Regex.IsMatch on a static-readonly field, brfalse → throw.
    public static void GuardInstanceThrow(string s)
    {
        if (!_staticPattern.IsMatch(s))
            throw new System.ArgumentException("invalid", nameof(s));
    }

    // Shape 2: static Regex.IsMatch overload, brfalse → throw. Pattern is inline ldstr.
    public static void GuardStaticThrow(string s)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(s, "^[a-z]+$"))
            throw new System.ArgumentException("invalid", nameof(s));
    }

    // Shape 3: brtrue direction (positive condition throws). Equivalent to `if (IsMatch) throw`.
    public static void GuardInstanceThrowInverted(string s)
    {
        if (_staticPattern.IsMatch(s))
            throw new System.ArgumentException("invalid", nameof(s));
    }

    // Shape 4: no-throw on unsafe path (returns early). Recognizer must NOT match — this is
    // the ReturnEarly variant explicitly out of scope for T3.
    public static void GuardInstanceReturn(string s)
    {
        if (!_staticPattern.IsMatch(s)) return;
    }

    // Shape 5: dynamically-constructed Regex (pattern not extractable). Recognizer should
    // still fire but with null pattern.
    public static void GuardDynamicPatternThrow(string s, string pattern)
    {
        var regex = new System.Text.RegularExpressions.Regex(pattern);
        if (!regex.IsMatch(s))
            throw new System.ArgumentException("invalid", nameof(s));
    }

    // Shape 6: non-Regex bool method call. Recognizer must NOT match.
    public static void GuardNonRegexThrow(string s)
    {
        if (!s.StartsWith("x"))
            throw new System.ArgumentException("invalid", nameof(s));
    }
}
```

- [ ] **Step 2: Build the fixtures project**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj -c Debug --nologo /v:quiet`
Expected: build succeeds, 0 warnings.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs
git commit -m "test-fixtures: RegexGuardFixtures for MatchRegexIsMatchAndThrow tests"
```

---

### Task 2: Failing test — instance Regex on static field

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` (append before class closing brace)

- [ ] **Step 1: Append the failing test**

Open `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs`. Locate the class closing brace (the last `}` before EOF). Append BEFORE that brace:

```csharp
    [Fact]
    public void MatchRegexIsMatchAndThrow_InstanceRegexOnStaticField_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardInstanceThrow(System.String)");

        var match = SinkShapes_Regex_Helper(m);  // see note below

        match.ShouldNotBeNull();
        match!.EstablishesBound.Relation.ShouldBe("regex_match");
        match.EstablishesBound.UpperBound.ShouldBe("^[a-zA-Z_][a-zA-Z0-9_]*$");
        match.EstablishesBound.Target.ShouldBe("s");
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }

    // Shared helper for the regex-matcher tests: returns the single Regex match in `m`, or null.
    private static SanitizerMatch? SinkShapes_Regex_Helper(Mono.Cecil.MethodDefinition m)
        => SanitizerShapes.MatchRegexIsMatchAndThrow(m).FirstOrDefault();
```

**Note:** The helper `SinkShapes_Regex_Helper` (a per-class shortcut for the matcher call) is defined inside this test class for terseness in the next 5 tests. The name avoids collision with the production `SinkShapes` class.

- [ ] **Step 2: Run and verify it fails (build-error red state)**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchRegexIsMatchAndThrow_InstanceRegexOnStaticField" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: build FAILS with `CS0117: 'SanitizerShapes' does not contain a definition for 'MatchRegexIsMatchAndThrow'`.

**Do NOT commit** — Task 3 commits test + implementation together.

---

### Task 3: Implement MatchRegexIsMatchAndThrow

**Files:**
- Modify: `tools/TaintAnalyzer/SanitizerShapes.cs` (append before class closing brace, after `TrySafeResolve` at line 1394)

- [ ] **Step 1: Add the matcher + helpers**

Locate the class closing brace of `SanitizerShapes` (the final `}` at line 1399). Append immediately before that brace:

```csharp
    // T3 sanitizer: <load tainted>; call/callvirt Regex::IsMatch; brfalse/brtrue → throw.
    // Recognizes both the instance overload (bool IsMatch(string)) and the static overload
    // (bool IsMatch(string, string)). Pattern is extracted best-effort: static overload from
    // inline ldstr; instance overload from the static-readonly field's .cctor or from
    // instance ctors. If extraction fails the match still fires with UpperBound = null.
    public static IEnumerable<SanitizerMatch> MatchRegexIsMatchAndThrow(MethodDefinition method)
    {
        if (method.Body is null) yield break;

        foreach (var ins in method.Body.Instructions)
        {
            if (ins.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
            var code = ins.OpCode.Code;
            if (code != Code.Brfalse && code != Code.Brfalse_S
                && code != Code.Brtrue && code != Code.Brtrue_S) continue;

            // The instruction immediately preceding the branch (skipping nops) must be a
            // call/callvirt to Regex::IsMatch.
            var prev = ins.Previous;
            while (prev is not null && prev.OpCode.Code == Code.Nop) prev = prev.Previous;
            if (prev is null) continue;
            if (prev.OpCode.Code != Code.Call && prev.OpCode.Code != Code.Callvirt) continue;
            if (prev.Operand is not MethodReference mr) continue;
            if (mr.DeclaringType.FullName != "System.Text.RegularExpressions.Regex") continue;
            if (mr.Name != "IsMatch") continue;

            // Determine throw direction via existing DetectBranchSides helper.
            var sides = DetectBranchSides(ins, method);
            if (sides is null) continue;
            if (sides.FailureKind != FailureKind.Throw) continue;  // T3 ships throw only.

            // Resolve target (the tainted-arg name) and pattern (best-effort).
            string target = ResolveIsMatchTargetName(prev, method) ?? "input";
            string? pattern = TryExtractRegexPattern(prev, method);

            yield return new SanitizerMatch
            {
                EstablishesBound = new EstablishesBound
                {
                    Target = target,
                    Relation = "regex_match",
                    UpperBound = pattern,
                    LowerBound = null,
                    VacuousUpperBound = false,
                },
                OnFailure = new OnFailure
                {
                    Kind = FailureKind.Throw,
                    Exception = sides.ThrowHelper is null
                        ? null
                        : ResolveExceptionType(SafeResolve(sides.ThrowHelper) ?? sides.ThrowHelper.Resolve()),
                },
                ComparisonIlOffset = prev.Offset,
            };
        }
    }

    // The tainted-value arg for IsMatch is the FIRST parameter (instance: only param;
    // static: input is param 0, pattern is param 1). Walk back across the call's arg-pushers
    // using net stack-balance to find the input pusher; read its provenance name.
    private static string? ResolveIsMatchTargetName(Instruction callIns, MethodDefinition method)
    {
        if (callIns.Operand is not MethodReference mr) return null;
        int totalPushers = mr.Parameters.Count + (mr.HasThis ? 1 : 0);
        if (totalPushers == 0) return null;

        // Walk back to the call's bottom pusher (receiver for instance, or input for static).
        // Then advance forward one slot for instance (receiver → first arg). For static, the
        // bottom pusher IS the input.
        var cur = callIns.Previous;
        int balance = 0;
        Instruction? bottomPusher = null;
        while (cur is not null)
        {
            if (cur.OpCode.Code == Code.Nop) { cur = cur.Previous; continue; }
            balance += StackEffectPushes(cur) - StackEffectPops(cur);
            if (balance >= totalPushers) { bottomPusher = cur; break; }
            cur = cur.Previous;
        }
        if (bottomPusher is null) return null;

        if (!mr.HasThis)
        {
            // Static overload: bottom pusher IS the input arg.
            return OperandName(bottomPusher, method);
        }
        // Instance overload: bottom pusher is the Regex receiver. The input pusher is the
        // next pusher whose net stack contribution is +1 (single push). For simple shapes
        // (1 param) that's just the next instruction after bottomPusher that pushes.
        var p = bottomPusher.Next;
        while (p is not null && p != callIns)
        {
            if (p.OpCode.Code != Code.Nop && StackEffectPushes(p) > 0)
                return OperandName(p, method);
            p = p.Next;
        }
        return null;
    }

    // Best-effort regex-pattern extraction. Returns null on any failure path.
    private static string? TryExtractRegexPattern(Instruction callIns, MethodDefinition method)
    {
        try
        {
            if (callIns.Operand is not MethodReference mr) return null;

            if (!mr.HasThis)
            {
                // Static overload: pattern is param 1 (the second arg). Walk back from the call
                // and find the second-from-bottom pusher. Easiest: the call has 2 params, no
                // receiver; the second arg's pusher is the LAST single-push before the call.
                // Backtrack one full arg from the call.
                var cur = callIns.Previous;
                while (cur is not null && cur.OpCode.Code == Code.Nop) cur = cur.Previous;
                if (cur is null) return null;
                if (cur.OpCode.Code == Code.Ldstr && cur.Operand is string s) return s;
                return null;
            }

            // Instance overload: walk back to find the Regex receiver-pusher (handled by
            // ResolveIsMatchTargetName's logic). Identify the field reference.
            int totalPushers = mr.Parameters.Count + (mr.HasThis ? 1 : 0);
            var cw = callIns.Previous;
            int balance = 0;
            Instruction? receiverPusher = null;
            while (cw is not null)
            {
                if (cw.OpCode.Code == Code.Nop) { cw = cw.Previous; continue; }
                balance += StackEffectPushes(cw) - StackEffectPops(cw);
                if (balance >= totalPushers) { receiverPusher = cw; break; }
                cw = cw.Previous;
            }
            if (receiverPusher is null) return null;

            FieldReference? regexFieldRef = null;
            bool isStaticField = false;
            if (receiverPusher.OpCode.Code == Code.Ldsfld && receiverPusher.Operand is FieldReference sf)
            {
                regexFieldRef = sf; isStaticField = true;
            }
            else if (receiverPusher.OpCode.Code == Code.Ldfld && receiverPusher.Operand is FieldReference ff)
            {
                regexFieldRef = ff; isStaticField = false;
            }
            else return null;

            FieldDefinition? regexField;
            try { regexField = regexFieldRef.Resolve(); }
            catch (AssemblyResolutionException) { return null; }
            if (regexField is null) return null;

            var ctorsToScan = isStaticField
                ? regexField.DeclaringType.Methods.Where(m => m.IsConstructor && m.IsStatic)
                : regexField.DeclaringType.Methods.Where(m => m.IsConstructor && !m.IsStatic);

            foreach (var ctor in ctorsToScan)
            {
                if (ctor.Body is null) continue;
                foreach (var bi in ctor.Body.Instructions)
                {
                    bool isStoreToField =
                        (bi.OpCode.Code == Code.Stsfld || bi.OpCode.Code == Code.Stfld)
                        && bi.Operand is FieldReference fr2
                        && fr2.FullName == regexFieldRef.FullName;
                    if (!isStoreToField) continue;

                    // Walk back from this store: find the newobj Regex::.ctor and the ldstr
                    // immediately before it (its first arg).
                    var b = bi.Previous;
                    Instruction? newobj = null;
                    while (b is not null)
                    {
                        if (b.OpCode.Code == Code.Newobj
                            && b.Operand is MethodReference cr
                            && cr.DeclaringType.FullName == "System.Text.RegularExpressions.Regex")
                        {
                            newobj = b; break;
                        }
                        b = b.Previous;
                    }
                    if (newobj is null) continue;

                    // Walk back from newobj across its arg-pushers; the first arg (param 0,
                    // the pattern) is at the bottom of the call's stack window.
                    if (newobj.Operand is not MethodReference newobjMr) continue;
                    int newobjPushers = newobjMr.Parameters.Count;  // newobj has no receiver in stack walk
                    var c = newobj.Previous;
                    int bal = 0;
                    Instruction? patternPusher = null;
                    while (c is not null)
                    {
                        if (c.OpCode.Code == Code.Nop) { c = c.Previous; continue; }
                        bal += StackEffectPushes(c) - StackEffectPops(c);
                        if (bal >= newobjPushers) { patternPusher = c; break; }
                        c = c.Previous;
                    }
                    if (patternPusher is null) continue;
                    if (patternPusher.OpCode.Code == Code.Ldstr && patternPusher.Operand is string lit)
                        return lit;
                }
            }
            return null;
        }
        catch (AssemblyResolutionException)
        {
            return null;
        }
    }

    private static int StackEffectPushes(Instruction ins)
    {
        if (ins.Operand is MethodReference mr2 &&
            (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt
             || ins.OpCode.Code == Code.Calli || ins.OpCode.Code == Code.Newobj))
        {
            if (ins.OpCode.Code == Code.Newobj) return 1;
            return mr2.ReturnType.FullName == "System.Void" ? 0 : 1;
        }
        return ins.OpCode.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 => 1,
            StackBehaviour.Push1_push1 => 2,
            StackBehaviour.Pushi => 1,
            StackBehaviour.Pushi8 => 1,
            StackBehaviour.Pushr4 => 1,
            StackBehaviour.Pushr8 => 1,
            StackBehaviour.Pushref => 1,
            _ => 0,
        };
    }

    private static int StackEffectPops(Instruction ins)
    {
        if (ins.Operand is MethodReference mr3 &&
            (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt
             || ins.OpCode.Code == Code.Calli || ins.OpCode.Code == Code.Newobj))
        {
            int pops = mr3.Parameters.Count;
            if (mr3.HasThis && ins.OpCode.Code != Code.Newobj) pops += 1;
            if (ins.OpCode.Code == Code.Calli) pops += 1;
            return pops;
        }
        return ins.OpCode.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 => 1,
            StackBehaviour.Popi => 1,
            StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 => 2,
            StackBehaviour.Popi_popi => 2,
            StackBehaviour.Popi_pop1 => 2,
            StackBehaviour.Popi_popi8 => 2,
            StackBehaviour.Popref_pop1 => 2,
            StackBehaviour.Popref_popi => 2,
            StackBehaviour.Popi_popi_popi => 3,
            StackBehaviour.Popref_popi_popi => 3,
            StackBehaviour.Popref_popi_popi8 => 3,
            StackBehaviour.Popref_popi_popr4 => 3,
            StackBehaviour.Popref_popi_popr8 => 3,
            StackBehaviour.Popref_popi_popref => 3,
            _ => 0,
        };
    }
```

**Note on `OperandName`:** The existing `SanitizerShapes` already has `internal static string? OperandName(Instruction ins, MethodDefinition method)` at line 597. Use it as-is.

- [ ] **Step 2: Run Task 2's test; verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchRegexIsMatchAndThrow_InstanceRegexOnStaticField" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test).

- [ ] **Step 3: Run all SanitizerShapesTests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SanitizerShapesTests" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: all prior tests + new one = all pass.

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs
git commit -m "analyzer: SanitizerShapes.MatchRegexIsMatchAndThrow for Regex::IsMatch + throw shapes"
```

---

### Task 4: Five guard-case tests (static, brtrue, no-throw, dynamic, non-Regex)

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs` (append tests before class closing brace)

- [ ] **Step 1: Append all five tests**

```csharp
    [Fact]
    public void MatchRegexIsMatchAndThrow_StaticOverload_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardStaticThrow(System.String)");

        var match = SinkShapes_Regex_Helper(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.Relation.ShouldBe("regex_match");
        match.EstablishesBound.UpperBound.ShouldBe("^[a-z]+$");
        match.EstablishesBound.Target.ShouldBe("s");
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void MatchRegexIsMatchAndThrow_BranchInverted_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardInstanceThrowInverted(System.String)");

        var match = SinkShapes_Regex_Helper(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.Relation.ShouldBe("regex_match");
        match.EstablishesBound.UpperBound.ShouldBe("^[a-zA-Z_][a-zA-Z0-9_]*$");
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void MatchRegexIsMatchAndThrow_NoThrowOnUnsafePath_ReturnsEmpty()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardInstanceReturn(System.String)");

        // Method falls back to early-return on unsafe path. T3 ships throw only — must not match.
        SinkShapes_Regex_Helper(m).ShouldBeNull();
    }

    [Fact]
    public void MatchRegexIsMatchAndThrow_PatternUnresolvable_ReturnsMatchWithNullPattern()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardDynamicPatternThrow(System.String,System.String)");

        var match = SinkShapes_Regex_Helper(m);

        match.ShouldNotBeNull();
        match!.EstablishesBound.Relation.ShouldBe("regex_match");
        match.EstablishesBound.UpperBound.ShouldBeNull();
        match.OnFailure.Kind.ShouldBe(FailureKind.Throw);
    }

    [Fact]
    public void MatchRegexIsMatchAndThrow_NonRegexBoolCall_ReturnsEmpty()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.RegexGuardFixtures::GuardNonRegexThrow(System.String)");

        // Method calls String::StartsWith, not Regex::IsMatch — recognizer must require Regex.
        SinkShapes_Regex_Helper(m).ShouldBeNull();
    }
```

- [ ] **Step 2: Run all five tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MatchRegexIsMatchAndThrow" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 6 pass (Task 2's test + the 5 new ones).

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SanitizerShapesTests.cs
git commit -m "test: MatchRegexIsMatchAndThrow guard cases (static, brtrue, return-early, dynamic, non-Regex)"
```

---

### Task 5: Wire MatchRegexIsMatchAndThrow into MatchAll

**Files:**
- Modify: `tools/TaintAnalyzer/SanitizerShapes.cs:271-281` (the `MatchAll` method body)

- [ ] **Step 1: Concat the new matcher's results into MatchAll**

Locate `MatchAll` at line 271. Replace its body:

```csharp
    public static IEnumerable<SanitizerMatch> MatchAll(MethodDefinition method)
    {
        // Yield matches across both failure-kinds, ordered by IL offset (already true since
        // each kind iterates the same body in order; we merge by offset to interleave both kinds
        // if a method had a mix).
        var matches = new List<SanitizerMatch>();
        matches.AddRange(MatchAllOfKind(method, FailureKind.Throw));
        matches.AddRange(MatchAllOfKind(method, FailureKind.ReturnEarly));
        matches.Sort((a, b) => a.ComparisonIlOffset.CompareTo(b.ComparisonIlOffset));
        return matches;
    }
```

with:

```csharp
    public static IEnumerable<SanitizerMatch> MatchAll(MethodDefinition method)
    {
        // Yield matches across both failure-kinds and the regex-validator matcher, ordered by
        // IL offset so a method with multiple sanitizer shapes interleaves them correctly.
        var matches = new List<SanitizerMatch>();
        matches.AddRange(MatchAllOfKind(method, FailureKind.Throw));
        matches.AddRange(MatchAllOfKind(method, FailureKind.ReturnEarly));
        matches.AddRange(MatchRegexIsMatchAndThrow(method));
        matches.Sort((a, b) => a.ComparisonIlOffset.CompareTo(b.ComparisonIlOffset));
        return matches;
    }
```

- [ ] **Step 2: Run all TaintAnalyzer.Tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: all tests pass (289 baseline + 6 new from Tasks 2,4 = 295). All prior sanitizer-related tests still green.

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer/SanitizerShapes.cs
git commit -m "analyzer: SanitizerShapes.MatchAll aggregates MatchRegexIsMatchAndThrow"
```

---

### Task 6: TraceEmitter emits source+sanitizer-only traces

**Files:**
- Modify: `tools/TaintAnalyzer/TraceEmitter.cs:43-48` + per-source emit body

- [ ] **Step 1: Update the no-sink early-return**

Locate TraceEmitter.cs:43-48:

```csharp
        if (rawSinkIndices.Count == 0)
        {
            // No sinks reached — emit empty output. Caller (Program.cs) writes nothing to stdout
            // / output file, indicating "analyzer found no tainted sink for these rules".
            return "";
        }
```

Replace with:

```csharp
        int rawSanitizerCount = hops.Count(h => h.Role == HopRole.Sanitizer);
        if (rawSinkIndices.Count == 0 && rawSanitizerCount == 0)
        {
            // No sinks AND no sanitizers — emit empty output. "Analyzer found no SQLi finding
            // for these rules" (clean and silent, distinct from "patched and detected").
            return "";
        }
```

- [ ] **Step 2: Add the source+sanitizer-only emit path**

Locate the `for (int s = 0; s < sinkIndices.Count; s++)` sink-iteration loop at line 83. AFTER that loop (i.e., after the closing brace of the for-loop body and before `return sb.ToString();`), append a new loop that handles the source+sanitizer-only case:

```csharp
        // T3 — emit a sanitizer-only document for each source that has at least one sanitizer
        // hop after it but no sink hop. This represents "Limes detected the fix" — the regex
        // (or other throw-shape) guard was recognized, and the walked source method does not
        // reach a sink. The document omits `sink:` and has empty `sanitizer_absence:`.
        for (int si = 0; si < sourceIndices.Count; si++)
        {
            int sourceIdx = sourceIndices[si];
            int nextSourceIdx = si + 1 < sourceIndices.Count ? sourceIndices[si + 1] : hops.Count;

            // Range of hops belonging to this source: (sourceIdx, nextSourceIdx).
            bool hasSinkForThisSource = sinkIndices.Any(idx => idx > sourceIdx && idx < nextSourceIdx);
            if (hasSinkForThisSource) continue;  // already emitted by the sink loop above

            var sanitizerHops = new List<HopRecord>();
            for (int i = sourceIdx + 1; i < nextSourceIdx; i++)
            {
                if (hops[i].Role is HopRole.Propagator or HopRole.Sanitizer)
                    sanitizerHops.Add(hops[i]);
            }
            if (!sanitizerHops.Any(h => h.Role == HopRole.Sanitizer)) continue;  // no sanitizer → silent

            var collapsed = CollapseAdjacentRedundantHops(sanitizerHops);
            var pathNodes = new List<PathNode>(collapsed.Count);
            for (int i = 0; i < collapsed.Count; i++)
            {
                pathNodes.Add(PathNodeFromHop(collapsed[i] with { Hop = i }));
            }

            var doc = new FixtureDocument
            {
                VulnId = rules.VulnId,
                Source = PathNodeFromHop(hops[sourceIdx]),
                Sink = null,
                Path = pathNodes,
                SanitizerAbsence = new List<SanitizerAbsence>(),
            };

            if (sb.Length > 0) sb.Append("---\n");
            sb.Append(s_serializer.Serialize(doc));
        }
```

- [ ] **Step 3: Build and run full TaintAnalyzer.Tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: all tests pass (still 295). Existing fixture anchors still pass.

- [ ] **Step 4: Commit**

```bash
git add tools/TaintAnalyzer/TraceEmitter.cs
git commit -m "analyzer: TraceEmitter emits source+sanitizer documents when no sink is reached"
```

---

### Task 7: TraceEmitter unit tests

**Files:**
- Modify: `tools/TaintAnalyzer.Tests/TraceEmitterTests.cs` (append before class closing brace)

- [ ] **Step 1: Inspect file for existing helpers**

```bash
grep -n "private static\|class TraceEmitterTests\|using " tools/TaintAnalyzer.Tests/TraceEmitterTests.cs | head -10
```

Note the existing helpers (e.g., a `MakeHop(...)` builder or similar) and the `RulesDocument` shape used. If there's a `MakeSourceHop` / `MakeSinkHop` / `MakeSanitizerHop` helper, reuse it. If not, build minimal `HopRecord` instances inline.

- [ ] **Step 2: Append two new tests**

Append BEFORE the class closing brace:

```csharp
    [Fact]
    public void Emit_SourceAndSanitizerNoSink_EmitsTrace()
    {
        var rules = new RulesDocument { VulnId = "test-sanitizer-only", SourceMethods = new List<SourceMethodEntry>() };
        var source = new HopRecord
        {
            Hop = 0, Method = "TestNamespace.TestClass.Source", File = "Test.cs", Line = 10,
            Role = HopRole.Source, TaintedValueIn = "arg", Transformation = "read_stream", TaintedValueOut = "arg",
        };
        var sanitizer = new HopRecord
        {
            Hop = 1, Method = "TestNamespace.TestClass.Source", File = "Test.cs", Line = 12,
            Role = HopRole.Sanitizer, TaintedValueIn = "arg", Transformation = "identity", TaintedValueOut = "arg",
            EstablishesBound = new EstablishesBound { Target = "arg", Relation = "regex_match", UpperBound = "^x$" },
            OnFailure = new OnFailure { Kind = FailureKind.Throw, Exception = "System.ArgumentException" },
        };
        var hops = new List<HopRecord> { source, sanitizer };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldNotBeNullOrEmpty();
        yaml.ShouldContain("role: sanitizer");
        yaml.ShouldContain("source:");
        yaml.ShouldNotContain("sink:");
    }

    [Fact]
    public void Emit_SourceOnlyNoSanitizerNoSink_EmitsEmpty()
    {
        var rules = new RulesDocument { VulnId = "test-source-only", SourceMethods = new List<SourceMethodEntry>() };
        var source = new HopRecord
        {
            Hop = 0, Method = "T.S", File = "T.cs", Line = 1,
            Role = HopRole.Source, TaintedValueIn = "arg", Transformation = "read_stream", TaintedValueOut = "arg",
        };
        var hops = new List<HopRecord> { source };

        var yaml = TraceEmitter.Emit(rules, hops, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldBeEmpty();
    }
```

If the existing `TraceEmitterTests.cs` uses a different `RulesDocument` constructor shape (e.g., positional constructor instead of init-only properties), adapt the test code to match. The MakeHop fields shown here cover all required `HopRecord` properties; if `HopRecord` has additional required fields (e.g., `Note` or `ResolvedVia` if added later), set them to `null` explicitly.

- [ ] **Step 3: Run the new tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~Emit_SourceAndSanitizerNoSink|FullyQualifiedName~Emit_SourceOnlyNoSanitizerNoSink" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 2 pass.

- [ ] **Step 4: Run all TaintAnalyzer.Tests**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: all pass (297 = 289 + 6 sanitizer + 2 emitter).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer.Tests/TraceEmitterTests.cs
git commit -m "test: TraceEmitter emits sanitizer-only doc when no sink; empty when source-only"
```

---

### Task 8: Synthetic source project + build script

**Files:**
- Create: `fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.cs`
- Create: `fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.csproj`
- Create: `scripts/build-sqli-regex-guard.sh`

- [ ] **Step 1: Create the directories**

```bash
mkdir -p fixtures/sqli-regex-guard-prefix/source
mkdir -p artifacts/sqli-regex-guard-prefix
```

- [ ] **Step 2: Create the source file**

Write `fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.cs`:

```csharp
namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void AppendWithParameters(string sql);
    }
}

namespace RegexGuardSqliPoc
{
    public sealed class GuardedSearchFragment
    {
        private static readonly System.Text.RegularExpressions.Regex _pattern =
            new(@"^[a-zA-Z_][a-zA-Z0-9_]*$",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        private readonly string _regConfig;
        public GuardedSearchFragment(string regConfig) => _regConfig = regConfig;

        private string Sql => $"a{_regConfig}b{_regConfig}c";

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            // Inline regex guard before the sink. The T3 recognizer fires here.
            if (!_pattern.IsMatch(_regConfig))
                throw new System.ArgumentException("invalid regConfig", nameof(_regConfig));
            builder.AppendWithParameters(this.Sql);
        }
    }
}
```

- [ ] **Step 3: Create the csproj**

Write `fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>RegexGuardSqliDemo</AssemblyName>
    <RootNamespace>RegexGuardSqliPoc</RootNamespace>
  </PropertyGroup>
</Project>
```

- [ ] **Step 4: Create the build script**

Write `scripts/build-sqli-regex-guard.sh`:

```bash
#!/usr/bin/env bash
# Builds fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.csproj into
# artifacts/sqli-regex-guard-prefix/. Mirrors scripts/build-sqli-command-builder.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-regex-guard-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-regex-guard-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/RegexGuardSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-regex-guard-prefix built at $OUT_DIR/RegexGuardSqliDemo.dll"
```

- [ ] **Step 5: Build the artifact**

```bash
chmod +x scripts/build-sqli-regex-guard.sh
scripts/build-sqli-regex-guard.sh
ls -la artifacts/sqli-regex-guard-prefix/RegexGuardSqliDemo.dll
```

Expected: DLL appears.

- [ ] **Step 6: Commit**

```bash
git add fixtures/sqli-regex-guard-prefix/source/ scripts/build-sqli-regex-guard.sh
git commit -m "fixture: sqli-regex-guard-prefix source project + build script"
```

---

### Task 9: Generate rules.yaml and lock trace.yaml for synthetic

**Files:**
- Create: `fixtures/sqli-regex-guard-prefix/rules.yaml`
- Create: `fixtures/sqli-regex-guard-prefix/trace.yaml`

- [ ] **Step 1: Create rules.yaml**

Write `fixtures/sqli-regex-guard-prefix/rules.yaml`:

```yaml
vuln_id: sqli-regex-guard-prefix
source_methods:
  - signature: RegexGuardSqliPoc.GuardedSearchFragment::Apply(Weasel.Postgresql.ICommandBuilder)
    seed_this_fields:
      - _regConfig
```

- [ ] **Step 2: Build analyzer in Release**

Run: `dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release --nologo /v:quiet`
Expected: success.

- [ ] **Step 3: Run analyzer; capture trace**

```bash
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/sqli-regex-guard-prefix/RegexGuardSqliDemo.dll \
    --rules fixtures/sqli-regex-guard-prefix/rules.yaml \
    --output fixtures/sqli-regex-guard-prefix/trace.yaml
echo "EXIT=$?"
cat fixtures/sqli-regex-guard-prefix/trace.yaml
```

Expected: exit 0, non-empty trace containing:
- `source:` block with `GuardedSearchFragment.Apply`.
- `path:` with a `role: sanitizer` hop where `relation: regex_match` and `upper_bound: '^[a-zA-Z_][a-zA-Z0-9_]*$'`.
- `path:` with propagator hops (call to get_Sql, field_load).
- `sink:` block with `kind: sql_injection`, `api: sql_command_builder_append`.
- `sanitizer_absence: []` (empty list — sanitizer suppresses absence).

**If trace is empty:** debug paths:
1. Verify the recognizer fires on Apply's IL — temporarily uncomment a `Console.Error.WriteLine` after the Regex IsMatch detection in `MatchRegexIsMatchAndThrow` to log entry. Remove before commit.
2. Confirm `seed_this_fields` seeds `_regConfig` (T2.1's existing fixture exercises this path, so the mechanism is known to work).
3. Confirm the sink still fires (it should — sanitizer hop doesn't suppress sink emission, just `sanitizer_absence`).

**If `sanitizer_absence:` is non-empty (the regex sanitizer didn't suppress it):** check that `ThrowShapeSanitisesATaintedParam` recognizes the new match — search `TaintWalker.cs` for that helper. The throw-shape sanitizer mechanism is gated on `OnFailure.Kind == Throw`; our match satisfies that. If suppression still doesn't happen, the issue is in the in-method sanitizer-on-path matching logic in `TraceEmitter`'s `hasSanitizer` check (`SanitizerBoundMatchesSink`). Our match's `Target == "_regConfig"` (resolved by `OperandName` walking the field load) — verify this matches against the sink's value-chain tokens.

- [ ] **Step 4: Add description block**

Edit `fixtures/sqli-regex-guard-prefix/trace.yaml`. After the `vuln_id:` line, add:

```yaml
fix_commit: ""
fix_pr: ""
description: >
  Synthetic regression fixture for milestone-T3 Phase 1: tainted this-field flowing
  through a regex-guarded $"..." interpolation into Weasel.Postgresql.ICommandBuilder
  ::AppendWithParameters. GuardedSearchFragment.Apply has an inline
  `if (!_pattern.IsMatch(_regConfig)) throw` before the sink-reaching code.
  The T3 sanitizer recognizer (MatchRegexIsMatchAndThrow) fires on this IL
  shape, emits a sanitizer hop with relation: regex_match, and suppresses
  `sanitizer_absence` via the existing throw-shape mechanism. Sink still fires
  (the IL still reaches AppendWithParameters), but the trace shows the
  sanitizer protection. Compare to fixtures/sqli-command-builder-prefix
  (T2.1 — same shape MINUS the guard, fires sanitizer_absence). Locked at
  milestone-T3 Phase 1; do not regenerate without re-locking.
```

- [ ] **Step 5: Run schema validator**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 63 pass.

- [ ] **Step 6: Commit**

```bash
git add fixtures/sqli-regex-guard-prefix/rules.yaml fixtures/sqli-regex-guard-prefix/trace.yaml
git commit -m "fixture: sqli-regex-guard-prefix rules + locked trace.yaml"
```

---

### Task 10: End-to-end synthetic fixture test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/SqliRegexGuardFixtureTests.cs`

- [ ] **Step 1: Write the test**

Write `tools/TaintAnalyzer.Tests/SqliRegexGuardFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class SqliRegexGuardFixtureTests
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
    public void SqliRegexGuardPrefix_TraceContainsSanitizerAndSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "sqli-regex-guard-prefix", "RegexGuardSqliDemo.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "sqli-regex-guard-prefix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // artifact not materialized in fresh checkouts

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"sqli-regex-{Guid.NewGuid()}.yaml");
        try
        {
            var rc = Program.Run(
                new[] { dllPath, "--rules", rulesPath, "--output", outPath },
                stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("relation: regex_match");
            trace.ShouldContain("kind: sql_injection");
            trace.ShouldContain("api: sql_command_builder_append");
            trace.ShouldContain("RegexGuardSqliPoc.GuardedSearchFragment");
            // The sanitizer suppresses sanitizer_absence — should be the empty form.
            trace.ShouldNotContain("expected_check:");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 2: Run and verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~SqliRegexGuardFixtureTests" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: PASS (1 test).

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/SqliRegexGuardFixtureTests.cs
git commit -m "test: end-to-end fixture run for sqli-regex-guard-prefix"
```

---

## Phase 1 checkpoint

Expected state after Task 10:
- Test count: 289 → 298 (6 sanitizer unit + 2 emitter + 1 e2e). 63 ValidateFixture.Tests unchanged. Total **361**.
- Anchors: all existing + new `sqli-regex-guard-prefix` green.
- Recognizer + emitter change ready for real Marten lock.

If anything's off, stop and investigate before Phase 2.

---

## Phase 2 — Marten 8.37 real-world lock

### Task 11: materialize-marten-8.37 script

**Files:**
- Create: `scripts/materialize-marten-8.37.sh`

- [ ] **Step 1: Inspect the 8.36 script for the pattern**

```bash
cat scripts/materialize-marten-8.36.sh
```

Read it carefully — the new script is a mechanical copy with the version bumped.

- [ ] **Step 2: Create the 8.37 script**

Write `scripts/materialize-marten-8.37.sh` — mirror `scripts/materialize-marten-8.36.sh` but substitute every literal `8.36` / `8.36.0` with `8.37` / `8.37.0` and every `marten-8.36` with `marten-8.37`. Don't change the TFM fallback logic, the .nopdb-marker behavior, or any other functional element.

- [ ] **Step 3: Make executable and materialize**

```bash
chmod +x scripts/materialize-marten-8.37.sh
scripts/materialize-marten-8.37.sh
ls -la artifacts/marten-8.37/
```

Expected: `Marten.dll` + (likely) `.nopdb-marker` appear. NuGet should print a vulnerability warning during restore IF 8.37 is still flagged at the GHSA level — that's informational, not a failure. The 8.37 release should clear the advisory; if NuGet still warns, the GHSA entry hasn't been updated and the script proceeds anyway.

- [ ] **Step 4: Commit**

```bash
git add scripts/materialize-marten-8.37.sh
git commit -m "script: materialize Marten 8.37.0 from NuGet into artifacts/"
```

---

### Task 12: Marten rules.yaml — discover the ctor signature

**Files:**
- Create: `fixtures/marten-vmw2-postfix/rules.yaml`

- [ ] **Step 1: Inspect Marten 8.37 IL for FullTextWhereFragment**

Build a quick discovery harness — a one-off script that uses Cecil to dump the type's ctors. Create `scripts/inspect-marten-fragment.sh` (NOT committed) OR just use a one-line Cecil program. Easiest: write a temporary `.cs` file:

```bash
mkdir -p /tmp/marten-inspect && cd /tmp/marten-inspect
cat > inspect.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Mono.Cecil" Version="0.11.5" />
  </ItemGroup>
</Project>
EOF
cat > Program.cs <<'EOF'
var asm = Mono.Cecil.AssemblyDefinition.ReadAssembly(args[0]);
foreach (var t in asm.MainModule.Types.Where(t => t.FullName.Contains("FullTextWhereFragment")))
{
    System.Console.WriteLine($"TYPE: {t.FullName}");
    foreach (var m in t.Methods.Where(m => m.IsConstructor))
    {
        System.Console.WriteLine($"  CTOR: {m.FullName}");
    }
    foreach (var m in t.Methods.Where(m => m.Name == "Apply" || m.Name == "ValidateRegConfig" || m.Name.Contains("Validate")))
    {
        System.Console.WriteLine($"  METHOD: {m.FullName}");
    }
}
EOF
cd -
dotnet run --project /tmp/marten-inspect/inspect.csproj -- $(pwd)/artifacts/marten-8.37/Marten.dll
```

Note all the printed ctor signatures and any `Validate*` helper methods. The rules.yaml needs the EXACT ctor full-name (without the `instance void` prefix that Cecil's `FullName` prepends — `FindMethod` accepts the short form `Namespace.Type::.ctor(Param1Type,Param2Type)`).

- [ ] **Step 2: Write rules.yaml with the discovered ctor signature**

Write `fixtures/marten-vmw2-postfix/rules.yaml`:

```yaml
vuln_id: marten-vmw2-postfix
source_methods:
  - signature: Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment::.ctor(<EXACT-SIGNATURE-FROM-STEP-1>)
```

Replace `<EXACT-SIGNATURE-FROM-STEP-1>` with the comma-separated parameter types you discovered. Example shape: `(System.String,System.String,System.String,System.String)` or `(System.String,System.String,System.Linq.Expressions.Expression`1<System.Func`2<...>>)` etc.

**Note:** if FullTextWhereFragment has multiple ctors, pick the one that takes `regConfig` as a parameter — likely the public-facing one. Inspect via Cecil if uncertain.

- [ ] **Step 3: Don't commit yet**

The trace file will be generated in Task 13. Wait until both rules and trace exist before committing both together.

---

### Task 13: Run analyzer + lock trace.yaml for Marten

**Files:**
- Create: `fixtures/marten-vmw2-postfix/trace.yaml`

- [ ] **Step 1: Create fixture dir**

```bash
mkdir -p fixtures/marten-vmw2-postfix
```

- [ ] **Step 2: Determine no-symbols flag**

```bash
NO_SYMBOLS_FLAG=""
if [ -f artifacts/marten-8.37/.nopdb-marker ]; then NO_SYMBOLS_FLAG="--no-symbols"; fi
echo "no-symbols flag: $NO_SYMBOLS_FLAG"
```

- [ ] **Step 3: Run analyzer**

```bash
dotnet tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll \
    artifacts/marten-8.37/Marten.dll \
    --rules fixtures/marten-vmw2-postfix/rules.yaml \
    --output fixtures/marten-vmw2-postfix/trace.yaml \
    $NO_SYMBOLS_FLAG
echo "EXIT=$?"
cat fixtures/marten-vmw2-postfix/trace.yaml | head -60
```

- [ ] **Step 4: Triage the result**

**Outcome A — Trace fires with expected sanitizer hop and no sink:** lock is good, proceed to Step 5.

Expected shape:
- `vuln_id: marten-vmw2-postfix`
- `source:` block on `FullTextWhereFragment..ctor`
- `path:` with at least one `role: sanitizer`, `relation: regex_match`, `upper_bound` containing `[a-zA-Z_]` (the Marten pattern; exact form is the PostgreSQL identifier regex).
- NO `sink:` block.
- `sanitizer_absence: []` (empty).

**Outcome B — Trace is empty:** the recognizer didn't fire OR the walker didn't reach the regex IsMatch. Debug paths:
1. Check whether `ValidateRegConfig` exists as a separate `private static` method and the ctor calls it. If so, the walker should follow the call — but only if it walks across method boundaries with tainted args. Verify by checking the walker's call-graph step against the inspector output from Task 12.
2. If `ValidateRegConfig` is inlined into the ctor body: the recognizer should fire inside the ctor directly. Verify with the temporary Console.Error.WriteLine debug technique.
3. If the recognizer fires but no hop appears in the trace: check that `MatchAll` returns the hit (it should — Task 5 wired it).

**Outcome C — Trace has sink fired (regex didn't sanitize):** the walker reached AppendWithParameters despite the guard. This means either (a) the recognizer is firing but `TraceEmitter`'s in-method sanitizer-on-path matching doesn't connect the regex hop to the sink's value chain, or (b) the sanitizer fires on a parameter name that doesn't match the sink's value chain. Inspect the trace's path hops to see what `establishes_bound.target` came out as; compare to the sink's `tainted_value_in`.

**Outcome D — Walker gap > 80 LOC:** stop, escalate per spec's escape valve.

- [ ] **Step 5: Add description block**

Edit `fixtures/marten-vmw2-postfix/trace.yaml`. After the `vuln_id:` line, add:

```yaml
fix_commit: ""
fix_pr: https://github.com/JasperFx/marten/pull/4343
description: >
  Real-world advisory fix lock for GHSA-vmw2-qwm8-x84c. Marten 8.37 adds a
  Regex.IsMatch guard in FullTextWhereFragment's constructor (via the
  ValidateRegConfig helper) that rejects regConfig values not matching
  ^[a-zA-Z_][a-zA-Z0-9_]{0,62}(\.[a-zA-Z_][a-zA-Z0-9_]{0,62})?$. Source is
  FullTextWhereFragment::.ctor with parameter-bitmask seeding. T3's
  MatchRegexIsMatchAndThrow recognizer fires inside the ctor (or its inlined
  helper); the trace contains source + sanitizer hop with no sink — the
  TraceEmitter's "patched" output shape. Compare against
  fixtures/marten-vmw2-prefix (T2.1's lock against 8.36) to see Limes
  distinguishing vulnerable from patched on the same advisory. Locked at
  milestone-T3 Phase 2; do not regenerate without re-locking.
```

- [ ] **Step 6: Run schema validator**

Run: `dotnet test tools/ValidateFixture.Tests/ValidateFixture.Tests.csproj --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: 63 pass (the new trace doesn't add a fixture test but must satisfy the schema).

- [ ] **Step 7: Commit**

```bash
git add fixtures/marten-vmw2-postfix/rules.yaml fixtures/marten-vmw2-postfix/trace.yaml
git commit -m "fixture: marten-vmw2-postfix rules + locked trace.yaml (GHSA-vmw2-qwm8-x84c fix in Marten 8.37)"
```

---

### Task 14: Marten end-to-end fixture test

**Files:**
- Create: `tools/TaintAnalyzer.Tests/MartenVmw2PostfixFixtureTests.cs`

- [ ] **Step 1: Write the test**

Write `tools/TaintAnalyzer.Tests/MartenVmw2PostfixFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;
using Xunit;

namespace TaintAnalyzer.Tests;

public class MartenVmw2PostfixFixtureTests
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
    public void MartenVmw2Postfix_TraceContainsSanitizerNoSink()
    {
        var dllPath = Path.Combine(RepoRoot, "artifacts", "marten-8.37", "Marten.dll");
        var rulesPath = Path.Combine(RepoRoot, "fixtures", "marten-vmw2-postfix", "rules.yaml");

        if (!File.Exists(dllPath)) return;  // Marten 8.37 not materialized in fresh checkouts

        var noPdbMarker = Path.Combine(RepoRoot, "artifacts", "marten-8.37", ".nopdb-marker");
        var noSymbols = File.Exists(noPdbMarker);

        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var outPath = Path.Combine(Path.GetTempPath(), $"marten-vmw2-postfix-{Guid.NewGuid()}.yaml");
        try
        {
            var args = new List<string> { dllPath, "--rules", rulesPath, "--output", outPath };
            if (noSymbols) args.Add("--no-symbols");

            var rc = Program.Run(args.ToArray(), stdout, stderr);

            rc.ShouldBe(0, $"analyzer exit code; stderr: {stderr}");
            File.Exists(outPath).ShouldBeTrue();

            var trace = File.ReadAllText(outPath);
            trace.ShouldContain("relation: regex_match");
            trace.ShouldContain("[a-zA-Z_]");  // a substring of the expected pattern
            trace.ShouldContain("Marten.Linq.SqlGeneration.Filters.FullTextWhereFragment");
            trace.ShouldNotContain("kind: sql_injection");
            trace.ShouldNotContain("sink:");
            // sanitizer_absence is empty for the patched form.
            trace.ShouldNotContain("expected_check:");
        }
        finally
        {
            if (File.Exists(outPath)) File.Delete(outPath);
        }
    }
}
```

- [ ] **Step 2: Run**

Run: `dotnet test tools/TaintAnalyzer.Tests/TaintAnalyzer.Tests.csproj --filter "FullyQualifiedName~MartenVmw2PostfixFixtureTests" --nologo /v:quiet -- xunit.parallelizeTestCollections=false`
Expected: PASS (or silently skip if Marten 8.37 not materialized in this checkout).

- [ ] **Step 3: Commit**

```bash
git add tools/TaintAnalyzer.Tests/MartenVmw2PostfixFixtureTests.cs
git commit -m "test: end-to-end fixture run for marten-vmw2-postfix"
```

---

### Task 15: Regression sweep + milestone close

**Files:** None (verification only)

- [ ] **Step 1: Full test suite**

Run: `dotnet test --nologo /v:quiet -- xunit.parallelizeTestCollections=false`

Expected:
- `TaintAnalyzer.Tests`: 289 + 10 (6 sanitizer unit + 2 emitter + 2 fixture-runners) = **299 passed**.
- `ValidateFixture.Tests`: 63 passed.
- **Total: 362 passed, 0 failed.**

- [ ] **Step 2: Scan-fixture locks**

```bash
bash fixtures/scan-protobuf-net/run 2>&1 | tail -2
bash fixtures/scan-nbmp-1.1.25/run 2>&1 | tail -2
```

Expected: each either confirms match or skips (artifact not materialized).

- [ ] **Step 3: Compare prefix vs postfix on Marten**

```bash
diff -u fixtures/marten-vmw2-prefix/trace.yaml fixtures/marten-vmw2-postfix/trace.yaml | head -60
```

Expected: clear differences — prefix has `sink:` + `sanitizer_absence:` with content; postfix has neither and instead has a sanitizer hop in the `path:`. This is the headline result of T3 — Limes distinguishes vulnerable from patched.

- [ ] **Step 4: Clean tree check**

```bash
git status
```

Expected: clean working tree.

- [ ] **Step 5: Summarize**

Report:
- 15 tasks completed (10 Phase 1 + 4 Phase 2 + 1 sweep).
- Test count: 289 → 299 TaintAnalyzer.Tests (+10); 63 ValidateFixture.Tests unchanged; **total 362**.
- New files: sanitizer matcher (`MatchRegexIsMatchAndThrow` + helpers), TraceEmitter source-only-sanitizer emission path, Phase 1 synthetic fixture + tests, Phase 2 Marten 8.37 fixture + test, materialize script, build script.
- Anchor regressions: none.
- Awaiting: user push of the worktree branch via fast-forward to main.
- Next steps: T3 closes the prefix-vs-postfix milestone for GHSA-vmw2-qwm8-x84c. Future T4 / S3 / etc — open. Possible next directions: extend the recognizer to other validator methods (Uri.IsWellFormedUriString, etc.) when a real advisory needs it; LINQ expression-tree analysis (still deferred from T2.1); other SQL sinks (Execute*, ExecuteSqlRaw, Dapper); other CWE-89-adjacent injection classes.
