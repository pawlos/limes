# Loop-Termination Detection (CWE-835) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--scan-profile loop` detector that flags read loops with no completion check (CWE-835), reproducing the CoreWCF GHSA-p86g-xrr2-pf7c infinite loop.

**Architecture:** A standalone structural pass (`LoopTerminationAnalyzer`) parallel to `TaintWalker`. It resolves a candidate method's async state machine, detects loop spans via IL back-edges, finds recognized read calls inside spans, and reports a finding when the loop has no completion-signal consumption. A new YAML finding schema is emitted by `LoopFindingEmitter`. The taint engine is not touched.

**Tech Stack:** C# / net10.0, Mono.Cecil 0.11.6 (IL inspection), xUnit + Shouldly (tests), hand-rolled deterministic YAML (matching `RulesYamlEmitter`).

**Spec:** `docs/superpowers/specs/2026-06-21-loop-termination-detection-design.md`

## Global Constraints

- Target framework: `net10.0`; SDK pinned by `global.json` (`10.0.103`, latestFeature).
- IL library: Mono.Cecil `0.11.6` only. No new package dependencies.
- Tests: xUnit `[Fact]` + Shouldly. Fixture assemblies load from `Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll")`.
- Output must be deterministic (stable ordering, no maps/anchors) so fixtures lock cleanly.
- `TaintWalker`, `TraceEmitter`, and the DoS/SQLi paths must not change behaviour.
- **Never run `git push`** — the user pushes to origin manually. Commit after each task.
- Detector reports the *idiom* (read loop with no completion check), not provable non-termination. PipeReader completion detection is precise; Stream/Socket is a documented best-effort heuristic for the synchronous result-local pattern.

---

### Task 1: `ReadLoopShapes` recognizers + loop unit fixtures

**Files:**
- Create: `tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs`
- Create: `tools/TaintAnalyzer/ReadLoopShapes.cs`
- Test: `tools/TaintAnalyzer.Tests/ReadLoopShapesTests.cs`

**Interfaces:**
- Produces: `enum ReadKind { PipeReader, StreamInt }`; `sealed record ReadMatch(ReadKind Kind, string Api)`; `ReadLoopShapes.RecognizeRead(MethodReference) -> ReadMatch?`; `ReadLoopShapes.IsPipeCompletionSignal(MethodReference) -> bool`.

- [ ] **Step 1: Create the handwritten fixtures**

`tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs`:

```csharp
using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TaintAnalyzer.Tests.Fixtures.Loop;

public class PipeLoops
{
    // read loop, never inspects IsCompleted -> FLAG
    public async Task PipeNoCheck(PipeReader reader)
    {
        int total = 0;
        while (total < 100)
        {
            ReadResult result = await reader.ReadAsync();
            total += (int)result.Buffer.Length;
            reader.AdvanceTo(result.Buffer.End);
        }
    }

    // read loop, inspects IsCompleted -> CLEAR
    public async Task PipeWithCheck(PipeReader reader)
    {
        while (true)
        {
            ReadResult result = await reader.ReadAsync();
            reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);
            if (result.IsCompleted) break;
        }
    }

    // single read, NOT in a loop -> CLEAR (Tier 2 back-edge gate)
    public async Task PipeSingleRead(PipeReader reader)
    {
        ReadResult result = await reader.ReadAsync();
        reader.AdvanceTo(result.Buffer.End);
    }
}

public class PlainLoops
{
    // loop with no read call -> CLEAR (not a candidate)
    public int LoopNoRead(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++) sum += i;
        return sum;
    }
}

public class StreamLoops
{
    // stream read loop, never checks count == 0 -> FLAG
    public int StreamNoCheck(Stream s, int limit)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (total < limit)
        {
            int n = s.Read(buf, 0, buf.Length);
            total += n;
        }
        return total;
    }

    // stream read loop, checks count == 0 -> CLEAR
    public int StreamWithCheck(Stream s)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (true)
        {
            int n = s.Read(buf, 0, buf.Length);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    // socket receive loop, never checks count == 0 -> FLAG
    public int SocketNoCheck(Socket sock, int limit)
    {
        byte[] buf = new byte[256];
        int total = 0;
        while (total < limit)
        {
            int n = sock.Receive(buf);
            total += n;
        }
        return total;
    }
}
```

- [ ] **Step 2: Build the fixtures project to confirm it compiles**

Run: `dotnet build tools/TaintAnalyzer.Tests.Fixtures/TaintAnalyzer.Tests.Fixtures.csproj`
Expected: build succeeds. If `PipeReader`/`ReadResult` fail to resolve, add `<PackageReference Include="System.IO.Pipelines" Version="9.0.0" />` to the fixtures csproj and rebuild (System.IO.Pipelines is normally in the shared framework, so this is a fallback).

- [ ] **Step 3: Write the failing test**

`tools/TaintAnalyzer.Tests/ReadLoopShapesTests.cs`:

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ReadLoopShapesTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    // Resolve the async state machine MoveNext for a fixture method and return its call instructions.
    private static List<MethodReference> CallsIn(string typeName, string methodName)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var t = ctx.Assembly.MainModule.GetType($"TaintAnalyzer.Tests.Fixtures.Loop.{typeName}");
        var m = t.Methods.First(x => x.Name == methodName);
        var body = AsyncStateMachineResolver.Resolve(m).Method.Body;
        return body.Instructions
            .Where(i => i.OpCode.Code is Code.Call or Code.Callvirt && i.Operand is MethodReference)
            .Select(i => (MethodReference)i.Operand)
            .ToList();
    }

    [Fact]
    public void RecognizesPipeReaderReadAsync()
    {
        var read = CallsIn("PipeLoops", "PipeNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).FirstOrDefault(r => r is not null);
        read!.Kind.ShouldBe(ReadKind.PipeReader);
        read.Api.ShouldBe("pipe_reader_read_async");
    }

    [Fact]
    public void RecognizesPipeCompletionSignal()
    {
        CallsIn("PipeLoops", "PipeWithCheck").Any(ReadLoopShapes.IsPipeCompletionSignal).ShouldBeTrue();
        CallsIn("PipeLoops", "PipeNoCheck").Any(ReadLoopShapes.IsPipeCompletionSignal).ShouldBeFalse();
    }

    [Fact]
    public void RecognizesStreamAndSocketReads()
    {
        CallsIn("StreamLoops", "StreamNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).Any(r => r?.Kind == ReadKind.StreamInt && r.Api == "stream_read")
            .ShouldBeTrue();
        CallsIn("StreamLoops", "SocketNoCheck")
            .Select(ReadLoopShapes.RecognizeRead).Any(r => r?.Kind == ReadKind.StreamInt && r.Api == "socket_receive")
            .ShouldBeTrue();
    }

    [Fact]
    public void IgnoresUnrelatedCalls()
    {
        ReadLoopShapes.RecognizeRead(CallsIn("PlainLoops", "LoopNoRead").First()).ShouldBeNull();
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter ReadLoopShapesTests`
Expected: FAIL (compile error — `ReadLoopShapes` / `ReadKind` do not exist yet).

- [ ] **Step 5: Implement `ReadLoopShapes`**

`tools/TaintAnalyzer/ReadLoopShapes.cs`:

```csharp
using Mono.Cecil;

namespace TaintAnalyzer;

public enum ReadKind { PipeReader, StreamInt }

public sealed record ReadMatch(ReadKind Kind, string Api);

// Recognizer table for loop-termination detection (CWE-835), mirroring SinkShapes.
// Two questions per call site: is this a recognized read, and is this a completion check?
public static class ReadLoopShapes
{
    public static ReadMatch? RecognizeRead(MethodReference mr)
    {
        var t = mr.DeclaringType.FullName;
        var n = mr.Name;
        return (t, n) switch
        {
            ("System.IO.Pipelines.PipeReader", "ReadAsync") => new ReadMatch(ReadKind.PipeReader, "pipe_reader_read_async"),
            ("System.IO.Stream", "Read")                     => new ReadMatch(ReadKind.StreamInt, "stream_read"),
            ("System.IO.Stream", "ReadAsync")                => new ReadMatch(ReadKind.StreamInt, "stream_read_async"),
            ("System.Net.Sockets.Socket", "Receive")         => new ReadMatch(ReadKind.StreamInt, "socket_receive"),
            ("System.Net.Sockets.Socket", "ReceiveAsync")    => new ReadMatch(ReadKind.StreamInt, "socket_receive_async"),
            _ => null,
        };
    }

    // PipeReader completion signal: ReadResult.IsCompleted getter.
    public static bool IsPipeCompletionSignal(MethodReference mr)
        => mr.Name == "get_IsCompleted" && mr.DeclaringType.Name == "ReadResult";
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter ReadLoopShapesTests`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs tools/TaintAnalyzer/ReadLoopShapes.cs tools/TaintAnalyzer.Tests/ReadLoopShapesTests.cs
git commit -m "analyzer: ReadLoopShapes read-API + completion recognizers; loop fixtures

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `LoopFinding` + `LoopTerminationAnalyzer` (back-edge + PipeReader path)

**Files:**
- Create: `tools/TaintAnalyzer/LoopFinding.cs`
- Create: `tools/TaintAnalyzer/LoopTerminationAnalyzer.cs`
- Test: `tools/TaintAnalyzer.Tests/LoopTerminationAnalyzerTests.cs`

**Interfaces:**
- Consumes: `ReadLoopShapes.RecognizeRead`, `ReadLoopShapes.IsPipeCompletionSignal` (Task 1); `AsyncStateMachineResolver.Resolve` and `AssemblyContext.GetSequencePoint` (existing).
- Produces: `sealed class LoopFinding { string Method; string ReadApi; bool ResolvedViaAsync; string LoopFile; int LoopLine; string ReadFile; int ReadLine; }`; `LoopTerminationAnalyzer.Analyze(AssemblyContext, MethodDefinition) -> IReadOnlyList<LoopFinding>`. Internal `StreamCompletionPresent` is added in Task 3.

- [ ] **Step 1: Create the finding record**

`tools/TaintAnalyzer/LoopFinding.cs`:

```csharp
namespace TaintAnalyzer;

// A CWE-835 finding: a read loop with no completion check. Not a taint path.
public sealed class LoopFinding
{
    public required string Method { get; init; }          // user-facing "Namespace.Type.Method"
    public required string ReadApi { get; init; }          // e.g. "pipe_reader_read_async"
    public required bool ResolvedViaAsync { get; init; }
    public required string LoopFile { get; init; }
    public required int LoopLine { get; init; }
    public required string ReadFile { get; init; }
    public required int ReadLine { get; init; }
}
```

- [ ] **Step 2: Write the failing test**

`tools/TaintAnalyzer.Tests/LoopTerminationAnalyzerTests.cs`:

```csharp
using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class LoopTerminationAnalyzerTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static IReadOnlyList<LoopFinding> Analyze(string typeName, string methodName)
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var t = ctx.Assembly.MainModule.GetType($"TaintAnalyzer.Tests.Fixtures.Loop.{typeName}");
        var m = t.Methods.First(x => x.Name == methodName);
        return LoopTerminationAnalyzer.Analyze(ctx, m);
    }

    [Fact]
    public void FlagsPipeReadLoopWithoutCompletionCheck()
    {
        var f = Analyze("PipeLoops", "PipeNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("pipe_reader_read_async");
        f[0].ResolvedViaAsync.ShouldBeTrue();
        f[0].Method.ShouldEndWith("PipeLoops.PipeNoCheck");
    }

    [Fact]
    public void ClearsPipeReadLoopWithCompletionCheck()
        => Analyze("PipeLoops", "PipeWithCheck").ShouldBeEmpty();

    [Fact]
    public void ClearsSingleReadNotInLoop()
        => Analyze("PipeLoops", "PipeSingleRead").ShouldBeEmpty();

    [Fact]
    public void ClearsLoopWithNoRead()
        => Analyze("PlainLoops", "LoopNoRead").ShouldBeEmpty();
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopTerminationAnalyzerTests`
Expected: FAIL (compile error — `LoopTerminationAnalyzer` does not exist).

- [ ] **Step 4: Implement the analyzer (PipeReader path; Stream stub returns false)**

`tools/TaintAnalyzer/LoopTerminationAnalyzer.cs`:

```csharp
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

// Standalone structural pass for CWE-835 (loop with unreachable exit condition).
// Detects read loops with no completion check. Does not use TaintWalker.
public static class LoopTerminationAnalyzer
{
    public static IReadOnlyList<LoopFinding> Analyze(AssemblyContext context, MethodDefinition method)
    {
        var findings = new List<LoopFinding>();
        var resolution = AsyncStateMachineResolver.Resolve(method);
        var body = resolution.Method.Body;
        if (body is null) return findings;

        var instrs = body.Instructions;
        var spans = ComputeLoopSpans(instrs);
        if (spans.Count == 0) return findings;

        foreach (var ins in instrs)
        {
            if (ins.OpCode.Code is not (Code.Call or Code.Callvirt)) continue;
            if (ins.Operand is not MethodReference mr) continue;
            var read = ReadLoopShapes.RecognizeRead(mr);
            if (read is null) continue;

            var range = EnclosingRange(spans, ins.Offset);
            if (range is null) continue; // Tier 2: the read must sit inside a loop

            bool completionPresent = read.Kind == ReadKind.PipeReader
                ? PipeCompletionPresent(instrs, range.Value)
                : StreamCompletionPresent(instrs, range.Value, ins);
            if (completionPresent) continue;

            var loopStart = instrs.First(i => i.Offset == range.Value.Start);
            var loopSp = context.GetSequencePoint(resolution.Method, loopStart);
            var readSp = context.GetSequencePoint(resolution.Method, ins);
            findings.Add(new LoopFinding
            {
                Method = $"{method.DeclaringType.FullName}.{method.Name}",
                ReadApi = read.Api,
                ResolvedViaAsync = resolution.RedirectedFromAsync,
                LoopFile = loopSp is null ? "" : Path.GetFileName(loopSp.Document.Url),
                LoopLine = loopSp?.StartLine ?? 0,
                ReadFile = readSp is null ? "" : Path.GetFileName(readSp.Document.Url),
                ReadLine = readSp?.StartLine ?? 0,
            });
        }
        return findings;
    }

    // A back-edge is a branch whose target offset is <= the branch's own offset.
    // The loop span is [targetOffset, branchOffset].
    private static List<(int Start, int End)> ComputeLoopSpans(IEnumerable<Instruction> instrs)
    {
        var spans = new List<(int, int)>();
        foreach (var ins in instrs)
        {
            switch (ins.OpCode.OperandType)
            {
                case OperandType.InlineBrTarget:
                case OperandType.ShortInlineBrTarget:
                    if (ins.Operand is Instruction t && t.Offset <= ins.Offset)
                        spans.Add((t.Offset, ins.Offset));
                    break;
                case OperandType.InlineSwitch:
                    if (ins.Operand is Instruction[] targets)
                        foreach (var sw in targets)
                            if (sw.Offset <= ins.Offset) spans.Add((sw.Offset, ins.Offset));
                    break;
            }
        }
        return spans;
    }

    // Combined range of every loop span enclosing `offset` (handles nested loops leniently).
    private static (int Start, int End)? EnclosingRange(List<(int Start, int End)> spans, int offset)
    {
        int start = int.MaxValue, end = int.MinValue;
        bool found = false;
        foreach (var s in spans)
            if (s.Start <= offset && offset <= s.End)
            {
                found = true;
                start = Math.Min(start, s.Start);
                end = Math.Max(end, s.End);
            }
        return found ? (start, end) : null;
    }

    private static bool PipeCompletionPresent(IEnumerable<Instruction> instrs, (int Start, int End) r)
    {
        foreach (var ins in instrs)
        {
            if (ins.Offset < r.Start || ins.Offset > r.End) continue;
            if (ins.OpCode.Code is (Code.Call or Code.Callvirt)
                && ins.Operand is MethodReference mr
                && ReadLoopShapes.IsPipeCompletionSignal(mr))
                return true;
        }
        return false;
    }

    // Implemented in Task 3.
    private static bool StreamCompletionPresent(IList<Instruction> instrs, (int Start, int End) r, Instruction readCall)
        => false;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopTerminationAnalyzerTests`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add tools/TaintAnalyzer/LoopFinding.cs tools/TaintAnalyzer/LoopTerminationAnalyzer.cs tools/TaintAnalyzer.Tests/LoopTerminationAnalyzerTests.cs
git commit -m "analyzer: LoopTerminationAnalyzer back-edge spans + PipeReader completion path

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Stream/Socket completion heuristic

**Files:**
- Modify: `tools/TaintAnalyzer/LoopTerminationAnalyzer.cs` (replace the `StreamCompletionPresent` stub + add helpers)
- Test: `tools/TaintAnalyzer.Tests/LoopTerminationAnalyzerTests.cs` (add cases)

**Interfaces:**
- Consumes: the loop-span machinery from Task 2.
- Produces: completes `StreamCompletionPresent` so StreamInt reads are evaluated.

- [ ] **Step 1: Add the failing tests**

Append to `LoopTerminationAnalyzerTests.cs`:

```csharp
    [Fact]
    public void FlagsStreamReadLoopWithoutZeroCheck()
    {
        var f = Analyze("StreamLoops", "StreamNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("stream_read");
    }

    [Fact]
    public void ClearsStreamReadLoopWithZeroCheck()
        => Analyze("StreamLoops", "StreamWithCheck").ShouldBeEmpty();

    [Fact]
    public void FlagsSocketReceiveLoopWithoutZeroCheck()
    {
        var f = Analyze("StreamLoops", "SocketNoCheck");
        f.Count.ShouldBe(1);
        f[0].ReadApi.ShouldBe("socket_receive");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopTerminationAnalyzerTests`
Expected: FAIL — `FlagsStreamReadLoopWithoutZeroCheck` and the socket case fail (stub returns false, so `StreamWithCheck` already "passes" by being flagged-then-empty? No: stub=false means completion never present, so `StreamWithCheck` is wrongly flagged → `ClearsStreamReadLoopWithZeroCheck` FAILS). Confirm at least the clear-case fails.

- [ ] **Step 3: Implement the heuristic**

In `LoopTerminationAnalyzer.cs`, replace the `StreamCompletionPresent` stub with:

```csharp
    // Best-effort: the synchronous read result is stored to a local immediately after the
    // call; completion is present iff that local is later loaded within the span as the
    // operand of a comparison or conditional branch (i.e. a check against the byte count).
    // Documented limitation: async Stream/Socket reads (await pattern) are not tracked and
    // may over-flag.
    private static bool StreamCompletionPresent(IList<Instruction> instrs, (int Start, int End) r, Instruction readCall)
    {
        if (!TryGetStlocIndex(readCall.Next, out int local)) return false;

        foreach (var ins in instrs)
        {
            if (ins.Offset < r.Start || ins.Offset > r.End) continue;
            if (!TryGetLdlocIndex(ins, out int li) || li != local) continue;

            var next = SkipNop(ins.Next);
            if (next is null) continue;
            if (IsComparisonOrCondBranch(next)) return true;
            if (IsZeroConst(next))
            {
                var after = SkipNop(next.Next);
                if (after is not null && IsComparisonOrCondBranch(after)) return true;
            }
        }
        return false;
    }

    private static Instruction? SkipNop(Instruction? i)
    {
        while (i is not null && i.OpCode.Code == Code.Nop) i = i.Next;
        return i;
    }

    private static bool IsZeroConst(Instruction i)
        => i.OpCode.Code == Code.Ldc_I4_0
           || (i.OpCode.Code == Code.Ldc_I4 && i.Operand is int v && v == 0)
           || (i.OpCode.Code == Code.Ldc_I4_S && i.Operand is sbyte sb && sb == 0);

    private static bool IsComparisonOrCondBranch(Instruction i)
        => i.OpCode.Code is Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un
           || i.OpCode.FlowControl == FlowControl.Cond_Branch;

    private static bool TryGetStlocIndex(Instruction? i, out int index)
    {
        index = -1;
        if (i is null) return false;
        switch (i.OpCode.Code)
        {
            case Code.Stloc_0: index = 0; return true;
            case Code.Stloc_1: index = 1; return true;
            case Code.Stloc_2: index = 2; return true;
            case Code.Stloc_3: index = 3; return true;
            case Code.Stloc:
            case Code.Stloc_S:
                if (i.Operand is VariableDefinition v) { index = v.Index; return true; }
                return false;
            default: return false;
        }
    }

    private static bool TryGetLdlocIndex(Instruction i, out int index)
    {
        index = -1;
        switch (i.OpCode.Code)
        {
            case Code.Ldloc_0: index = 0; return true;
            case Code.Ldloc_1: index = 1; return true;
            case Code.Ldloc_2: index = 2; return true;
            case Code.Ldloc_3: index = 3; return true;
            case Code.Ldloc:
            case Code.Ldloc_S:
                if (i.Operand is VariableDefinition v) { index = v.Index; return true; }
                return false;
            default: return false;
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopTerminationAnalyzerTests`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/LoopTerminationAnalyzer.cs tools/TaintAnalyzer.Tests/LoopTerminationAnalyzerTests.cs
git commit -m "analyzer: Stream/Socket completion heuristic (result-local zero-check)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `LoopFindingEmitter` (YAML)

**Files:**
- Create: `tools/TaintAnalyzer/LoopFindingEmitter.cs`
- Test: `tools/TaintAnalyzer.Tests/LoopFindingEmitterTests.cs`

**Interfaces:**
- Consumes: `LoopFinding` (Task 2).
- Produces: `LoopFindingEmitter.Emit(string vulnId, IReadOnlyList<LoopFinding>) -> string`. Findings sorted by `(Method, ReadLine, ReadFile)`.

- [ ] **Step 1: Write the failing test**

`tools/TaintAnalyzer.Tests/LoopFindingEmitterTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class LoopFindingEmitterTests
{
    [Fact]
    public void EmitsEmptyFindingsList()
    {
        var yaml = LoopFindingEmitter.Emit("scan-Foo", Array.Empty<LoopFinding>());
        yaml.ShouldContain("vuln_id: scan-Foo");
        yaml.ShouldContain("findings: []");
    }

    [Fact]
    public void EmitsFindingFields()
    {
        var f = new LoopFinding
        {
            Method = "A.B.OnConnectedAsync", ReadApi = "pipe_reader_read_async",
            ResolvedViaAsync = true, LoopFile = "B.cs", LoopLine = 25, ReadFile = "B.cs", ReadLine = 27,
        };
        var yaml = LoopFindingEmitter.Emit("scan-X", new[] { f });
        yaml.ShouldContain("cwe: 835");
        yaml.ShouldContain("method: A.B.OnConnectedAsync");
        yaml.ShouldContain("resolved_via: async_state_machine");
        yaml.ShouldContain("api: pipe_reader_read_async");
        yaml.ShouldContain("completion_signal: absent");
        yaml.ShouldContain("line: 27");
    }

    [Fact]
    public void OmitsResolvedViaWhenNotAsync()
    {
        var f = new LoopFinding
        {
            Method = "A.B.Sync", ReadApi = "stream_read", ResolvedViaAsync = false,
            LoopFile = "", LoopLine = 0, ReadFile = "", ReadLine = 0,
        };
        LoopFindingEmitter.Emit("scan-X", new[] { f }).ShouldNotContain("resolved_via");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopFindingEmitterTests`
Expected: FAIL (compile error — `LoopFindingEmitter` does not exist).

- [ ] **Step 3: Implement the emitter**

`tools/TaintAnalyzer/LoopFindingEmitter.cs`:

```csharp
using System.Text;

namespace TaintAnalyzer;

// Hand-rolled deterministic YAML for CWE-835 loop findings (distinct from the taint trace
// schema). Findings are sorted so the document is stable and lockable.
public static class LoopFindingEmitter
{
    public static string Emit(string vulnId, IReadOnlyList<LoopFinding> findings)
    {
        var sb = new StringBuilder();
        sb.Append("vuln_id: ").AppendLine(vulnId);

        if (findings.Count == 0)
        {
            sb.AppendLine("findings: []");
            return sb.ToString();
        }

        var ordered = findings
            .OrderBy(f => f.Method, StringComparer.Ordinal)
            .ThenBy(f => f.ReadLine)
            .ThenBy(f => f.ReadFile, StringComparer.Ordinal);

        sb.AppendLine("findings:");
        foreach (var f in ordered)
        {
            sb.AppendLine("  - cwe: 835");
            sb.Append("    method: ").AppendLine(f.Method);
            if (f.ResolvedViaAsync) sb.AppendLine("    resolved_via: async_state_machine");
            sb.AppendLine("    loop:");
            sb.Append("      file: \"").Append(f.LoopFile).AppendLine("\"");
            sb.Append("      line: ").AppendLine(f.LoopLine.ToString());
            sb.AppendLine("    read:");
            sb.Append("      api: ").AppendLine(f.ReadApi);
            sb.Append("      file: \"").Append(f.ReadFile).AppendLine("\"");
            sb.Append("      line: ").AppendLine(f.ReadLine.ToString());
            sb.AppendLine("    completion_signal: absent");
        }
        return sb.ToString();
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopFindingEmitterTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/TaintAnalyzer/LoopFindingEmitter.cs tools/TaintAnalyzer.Tests/LoopFindingEmitterTests.cs
git commit -m "analyzer: LoopFindingEmitter — deterministic CWE-835 finding YAML

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `EnumerateLoopCandidates` + Loop visibility relaxation

**Files:**
- Modify: `tools/TaintAnalyzer/ScanProfile.cs` (add `Loop`)
- Modify: `tools/TaintAnalyzer/EntryPointEnumerator.cs` (add `EnumerateLoopCandidates`; relax `VisibilityReject` for `Loop`)
- Modify: `tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs` (add an internal-type fixture)
- Test: `tools/TaintAnalyzer.Tests/LoopCandidateEnumerationTests.cs`

**Interfaces:**
- Consumes: `ScanProfile.Loop`; existing private `HardReject`/`VisibilityReject`/`ExclusionReject`.
- Produces: `EntryPointEnumerator.EnumerateLoopCandidates(AssemblyContext, EnumeratorConfig, ReverseCallGraph) -> IEnumerable<MethodDefinition>`.

- [ ] **Step 1: Add `Loop` to the profile enum**

In `tools/TaintAnalyzer/ScanProfile.cs`, change the enum and comment:

```csharp
// Selects what a --scan run enumerates and reports.
//   Dos  — byte-source DoS shapes (default).
//   Sqli — string sources gated on transitive reach to a SQL sink (CWE-89).
//   Loop — read loops with no completion check (CWE-835); structural, no taint source.
public enum ScanProfile { Dos, Sqli, Loop }
```

- [ ] **Step 2: Add an internal-type fixture (mirrors CoreWCF's internal middleware)**

Append to `tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs`:

```csharp
// internal type, public read-loop method invoked via a delegate the call graph can't
// resolve — must still be enumerated under the Loop visibility relaxation.
internal class InternalMiddleware
{
    public async Task OnConnectedAsync(PipeReader reader)
    {
        int total = 0;
        while (total < 100)
        {
            ReadResult result = await reader.ReadAsync();
            total += (int)result.Buffer.Length;
            reader.AdvanceTo(result.Buffer.End);
        }
    }
}
```

- [ ] **Step 3: Write the failing test**

`tools/TaintAnalyzer.Tests/LoopCandidateEnumerationTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class LoopCandidateEnumerationTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static List<string> Candidates()
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        return EntryPointEnumerator
            .EnumerateLoopCandidates(ctx, EnumeratorConfig.Default, graph)
            .Select(m => $"{m.DeclaringType.FullName}.{m.Name}")
            .ToList();
    }

    [Fact]
    public void IncludesPublicMethodOnPublicType()
        => Candidates().ShouldContain(s => s.EndsWith("PipeLoops.PipeNoCheck"));

    [Fact]
    public void IncludesPublicMethodOnInternalType()
        => Candidates().ShouldContain(s => s.EndsWith("InternalMiddleware.OnConnectedAsync"));

    [Fact]
    public void ExcludesCompilerGeneratedStateMachineTypes()
        => Candidates().ShouldNotContain(s => s.Contains("<OnConnectedAsync>") || s.Contains("MoveNext"));
}
```

- [ ] **Step 4: Run to verify failure**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopCandidateEnumerationTests`
Expected: FAIL (compile error — `EnumerateLoopCandidates` does not exist).

- [ ] **Step 5: Relax visibility and add the enumerator**

In `tools/TaintAnalyzer/EntryPointEnumerator.cs`, update the SQLi relaxation line inside `VisibilityReject` to also cover `Loop`:

```csharp
        // SQLi and Loop profiles: a `public` method is part of the callable surface even
        // when its declaring type is internal (e.g. CoreWCF's internal framing middleware
        // invoked through a delegate the call graph can't resolve when scanning alone).
        if ((profile == ScanProfile.Sqli || profile == ScanProfile.Loop) && m.IsPublic) return false;
```

Add the new enumerator method (e.g. directly after the `Enumerate(...)` overloads):

```csharp
    // Loop profile: no taint-source shape. Every non-compiler-generated method passing the
    // hard/visibility/exclusion rejects is a candidate; LoopTerminationAnalyzer decides if a
    // read loop exists. Visibility uses the Loop relaxation (public-on-internal accepted).
    public static IEnumerable<MethodDefinition> EnumerateLoopCandidates(
        AssemblyContext context,
        EnumeratorConfig config,
        ReverseCallGraph callGraph)
    {
        foreach (var type in AllTypes(context.Assembly))
        {
            if (IsCompilerGeneratedType(type)) continue;
            foreach (var method in type.Methods)
            {
                if (HardReject(method)) continue;
                if (VisibilityReject(method, callGraph, ScanProfile.Loop)) continue;
                if (ExclusionReject(method, config)) continue;
                yield return method;
            }
        }
    }
```

- [ ] **Step 6: Run to verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter LoopCandidateEnumerationTests`
Expected: PASS (3 tests).

- [ ] **Step 7: Run the full suite to confirm no regression in Dos/Sqli enumeration**

Run: `dotnet test tools/TaintAnalyzer.Tests`
Expected: PASS (all existing + new).

- [ ] **Step 8: Commit**

```bash
git add tools/TaintAnalyzer/ScanProfile.cs tools/TaintAnalyzer/EntryPointEnumerator.cs tools/TaintAnalyzer.Tests.Fixtures/LoopFixtures.cs tools/TaintAnalyzer.Tests/LoopCandidateEnumerationTests.cs
git commit -m "analyzer: EnumerateLoopCandidates + Loop visibility relaxation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: CLI wiring — `--scan-profile loop` pipeline

**Files:**
- Modify: `tools/TaintAnalyzer/Program.cs` (parse `loop`; add the Loop pipeline branch; usage text)
- Test: `tools/TaintAnalyzer.Tests/ProgramLoopProfileTests.cs`

**Interfaces:**
- Consumes: `EntryPointEnumerator.EnumerateLoopCandidates`, `LoopTerminationAnalyzer.Analyze`, `LoopFindingEmitter.Emit`, `EnumeratorConfig.Default`/`.Load`.
- Produces: `--scan-profile loop` end-to-end behaviour from `Program.Run`.

- [ ] **Step 1: Write the failing tests**

`tools/TaintAnalyzer.Tests/ProgramLoopProfileTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ProgramLoopProfileTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static (int code, string outText, string errText) Run(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Program.Run(args, o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public void LoopProfile_FlagsNoCheckLoops_ClearsCheckedOnes()
    {
        var (code, outText, _) = Run(FixturePath, "--scan", "--scan-profile", "loop");
        code.ShouldBe(0);
        outText.ShouldContain("cwe: 835");
        outText.ShouldContain("PipeLoops.PipeNoCheck");
        outText.ShouldContain("StreamLoops.StreamNoCheck");
        outText.ShouldContain("StreamLoops.SocketNoCheck");
        outText.ShouldContain("InternalMiddleware.OnConnectedAsync");
        outText.ShouldNotContain("PipeWithCheck");
        outText.ShouldNotContain("StreamWithCheck");
        outText.ShouldNotContain("PipeSingleRead");
        outText.ShouldNotContain("LoopNoRead");
    }

    [Fact]
    public void LoopProfile_RequiresScan()
    {
        var (code, _, errText) = Run(FixturePath, "--scan-profile", "loop");
        code.ShouldBe(2);
        errText.ShouldContain("--scan-profile requires --scan");
    }

    [Fact]
    public void LoopProfile_RejectsEmitRules()
    {
        var (code, _, errText) = Run(FixturePath, "--scan", "--scan-profile", "loop", "--emit-rules", "x.yaml");
        code.ShouldBe(2);
        errText.ShouldContain("--emit-rules");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter ProgramLoopProfileTests`
Expected: FAIL — `loop` is rejected as an unknown profile, and the Loop pipeline does not exist.

- [ ] **Step 3: Parse the `loop` profile value**

In `tools/TaintAnalyzer/Program.cs`, in the `--scan-profile` switch, add the `loop` case and update the error message:

```csharp
                switch (args[i])
                {
                    case "dos": scanProfile = ScanProfile.Dos; break;
                    case "sqli": scanProfile = ScanProfile.Sqli; break;
                    case "loop": scanProfile = ScanProfile.Loop; break;
                    default:
                        stderr.WriteLine($"error: unknown scan profile '{args[i]}' (expected dos|sqli|loop)");
                        return 2;
                }
```

- [ ] **Step 4: Add the Loop pipeline branch**

In `Program.cs`, inside `using (context) { ... }`, immediately after `int sourcesCount = 0;` and before `RulesDocument rules;`, insert:

```csharp
            if (scan && scanProfile == ScanProfile.Loop)
            {
                if (emitRulesPath is not null)
                {
                    stderr.WriteLine("error: --emit-rules is not supported with --scan-profile loop");
                    return 2;
                }

                EnumeratorConfig loopCfg;
                if (enumeratorConfigPath is not null)
                {
                    if (!File.Exists(enumeratorConfigPath))
                    {
                        stderr.WriteLine($"error: enumerator-config file not found: {enumeratorConfigPath}");
                        return 1;
                    }
                    try { loopCfg = EnumeratorConfig.Load(File.ReadAllText(enumeratorConfigPath)); }
                    catch (EnumeratorConfigException ex)
                    {
                        stderr.WriteLine($"error: enumerator-config: {ex.Message}");
                        return 1;
                    }
                }
                else
                {
                    loopCfg = EnumeratorConfig.Default;
                }

                var loopGraph = new ReverseCallGraph(context.Assembly);
                var loopFindings = new List<LoopFinding>();
                foreach (var m in EntryPointEnumerator.EnumerateLoopCandidates(context, loopCfg, loopGraph))
                    loopFindings.AddRange(LoopTerminationAnalyzer.Analyze(context, m));

                if (progress)
                    stderr.WriteLine($"[scan] loop profile: {loopFindings.Count} findings ({sw.ElapsedMilliseconds}ms)");

                var loopYaml = LoopFindingEmitter.Emit(
                    "scan-" + Path.GetFileNameWithoutExtension(target), loopFindings);
                if (outputPath is null) stdout.Write(loopYaml);
                else File.WriteAllText(outputPath, loopYaml);
                return 0;
            }
```

- [ ] **Step 5: Update the usage string**

In `PrintUsage`, change the `--scan-profile` hint to include `loop`:

```csharp
        stderr.WriteLine("usage: TaintAnalyzer <target.dll> [--rules <rules.yaml> | --scan [--scan-profile dos|sqli|loop]] [--output <trace.yaml>] [--no-symbols]");
```

- [ ] **Step 6: Run to verify pass**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter ProgramLoopProfileTests`
Expected: PASS (3 tests).

- [ ] **Step 7: Run the full suite**

Run: `dotnet test TaintAnalyzer.sln`
Expected: PASS (all green).

- [ ] **Step 8: Commit**

```bash
git add tools/TaintAnalyzer/Program.cs tools/TaintAnalyzer.Tests/ProgramLoopProfileTests.cs
git commit -m "analyzer: --scan-profile loop CLI pipeline (CWE-835)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: CoreWCF fixture, end-to-end test, and docs

**Files:**
- Create: `scripts/materialize-corewcf-netframing.sh`
- Create: `fixtures/corewcf-p86g-prefix/findings.yaml` (locked reference)
- Create: `fixtures/corewcf-p86g-postfix/findings.yaml` (locked reference)
- Create: `tools/TaintAnalyzer.Tests/CoreWcfP86gFixtureTests.cs`
- Modify: `README.md` (document `loop` profile)

**Interfaces:**
- Consumes: the full `--scan-profile loop` CLI from Task 6.

- [ ] **Step 1: Write the materialize script**

`scripts/materialize-corewcf-netframing.sh`:

```bash
#!/usr/bin/env bash
# Materialize CoreWCF.NetFramingBase 1.9.0 (vulnerable, GHSA-p86g-xrr2-pf7c) and
# 1.9.1 (patched) DLLs into artifacts/ for the loop-termination fixture e2e tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="$ROOT/artifacts"

fetch() {
  local ver="$1"
  local dir="$ART/corewcf-netframing-$ver"
  mkdir -p "$dir"
  local tmp; tmp="$(mktemp -d)"
  curl -sL -o "$tmp/p.nupkg" "https://www.nuget.org/api/v2/package/CoreWCF.NetFramingBase/$ver"
  unzip -o -q "$tmp/p.nupkg" -d "$tmp/x"
  cp "$tmp/x/lib/netstandard2.0/CoreWCF.NetFramingBase.dll" "$dir/"
  rm -rf "$tmp"
  echo "materialized $dir"
}

fetch 1.9.0
fetch 1.9.1
```

Run: `chmod +x scripts/materialize-corewcf-netframing.sh && ./scripts/materialize-corewcf-netframing.sh`
Expected: two `materialized .../artifacts/corewcf-netframing-1.9.{0,1}` lines; the DLLs exist. (`artifacts/` is gitignored, so the DLLs are not committed.)

- [ ] **Step 2: Capture the locked findings (manual reference) and confirm the detector by hand**

Run the prefix:
`dotnet run --project tools/TaintAnalyzer -- artifacts/corewcf-netframing-1.9.0/CoreWCF.NetFramingBase.dll --scan --scan-profile loop --no-symbols`
Expected: findings include `DuplexFramingMiddleware.OnConnectedAsync` and `SingletonFramingMiddleware.OnConnectedAsync`, each `cwe: 835`, `api: pipe_reader_read_async`, `completion_signal: absent`.

Run the postfix:
`dotnet run --project tools/TaintAnalyzer -- artifacts/corewcf-netframing-1.9.1/CoreWCF.NetFramingBase.dll --scan --scan-profile loop --no-symbols`
Expected: `findings: []`.

Save the prefix output verbatim to `fixtures/corewcf-p86g-prefix/findings.yaml` and the postfix output to `fixtures/corewcf-p86g-postfix/findings.yaml` (locked references; `file: ""`/`line: 0` because `--no-symbols`).

> If the prefix is unexpectedly empty, the back-edge of the loop did not survive the async `MoveNext` rewrite — this is the milestone's known risk. Debug by dumping `LoopTerminationAnalyzer.ComputeLoopSpans` over the resolved `MoveNext` of `OnConnectedAsync`; adjust span detection (e.g. include `leave`/`Switch` targets, already handled) before proceeding. Do not weaken the completion check to force a finding.

- [ ] **Step 3: Write the end-to-end test (guarded by artifact presence)**

`tools/TaintAnalyzer.Tests/CoreWcfP86gFixtureTests.cs`:

```csharp
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class CoreWcfP86gFixtureTests
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

    private static string Dll(string ver) =>
        Path.Combine(RepoRoot, "artifacts", $"corewcf-netframing-{ver}", "CoreWCF.NetFramingBase.dll");

    private static string RunLoop(string dll)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        Program.Run(new[] { dll, "--scan", "--scan-profile", "loop", "--no-symbols" }, o, e)
            .ShouldBe(0, $"stderr: {e}");
        return o.ToString();
    }

    [Fact]
    public void Prefix_1_9_0_FlagsBothFramingMiddlewares()
    {
        var dll = Dll("1.9.0");
        if (!File.Exists(dll)) return; // artifact not materialized in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("cwe: 835");
        outText.ShouldContain("api: pipe_reader_read_async");
        outText.ShouldContain("DuplexFramingMiddleware.OnConnectedAsync");
        outText.ShouldContain("SingletonFramingMiddleware.OnConnectedAsync");
    }

    [Fact]
    public void Postfix_1_9_1_ProducesNoFindings()
    {
        var dll = Dll("1.9.1");
        if (!File.Exists(dll)) return; // artifact not materialized in this checkout

        var outText = RunLoop(dll);
        outText.ShouldContain("findings: []");
        outText.ShouldNotContain("DuplexFramingMiddleware");
    }
}
```

- [ ] **Step 4: Run the e2e test**

Run: `dotnet test tools/TaintAnalyzer.Tests --filter CoreWcfP86gFixtureTests`
Expected: PASS (2 tests — they run because the artifacts were materialized in Step 1).

- [ ] **Step 5: Document the profile in README**

In `README.md`, in the scan-mode section, add a `loop` example after the SQLi one:

````markdown
# Loop-termination scan (CWE-835): read loops with no completion check
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --scan-profile loop
````

And update the `--scan-profile` flag row in the flag table:

```markdown
| `--scan-profile dos\|sqli\|loop` | Selects what `--scan` enumerates and reports (default `dos`). `loop` finds read loops with no completion check (CWE-835). Requires `--scan`. |
```

- [ ] **Step 6: Run the full suite**

Run: `dotnet test TaintAnalyzer.sln`
Expected: PASS (all green).

- [ ] **Step 7: Commit**

```bash
git add scripts/materialize-corewcf-netframing.sh fixtures/corewcf-p86g-prefix/findings.yaml fixtures/corewcf-p86g-postfix/findings.yaml tools/TaintAnalyzer.Tests/CoreWcfP86gFixtureTests.cs README.md
git commit -m "fixture+docs: CoreWCF GHSA-p86g loop-termination e2e; README loop profile

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Tier 1 (read present ∧ completion absent) → Tasks 2, 3. Tier 2 (back-edge gate) → Task 2 (`EnclosingRange` / `ComputeLoopSpans`, validated by `ClearsSingleReadNotInLoop`). ✓
- PipeReader + Stream/Socket recognizers → Task 1; PipeReader completion → Task 2; Stream/Socket completion → Task 3. ✓
- New finding schema + emitter → Task 4. ✓
- Async `MoveNext` resolution → Task 2 (`AsyncStateMachineResolver`), proven by `ResolvedViaAsync` assertion and the CoreWCF e2e. ✓
- Enumeration without source-shape + Loop visibility relaxation → Task 5. ✓
- CLI `--scan-profile loop` + guards → Task 6. ✓
- CoreWCF prefix/postfix fixture + materialize script + docs → Task 7. ✓
- Stated limitation (idiom, not provable non-termination; Stream/Socket heuristic bounds) → comments in Task 1/3 and README note. ✓

**Placeholder scan:** No TBD/TODO. The Task 2 `StreamCompletionPresent` stub returning `false` is intentional and explicitly replaced in Task 3. ✓

**Type consistency:** `ReadMatch(Kind, Api)`, `ReadKind`, `LoopFinding` field names (`Method`, `ReadApi`, `ResolvedViaAsync`, `LoopFile`, `LoopLine`, `ReadFile`, `ReadLine`), `RecognizeRead`, `IsPipeCompletionSignal`, `Analyze`, `Emit`, `EnumerateLoopCandidates` are used identically across all tasks. ✓
```
