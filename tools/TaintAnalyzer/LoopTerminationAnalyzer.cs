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
