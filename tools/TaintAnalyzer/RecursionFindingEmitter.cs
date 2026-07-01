using System.Text;

namespace TaintAnalyzer;

// Hand-rolled deterministic YAML for CWE-674 recursion findings, mirroring LoopFindingEmitter.
// Findings are sorted so the document is stable and lockable.
public static class RecursionFindingEmitter
{
    public static string Emit(string vulnId, IReadOnlyList<RecursionFinding> findings)
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
            .ThenBy(f => f.CallLine)
            .ThenBy(f => f.CallFile, StringComparer.Ordinal);

        sb.AppendLine("findings:");
        foreach (var f in ordered)
        {
            sb.AppendLine("  - cwe: 674");
            sb.Append("    method: ").AppendLine(f.Method);
            sb.Append("    recursion: ").AppendLine(f.Kind);
            if (f.ResolvedViaAsync) sb.AppendLine("    resolved_via: async_state_machine");
            if (f.Kind == "mutual" && f.Cycle is not null)
            {
                sb.AppendLine("    cycle:");
                foreach (var member in f.Cycle)
                    sb.Append("      - ").AppendLine(member);
            }
            sb.AppendLine("    call:");
            sb.Append("      file: \"").Append(f.CallFile).AppendLine("\"");
            sb.Append("      line: ").AppendLine(f.CallLine.ToString());
            sb.AppendLine("    guard: absent");
        }
        return sb.ToString();
    }
}
