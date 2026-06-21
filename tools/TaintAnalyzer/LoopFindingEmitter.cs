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
