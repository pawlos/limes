using System.Text;

namespace TaintAnalyzer;

// Hand-rolled emitter rather than reusing YamlDotNet's serializer because the
// SourceMethodEntry shape is dual (scalar vs mapping) and the existing
// SourceMethodEntryConverter only handles the read direction.
//
// Output is deterministic — no maps, no anchors, no random key ordering —
// which keeps fixture-comparison clean.
public static class RulesYamlEmitter
{
    public static string Emit(string vulnId, IReadOnlyList<SourceMethodEntry> entries)
    {
        var sb = new StringBuilder();
        sb.Append("vuln_id: ").AppendLine(vulnId);

        if (entries.Count == 0)
        {
            sb.AppendLine("source_methods: []");
            return sb.ToString();
        }

        sb.AppendLine("source_methods:");
        foreach (var entry in entries)
        {
            bool hasExtras = (entry.SeedThisFields is { Count: > 0 })
                          || (entry.TaintFromExternalReturns is { Count: > 0 });

            if (!hasExtras)
            {
                sb.Append("  - ").AppendLine(entry.Signature);
            }
            else
            {
                sb.Append("  - signature: ").AppendLine(entry.Signature);
                if (entry.SeedThisFields is { Count: > 0 } seeds)
                {
                    sb.AppendLine("    seed_this_fields:");
                    foreach (var f in seeds) sb.Append("      - ").AppendLine(f);
                }
                if (entry.TaintFromExternalReturns is { Count: > 0 } ext)
                {
                    sb.AppendLine("    taint_from_external_returns:");
                    foreach (var s in ext) sb.Append("      - ").AppendLine(s);
                }
            }
        }
        return sb.ToString();
    }
}
