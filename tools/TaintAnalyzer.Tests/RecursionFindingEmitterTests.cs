using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class RecursionFindingEmitterTests
{
    [Fact]
    public void EmitsEmptyFindingsList()
    {
        var yaml = RecursionFindingEmitter.Emit("scan-x", new List<RecursionFinding>());
        yaml.ShouldContain("vuln_id: scan-x");
        yaml.ShouldContain("findings: []");
    }

    [Fact]
    public void EmitsFindingWithCweAndGuardAbsent()
    {
        var yaml = RecursionFindingEmitter.Emit("scan-x", new List<RecursionFinding>
        {
            new() { Method = "N.T.M", ResolvedViaAsync = false, CallFile = "T.cs", CallLine = 12 },
        });
        yaml.ShouldContain("cwe: 674");
        yaml.ShouldContain("method: N.T.M");
        yaml.ShouldContain("recursion: self");
        yaml.ShouldContain("line: 12");
        yaml.ShouldContain("guard: absent");
        yaml.ShouldNotContain("resolved_via");
    }

    [Fact]
    public void EmitsMutualCycleWithMembers()
    {
        var yaml = RecursionFindingEmitter.Emit("scan-x", new List<RecursionFinding>
        {
            new()
            {
                Method = "N.A.M", ResolvedViaAsync = false, CallFile = "A.cs", CallLine = 7,
                Kind = "mutual", Cycle = new[] { "N.A.M", "N.B.M" },
            },
        });
        yaml.ShouldContain("recursion: mutual");
        yaml.ShouldContain("cycle:");
        yaml.ShouldContain("- N.A.M");
        yaml.ShouldContain("- N.B.M");
        yaml.ShouldContain("guard: absent");
    }

    [Fact]
    public void EmitsAsyncMarkerAndSortsDeterministically()
    {
        var yaml = RecursionFindingEmitter.Emit("scan-x", new List<RecursionFinding>
        {
            new() { Method = "N.T.Zeta", ResolvedViaAsync = true, CallFile = "b.cs", CallLine = 5 },
            new() { Method = "N.T.Alpha", ResolvedViaAsync = false, CallFile = "a.cs", CallLine = 9 },
        });
        yaml.ShouldContain("resolved_via: async_state_machine");
        yaml.IndexOf("N.T.Alpha", StringComparison.Ordinal)
            .ShouldBeLessThan(yaml.IndexOf("N.T.Zeta", StringComparison.Ordinal));
    }
}
