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
