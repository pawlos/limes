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
    {
        // The async state machine (e.g. InternalMiddleware/<OnConnectedAsync>d__0) is
        // compiler-generated and must not be enumerated; we reach it only via async
        // resolution from the user-facing method. The "d__" marker identifies these types.
        Candidates().ShouldNotContain(s => s.Contains("d__"));
    }
}
