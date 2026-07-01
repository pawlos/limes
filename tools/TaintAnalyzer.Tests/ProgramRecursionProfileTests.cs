using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class ProgramRecursionProfileTests
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
    public void RecursionProfile_FlagsUnguarded_ClearsGuarded()
    {
        var (code, outText, _) = Run(FixturePath, "--scan", "--scan-profile", "recursion");
        code.ShouldBe(0);
        outText.ShouldContain("cwe: 674");
        outText.ShouldContain("ReferenceHolder.ResolveTarget");
        outText.ShouldContain("OpenApiReferenceHolder.get_RecursiveTarget");
        outText.ShouldNotContain("GuardedReferenceHolder");
        outText.ShouldNotContain("DepthLimitedHolder");
        outText.ShouldNotContain("PlainResolver");
        // Mutual-recursion (SCC) cycle is flagged; guarded mutual cycle is cleared.
        outText.ShouldContain("recursion: mutual");
        outText.ShouldContain("MutualA.Resolve");
        outText.ShouldNotContain("GuardedMutualA");
    }

    [Fact]
    public void RecursionProfile_RequiresScan()
    {
        var (code, _, errText) = Run(FixturePath, "--rules", "r.yaml", "--scan-profile", "recursion");
        code.ShouldBe(2);
        errText.ShouldContain("--scan-profile requires --scan");
    }

    [Fact]
    public void RecursionProfile_RejectsEmitRules()
    {
        var (code, _, errText) = Run(FixturePath, "--scan", "--scan-profile", "recursion", "--emit-rules", "x.yaml");
        code.ShouldBe(2);
        errText.ShouldContain("--emit-rules");
    }
}
