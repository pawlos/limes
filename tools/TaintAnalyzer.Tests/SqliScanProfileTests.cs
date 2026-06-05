using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliScanProfileTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Default_StringSourceTypes_ContainsString()
    {
        EnumeratorConfig.Default.StringSourceTypes.ShouldContain("System.String");
    }

    private static List<SourceMethodEntry> SqliEnumerate()
    {
        var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var reach = new SqlSinkReachability(ctx.Assembly);
        return EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph, ScanProfile.Sqli, reach)
            .ToList();
    }

    [Fact]
    public void Sqli_MatchesStringParamReachingSink()
    {
        SqliEnumerate().ShouldContain(e =>
            e.Signature.Contains("StringParamQuery::Where(System.String)"));
    }

    [Fact]
    public void Sqli_MatchesThisFieldFragment_WithStringSeed()
    {
        var apply = SqliEnumerate()
            .FirstOrDefault(e => e.Signature.Contains("FieldFragment::Apply("));
        apply.ShouldNotBeNull();
        apply!.SeedThisFields.ShouldNotBeNull();
        apply.SeedThisFields!.ShouldContain("_regConfig");
    }

    [Fact]
    public void Sqli_GatesOutNonSinkStringMethod()
    {
        SqliEnumerate().ShouldNotContain(e => e.Signature.Contains("StringNoSink::Log"));
    }

    [Fact]
    public void DosProfile_DoesNotEnumerateStringSources()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        // 3-arg overload == dos profile == today's behaviour.
        var entries = EntryPointEnumerator.Enumerate(ctx, EnumeratorConfig.Default, graph).ToList();
        entries.ShouldNotContain(e => e.Signature.Contains("StringParamQuery::Where"));
    }
}
