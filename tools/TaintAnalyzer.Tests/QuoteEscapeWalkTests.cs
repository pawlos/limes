using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class QuoteEscapeWalkTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == $"TaintAnalyzer.Tests.Fixtures.{typeName}"
                                 && m.Name == methodName);

    [Fact]
    public void RawAppendOfTaintedField_ReachesRawSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFragment", "ApplyRaw"), 0, new[] { "_key" });

        summary.ReachedSink.ShouldBeTrue();
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.SqlCommandBuilderAppendRaw);
    }

    [Fact]
    public void QuoteEscapedAppend_EmitsSanitizerHopAndNoSink()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFragment", "ApplyEscaped"), 0, new[] { "_key" });

        summary.ReachedSink.ShouldBeFalse();

        var sanitizers = summary.Hops.Where(h => h.Role == HopRole.Sanitizer).ToList();
        sanitizers.Count.ShouldBe(1);
        sanitizers[0].Transformation.ShouldBe("sql_quote_escape");
        sanitizers[0].TaintedValueIn.ShouldBe("_key");
        sanitizers[0].TaintedValueOut.ShouldBe("sql_quote_escaped(_key)");
        sanitizers[0].EstablishesBound.ShouldBeNull();
        sanitizers[0].OnFailure.ShouldBeNull();
    }

    [Fact]
    public void UntaintedEscape_EmitsNoSanitizerHop()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var walker = new TaintWalker(ctx);

        // No seed: `s` is untainted, so the Replace result is untainted and nothing is reported.
        var summary = walker.WalkWithSeed(Find(ctx, "QuoteEscapeFixtures", "Escape"), 0, Array.Empty<string>());

        summary.Hops.ShouldNotContain(h => h.Role == HopRole.Sanitizer);
    }
}
