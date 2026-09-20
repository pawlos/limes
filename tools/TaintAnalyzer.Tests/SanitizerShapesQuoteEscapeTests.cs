using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SanitizerShapesQuoteEscapeTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition Find(AssemblyContext ctx, string typeName, string methodName) =>
        ctx.AllMethods().First(m => m.DeclaringType.FullName == $"TaintAnalyzer.Tests.Fixtures.{typeName}"
                                 && m.Name == methodName);

    [Fact]
    public void Escape_QuoteDoubling_Matches()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFixtures", "Escape");

        var matches = SanitizerShapes.MatchSqlQuoteEscapes(m).ToList();

        matches.Count.ShouldBe(1);
        var callOffsets = m.Body.Instructions
            .Where(i => i.Operand is MethodReference mr && mr.Name == "Replace")
            .Select(i => i.Offset)
            .ToList();
        callOffsets.ShouldContain(matches[0].CallIlOffset);
    }

    [Theory]
    [InlineData("DoubleQuoteEscape")]
    [InlineData("StripQuote")]
    [InlineData("CharOverload")]
    [InlineData("EscapeViaLocals")]
    public void NonQuoteDoublingShapes_DoNotMatch(string methodName)
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFixtures", methodName);

        SanitizerShapes.MatchSqlQuoteEscapes(m).ShouldBeEmpty();
    }

    [Fact]
    public void MethodWithoutReplace_DoesNotMatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = Find(ctx, "QuoteEscapeFragment", "ApplyRaw");

        SanitizerShapes.MatchSqlQuoteEscapes(m).ShouldBeEmpty();
    }
}
