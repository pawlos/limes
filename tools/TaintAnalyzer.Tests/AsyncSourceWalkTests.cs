using Shouldly;

namespace TaintAnalyzer.Tests;

public class AsyncSourceWalkTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void AnalyzeAsyncSource_EmitsMatchHttpReadSink_AndMarksResolvedViaAsyncStateMachine()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Find the user-facing async method by name.
        var source = ctx.AllMethods()
            .First(m => m.DeclaringType.FullName == "TaintAnalyzer.Tests.Fixtures.AsyncSinkFixtures"
                     && m.Name == "AsyncReadResponse");

        var resolution = AsyncStateMachineResolver.Resolve(source);
        resolution.RedirectedFromAsync.ShouldBeTrue();

        var walker = new TaintWalker(ctx)
        {
            TaintFromExternalReturns = new[] { "HttpClient::PostAsync" },
        };

        // MoveNext has no parameters; seed captured `this`-fields whose name matches a parameter.
        var smFieldNames = resolution.Method.DeclaringType.Fields
            .Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var seedFields = source.Parameters
            .Select(p => p.Name)
            .Where(name => smFieldNames.Contains(name))
            .ToList();

        var summary = walker.WalkWithSeed(resolution.Method, 0, seedFields);

        // The sink is a MatchHttpRead (HttpContentRead from ReadAsByteArrayAsync).
        summary.Hops.ShouldContain(h => h.Role == HopRole.Sink && h.SinkApi == SinkApi.HttpContentRead);
    }
}
