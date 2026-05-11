using Mono.Cecil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class EntryPointEnumeratorTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Enumerate_RejectsCtorTakingStream()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        // .ctor in HasCtorWithStream takes Stream but must be rejected.
        entries.ShouldNotContain(e => e.Signature.Contains("HasCtorWithStream::.ctor"));
    }

    [Fact]
    public void Enumerate_RejectsAbstractMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("HasAbstractMethod::Read"));
    }

    [Fact]
    public void Enumerate_RejectsPropertyAccessors()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("set_Backing"));
        entries.ShouldNotContain(e => e.Signature.Contains("get_Backing"));
    }

    [Fact]
    public void Enumerate_MatchesStreamParameter()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e =>
            e.Signature.Contains("StreamReaderShape::Read(System.IO.Stream)"));
    }

    [Fact]
    public void Enumerate_MatchesSpanByteParameter()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e =>
            e.Signature.Contains("SpanByteReaderShape::Read") &&
            e.Signature.Contains("System.Byte"));
    }

    [Fact]
    public void Enumerate_DoesNotMatchString()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("StringReaderShape::Read"));
    }

    [Fact]
    public void Enumerate_DoesNotMatchSpanInt()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("SpanIntReaderShape::Read"));
    }

    [Fact]
    public void Enumerate_MatchesFileStreamViaBaseTypeWalk()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e => e.Signature.Contains("FileStreamReaderShape::Read"));
    }

    [Fact]
    public void Enumerate_MatchesByteArrayParameter()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e =>
            e.Signature.Contains("ByteArrayReaderShape::Read(System.Byte[])"));
    }

    [Fact]
    public void Enumerate_MatchesBinaryReaderParameter()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e =>
            e.Signature.Contains("BinaryReaderShape::Read(System.IO.BinaryReader)"));
    }
}
