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

    [Fact]
    public void Enumerate_ThisFieldShape_GatedByConfig()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);

        // Default config: NOT included.
        var withoutFlag = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();
        withoutFlag.ShouldNotContain(e => e.Signature.Contains("StreamInputDecoder::ReadString"));

        // With flag: included AND emits seed_this_fields.
        var withFlag = EntryPointEnumerator
            .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
            .ToList();
        var entry = withFlag.FirstOrDefault(e => e.Signature.Contains("StreamInputDecoder::ReadString"));
        entry.ShouldNotBeNull();
        entry!.SeedThisFields.ShouldNotBeNull();
        entry.SeedThisFields!.ShouldContain("_input");
    }

    [Fact]
    public void Enumerate_ThisFieldShape_RequiresMatchingTypeName()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
            .ToList();

        // NotADecoderType holds a Stream field but its name doesn't match any pattern.
        entries.ShouldNotContain(e => e.Signature.Contains("NotADecoderType::ReadString"));
    }

    [Fact]
    public void Enumerate_ThisFieldShape_RequiresByteSourceField()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, new EnumeratorConfig { IncludeThisField = true }, graph)
            .ToList();

        // EmptyDecoder matches the type-name pattern but has no Stream field.
        entries.ShouldNotContain(e => e.Signature.Contains("EmptyDecoder::ReadString"));
    }

    [Fact]
    public void Enumerate_RejectsPrivateAndProtectedMethods()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("HasPrivateAndProtected::PrivateMethod"));
        entries.ShouldNotContain(e => e.Signature.Contains("HasPrivateAndProtected::ProtectedMethod"));
    }

    [Fact]
    public void Enumerate_AcceptsReachableInternal()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldContain(e => e.Signature.Contains("InternalReachable::Helper"));
    }

    [Fact]
    public void Enumerate_RejectsOrphanInternal()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var graph = new ReverseCallGraph(ctx.Assembly);
        var entries = EntryPointEnumerator
            .Enumerate(ctx, EnumeratorConfig.Default, graph)
            .ToList();

        entries.ShouldNotContain(e => e.Signature.Contains("InternalOrphan::Orphan"));
    }
}
