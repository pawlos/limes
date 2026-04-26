using Shouldly;
using TaintAnalyzer;
using TaintAnalyzer.ValidateFixture;
using YamlDotNet.Serialization;

namespace TaintAnalyzer.Tests;

public class TraceEmitterTests
{
    [Fact]
    public void Emit_SyntheticHops_ProducesValidYaml()
    {
        var rules = new RulesDocument { VulnId = "test-0001", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
        };
        var propagator = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Propagator,
            TaintedValueIn = "stream", Transformation = "arithmetic", TaintedValueOut = "size",
            Dispatch = new ResolvedDispatch { Kind = "direct", StaticType = "Ns.T", ResolvedTargets = Array.Empty<string>(), ClosureBoundary = false },
        };
        var sink = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size",
        };
        var absences = new List<EmittedSanitizerAbsence>
        {
            new() { Location = "T.cs:15", TaintedValue = "size", ExpectedCheck = "size must be bounded before reaching new_array at T.cs:20" },
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, propagator, sink }, absences);

        yaml.ShouldContain("vuln_id: test-0001");
        yaml.ShouldContain("method: Ns.T.M");
        yaml.ShouldContain("kind: allocation");
        yaml.ShouldContain("api: new_array");
        yaml.ShouldContain("tainted_value: size");
        yaml.ShouldContain("expected_check: ");
    }

    [Fact]
    public void Emit_PostFixWithSanitizer_EmitsEmptySanitizerAbsenceList()
    {
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 1, Role = HopRole.Source,
            TaintedValueIn = "n", Transformation = "read_stream", TaintedValueOut = "n",
        };
        var sanitizerHop = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 2, Role = HopRole.Sanitizer,
            TaintedValueIn = "n", Transformation = "identity", TaintedValueOut = "n",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "1024" },
            OnFailure = new OnFailure { Kind = FailureKind.Throw, Exception = "System.ArgumentOutOfRangeException" },
            Dispatch = new ResolvedDispatch { Kind = "direct", StaticType = "Ns.T", ResolvedTargets = Array.Empty<string>(), ClosureBoundary = false },
        };
        var sink = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 3, Role = HopRole.Sink,
            TaintedValueIn = "n", Transformation = "identity", TaintedValueOut = "n",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sanitizerHop, sink },
            Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldMatch(@"sanitizer_absence:\s*\[\s*\]");
    }

    [Fact]
    public void Emit_OmittedVulnId_DoesNotEmitKey()
    {
        var rules = new RulesDocument { VulnId = null, SourceMethods = new() { "Ns.T::M()" } };
        var sourceHop = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 1, Role = HopRole.Source,
            TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
        };
        var sink = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 2, Role = HopRole.Sink,
            TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "x",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { sourceHop, sink }, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldNotContain("vuln_id:");
    }

    [Fact]
    public void Emit_TwoSinks_ProducesTwoDocumentsSeparatedByDocMarker()
    {
        // Two sinks reached from the same source — emitter should produce a multi-document YAML
        // with `---` between docs. Each document repeats the source and shares the propagator
        // prefix; the sink and the immediately-preceding propagator differ.
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var src = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
        };
        var prop1 = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Propagator,
            TaintedValueIn = "stream", Transformation = "arithmetic", TaintedValueOut = "n1",
        };
        var sink1 = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "n1", Transformation = "identity", TaintedValueOut = "n1",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n1",
        };
        var prop2 = new HopRecord
        {
            Hop = 3, Method = "Ns.T.M", File = "T.cs", Line = 25, Role = HopRole.Propagator,
            TaintedValueIn = "stream", Transformation = "arithmetic", TaintedValueOut = "n2",
        };
        var sink2 = new HopRecord
        {
            Hop = 4, Method = "Ns.T.M", File = "T.cs", Line = 30, Role = HopRole.Sink,
            TaintedValueIn = "n2", Transformation = "identity", TaintedValueOut = "n2",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "n2",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { src, prop1, sink1, prop2, sink2 }, Array.Empty<EmittedSanitizerAbsence>());

        // Two sinks → two documents. The serializer emits a `...\n` doc-end marker between docs.
        var docs = yaml.Split("\n---\n");
        docs.Length.ShouldBe(2);

        // First doc → sink at line 20 with size_expression n1.
        docs[0].ShouldContain("line: 20");
        docs[0].ShouldContain("size_expression: n1");
        docs[0].ShouldNotContain("line: 30");

        // Second doc → sink at line 30, size_expression n2.
        docs[1].ShouldContain("line: 30");
        docs[1].ShouldContain("size_expression: n2");
    }

    [Fact]
    public void Emit_NoSinks_ReturnsEmptyOutput()
    {
        // Walker found no tainted sink. Emitter shouldn't crash; it should return empty output
        // so the caller writes an empty file / stdout (analyzer reports nothing found).
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M()" } };
        var src = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 1, Role = HopRole.Source,
            TaintedValueIn = "x", Transformation = "identity", TaintedValueOut = "x",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { src }, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldBeEmpty();
    }

    [Fact]
    public void Emit_SinkWithoutPrecedingSanitizer_SynthesizesAbsenceAtPreSinkPropagator()
    {
        // Pre-fix shape: source → propagator → sink, no sanitizer. Emitter synthesizes one
        // sanitizer_absence pointing at the propagator immediately preceding the sink.
        // (The walker no longer synthesizes — the emitter has the per-sink path context.)
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var src = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "n", Transformation = "read_stream", TaintedValueOut = "n",
        };
        var prop = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Propagator,
            TaintedValueIn = "n", Transformation = "arithmetic", TaintedValueOut = "size",
        };
        var sink = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { src, prop, sink }, Array.Empty<EmittedSanitizerAbsence>());

        yaml.ShouldContain("location: T.cs:15");           // pre-sink propagator's location
        yaml.ShouldContain("tainted_value: size");
        yaml.ShouldContain("must be bounded before reaching new_array at T.cs:20");
    }

    [Fact]
    public void Emit_SanitizerBetweenSinks_AbsenceOnFirstOnly()
    {
        // First sink has no sanitizer on its path (source → propagator → sink1) → absence.
        // Second sink is preceded by a sanitizer that appears between sink1 and sink2 → no absence.
        // Demonstrates that "sanitizer on path" uses full path from source to that specific sink.
        var rules = new RulesDocument { VulnId = "v", SourceMethods = new() { "Ns.T::M(System.Int32)" } };
        var src = new HopRecord
        {
            Hop = 0, Method = "Ns.T.M", File = "T.cs", Line = 10, Role = HopRole.Source,
            TaintedValueIn = "n", Transformation = "read_stream", TaintedValueOut = "n",
        };
        var prop1 = new HopRecord
        {
            Hop = 1, Method = "Ns.T.M", File = "T.cs", Line = 13, Role = HopRole.Propagator,
            TaintedValueIn = "n", Transformation = "arithmetic", TaintedValueOut = "size1",
        };
        var sink1 = new HopRecord
        {
            Hop = 2, Method = "Ns.T.M", File = "T.cs", Line = 15, Role = HopRole.Sink,
            TaintedValueIn = "size1", Transformation = "identity", TaintedValueOut = "size1",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size1",
        };
        var sanitizer = new HopRecord
        {
            Hop = 3, Method = "Ns.T.M", File = "T.cs", Line = 17, Role = HopRole.Sanitizer,
            TaintedValueIn = "n", Transformation = "identity", TaintedValueOut = "n",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "1024" },
            OnFailure = new OnFailure { Kind = FailureKind.Throw, Exception = "System.ArgumentOutOfRangeException" },
        };
        var prop2 = new HopRecord
        {
            Hop = 4, Method = "Ns.T.M", File = "T.cs", Line = 18, Role = HopRole.Propagator,
            TaintedValueIn = "n", Transformation = "arithmetic", TaintedValueOut = "size2",
        };
        var sink2 = new HopRecord
        {
            Hop = 5, Method = "Ns.T.M", File = "T.cs", Line = 20, Role = HopRole.Sink,
            TaintedValueIn = "size2", Transformation = "identity", TaintedValueOut = "size2",
            SinkKind = SinkKind.Allocation, SinkApi = SinkApi.NewArray, SizeExpression = "size2",
        };

        var yaml = TraceEmitter.Emit(rules, new[] { src, prop1, sink1, sanitizer, prop2, sink2 }, Array.Empty<EmittedSanitizerAbsence>());

        var docs = yaml.Split("\n---\n");
        docs.Length.ShouldBe(2);

        // First doc: only prop1 between source and sink1 → no sanitizer on path → absence at line 13.
        docs[0].ShouldContain("line: 15");
        docs[0].ShouldContain("location: T.cs:13");
        docs[0].ShouldContain("tainted_value: size1");

        // Second doc: prop1 + sanitizer + prop2 between source and sink2 → sanitizer on path → no absence.
        docs[1].ShouldContain("line: 20");
        docs[1].ShouldMatch(@"sanitizer_absence:\s*\[\s*\]");
    }
}
