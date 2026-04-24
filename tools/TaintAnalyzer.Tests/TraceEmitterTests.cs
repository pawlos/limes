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
}
