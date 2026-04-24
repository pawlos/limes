using TaintAnalyzer.ValidateFixture;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer;

public static class TraceEmitter
{
    private static readonly ISerializer s_serializer = new SerializerBuilder()
        .WithNamingConvention(NullNamingConvention.Instance)   // emitter uses YamlMember aliases on FixtureDocument
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();

    public static string Emit(
        RulesDocument rules,
        IReadOnlyList<HopRecord> hops,
        IReadOnlyList<EmittedSanitizerAbsence> absences)
    {
        var sourceHop = hops.First(h => h.Role == HopRole.Source);
        var sinkHop = hops.First(h => h.Role == HopRole.Sink);

        var doc = new FixtureDocument
        {
            VulnId = rules.VulnId,
            Source = PathNodeFromHop(sourceHop),
            Sink = PathNodeFromHop(sinkHop),
            Path = hops
                .Where(h => h.Role is HopRole.Propagator or HopRole.Sanitizer)
                .Select(PathNodeFromHop)
                .ToList(),
            SanitizerAbsence = absences
                .Select(a => new SanitizerAbsence
                {
                    Location = a.Location,
                    TaintedValue = a.TaintedValue,
                    ExpectedCheck = a.ExpectedCheck,
                })
                .ToList(),
        };

        return s_serializer.Serialize(doc);
    }

    private static PathNode PathNodeFromHop(HopRecord h)
    {
        var dispatch = h.Dispatch is { } d
            ? new Dispatch
            {
                Kind = d.Kind,
                StaticType = d.StaticType,
                ResolvedTargets = d.ResolvedTargets.ToList(),
                ClosureBoundary = d.ClosureBoundary,
            }
            : null;

        var eb = h.EstablishesBound is { } bound
            ? new ValidateFixture.EstablishesBound { Target = bound.Target, Relation = bound.Relation, UpperBound = bound.UpperBound, LowerBound = bound.LowerBound }
            : null;

        var onFail = h.OnFailure is { } of
            ? new ValidateFixture.OnFailure
            {
                Kind = of.Kind switch { FailureKind.Throw => "throw", FailureKind.ReturnEarly => "return_early", _ => "unknown" },
                Exception = of.Exception,
            }
            : null;

        return new PathNode
        {
            Hop = h.Role is HopRole.Source or HopRole.Sink ? null : h.Hop,
            Method = h.Method,
            File = h.File,
            Line = h.Line,
            Role = h.Role switch
            {
                HopRole.Source => "source",
                HopRole.Propagator => "propagator",
                HopRole.Sanitizer => "sanitizer",
                HopRole.Sink => "sink",
                _ => "unknown",
            },
            TaintedValueIn = h.TaintedValueIn,
            Transformation = h.Transformation,
            TaintedValueOut = h.TaintedValueOut,
            Note = h.Note,
            Dispatch = dispatch,
            EstablishesBound = eb,
            OnFailure = onFail,
            Kind = h.Role == HopRole.Sink ? SinkKindToString(h.SinkKind) :
                   h.Role == HopRole.Source ? "decoder_entry" : null,
            Api = h.Role == HopRole.Sink ? SinkApiToString(h.SinkApi) : null,
            SizeExpression = h.SizeExpression,
            AccessExpression = h.AccessExpression,
        };
    }

    private static string? SinkKindToString(SinkKind? k) => k switch
    {
        SinkKind.Allocation => "allocation",
        SinkKind.SpanAccess => "span_access",
        _ => null,
    };

    private static string? SinkApiToString(SinkApi? a) => a switch
    {
        SinkApi.NewArray => "new_array",
        SinkApi.ArrayPoolRent => "array_pool_rent",
        SinkApi.SpanSlice => "span_slice",
        SinkApi.SpanIndex => "span_index",
        _ => null,
    };
}
