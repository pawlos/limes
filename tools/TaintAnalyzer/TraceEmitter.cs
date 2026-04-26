using System.Text;
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

    // Emits one YAML document per (source, sink) pair, separated by `\n---\n`. Each document is a
    // self-contained FixtureDocument (source + sink + path + sanitizer_absence). The walker's flat
    // hop list is partitioned per-sink: each sink's path is the propagator/sanitizer hops between
    // the most-recent preceding Source hop and the sink itself. Sibling sinks reachable from the
    // same source share their prefix hops (those hops appear in both documents) — refining to
    // "ancestors only" partitioning would need per-hop call-depth tracking and is out of scope.
    //
    // Sanitizer-absence synthesis lives here (not in the walker) because per-sink path context is
    // required: an absence is synthesized only when the path between source and sink contains no
    // sanitizer hop. The `absences` parameter is retained for API compatibility; the walker passes
    // an empty list and the emitter ignores it.
    public static string Emit(
        RulesDocument rules,
        IReadOnlyList<HopRecord> hops,
        IReadOnlyList<EmittedSanitizerAbsence> absences)
    {
        _ = absences;   // walker no longer synthesizes; per-sink synthesis below uses the path

        // Index source/sink hops by position in the flat list so we can pair each sink with the
        // most-recent preceding source.
        var sinkIndices = new List<int>();
        var sourceIndices = new List<int>();
        for (int i = 0; i < hops.Count; i++)
        {
            if (hops[i].Role == HopRole.Sink) sinkIndices.Add(i);
            else if (hops[i].Role == HopRole.Source) sourceIndices.Add(i);
        }

        if (sinkIndices.Count == 0)
        {
            // No sinks reached — emit empty output. Caller (Program.cs) writes nothing to stdout
            // / output file, indicating "analyzer found no tainted sink for these rules".
            return "";
        }

        var sb = new StringBuilder();
        for (int s = 0; s < sinkIndices.Count; s++)
        {
            int sinkIdx = sinkIndices[s];
            var sinkHop = hops[sinkIdx];

            // Most-recent source preceding this sink.
            int sourceIdx = -1;
            for (int j = sourceIndices.Count - 1; j >= 0; j--)
            {
                if (sourceIndices[j] < sinkIdx) { sourceIdx = sourceIndices[j]; break; }
            }
            if (sourceIdx < 0)
            {
                // No source before this sink — defensive; shouldn't happen with our walker since
                // Program.cs always inserts a Source hop before each walked source method.
                continue;
            }
            var sourceHop = hops[sourceIdx];

            // Path: propagator/sanitizer hops between source and sink. We renumber the hops
            // sequentially (0, 1, 2, …) within each document so each trace reads as a self-
            // contained chain, mirroring the human-authored fixture style.
            var pathHops = new List<HopRecord>();
            for (int i = sourceIdx + 1; i < sinkIdx; i++)
            {
                if (hops[i].Role is HopRole.Propagator or HopRole.Sanitizer)
                {
                    pathHops.Add(hops[i]);
                }
            }
            var pathNodes = new List<PathNode>(pathHops.Count);
            for (int i = 0; i < pathHops.Count; i++)
            {
                pathNodes.Add(PathNodeFromHop(pathHops[i] with { Hop = i }));
            }

            // Per-sink absence: synthesize one entry only if no sanitizer hop appears on this
            // sink's path. Five-level location preference (most-to-least specific):
            //
            //   1. The walker's `FirstTaintedLine` — when the sink reads its size/access value
            //      directly from a local (e.g., `new T[localVar]`), the walker tracks where
            //      that local FIRST received a tainted assignment. This points at the value's
            //      origin even when linear walking re-assigned the local across branches.
            //   2. First propagator in the sink's method whose `tainted_value_out` is a
            //      substring of the sink's `size_expression` / `access_expression` — picks a
            //      hop on the actual value chain feeding the sink.
            //   3. First *value-introducing* propagator in the sink's method — `arithmetic` /
            //      `field_load` / `cast` / `read_stream` (skip `identity`, the call-boundary
            //      marker). Used when no provenance substring matches.
            //   4. Any propagator in the sink's method — only call-boundary identity hops.
            //   5. Last path hop — sink reached with no in-method propagator.
            var sinkAbsences = new List<SanitizerAbsence>();
            bool hasSanitizer = pathHops.Any(h => h.Role == HopRole.Sanitizer);
            if (!hasSanitizer && pathHops.Count > 0)
            {
                var sinkApi = SinkApiToString(sinkHop.SinkApi) ?? "unknown";
                string location;
                string taintedValue;

                if (sinkHop.FirstTaintedLine is { } firstLine && sinkHop.FirstTaintedFile is { } firstFile)
                {
                    location = $"{firstFile}:{firstLine}";
                    // Prefer the first-tainted provenance (snapshot at the earliest stloc to
                    // the size local) over the sink's `size_expression`. The latter reflects
                    // the linear walker's *last* write to the local — which can come from a
                    // sibling branch and lose information about the actual first-tainted
                    // value chain.
                    taintedValue = sinkHop.FirstTaintedProvenance
                                   ?? sinkHop.SizeExpression
                                   ?? sinkHop.AccessExpression
                                   ?? sinkHop.TaintedValueIn;
                }
                else
                {
                    var sinkValueChain = sinkHop.SizeExpression
                                         ?? sinkHop.AccessExpression
                                         ?? sinkHop.TaintedValueIn
                                         ?? "";
                    var preSink =
                        pathHops.FirstOrDefault(h => h.Role == HopRole.Propagator
                                                  && h.Method == sinkHop.Method
                                                  && IsValueIntroducing(h.Transformation)
                                                  && !string.IsNullOrEmpty(h.TaintedValueOut)
                                                  && sinkValueChain.Contains(h.TaintedValueOut!, StringComparison.Ordinal))
                        ?? pathHops.FirstOrDefault(h => h.Role == HopRole.Propagator
                                                  && h.Method == sinkHop.Method
                                                  && IsValueIntroducing(h.Transformation))
                        ?? pathHops.FirstOrDefault(h => h.Role == HopRole.Propagator && h.Method == sinkHop.Method)
                        ?? pathHops[^1];
                    location = $"{preSink.File}:{preSink.Line}";
                    taintedValue = preSink.TaintedValueOut;
                }

                sinkAbsences.Add(new SanitizerAbsence
                {
                    Location = location,
                    TaintedValue = taintedValue,
                    ExpectedCheck = $"{taintedValue} must be bounded before reaching {sinkApi} at {sinkHop.File}:{sinkHop.Line}",
                });
            }

            var doc = new FixtureDocument
            {
                VulnId = rules.VulnId,
                Source = PathNodeFromHop(sourceHop),
                Sink = PathNodeFromHop(sinkHop),
                Path = pathNodes,
                SanitizerAbsence = sinkAbsences,
            };

            if (sb.Length > 0) sb.Append("---\n");
            sb.Append(s_serializer.Serialize(doc));
        }

        return sb.ToString();
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

    // Transformations that introduce a tainted value via computation, vs `identity` which is
    // just the cross-method call boundary marker.
    private static bool IsValueIntroducing(string? transformation)
        => transformation is "arithmetic" or "field_load" or "cast" or "read_stream";

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
