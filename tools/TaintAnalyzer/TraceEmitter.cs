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
        var rawSinkIndices = new List<int>();
        var sourceIndices = new List<int>();
        for (int i = 0; i < hops.Count; i++)
        {
            if (hops[i].Role == HopRole.Sink) rawSinkIndices.Add(i);
            else if (hops[i].Role == HopRole.Source) sourceIndices.Add(i);
        }

        if (rawSinkIndices.Count == 0)
        {
            // No sinks reached — emit empty output. Caller (Program.cs) writes nothing to stdout
            // / output file, indicating "analyzer found no tainted sink for these rules".
            return "";
        }

        // U8 — dedup sinks by (method, sink-shape, primary-operand-name). Extends milestone-D's
        // U1.a (which used (method, line)) to collapse multiple sinks of the same shape with the
        // same load-bearing operand within one method — even when they fire at distinct lines.
        // Models the #3074 case: three `new byte[colorMapSizeBytes]` calls in
        // BmpDecoderCore.ReadFileHeader at distinct lines all share key
        // (BmpDecoderCore.ReadFileHeader, (allocation, new_array), colorMapSizeBytes).
        //
        // Primary-operand-name resolution order:
        //   1. SizeExpression (allocation sinks).
        //   2. AccessExpression (span sinks).
        //   3. TaintedValueIn (defensive fallback — every sink hop has this).
        var sinkIndices = new List<int>();
        var seenSinkKeys = new HashSet<(string method, SinkKind kind, SinkApi api, string operand)>();
        foreach (int idx in rawSinkIndices)
        {
            var sh = hops[idx];
            var operand = sh.SizeExpression
                ?? sh.AccessExpression
                ?? sh.TaintedValueIn;
            var key = (sh.Method ?? "", sh.SinkKind!.Value, sh.SinkApi!.Value, operand);
            if (seenSinkKeys.Add(key))
            {
                sinkIndices.Add(idx);
            }
        }

        // U11 — path-prefix fingerprint dedup: group sinks sharing the same first 3 distinct
        // propagator-method names. Same-method sinks within a group are all kept (distinct sites).
        // Cross-method sinks: keep the one with the most arithmetic/field_load hops in its own
        // method (most load-bearing); tiebreak by depth.
        sinkIndices = FingerprintDedup(hops, sinkIndices, sourceIndices);

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
            // U9 — collapse adjacent redundant hops. Runs unconditionally (not gated on --strict)
            // so the YAML the user reads matches what the validator counts.
            pathHops = CollapseAdjacentRedundantHops(pathHops);
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
            // A sanitizer is "on the path for this sink" only if it's in the SAME method as the
            // sink AND its `establishes_bound.target` is on the sink's transitive value chain.
            // The same-method filter rejects callee-side sanitizers (e.g., format-marker switches
            // in ReadFileHeader). The transitive-chain filter rejects in-method sanitizers that
            // bound an unrelated local — e.g., `ReadInternationalTextChunk` has checks on
            // `compressionFlag`/`languageLength` but none on `translatedKeywordLength`, so a
            // `translatedKeywordLength`-fed Slice should still emit absence.
            //
            // The chain is seeded with BOTH the sink's local-debug-name tainted_value and its
            // FirstTaintedProvenance (the IL-level derivation chain). The first names the local
            // ("colorMapSizeBytes"), the second names the upstream values that fed it
            // ("BmpFileHeader.get_Offset+..."). Both forms appear in real fixtures' sanitizer
            // targets, so we include both. The chain is then grown by walking same-method
            // propagators backwards.
            var sinkLocal = sinkHop.SizeExpression ?? sinkHop.AccessExpression ?? sinkHop.TaintedValueIn ?? "";
            var sinkProv = sinkHop.FirstTaintedProvenance ?? "";
            var chainTokens = BuildTransitiveValueChainTokens(sinkLocal + " " + sinkProv, pathHops, sinkHop.Method);
            bool hasSanitizer = pathHops.Any(h =>
                h.Role == HopRole.Sanitizer
                && h.Method == sinkHop.Method
                && SanitizerBoundMatchesSink(h, chainTokens));
            if (!hasSanitizer && pathHops.Count > 0)
            {
                var sinkApi = SinkApiToString(sinkHop.SinkApi) ?? "unknown";
                string location;
                string taintedValue;

                if (sinkHop.FirstTaintedLine is { } firstLine && sinkHop.FirstTaintedFile is { } firstFile)
                {
                    location = $"{firstFile}:{firstLine}";
                    // Combine the local-debug-name (e.g., `translatedKeywordLength` — what
                    // fixture authors typically use) with the IL-level FirstTaintedProvenance
                    // (e.g., `BmpFileHeader.get_Offset+...` — what some fixture authors use to
                    // name upstream values). Concatenating both makes the soft-match resilient
                    // to either fixture-author convention without needing bidirectional name
                    // normalization. The tokenizer ignores non-alphanumeric separators.
                    var localPart = sinkHop.SizeExpression ?? sinkHop.AccessExpression ?? sinkHop.TaintedValueIn ?? "";
                    var provPart = sinkHop.FirstTaintedProvenance ?? "";
                    taintedValue = (localPart, provPart) switch
                    {
                        ("", "") => "",
                        ("", var p) => p,
                        (var l, "") => l,
                        var (l, p) when l == p => l,
                        var (l, p) => $"{l} (via {p})",
                    };
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
                    // Combine the sink's own tainted_value (typically the parameter/local name
                    // at the sink site, e.g., `count`) with the preSink hop's value-out (the
                    // upstream propagation chain, e.g., `StreamExtensions.ReadBytesExactly`).
                    // Same rationale as the firstLine branch — fixtures use either name; both
                    // tokens contribute to soft-match.
                    var preChain = preSink.TaintedValueOut ?? "";
                    taintedValue = (sinkValueChain, preChain) switch
                    {
                        ("", "") => "",
                        ("", var p) => p,
                        (var l, "") => l,
                        var (l, p) when l == p => l,
                        var (l, p) => $"{l} (via {p})",
                    };
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
            ResolvedVia = h.ResolvedVia,
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

    // Token-overlap test: does the sanitizer's bound TARGET share a token with the sink's
    // transitive value chain? Conservative: when the chain is empty or the sanitizer has no
    // bound info, count as guarding (matches pre-refinement behavior of "any same-method
    // sanitizer suppresses absence"). Restricting to target (not upper/lower) avoids false
    // suppression by checks like `stream.Position <= offset - colorMapSizeBytes` — that
    // references colorMapSizeBytes in its bound *expression* but actually constrains
    // stream.Position, not the colorMapSizeBytes that feeds the allocation.
    private static bool SanitizerBoundMatchesSink(HopRecord sanitizer, HashSet<string> chainTokens)
    {
        if (chainTokens.Count == 0) return true;
        var target = sanitizer.EstablishesBound?.Target;
        if (string.IsNullOrEmpty(target)) return true;
        var tgtTokens = TokenizeForMatch(target);
        if (tgtTokens.Count == 0) tgtTokens = ShortTokens(target);
        return tgtTokens.Overlaps(chainTokens);
    }

    // Build the set of tokens reachable from the sink's tainted value by walking propagators
    // backwards. A same-method propagator whose `tainted_value_out` already has a token in the
    // current chain contributes its `tainted_value_in` to the chain. Iterates to fixpoint
    // (capped at hop count). Used so a sanitizer that bounds an upstream local in the chain
    // (e.g., `n` flowing to `size2` via arithmetic) is recognized as guarding the sink.
    private static HashSet<string> BuildTransitiveValueChainTokens(string seed, IReadOnlyList<HopRecord> hops, string sinkMethod)
    {
        var chain = TokenizeForMatch(seed);
        if (chain.Count == 0) chain = ShortTokens(seed);
        bool grew;
        int iter = 0;
        do
        {
            grew = false;
            foreach (var h in hops)
            {
                if (h.Role != HopRole.Propagator) continue;
                if (h.Method != sinkMethod) continue;
                var outTokens = TokenizeForMatch(h.TaintedValueOut ?? "");
                if (outTokens.Count == 0) outTokens = ShortTokens(h.TaintedValueOut ?? "");
                if (!outTokens.Overlaps(chain)) continue;
                var inTokens = TokenizeForMatch(h.TaintedValueIn ?? "");
                if (inTokens.Count == 0) inTokens = ShortTokens(h.TaintedValueIn ?? "");
                foreach (var t in inTokens)
                {
                    if (chain.Add(t)) grew = true;
                }
            }
        } while (grew && ++iter < hops.Count);
        return chain;
    }

    private static HashSet<string> TokenizeForMatch(string s)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        var sb = new System.Text.StringBuilder();
        foreach (var c in s)
        {
            if (char.IsLetterOrDigit(c)) sb.Append(c);
            else if (sb.Length > 0)
            {
                if (sb.Length >= 4) set.Add(sb.ToString().ToLowerInvariant());
                sb.Clear();
            }
        }
        if (sb.Length >= 4) set.Add(sb.ToString().ToLowerInvariant());
        return set;
    }

    // Fallback tokenizer for short identifiers (single-letter/digit locals like `n`/`i`) —
    // returns ALL alphanumeric runs regardless of length, so a sanitizer bounding `n` and a
    // sink-chain entry `n` still match.
    private static HashSet<string> ShortTokens(string s)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        var sb = new System.Text.StringBuilder();
        foreach (var c in s)
        {
            if (char.IsLetterOrDigit(c)) sb.Append(c);
            else if (sb.Length > 0) { set.Add(sb.ToString().ToLowerInvariant()); sb.Clear(); }
        }
        if (sb.Length > 0) set.Add(sb.ToString().ToLowerInvariant());
        return set;
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
        SinkApi.Stackalloc => "stackalloc",
        SinkApi.HttpContentRead => "http_content_read",
        SinkApi.HttpClientRead => "http_client_read",
        _ => null,
    };

    // U11 helpers — path-prefix fingerprint dedup.

    private static int FindPrecedingSourceIndex(List<int> sourceIndices, int sinkIdx)
    {
        for (int j = sourceIndices.Count - 1; j >= 0; j--)
        {
            if (sourceIndices[j] < sinkIdx) return sourceIndices[j];
        }
        return -1;
    }

    private static int CountInMethodArithmeticHops(
        IReadOnlyList<HopRecord> hops, int sourceIdx, int sinkIdx, string? sinkMethod)
    {
        int count = 0;
        for (int i = sourceIdx + 1; i < sinkIdx; i++)
        {
            var hop = hops[i];
            if (hop.Role == HopRole.Propagator
                && hop.Method == sinkMethod
                && (hop.Transformation == "arithmetic" || hop.Transformation == "field_load"))
                count++;
        }
        return count;
    }

    private static (string, string, string) ComputeFingerprint(
        IReadOnlyList<HopRecord> hops, int sourceIdx, int sinkIdx)
    {
        // First 3 distinct method names in the propagator path (method must change from
        // the previous hop's method to count as a new entry).
        var methods = new List<string>(3);
        string? prev = null;
        for (int i = sourceIdx + 1; i < sinkIdx && methods.Count < 3; i++)
        {
            var hop = hops[i];
            if (hop.Role != HopRole.Propagator) continue;
            if (hop.Method != prev)
            {
                methods.Add(hop.Method);
                prev = hop.Method;
            }
        }
        while (methods.Count < 3) methods.Add("");
        return (methods[0], methods[1], methods[2]);
    }

    private static List<int> FingerprintDedup(
        IReadOnlyList<HopRecord> hops,
        List<int> sinkIndices,
        List<int> sourceIndices)
    {
        // Group sinks by path-prefix fingerprint.
        var groups = new Dictionary<(string, string, string), List<int>>();
        var orphans = new List<int>(); // sinks with no preceding source

        foreach (int sinkIdx in sinkIndices)
        {
            int sourceIdx = FindPrecedingSourceIndex(sourceIndices, sinkIdx);
            if (sourceIdx < 0) { orphans.Add(sinkIdx); continue; }
            var fp = ComputeFingerprint(hops, sourceIdx, sinkIdx);
            if (!groups.TryGetValue(fp, out var group))
                groups[fp] = group = new List<int>();
            group.Add(sinkIdx);
        }

        var result = new List<int>(orphans);
        foreach (var group in groups.Values)
        {
            if (group.Count == 1) { result.Add(group[0]); continue; }

            // If all sinks in this group are in the same method, keep them all —
            // they are distinct vulnerability sites within the same callee.
            bool allSameMethod = group.Select(idx => hops[idx].Method).Distinct().Count() == 1;
            if (allSameMethod) { result.AddRange(group); continue; }

            // Different sink methods: keep the one with the most arithmetic+field_load
            // propagator hops within its own sink method. This prefers the sink where the
            // dangerous size value is locally computed (most load-bearing).
            // When tied on score, prefer the deeper sink (larger sinkIdx - sourceIdx).
            int bestIdx = group[0];
            int bestScore = -1;
            int bestDepth = -1;
            foreach (int sinkIdx in group)
            {
                int sourceIdx = FindPrecedingSourceIndex(sourceIndices, sinkIdx);
                int score = CountInMethodArithmeticHops(hops, sourceIdx, sinkIdx, hops[sinkIdx].Method);
                int depth = sinkIdx - sourceIdx;
                if (score > bestScore || (score == bestScore && depth > bestDepth))
                {
                    bestIdx = sinkIdx;
                    bestScore = score;
                    bestDepth = depth;
                }
            }
            result.Add(bestIdx);
        }

        result.Sort();
        return result;
    }

    // U9 — adjacent identical-tuple hop dedup. Runs after `pathHops` is built per document,
    // collapsing redundant runs that the walker's emission generated. Two sub-rules in one pass:
    //
    //   Rule 1 (identity special case): `hop[i+1].transformation == "identity"` AND
    //                                   `hop[i+1].method == hop[i].method` → drop hop[i+1].
    //                                   Catches in-method identity chains spanning distinct lines
    //                                   that milestone-D's U2 (call-boundary filter) misses.
    //
    //   Rule 2 (general tuple match): `(method, file, line, transformation, tainted_value_in)` of
    //                                  hop[i+1] equals that of hop[i] → drop hop[i+1].
    //                                  Catches non-identity adjacent repeats.
    //
    // Source/sink/sanitizer hops are never in pathHops (they're top-level in the doc), so we
    // never collapse them. Sanitizer hops *can* be in pathHops — they're never dropped because
    // their (transformation, method) tuple, while sometimes "identity" same-method, is gated
    // by their distinct Role. We check Role explicitly to be safe.
    private static List<HopRecord> CollapseAdjacentRedundantHops(IReadOnlyList<HopRecord> pathHops)
    {
        if (pathHops.Count < 2) return new List<HopRecord>(pathHops);

        var result = new List<HopRecord>(pathHops.Count) { pathHops[0] };
        for (int i = 1; i < pathHops.Count; i++)
        {
            var prev = result[^1];
            var curr = pathHops[i];

            // Never collapse sanitizer hops — they carry FX063 / FX023 audit signal.
            if (curr.Role == HopRole.Sanitizer || prev.Role == HopRole.Sanitizer)
            {
                result.Add(curr);
                continue;
            }

            // Rule 1 — identity special case.
            bool rule1 = curr.Transformation == "identity" && curr.Method == prev.Method;

            // Rule 2 — general tuple match.
            bool rule2 = curr.Method == prev.Method
                && curr.File == prev.File
                && curr.Line == prev.Line
                && curr.Transformation == prev.Transformation
                && curr.TaintedValueIn == prev.TaintedValueIn;

            if (rule1 || rule2)
            {
                continue; // drop curr
            }
            result.Add(curr);
        }
        return result;
    }
}
