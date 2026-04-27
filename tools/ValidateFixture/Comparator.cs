using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace TaintAnalyzer.ValidateFixture;

// Compares one ground-truth FixtureDocument against the analyzer's multi-document output.
// Multi-doc selection: pick the analyzer doc whose `sink.method` + normalized `sink.file:line`
// matches the ground truth. If no doc matches → FX061 (ground-truth sink not present in analyzer
// output). Once matched, run FX060 / FX061 / FX062 / FX063 checks against that doc.
//
// File-name normalization: ground-truth fixtures encode paths as `src__ImageSharp__...__File.cs`
// (the snippets-archive convention); analyzer output emits just the basename `File.cs`. Both are
// normalized via "replace `__` with path separator → take basename" so cross-format comparison
// works without forcing either side to change its representation.
public sealed class Comparator
{
    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    private const int DefaultDocMultiplier = 3;
    private const int DefaultDocSlack = 1;
    private const int DefaultHopMultiplier = 5;
    private const int DefaultHopSlack = 10;
    private const int StrictHopMultiplier = 2;

    public IReadOnlyList<Diagnostic> Compare(FixtureDocument groundTruth, IReadOnlyList<FixtureDocument> analyzerDocs)
    {
        var diagnostics = new List<Diagnostic>();

        if (groundTruth.Sink is null)
        {
            diagnostics.Add(new Diagnostic("FX061", "sink mismatch: ground-truth has no sink"));
            return diagnostics;
        }

        var matched = FindMatchingDoc(groundTruth, analyzerDocs);
        if (matched is null)
        {
            var gtSink = groundTruth.Sink;
            diagnostics.Add(new Diagnostic("FX061",
                $"sink mismatch: ground-truth sink not found in analyzer output. " +
                $"expected={gtSink.Method} at {NormalizeFile(gtSink.File)}:{gtSink.Line}. " +
                $"analyzer reported {analyzerDocs.Count} document(s) with sinks: " +
                string.Join(", ", analyzerDocs.Select(d =>
                    $"{d.Sink?.Method}@{NormalizeFile(d.Sink?.File)}:{d.Sink?.Line}"))));
            return diagnostics;
        }

        CompareSource(groundTruth, matched, diagnostics);
        CompareSink(groundTruth, matched, diagnostics);
        CompareSanitizerAbsence(groundTruth, matched, diagnostics);
        CompareSanitizerHops(groundTruth, matched, diagnostics);

        // Informational only — never fails.
        var gtPathCount = groundTruth.Path?.Count ?? 0;
        var anPathCount = matched.Path?.Count ?? 0;
        if (gtPathCount != anPathCount)
        {
            diagnostics.Add(new Diagnostic("FX-info",
                $"propagator hop count delta: ground-truth={gtPathCount}, analyzer={anPathCount}"));
        }

        return diagnostics;
    }

    // Reads a YAML stream possibly containing multiple `---`-separated documents into a list of
    // FixtureDocument. Empty documents are skipped. Single-doc inputs return a 1-element list.
    public static IReadOnlyList<FixtureDocument> LoadAll(string yaml)
    {
        var docs = new List<FixtureDocument>();
        var parser = new Parser(new StringReader(yaml));
        parser.Consume<StreamStart>();
        while (parser.Accept<DocumentStart>(out _))
        {
            var doc = s_deserializer.Deserialize<FixtureDocument>(parser);
            if (doc is not null) docs.Add(doc);
        }
        return docs;
    }

    private static FixtureDocument? FindMatchingDoc(FixtureDocument groundTruth, IReadOnlyList<FixtureDocument> analyzerDocs)
    {
        var gtSink = groundTruth.Sink!;
        foreach (var doc in analyzerDocs)
        {
            var anSink = doc.Sink;
            if (anSink is null) continue;
            if (!StringEqualsIgnoringNull(anSink.Method, gtSink.Method)) continue;
            if (!FilesMatch(anSink.File, gtSink.File)) continue;
            if (anSink.Line != gtSink.Line) continue;
            return doc;
        }
        return null;
    }

    private static void CompareSource(FixtureDocument gt, FixtureDocument an, List<Diagnostic> diagnostics)
    {
        var g = gt.Source;
        var a = an.Source;
        if (g is null || a is null)
        {
            if (g != a) diagnostics.Add(new Diagnostic("FX060", $"source mismatch: presence expected={(g is null ? "<null>" : "<set>")} actual={(a is null ? "<null>" : "<set>")}"));
            return;
        }
        if (!StringEqualsIgnoringNull(g.Method, a.Method))
        {
            diagnostics.Add(new Diagnostic("FX060", $"source mismatch: method expected={g.Method} actual={a.Method}"));
        }
        // Source line tolerated within ±2: human-authored fixtures typically pin the source line
        // at the method's *declaration* line, while the analyzer derives line from the first
        // PDB sequence point in the body — which Roslyn places at the opening brace, one line
        // below the declaration. The two conventions are off by 1 in the common case; ±2
        // covers braces-on-same-line and other minor stylistic variations without giving up
        // file or method-name strictness.
        bool fileMatches = FilesMatch(g.File, a.File);
        bool lineWithinTolerance = g.Line.HasValue && a.Line.HasValue && Math.Abs(g.Line.Value - a.Line.Value) <= 2;
        if (!fileMatches || !lineWithinTolerance)
        {
            diagnostics.Add(new Diagnostic("FX060",
                $"source mismatch: location expected={NormalizeFile(g.File)}:{g.Line} actual={NormalizeFile(a.File)}:{a.Line} (±2 lines tolerance)"));
        }
    }

    private static void CompareSink(FixtureDocument gt, FixtureDocument an, List<Diagnostic> diagnostics)
    {
        // The matched doc was chosen so method/file:line align — we only re-check kind/api here.
        var g = gt.Sink!;
        var a = an.Sink!;
        if (!StringEqualsIgnoringNull(g.Kind, a.Kind))
        {
            diagnostics.Add(new Diagnostic("FX061", $"sink mismatch: kind expected={g.Kind} actual={a.Kind} at {NormalizeFile(g.File)}:{g.Line}"));
        }
        if (!StringEqualsIgnoringNull(g.Api, a.Api))
        {
            diagnostics.Add(new Diagnostic("FX061", $"sink mismatch: api expected={g.Api} actual={a.Api} at {NormalizeFile(g.File)}:{g.Line}"));
        }
    }

    private static void CompareSanitizerAbsence(FixtureDocument gt, FixtureDocument an, List<Diagnostic> diagnostics)
    {
        var gtList = gt.SanitizerAbsence ?? new List<SanitizerAbsence>();
        var anList = an.SanitizerAbsence ?? new List<SanitizerAbsence>();

        // Both empty → post-fix doc agreement. Pass.
        if (gtList.Count == 0 && anList.Count == 0) return;

        // GT has absences but analyzer has none → analyzer missed the unsanitized flow entirely.
        if (gtList.Count > 0 && anList.Count == 0)
        {
            diagnostics.Add(new Diagnostic("FX062",
                $"sanitizer_absence mismatch: ground-truth declares {gtList.Count} absence(s) but analyzer reports none"));
            return;
        }

        // Analyzer reported absences but GT declares none → analyzer false-positive.
        if (gtList.Count == 0 && anList.Count > 0)
        {
            diagnostics.Add(new Diagnostic("FX062",
                $"sanitizer_absence mismatch: ground-truth declares no absence but analyzer reports {anList.Count} (likely false-positive)"));
            return;
        }

        // Both have entries: each analyzer entry must match SOME ground-truth entry. Analyzer is
        // allowed to underapproximate (emit fewer absences than the fixture authors documented —
        // e.g., #3079 has one fixture absence per unsanitized value but our emitter produces one
        // absence per sink). Surplus ground-truth entries that don't have an analyzer counterpart
        // are surfaced as info (`FX-info`) so they're visible without failing the comparison.
        for (int ai = 0; ai < anList.Count; ai++)
        {
            var a = anList[ai];
            var matchedIdx = FindMatchingGroundTruth(gtList, a);
            if (matchedIdx < 0)
            {
                diagnostics.Add(new Diagnostic("FX062",
                    $"sanitizer_absence mismatch: analyzer entry {ai} (location={a.Location} tainted_value={a.TaintedValue}) " +
                    $"has no matching ground-truth entry (location ±2 lines AND tainted_value soft-match)"));
            }
        }

        if (gtList.Count > anList.Count)
        {
            diagnostics.Add(new Diagnostic("FX-info",
                $"sanitizer_absence count delta: ground-truth={gtList.Count}, analyzer={anList.Count} (analyzer underapproximation tolerated)"));
        }
    }

    private static int FindMatchingGroundTruth(IReadOnlyList<SanitizerAbsence> gtList, SanitizerAbsence a)
    {
        var (anFile, anLine) = ParseLocation(a.Location);
        for (int i = 0; i < gtList.Count; i++)
        {
            var g = gtList[i];
            var (gtFile, gtLine) = ParseLocation(g.Location);
            bool fileMatches = FilesMatch(gtFile, anFile);
            bool lineWithinTolerance = gtLine.HasValue && anLine.HasValue && Math.Abs(gtLine.Value - anLine.Value) <= 2;
            if (fileMatches && lineWithinTolerance && TaintedValueSoftMatch(g.TaintedValue, a.TaintedValue))
            {
                return i;
            }
        }
        return -1;
    }

    private static void CompareSanitizerHops(FixtureDocument gt, FixtureDocument an, List<Diagnostic> diagnostics)
    {
        var gtSanitizers = (gt.Path ?? new List<PathNode>())
            .Where(n => n.Role == "sanitizer").ToList();
        var anSanitizers = (an.Path ?? new List<PathNode>())
            .Where(n => n.Role == "sanitizer").ToList();

        for (int i = 0; i < gtSanitizers.Count; i++)
        {
            var g = gtSanitizers[i];
            // Exact file:line match — sanitizers are point-precise.
            var a = anSanitizers.FirstOrDefault(n => FilesMatch(n.File, g.File) && n.Line == g.Line);
            if (a is null)
            {
                diagnostics.Add(new Diagnostic("FX063",
                    $"sanitizer hop mismatch: ground-truth sanitizer at {NormalizeFile(g.File)}:{g.Line} " +
                    $"not present in analyzer output for hop {i}"));
                continue;
            }

            // establishes_bound: target + relation + (whichever of upper/lower is set on gt).
            if (g.EstablishesBound is { } gb)
            {
                if (a.EstablishesBound is null)
                {
                    diagnostics.Add(new Diagnostic("FX063",
                        $"sanitizer hop mismatch: establishes_bound expected={Describe(gb)} actual=<null> for hop {i}"));
                }
                else
                {
                    var ab = a.EstablishesBound;
                    if (!StringEqualsIgnoringNull(gb.Target, ab.Target))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: establishes_bound.target expected={gb.Target} actual={ab.Target} for hop {i}"));
                    }
                    if (!StringEqualsIgnoringNull(gb.Relation, ab.Relation))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: establishes_bound.relation expected={gb.Relation} actual={ab.Relation} for hop {i}"));
                    }
                    if (gb.UpperBound is not null && !StringEqualsIgnoringNull(gb.UpperBound, ab.UpperBound))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: establishes_bound.upper_bound expected={gb.UpperBound} actual={ab.UpperBound} for hop {i}"));
                    }
                    if (gb.LowerBound is not null && !StringEqualsIgnoringNull(gb.LowerBound, ab.LowerBound))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: establishes_bound.lower_bound expected={gb.LowerBound} actual={ab.LowerBound} for hop {i}"));
                    }
                }
            }

            // on_failure.kind always; on_failure.exception only when kind is "throw".
            if (g.OnFailure is { } gf)
            {
                if (a.OnFailure is null)
                {
                    diagnostics.Add(new Diagnostic("FX063",
                        $"sanitizer hop mismatch: on_failure expected.kind={gf.Kind} actual=<null> for hop {i}"));
                }
                else
                {
                    if (!StringEqualsIgnoringNull(gf.Kind, a.OnFailure.Kind))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: on_failure.kind expected={gf.Kind} actual={a.OnFailure.Kind} for hop {i}"));
                    }
                    if (string.Equals(gf.Kind, "throw", StringComparison.Ordinal)
                        && !StringEqualsIgnoringNull(gf.Exception, a.OnFailure.Exception))
                    {
                        diagnostics.Add(new Diagnostic("FX063",
                            $"sanitizer hop mismatch: on_failure.exception expected={gf.Exception} actual={a.OnFailure.Exception} for hop {i}"));
                    }
                }
            }
        }
    }

    // File-equality with the encoded-path / basename-only normalization. Returns true iff the
    // last path component (after normalization) matches case-sensitively.
    private static bool FilesMatch(string? a, string? b)
    {
        if (a is null && b is null) return true;
        if (a is null || b is null) return false;
        return string.Equals(NormalizeFile(a), NormalizeFile(b), StringComparison.Ordinal);
    }

    private static string NormalizeFile(string? f)
    {
        if (string.IsNullOrEmpty(f)) return "";
        // Replace the snippets-archive separator `__` with a path slash, then take the basename.
        // This makes `src__ImageSharp__Formats__Bmp__File.cs` and `File.cs` both reduce to `File.cs`.
        var withSlashes = f.Replace("__", "/");
        var slashIdx = withSlashes.LastIndexOfAny(new[] { '/', '\\' });
        return slashIdx < 0 ? withSlashes : withSlashes.Substring(slashIdx + 1);
    }

    private static (string? File, int? Line) ParseLocation(string? location)
    {
        if (string.IsNullOrEmpty(location)) return (null, null);
        var idx = location.LastIndexOf(':');
        if (idx < 0) return (location, null);
        var filePart = location.Substring(0, idx);
        if (!int.TryParse(location.AsSpan(idx + 1), out var line)) return (filePart, null);
        return (filePart, line);
    }

    private static bool StringEqualsIgnoringNull(string? a, string? b)
        => string.Equals(a ?? "", b ?? "", StringComparison.Ordinal);

    // tainted_value soft-match: human-authored fixtures use C# member syntax
    // (`fileHeader.Value.Offset`) while the analyzer emits Cecil-style names
    // (`BmpFileHeader.get_Offset+BmpInfoHeader.get_HeaderSize`). Strict equality is
    // unachievable without bidirectional name normalization. Instead, accept when both sides
    // share at least one tokenized substring of length ≥ 4 (case-insensitive). Tokens are
    // alphanumeric runs after splitting on `.`, `+`, `_`, etc. Length-4 floor avoids spurious
    // matches on short identifiers like `n` or `idx`. Returns true on exact match too.
    private static bool TaintedValueSoftMatch(string? gt, string? an)
    {
        if (StringEqualsIgnoringNull(gt, an)) return true;
        if (string.IsNullOrEmpty(gt) || string.IsNullOrEmpty(an)) return false;

        var gtTokens = Tokenize(gt).Where(t => t.Length >= 4).Select(t => t.ToLowerInvariant()).ToHashSet();
        var anTokens = Tokenize(an).Where(t => t.Length >= 4).Select(t => t.ToLowerInvariant()).ToHashSet();
        return gtTokens.Overlaps(anTokens);
    }

    private static IEnumerable<string> Tokenize(string s)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in s)
        {
            if (char.IsLetterOrDigit(c)) sb.Append(c);
            else if (sb.Length > 0) { yield return sb.ToString(); sb.Clear(); }
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    private static string Describe(EstablishesBound b)
    {
        var bound = b.UpperBound is { } u ? $"<= {u}" : b.LowerBound is { } l ? $">= {l}" : "?";
        return $"{b.Target} {b.Relation} {bound}";
    }

    private static string Truncate(string? s, int max = 80)
    {
        if (string.IsNullOrEmpty(s)) return "<empty>";
        return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
    }

    // FX064: over-emission budget. Counts documents and total hops on each side.
    // Default mode: D_a ≤ 3·D_g + 1, H_a ≤ 5·H_g + 10 (warnings only — exit code unchanged).
    // Strict mode:  D_a ≤ D_g,        H_a ≤ 2·H_g       (failures — caller exits 1).
    // `strict` only affects the diagnostic code returned; the caller decides exit code.
    public IReadOnlyList<Diagnostic> CompareBudget(
        IReadOnlyList<FixtureDocument> groundTruth,
        IReadOnlyList<FixtureDocument> analyzer,
        bool strict)
    {
        var diagnostics = new List<Diagnostic>();
        int dG = groundTruth.Count;
        int dA = analyzer.Count;
        int hG = groundTruth.Sum(d => d.Path?.Count ?? 0);
        int hA = analyzer.Sum(d => d.Path?.Count ?? 0);

        int dCeiling = strict ? dG : DefaultDocMultiplier * dG + DefaultDocSlack;
        int hCeiling = strict ? StrictHopMultiplier * hG : DefaultHopMultiplier * hG + DefaultHopSlack;

        if (dA > dCeiling)
        {
            diagnostics.Add(new Diagnostic("FX064",
                $"budget exceeded: documents D_a={dA} (≤{dCeiling}) [{(strict ? "strict" : "default")} mode]"));
        }
        if (hA > hCeiling)
        {
            diagnostics.Add(new Diagnostic("FX064",
                $"budget exceeded: hops H_a={hA} (≤{hCeiling}) [{(strict ? "strict" : "default")} mode]"));
        }
        return diagnostics;
    }
}
