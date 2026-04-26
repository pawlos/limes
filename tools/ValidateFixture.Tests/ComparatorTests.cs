using Shouldly;
using TaintAnalyzer.ValidateFixture;

namespace TaintAnalyzer.ValidateFixture.Tests;

public class ComparatorTests
{
    private readonly Comparator _comparator = new();

    private static FixtureDocument MakeDocument(
        PathNode? source = null,
        PathNode? sink = null,
        IEnumerable<PathNode>? path = null,
        IEnumerable<SanitizerAbsence>? absences = null)
    {
        return new FixtureDocument
        {
            Source = source,
            Sink = sink,
            Path = path?.ToList(),
            SanitizerAbsence = absences?.ToList() ?? new List<SanitizerAbsence>(),
        };
    }

    private static PathNode SourceNode(string method = "Ns.T.M", string file = "T.cs", int line = 10) => new()
    {
        Method = method, File = file, Line = line, Role = "source",
        Kind = "decoder_entry",
        TaintedValueIn = "stream", Transformation = "read_stream", TaintedValueOut = "stream",
    };

    private static PathNode SinkNode(string method = "Ns.T.M", string file = "T.cs", int line = 100,
        string kind = "allocation", string api = "new_array") => new()
    {
        Method = method, File = file, Line = line, Role = "sink",
        Kind = kind, Api = api,
        TaintedValueIn = "size", Transformation = "identity", TaintedValueOut = "size",
        SizeExpression = "size",
    };

    [Fact]
    public void Compare_IdenticalDocs_NoDiagnostics()
    {
        var src = SourceNode();
        var sink = SinkNode();
        var gt = MakeDocument(src, sink);
        var an = MakeDocument(src, sink);

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldBeEmpty();
    }

    [Fact]
    public void Compare_NoMatchingSinkInAnalyzer_ReportsFX061()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(line: 100));
        var anWithDifferentSink = MakeDocument(SourceNode(), SinkNode(line: 200));

        var diags = _comparator.Compare(gt, new[] { anWithDifferentSink });

        diags.ShouldContain(d => d.Code == "FX061" && d.Message.Contains("not found in analyzer"));
    }

    [Fact]
    public void Compare_AnalyzerHasMultipleDocs_PicksMatchingByMethodAndFileLine()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(line: 200, api: "new_array"));
        var anDoc1 = MakeDocument(SourceNode(), SinkNode(line: 100, api: "new_array"));
        var anDoc2 = MakeDocument(SourceNode(), SinkNode(line: 200, api: "new_array"));   // matches
        var anDoc3 = MakeDocument(SourceNode(), SinkNode(line: 300, api: "new_array"));

        var diags = _comparator.Compare(gt, new[] { anDoc1, anDoc2, anDoc3 });

        diags.Where(d => d.Code != "FX-info").ShouldBeEmpty();
    }

    [Fact]
    public void Compare_FilesEncodedWithDoubleUnderscore_NormalizedForMatching()
    {
        // Ground-truth fixtures encode paths as `src__ImageSharp__Bmp__File.cs`; analyzer
        // emits the basename `File.cs`. Comparator normalizes both.
        var gt = MakeDocument(SourceNode(file: "src__ImageSharp__Bmp__File.cs", line: 10),
                              SinkNode(file: "src__ImageSharp__Bmp__File.cs", line: 100));
        var an = MakeDocument(SourceNode(file: "File.cs", line: 10),
                              SinkNode(file: "File.cs", line: 100));

        var diags = _comparator.Compare(gt, new[] { an });

        diags.Where(d => d.Code != "FX-info").ShouldBeEmpty();
    }

    [Fact]
    public void Compare_FX060_SourceMethodMismatch_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(method: "Ns.T.M"), SinkNode());
        var an = MakeDocument(SourceNode(method: "Ns.T.Other"), SinkNode());

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX060" && d.Message.Contains("method"));
    }

    [Fact]
    public void Compare_FX060_SourceLineWithinTolerance_NoDiagnostic()
    {
        // Source line tolerated within ±2 (declaration-vs-body-opening-brace ambiguity).
        var gt = MakeDocument(SourceNode(line: 128), SinkNode());
        var an = MakeDocument(SourceNode(line: 129), SinkNode());

        var diags = _comparator.Compare(gt, new[] { an });

        diags.Where(d => d.Code == "FX060").ShouldBeEmpty();
    }

    [Fact]
    public void Compare_FX060_SourceLineOutsideTolerance_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(line: 10), SinkNode());
        var an = MakeDocument(SourceNode(line: 99), SinkNode());

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX060" && d.Message.Contains("location"));
    }

    [Fact]
    public void Compare_FX061_SinkKindMismatch_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(kind: "allocation"));
        var an = MakeDocument(SourceNode(), SinkNode(kind: "span_access"));

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX061" && d.Message.Contains("kind"));
    }

    [Fact]
    public void Compare_FX061_SinkApiMismatch_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(api: "new_array"));
        var an = MakeDocument(SourceNode(), SinkNode(api: "array_pool_rent"));

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX061" && d.Message.Contains("api"));
    }

    [Fact]
    public void Compare_FX062_AbsenceCountMismatch_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "x", ExpectedCheck = "..." },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            absences: Array.Empty<SanitizerAbsence>());

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("count"));
    }

    [Fact]
    public void Compare_FX062_AbsenceTaintedValueDisjointTokens_ReportsDiagnostic()
    {
        // Tokens have no overlap of length ≥ 4 — strict mismatch.
        var gt = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "alphabet", ExpectedCheck = "human prose" },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "betalpha", ExpectedCheck = "auto-generated" },
            });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("tainted_value"));
        // expected_check is NOT compared, but it's surfaced as context when other fields mismatch.
        diags.Single(d => d.Code == "FX062" && d.Message.Contains("tainted_value"))
            .Message.ShouldContain("human prose");
    }

    [Fact]
    public void Compare_FX062_AbsenceTaintedValueSoftMatchOnSharedToken_NoDiagnostic()
    {
        // Real-world divergence: fixture uses C# member syntax, analyzer uses Cecil-style names.
        // Soft-match accepts when at least one tokenized substring of length ≥ 4 appears in both.
        // Mirrors the #3074 case where "Offset" appears in both sides' tainted_value strings.
        var gt = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "fileHeader.Value.Offset", ExpectedCheck = "..." },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "BmpFileHeader.get_Offset+BmpInfoHeader.get_HeaderSize", ExpectedCheck = "..." },
            });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.Where(d => d.Code == "FX062").ShouldBeEmpty();
    }

    [Fact]
    public void Compare_FX062_AbsenceLocationWithinTolerance_NoDiagnostic()
    {
        // Spec: ±2 line tolerance on absence location.
        var gt = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "x", ExpectedCheck = "..." },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:52", TaintedValue = "x", ExpectedCheck = "..." },
            });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.Where(d => d.Code == "FX062").ShouldBeEmpty();
    }

    [Fact]
    public void Compare_FX062_AbsenceLocationOutsideTolerance_ReportsDiagnostic()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:50", TaintedValue = "x", ExpectedCheck = "..." },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            absences: new[] {
                new SanitizerAbsence { Location = "T.cs:60", TaintedValue = "x", ExpectedCheck = "..." },
            });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX062" && d.Message.Contains("location"));
    }

    [Fact]
    public void Compare_FX063_SanitizerHopMissing_ReportsDiagnostic()
    {
        var sanitizer = new PathNode
        {
            Method = "Ns.T.M", File = "T.cs", Line = 50, Role = "sanitizer",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "1024" },
            OnFailure = new OnFailure { Kind = "throw", Exception = "System.IO.IOException" },
        };
        var gt = MakeDocument(SourceNode(), SinkNode(), path: new[] { sanitizer });
        var an = MakeDocument(SourceNode(), SinkNode(), path: Array.Empty<PathNode>());

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("not present"));
    }

    [Fact]
    public void Compare_FX063_SanitizerHopBoundMismatch_ReportsDiagnostic()
    {
        var gtSanitizer = new PathNode
        {
            Method = "Ns.T.M", File = "T.cs", Line = 50, Role = "sanitizer",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "1024" },
            OnFailure = new OnFailure { Kind = "throw", Exception = "System.IO.IOException" },
        };
        var anSanitizer = new PathNode
        {
            Method = "Ns.T.M", File = "T.cs", Line = 50, Role = "sanitizer",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = "<=", UpperBound = "65536" },
            OnFailure = new OnFailure { Kind = "throw", Exception = "System.IO.IOException" },
        };
        var gt = MakeDocument(SourceNode(), SinkNode(), path: new[] { gtSanitizer });
        var an = MakeDocument(SourceNode(), SinkNode(), path: new[] { anSanitizer });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("upper_bound"));
    }

    [Fact]
    public void Compare_FX063_OnFailureKindMismatch_ReportsDiagnostic()
    {
        var gtSan = new PathNode
        {
            Method = "Ns.T.M", File = "T.cs", Line = 50, Role = "sanitizer",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = ">=", LowerBound = "0" },
            OnFailure = new OnFailure { Kind = "throw", Exception = "System.IO.IOException" },
        };
        var anSan = new PathNode
        {
            Method = "Ns.T.M", File = "T.cs", Line = 50, Role = "sanitizer",
            EstablishesBound = new EstablishesBound { Target = "n", Relation = ">=", LowerBound = "0" },
            OnFailure = new OnFailure { Kind = "return_early" },
        };
        var gt = MakeDocument(SourceNode(), SinkNode(), path: new[] { gtSan });
        var an = MakeDocument(SourceNode(), SinkNode(), path: new[] { anSan });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.ShouldContain(d => d.Code == "FX063" && d.Message.Contains("on_failure.kind"));
    }

    [Fact]
    public void Compare_HopCountDelta_EmitsInfoNotFailure()
    {
        var gt = MakeDocument(SourceNode(), SinkNode(),
            path: new[] {
                new PathNode { Role = "propagator", Method = "Ns.T.M", File = "T.cs", Line = 20 },
            });
        var an = MakeDocument(SourceNode(), SinkNode(),
            path: new[] {
                new PathNode { Role = "propagator", Method = "Ns.T.M", File = "T.cs", Line = 20 },
                new PathNode { Role = "propagator", Method = "Ns.T.M", File = "T.cs", Line = 30 },
                new PathNode { Role = "propagator", Method = "Ns.T.M", File = "T.cs", Line = 40 },
            });

        var diags = _comparator.Compare(gt, new[] { an });

        diags.Where(d => d.Code != "FX-info").ShouldBeEmpty();   // no failure
        diags.ShouldContain(d => d.Code == "FX-info" && d.Message.Contains("propagator hop count delta"));
    }

    [Fact]
    public void LoadAll_MultiDocumentYaml_ReturnsAllDocuments()
    {
        const string yaml = """
            vuln_id: a
            sink:
              line: 100
            ---
            vuln_id: b
            sink:
              line: 200
            """;

        var docs = Comparator.LoadAll(yaml);

        docs.Count.ShouldBe(2);
        docs[0].VulnId.ShouldBe("a");
        docs[1].VulnId.ShouldBe("b");
    }

    [Fact]
    public void LoadAll_SingleDocumentYaml_ReturnsSingletonList()
    {
        const string yaml = "vuln_id: only\nsink:\n  line: 100\n";

        var docs = Comparator.LoadAll(yaml);

        docs.Count.ShouldBe(1);
        docs[0].VulnId.ShouldBe("only");
    }
}
