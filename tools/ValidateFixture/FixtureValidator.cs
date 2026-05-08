using System.Collections.Frozen;
using System.IO;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TaintAnalyzer.ValidateFixture;

public sealed record Diagnostic(string Code, string Message);

public sealed class FixtureValidator
{
    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public IReadOnlyList<Diagnostic> Validate(string yaml, string? snippetsDir)
    {
        var diagnostics = new List<Diagnostic>();

        FixtureDocument? doc;
        try
        {
            doc = s_deserializer.Deserialize<FixtureDocument>(yaml);
        }
        catch (YamlException ex)
        {
            diagnostics.Add(new Diagnostic("FX000", $"malformed YAML: {ex.Message}"));
            return diagnostics;
        }

        if (doc is null)
        {
            diagnostics.Add(new Diagnostic("FX000", "document is empty"));
            return diagnostics;
        }

        Require(doc.VulnId, "FX001", "vuln_id", diagnostics);
        Require(doc.FixCommit, "FX002", "fix_commit", diagnostics);
        Require(doc.FixPr, "FX003", "fix_pr", diagnostics);
        Require(doc.Description, "FX004", "description", diagnostics);
        Require(doc.Source, "FX005", "source", diagnostics);
        Require(doc.Sink, "FX006", "sink", diagnostics);
        Require(doc.Path, "FX007", "path", diagnostics);
        Require(doc.SanitizerAbsence, "FX008", "sanitizer_absence", diagnostics);

        if (doc.Sink is { } sinkForVocab)
        {
            CheckVocab(sinkForVocab.Kind, Vocabularies.SinkKinds, "FX015", "sink.kind", diagnostics);
            CheckVocab(sinkForVocab.Api,  Vocabularies.SinkApis,  "FX015", "sink.api",  diagnostics);
        }

        if (doc.Sink is { } sinkForCoupling && sinkForCoupling.Kind is { } sinkKind
            && Vocabularies.SinkKinds.Contains(sinkKind))
        {
            if (string.Equals(sinkKind, "allocation", StringComparison.Ordinal))
            {
                if (sinkForCoupling.Api is { } api && Vocabularies.SinkApis.Contains(api))
                {
                    if (api is not ("new_array" or "array_pool_rent" or "alloc_hglobal" or "memory_pool_rent" or "stackalloc" or "http_content_read" or "http_client_read"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'allocation' is not compatible with sink.api '{api}' (expected one of new_array, array_pool_rent, alloc_hglobal, memory_pool_rent, stackalloc, http_content_read, http_client_read)"));
                    }
                }
                if (string.IsNullOrWhiteSpace(sinkForCoupling.SizeExpression))
                {
                    diagnostics.Add(new Diagnostic("FX024",
                        "sink.kind 'allocation' requires sink.size_expression to be populated"));
                }
            }
            else if (string.Equals(sinkKind, "span_access", StringComparison.Ordinal))
            {
                if (sinkForCoupling.Api is { } api && Vocabularies.SinkApis.Contains(api))
                {
                    if (api is not ("span_index" or "span_slice"))
                    {
                        diagnostics.Add(new Diagnostic("FX024",
                            $"sink.kind 'span_access' is not compatible with sink.api '{api}' (expected span_index or span_slice)"));
                    }
                }
                if (string.IsNullOrWhiteSpace(sinkForCoupling.AccessExpression))
                {
                    diagnostics.Add(new Diagnostic("FX024",
                        "sink.kind 'span_access' requires sink.access_expression to be populated"));
                }
            }
        }

        if (doc.Path is { } path)
        {
            for (int i = 0; i < path.Count; i++)
            {
                var node = path[i];
                CheckVocab(node.Role, Vocabularies.Roles, "FX010", $"path[{i}].role", diagnostics);
                CheckVocab(node.Transformation, Vocabularies.Transformations, "FX011", $"path[{i}].transformation", diagnostics);
                if (node.Dispatch is { Kind: { } dk })
                {
                    CheckVocab(dk, Vocabularies.DispatchKinds, "FX012", $"path[{i}].dispatch.kind", diagnostics);
                }
                if (node.EstablishesBound is { Relation: { } rel })
                {
                    CheckVocab(rel, Vocabularies.Relations, "FX013", $"path[{i}].establishes_bound.relation", diagnostics);
                }
                if (node.OnFailure is { Kind: { } fk })
                {
                    CheckVocab(fk, Vocabularies.FailureKinds, "FX014", $"path[{i}].on_failure.kind", diagnostics);
                }

                if (string.Equals(node.Role, "sanitizer", StringComparison.Ordinal))
                {
                    if (node.EstablishesBound is null)
                    {
                        diagnostics.Add(new Diagnostic("FX023", $"sanitizer node path[{i}] missing required field: establishes_bound"));
                    }
                    else
                    {
                        RequireField(node.EstablishesBound.Target,   "FX023", $"path[{i}].establishes_bound.target",   diagnostics);
                        RequireField(node.EstablishesBound.Relation, "FX023", $"path[{i}].establishes_bound.relation", diagnostics);
                        bool hasUpper = !string.IsNullOrWhiteSpace(node.EstablishesBound.UpperBound);
                        bool hasLower = !string.IsNullOrWhiteSpace(node.EstablishesBound.LowerBound);
                        if (!hasUpper && !hasLower)
                        {
                            diagnostics.Add(new Diagnostic("FX023",
                                $"sanitizer node path[{i}].establishes_bound requires at least one of upper_bound or lower_bound"));
                        }
                    }

                    if (node.OnFailure is null)
                    {
                        diagnostics.Add(new Diagnostic("FX023", $"sanitizer node path[{i}] missing required field: on_failure"));
                    }
                    else
                    {
                        RequireField(node.OnFailure.Kind, "FX023", $"path[{i}].on_failure.kind", diagnostics);
                        if (string.Equals(node.OnFailure.Kind, "throw", StringComparison.Ordinal))
                        {
                            RequireField(node.OnFailure.Exception, "FX023", $"path[{i}].on_failure.exception", diagnostics);
                        }
                    }
                }
            }
        }

        if (doc.Path is { } pathNodes)
        {
            for (int i = 0; i < pathNodes.Count; i++)
            {
                var n = pathNodes[i];
                RequireField(n.Hop, "FX020", $"path[{i}].hop", diagnostics);
                RequireField(n.Method, "FX020", $"path[{i}].method", diagnostics);
                RequireField(n.File, "FX020", $"path[{i}].file", diagnostics);
                RequireField(n.Line, "FX020", $"path[{i}].line", diagnostics);
                RequireField(n.Role, "FX020", $"path[{i}].role", diagnostics);
                RequireField(n.TaintedValueIn, "FX020", $"path[{i}].tainted_value_in", diagnostics);
                RequireField(n.TaintedValueOut, "FX020", $"path[{i}].tainted_value_out", diagnostics);
                RequireField(n.Transformation, "FX020", $"path[{i}].transformation", diagnostics);
                if (n.Dispatch is not null)
                    RequireField(n.Dispatch.Kind, "FX020", $"path[{i}].dispatch.kind", diagnostics);
            }
        }

        if (doc.SanitizerAbsence is { } sas)
        {
            for (int i = 0; i < sas.Count; i++)
            {
                var s = sas[i];
                RequireField(s.Location, "FX030", $"sanitizer_absence[{i}].location", diagnostics);
                RequireField(s.ExpectedCheck, "FX030", $"sanitizer_absence[{i}].expected_check", diagnostics);
                RequireField(s.TaintedValue, "FX030", $"sanitizer_absence[{i}].tainted_value", diagnostics);
                RequireField(s.PresentPreFix, "FX030", $"sanitizer_absence[{i}].present_pre_fix", diagnostics);
                RequireField(s.PresentPostFix, "FX030", $"sanitizer_absence[{i}].present_post_fix", diagnostics);
            }
        }

        if (snippetsDir is not null && doc.Path is { } pn)
        {
            for (int i = 0; i < pn.Count; i++)
            {
                CheckFileLine(pn[i].File, pn[i].Line, $"path[{i}]", snippetsDir, diagnostics);
            }
            // Also check source/sink top-level shapes.
            if (doc.Source is { } src) CheckFileLine(src.File, src.Line, "source", snippetsDir, diagnostics);
            if (doc.Sink is { } snk) CheckFileLine(snk.File, snk.Line, "sink", snippetsDir, diagnostics);
        }

        return diagnostics;

        static void CheckFileLine(string? file, int? line, string where, string snippetsDir, List<Diagnostic> diagnostics)
        {
            if (file is null || line is null) return; // already reported by FX020
            var full = System.IO.Path.Combine(snippetsDir, file);
            if (!File.Exists(full))
            {
                diagnostics.Add(new Diagnostic("FX040", $"{where}: file not found in snippets dir: {file}"));
                return;
            }
            int count = File.ReadLines(full).Count();
            if (line.Value < 1 || line.Value > count)
            {
                diagnostics.Add(new Diagnostic("FX041", $"{where}: line {line.Value} out of range in {file} (has {count} lines)"));
            }
        }

        static void CheckVocab(string? value, FrozenSet<string> allowed, string code, string where, List<Diagnostic> diagnostics)
        {
            if (value is not null && !allowed.Contains(value))
            {
                diagnostics.Add(new Diagnostic(code, $"invalid value '{value}' at {where}; allowed: {string.Join(", ", allowed.Order(StringComparer.Ordinal))}"));
            }
        }

        static void RequireField<T>(T? value, string code, string where, List<Diagnostic> diagnostics)
        {
            if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
            {
                diagnostics.Add(new Diagnostic(code, $"missing field: {where}"));
            }
        }
    }

    private static void Require<T>(T? value, string code, string name, List<Diagnostic> diagnostics)
    {
        if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
        {
            diagnostics.Add(new Diagnostic(code, $"missing required field: {name}"));
        }
    }
}
