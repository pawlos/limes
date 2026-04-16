using YamlDotNet.Serialization;

namespace SixLabors.TaintAnalyzer.ValidateFixture;

public sealed class FixtureDocument
{
    [YamlMember(Alias = "vuln_id")] public string? VulnId { get; init; }
    [YamlMember(Alias = "fix_commit")] public string? FixCommit { get; init; }
    [YamlMember(Alias = "fix_pr")] public string? FixPr { get; init; }
    [YamlMember(Alias = "description")] public string? Description { get; init; }
    [YamlMember(Alias = "source")] public PathNode? Source { get; init; }
    [YamlMember(Alias = "sink")] public PathNode? Sink { get; init; }
    [YamlMember(Alias = "path")] public List<PathNode>? Path { get; init; }
    [YamlMember(Alias = "sanitizer_absence")] public List<SanitizerAbsence>? SanitizerAbsence { get; init; }
}

public sealed class PathNode
{
    [YamlMember(Alias = "hop")] public int? Hop { get; init; }
    [YamlMember(Alias = "method")] public string? Method { get; init; }
    [YamlMember(Alias = "file")] public string? File { get; init; }
    [YamlMember(Alias = "line")] public int? Line { get; init; }
    [YamlMember(Alias = "role")] public string? Role { get; init; }
    [YamlMember(Alias = "tainted_value_in")] public string? TaintedValueIn { get; init; }
    [YamlMember(Alias = "transformation")] public string? Transformation { get; init; }
    [YamlMember(Alias = "tainted_value_out")] public string? TaintedValueOut { get; init; }
    [YamlMember(Alias = "dispatch")] public Dispatch? Dispatch { get; init; }
    [YamlMember(Alias = "note")] public string? Note { get; init; }

    // Fields used only on the top-level `source` / `sink` shapes.
    [YamlMember(Alias = "kind")] public string? Kind { get; init; }
    [YamlMember(Alias = "tainted_inputs")] public List<TaintedInput>? TaintedInputs { get; init; }
    [YamlMember(Alias = "api")] public string? Api { get; init; }
    [YamlMember(Alias = "size_expression")] public string? SizeExpression { get; init; }
}

public sealed class Dispatch
{
    [YamlMember(Alias = "kind")] public string? Kind { get; init; }
    [YamlMember(Alias = "static_type")] public string? StaticType { get; init; }
    [YamlMember(Alias = "resolved_targets")] public List<string>? ResolvedTargets { get; init; }
    [YamlMember(Alias = "closure_boundary")] public bool? ClosureBoundary { get; init; }
}

public sealed class TaintedInput
{
    [YamlMember(Alias = "name")] public string? Name { get; init; }
    [YamlMember(Alias = "origin")] public string? Origin { get; init; }
}

public sealed class SanitizerAbsence
{
    [YamlMember(Alias = "location")] public string? Location { get; init; }
    [YamlMember(Alias = "expected_check")] public string? ExpectedCheck { get; init; }
    [YamlMember(Alias = "tainted_value")] public string? TaintedValue { get; init; }
    [YamlMember(Alias = "present_pre_fix")] public bool? PresentPreFix { get; init; }
    [YamlMember(Alias = "present_post_fix")] public bool? PresentPostFix { get; init; }
    [YamlMember(Alias = "fix_evidence")] public FixEvidence? FixEvidence { get; init; }
}

public sealed class FixEvidence
{
    [YamlMember(Alias = "commit")] public string? Commit { get; init; }
    [YamlMember(Alias = "added_lines")] public string? AddedLines { get; init; }
}
