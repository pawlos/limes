namespace TaintAnalyzer;

public enum HopRole { Source, Propagator, Sanitizer, Sink }

public enum SinkKind { Allocation, SpanAccess, SqlInjection }

public enum SinkApi { NewArray, ArrayPoolRent, SpanSlice, SpanIndex, Stackalloc, HttpContentRead, HttpClientRead, SqlCommandText }

public enum FailureKind { Throw, ReturnEarly }

public sealed class ResolvedDispatch
{
    public required string Kind { get; init; }            // "direct" or "virtual"
    public required string StaticType { get; init; }
    public required IReadOnlyList<string> ResolvedTargets { get; init; }
    public required bool ClosureBoundary { get; init; }
}

public sealed class EstablishesBound
{
    public required string Target { get; init; }
    public required string Relation { get; init; }
    public string? UpperBound { get; init; }
    public string? LowerBound { get; init; }
    // True when the upper bound resolves to int.MaxValue at static analysis time — i.e. the guard
    // `value <= MaxDocumentSize` is trivially satisfied for every valid int32 and provides no
    // protection. A vacuous upper bound does not suppress sanitizer_absence emission.
    public bool VacuousUpperBound { get; init; }
}

public sealed class OnFailure
{
    public required FailureKind Kind { get; init; }
    public string? Exception { get; init; }
}

public sealed record HopRecord
{
    public required int Hop { get; init; }
    public required string Method { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required HopRole Role { get; init; }
    public required string TaintedValueIn { get; init; }
    public required string Transformation { get; init; }
    public required string TaintedValueOut { get; init; }
    public ResolvedDispatch? Dispatch { get; init; }
    public string? Note { get; init; }
    public string? ResolvedVia { get; init; }

    // Sanitizer-only
    public EstablishesBound? EstablishesBound { get; init; }
    public OnFailure? OnFailure { get; init; }

    // Sink-only
    public SinkKind? SinkKind { get; init; }
    public SinkApi? SinkApi { get; init; }
    public string? SizeExpression { get; init; }
    public string? AccessExpression { get; init; }

    // Sink-only: line where the local feeding the sink's size/access value FIRST received a
    // tainted assignment in the walked method body, plus the provenance string at that
    // moment. `null` when the sink doesn't read from a single local (e.g., the size is an
    // inline arithmetic expression with no clean source local). Used by the trace emitter to
    // pin sanitizer_absence at the value's origin rather than at the last branch's overwrite
    // site — and to surface the *first* tainted value's provenance, not the linear-walker's
    // last-write-wins provenance which may belong to a sibling branch.
    public string? FirstTaintedFile { get; init; }
    public int? FirstTaintedLine { get; init; }
    public string? FirstTaintedProvenance { get; init; }
}

public sealed class EmittedSanitizerAbsence
{
    public required string Location { get; init; }        // "file:line"
    public required string ExpectedCheck { get; init; }
    public required string TaintedValue { get; init; }
}

// Per-method analysis summary used for cross-method propagation.
public sealed class MethodSummary
{
    public required string MethodFullName { get; init; }
    public required int TaintedParamBitmask { get; init; }
    public required bool ReturnsTainted { get; init; }
    public required IReadOnlyList<string> NewlyTaintedThisFields { get; init; }
    public required IReadOnlyList<HopRecord> Hops { get; init; }
    public required IReadOnlyList<EmittedSanitizerAbsence> Absences { get; init; }
    public required bool ReachedSink { get; init; }
    public required bool AppliedValueClamp { get; init; }
    public required bool AppliedThrowShapeSanitiser { get; init; }
}
