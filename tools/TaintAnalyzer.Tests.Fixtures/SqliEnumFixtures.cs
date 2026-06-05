using Weasel.Postgresql;

namespace TaintAnalyzer.Tests.Fixtures.SqliEnum;

// string PARAMETER path: public string-param method that reaches a SQL sink.
public class StringParamQuery
{
    private readonly IFakeCommandBuilder _b;
    public StringParamQuery(IFakeCommandBuilder b) { _b = b; }
    public void Where(string clause) { _b.AppendWithParameters(clause); }
}

// this-FIELD path: string field set in ctor, read by a sink-reaching method that
// takes NO string parameter (mirrors Marten's FullTextWhereFragment.Apply).
public class FieldFragment
{
    private readonly string _regConfig;
    private readonly IFakeCommandBuilder _b;
    public FieldFragment(string regConfig, IFakeCommandBuilder b) { _regConfig = regConfig; _b = b; }
    public void Apply() { _b.AppendWithParameters(_regConfig); }
}

// string method that does NOT reach a SQL sink — must be gated out.
public class StringNoSink
{
    public void Log(string msg) { _ = msg.Trim(); }
}

// INTERNAL type with a public sink-reaching method (mirrors Marten's internal
// FullTextWhereFragment whose public Apply is dispatched via a cross-assembly
// interface). Not reachable-from-public within this assembly, so it is surfaced
// only by the sqli profile's visibility relaxation.
internal class InternalFragment
{
    private readonly string _cfg;
    private readonly IFakeCommandBuilder _b;
    public InternalFragment(string cfg, IFakeCommandBuilder b) { _cfg = cfg; _b = b; }
    public void Apply() { _b.AppendWithParameters(_cfg); }
}
