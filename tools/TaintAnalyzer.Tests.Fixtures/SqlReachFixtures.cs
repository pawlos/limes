using Weasel.Postgresql;

namespace TaintAnalyzer.Tests.Fixtures.SqlReach;

// Calls AppendWithParameters directly -> a DIRECT sink caller.
public class DirectSink
{
    private readonly IFakeCommandBuilder _b;
    public DirectSink(IFakeCommandBuilder b) { _b = b; }
    public void Emit(string sql) { _b.AppendWithParameters(sql); }
}

// Calls DirectSink.Emit -> reaches a sink TRANSITIVELY (one hop).
public class TransitiveSink
{
    private readonly DirectSink _d;
    public TransitiveSink(DirectSink d) { _d = d; }
    public void Run(string sql) { _d.Emit(sql); }
}

// No path to any SQL sink.
public class NoSink
{
    public void Compute(string s) { _ = s.Length; }
}
