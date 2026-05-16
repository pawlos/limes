using System.Data.Common;

namespace InterpolatedSqliPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    // Tainted parameter flows through $"..." interpolation into DbCommand.CommandText.
    // 5-part interpolation forces Roslyn to emit DefaultInterpolatedStringHandler
    // (1-hole 3-part forms get optimized to String.Concat). The T2 Phase-1 walker
    // recognizer taints the handler local on AppendFormatted(regConfig);
    // ToStringAndClear's byref receiver carries that taint to its string return; the
    // T1 set_CommandText matcher then fires the SqlInjection sink.
    public void Search(string regConfig)
    {
        _cmd.CommandText = $"a{regConfig}b{regConfig}c";
        _cmd.ExecuteNonQuery();
    }
}
