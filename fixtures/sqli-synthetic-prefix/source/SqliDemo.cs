using System.Data.Common;

namespace SqliSyntheticPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    // Single tainted parameter concatenated into a SQL fragment.
    // The 3-string `+` chain lowers to String.Concat(string, string, string) —
    // a fixed-arity overload the walker's HandleCall over-approximation handles
    // (any tainted arg → tainted return). A 5+-string chain would lower to
    // String.Concat(string[]) and lose taint at stelem.ref (walker doesn't
    // propagate taint through array-element stores). Keep this fixed-arity.
    public void Search(string regConfig)
    {
        _cmd.CommandText = "to_tsvector('" + regConfig + "'::regconfig, body)";
        _cmd.ExecuteNonQuery();
    }
}
