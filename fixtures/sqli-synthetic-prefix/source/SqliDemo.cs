using System.Data.Common;

namespace SqliSyntheticPoc;

public sealed class SearchService
{
    private readonly DbCommand _cmd;
    public SearchService(DbCommand cmd) => _cmd = cmd;

    public void Search(string regConfig, string term)
    {
        var sql = "SELECT * FROM docs WHERE to_tsvector('"
                  + regConfig
                  + "'::regconfig, body) @@ to_tsquery('"
                  + term
                  + "')";
        _cmd.CommandText = sql;
        _cmd.ExecuteNonQuery();
    }
}
