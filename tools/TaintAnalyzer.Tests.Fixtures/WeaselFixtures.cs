namespace Weasel.Postgresql;

public interface IFakeCommandBuilder
{
    void AppendWithParameters(string sql);
    void Append(string sql);
}
