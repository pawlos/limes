namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void Append(string sql);
    }
}

namespace RawAppendSqliPoc
{
    // Mirrors Marten's DictionaryContainsKeyFilter.Apply (GHSA-rfx3-98h7-v3xp): an
    // attacker-controlled dictionary key is appended raw inside a single-quoted literal.
    public sealed class DictionaryKeyFragment
    {
        private readonly string _key;

        public DictionaryKeyFragment(string key) => _key = key;

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            builder.Append("d.data #> '{");
            builder.Append(_key);
            builder.Append("}' is not null");
        }
    }
}
