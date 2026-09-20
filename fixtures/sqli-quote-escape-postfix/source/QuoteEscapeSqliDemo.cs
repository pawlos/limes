namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void Append(string sql);
    }
}

namespace QuoteEscapeSqliPoc
{
    // The patched shape: the key is quote-doubled before it reaches the builder, which is
    // exactly what Marten 9.13.0 added to DictionaryContainsKeyFilter.Apply.
    public sealed class DictionaryKeyFragment
    {
        private readonly string _key;

        public DictionaryKeyFragment(string key) => _key = key;

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            builder.Append("d.data #> '{");
            builder.Append(_key.Replace("'", "''"));
            builder.Append("}' is not null");
        }
    }
}
