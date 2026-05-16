namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void AppendWithParameters(string sql);
    }
}

namespace CommandBuilderSqliPoc
{
    public sealed class SearchFragment
    {
        private readonly string _regConfig;
        public SearchFragment(string regConfig) => _regConfig = regConfig;

        // 5-part interpolation forces DefaultInterpolatedStringHandler emission
        // (the T2 Phase 1 walker primitive operates on this chain).
        private string Sql => $"a{_regConfig}b{_regConfig}c";

        // Source-method for the lock. Walker enters here with _regConfig pre-seeded
        // tainted via rules.yaml's seed_this_fields. ldfld _regConfig pushes tainted;
        // AppendFormatted taints the handler local; ToStringAndClear returns tainted
        // string; AppendWithParameters fires the new SqlCommandBuilderAppend sink.
        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            builder.AppendWithParameters(this.Sql);
        }
    }
}
