namespace Weasel.Postgresql
{
    public interface ICommandBuilder
    {
        void AppendWithParameters(string sql);
    }
}

namespace RegexGuardSqliPoc
{
    public sealed class GuardedSearchFragment
    {
        private static readonly System.Text.RegularExpressions.Regex _pattern =
            new(@"^[a-zA-Z_][a-zA-Z0-9_]*$",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        private readonly string _regConfig;
        public GuardedSearchFragment(string regConfig) => _regConfig = regConfig;

        private string Sql => $"a{_regConfig}b{_regConfig}c";

        public void Apply(Weasel.Postgresql.ICommandBuilder builder)
        {
            // Inline regex guard before the sink. The T3 recognizer fires here.
            if (!_pattern.IsMatch(_regConfig))
                throw new System.ArgumentException("invalid regConfig", nameof(_regConfig));
            builder.AppendWithParameters(this.Sql);
        }
    }
}
