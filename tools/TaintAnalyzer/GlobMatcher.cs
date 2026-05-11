using System.Text.RegularExpressions;

namespace TaintAnalyzer;

// Simple glob matcher: `*` is a wildcard for zero or more characters; all other
// characters match literally. No `?`, no `**`, no character classes. We translate
// to a regex once per pattern; for the small number of patterns in a config file
// the per-pattern cache is fine.
internal static class GlobMatcher
{
    private static readonly Dictionary<string, Regex> s_cache = new();

    public static bool Matches(string pattern, string input)
    {
        if (!s_cache.TryGetValue(pattern, out var rx))
        {
            var escaped = Regex.Escape(pattern).Replace("\\*", ".*");
            rx = new Regex("^" + escaped + "$", RegexOptions.CultureInvariant);
            s_cache[pattern] = rx;
        }
        return rx.IsMatch(input);
    }
}
