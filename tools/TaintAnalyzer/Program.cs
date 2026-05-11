using TaintAnalyzer;

namespace TaintAnalyzer;

public static class Program
{
    public static int Main(string[] args) => Run(args, Console.Out, Console.Error);

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length < 1)
        {
            PrintUsage(stderr);
            return 2;
        }

        string? target = null;
        string? rulesPath = null;
        string? outputPath = null;
        bool noSymbols = false;

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--rules")
            {
                if (++i >= args.Length) { stderr.WriteLine("error: --rules requires a path"); return 2; }
                rulesPath = args[i];
            }
            else if (a == "--output")
            {
                if (++i >= args.Length) { stderr.WriteLine("error: --output requires a path"); return 2; }
                outputPath = args[i];
            }
            else if (a == "--no-symbols")
            {
                noSymbols = true;
            }
            else if (a.StartsWith("--", StringComparison.Ordinal))
            {
                stderr.WriteLine($"error: unknown flag {a}");
                PrintUsage(stderr);
                return 2;
            }
            else if (target is null)
            {
                target = a;
            }
            else
            {
                stderr.WriteLine($"error: unexpected positional argument: {a}");
                PrintUsage(stderr);
                return 2;
            }
        }

        if (target is null || rulesPath is null)
        {
            PrintUsage(stderr);
            return 2;
        }

        if (!File.Exists(target))
        {
            stderr.WriteLine($"error: target assembly not found: {target}");
            return 1;
        }
        if (!File.Exists(rulesPath))
        {
            stderr.WriteLine($"error: rules file not found: {rulesPath}");
            return 1;
        }

        RulesDocument rules;
        try
        {
            rules = RulesDocument.Load(File.ReadAllText(rulesPath));
        }
        catch (RulesDocumentException ex)
        {
            stderr.WriteLine($"error: rules: {ex.Message}");
            return 1;
        }

        AssemblyContext context;
        try
        {
            context = AssemblyContext.Load(target, noSymbols);
        }
        catch (AssemblyContextException ex)
        {
            stderr.WriteLine($"error: assembly: {ex.Message}");
            return 1;
        }

        using (context)
        {
            var walker = new TaintWalker(context);
            var allHops = new List<HopRecord>();

            foreach (var entry in rules.SourceMethods!)
            {
                var source = context.FindMethod(entry.Signature);
                if (source is null)
                {
                    var suggestion = SuggestNearest(context, entry.Signature);
                    stderr.WriteLine($"error: source method not found: {entry.Signature}");
                    if (suggestion is not null) stderr.WriteLine($"   closest in target: {suggestion}");
                    return 1;
                }

                var resolution = AsyncStateMachineResolver.Resolve(source);
                walker.TaintFromExternalReturns = entry.TaintFromExternalReturns
                    ?? (IReadOnlyList<string>)Array.Empty<string>();

                int bitmask;
                IReadOnlyCollection<string> seedFields;
                if (resolution.RedirectedFromAsync)
                {
                    // MoveNext takes no parameters; captured arguments live as `this`-fields whose names
                    // match the original method's parameter names. Seed those fields as tainted.
                    bitmask = 0;
                    var smFieldNames = resolution.Method.DeclaringType.Fields
                        .Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
                    seedFields = source.Parameters
                        .Select(p => p.Name)
                        .Where(name => smFieldNames.Contains(name))
                        .ToList();
                }
                else
                {
                    bitmask = (1 << source.Parameters.Count) - 1;
                    seedFields = entry.SeedThisFields ?? (IReadOnlyCollection<string>)Array.Empty<string>();
                }

                var summary = walker.WalkWithSeed(resolution.Method, bitmask, seedFields);

                // Source hop reflects the user-facing method (not MoveNext).
                var sp = source.Body is null ? null : context.GetSequencePoint(source, source.Body.Instructions.First());
                allHops.Add(new HopRecord
                {
                    Hop = 0,
                    Method = $"{source.DeclaringType.FullName}.{source.Name}",
                    File = sp is null ? "" : Path.GetFileName(sp.Document.Url),
                    Line = sp?.StartLine ?? 0,
                    Role = HopRole.Source,
                    TaintedValueIn = source.Parameters.FirstOrDefault()?.Name ?? "arg0",
                    Transformation = "read_stream",
                    TaintedValueOut = source.Parameters.FirstOrDefault()?.Name ?? "arg0",
                    ResolvedVia = resolution.RedirectedFromAsync ? "async_state_machine" : null,
                });
                allHops.AddRange(summary.Hops);
            }

            var yaml = TraceEmitter.Emit(rules, allHops, Array.Empty<EmittedSanitizerAbsence>());

            if (outputPath is null)
            {
                stdout.Write(yaml);
            }
            else
            {
                File.WriteAllText(outputPath, yaml);
            }
        }

        return 0;
    }

    private static string? SuggestNearest(AssemblyContext ctx, string sig)
    {
        int bestDist = int.MaxValue;
        string? best = null;
        foreach (var candidate in ctx.AllSignatures())
        {
            var d = Distance(sig, candidate);
            if (d < bestDist)
            {
                bestDist = d;
                best = candidate;
            }
        }
        return best;
    }

    // Simple Levenshtein; cheap to reimplement, no extra dependency.
    private static int Distance(string a, string b)
    {
        var dp = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) dp[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) dp[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
                dp[i, j] = a[i - 1] == b[j - 1]
                    ? dp[i - 1, j - 1]
                    : 1 + Math.Min(dp[i - 1, j - 1], Math.Min(dp[i - 1, j], dp[i, j - 1]));
        return dp[a.Length, b.Length];
    }

    private static void PrintUsage(TextWriter stderr)
    {
        stderr.WriteLine("usage: TaintAnalyzer <target.dll> --rules <rules.yaml> [--output <trace.yaml>] [--no-symbols]");
    }
}
