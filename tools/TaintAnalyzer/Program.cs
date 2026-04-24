using TaintAnalyzer;

namespace TaintAnalyzer;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            PrintUsage();
            return 2;
        }

        string? target = null;
        string? rulesPath = null;
        string? outputPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--rules")
            {
                if (++i >= args.Length) { Console.Error.WriteLine("error: --rules requires a path"); return 2; }
                rulesPath = args[i];
            }
            else if (a == "--output")
            {
                if (++i >= args.Length) { Console.Error.WriteLine("error: --output requires a path"); return 2; }
                outputPath = args[i];
            }
            else if (a.StartsWith("--", StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"error: unknown flag {a}");
                PrintUsage();
                return 2;
            }
            else if (target is null)
            {
                target = a;
            }
            else
            {
                Console.Error.WriteLine($"error: unexpected positional argument: {a}");
                PrintUsage();
                return 2;
            }
        }

        if (target is null || rulesPath is null)
        {
            PrintUsage();
            return 2;
        }

        if (!File.Exists(target))
        {
            Console.Error.WriteLine($"error: target assembly not found: {target}");
            return 1;
        }
        if (!File.Exists(rulesPath))
        {
            Console.Error.WriteLine($"error: rules file not found: {rulesPath}");
            return 1;
        }

        RulesDocument rules;
        try
        {
            rules = RulesDocument.Load(File.ReadAllText(rulesPath));
        }
        catch (RulesDocumentException ex)
        {
            Console.Error.WriteLine($"error: rules: {ex.Message}");
            return 1;
        }

        AssemblyContext context;
        try
        {
            context = AssemblyContext.Load(target);
        }
        catch (AssemblyContextException ex)
        {
            Console.Error.WriteLine($"error: assembly: {ex.Message}");
            return 1;
        }

        using (context)
        {
            var walker = new TaintWalker(context);
            var allHops = new List<HopRecord>();
            var allAbsences = new List<EmittedSanitizerAbsence>();

            foreach (var sig in rules.SourceMethods!)
            {
                var source = context.FindMethod(sig);
                if (source is null)
                {
                    var suggestion = SuggestNearest(context, sig);
                    Console.Error.WriteLine($"error: source method not found: {sig}");
                    if (suggestion is not null) Console.Error.WriteLine($"   closest in target: {suggestion}");
                    return 1;
                }

                // Seed: every non-receiver parameter tainted (source defines which params are attacker-controlled).
                int bitmask = (1 << source.Parameters.Count) - 1;
                var summary = walker.Walk(source, bitmask);

                // Emit a `source` hop from the source method's first sequence point.
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
                });
                allHops.AddRange(summary.Hops);
                allAbsences.AddRange(summary.Absences);
            }

            var yaml = TraceEmitter.Emit(rules, allHops, allAbsences);

            if (outputPath is null)
            {
                Console.Write(yaml);
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

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: TaintAnalyzer <target.dll> --rules <rules.yaml> [--output <trace.yaml>]");
    }
}
