using System.IO;
using YamlDotNet.Core;

namespace TaintAnalyzer.ValidateFixture;

public static class Program
{
    public static int Main(string[] args)
    {
        // Two modes:
        //   ValidateFixture <trace.yaml> [--snippets-dir <dir>]
        //       Schema-validate one fixture document.
        //   ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>
        //       Compare an analyzer's multi-doc output against the ground-truth fixture.
        if (args.Length >= 1 && args[0] == "--compare")
        {
            return RunCompare(args);
        }
        return RunValidate(args);
    }

    private static int RunValidate(string[] args)
    {
        if (args.Length < 1)
        {
            PrintUsage();
            return 2;
        }

        var yamlPath = args[0];
        string? snippetsDir = null;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--snippets-dir")
            {
                if (i + 1 >= args.Length)
                {
                    Console.Error.WriteLine("error: --snippets-dir requires a directory argument");
                    PrintUsage();
                    return 2;
                }
                snippetsDir = args[i + 1];
                i++; // skip the value we just consumed
            }
        }

        if (!File.Exists(yamlPath))
        {
            Console.Error.WriteLine($"error: file not found: {yamlPath}");
            return 2;
        }

        var yaml = File.ReadAllText(yamlPath);
        var diagnostics = new FixtureValidator().Validate(yaml, snippetsDir);

        foreach (var d in diagnostics)
        {
            Console.Error.WriteLine($"{d.Code}: {d.Message}");
        }

        if (diagnostics.Count == 0)
        {
            Console.WriteLine($"OK: {yamlPath}");
            return 0;
        }

        Console.Error.WriteLine($"FAIL: {diagnostics.Count} diagnostic(s)");
        return 1;
    }

    private static int RunCompare(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine("error: --compare requires exactly two paths");
            PrintUsage();
            return 2;
        }

        var groundTruthPath = args[1];
        var analyzerPath = args[2];

        if (!File.Exists(groundTruthPath))
        {
            Console.Error.WriteLine($"error: ground-truth file not found: {groundTruthPath}");
            return 2;
        }
        if (!File.Exists(analyzerPath))
        {
            Console.Error.WriteLine($"error: analyzer-output file not found: {analyzerPath}");
            return 2;
        }

        var groundTruthYaml = File.ReadAllText(groundTruthPath);
        var analyzerYaml = File.ReadAllText(analyzerPath);

        IReadOnlyList<FixtureDocument> gtDocs;
        IReadOnlyList<FixtureDocument> anDocs;
        try
        {
            gtDocs = Comparator.LoadAll(groundTruthYaml);
            anDocs = Comparator.LoadAll(analyzerYaml);
        }
        catch (YamlException ex)
        {
            Console.Error.WriteLine($"error: malformed YAML: {ex.Message}");
            return 2;
        }

        if (gtDocs.Count == 0)
        {
            Console.Error.WriteLine("error: ground-truth file is empty");
            return 2;
        }
        if (anDocs.Count == 0)
        {
            Console.Error.WriteLine("error: analyzer-output file is empty");
            return 2;
        }

        // Ground truth is single-doc by convention; if it has multiple, compare each against the
        // analyzer's multi-doc output independently and aggregate diagnostics.
        var comparator = new Comparator();
        var allDiagnostics = new List<Diagnostic>();
        foreach (var gt in gtDocs)
        {
            allDiagnostics.AddRange(comparator.Compare(gt, anDocs));
        }

        foreach (var d in allDiagnostics)
        {
            Console.Error.WriteLine($"{d.Code} {d.Message}");
        }

        var failures = allDiagnostics.Count(d => d.Code != "FX-info");
        if (failures == 0)
        {
            Console.WriteLine($"OK: {analyzerPath} matches {groundTruthPath}");
            return 0;
        }

        Console.Error.WriteLine($"FAIL: {failures} mismatch diagnostic(s)");
        return 1;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
        Console.Error.WriteLine("       ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>");
    }
}
