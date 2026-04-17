using System.IO;

namespace TaintAnalyzer.ValidateFixture;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
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
                    Console.Error.WriteLine("usage: ValidateFixture <trace.yaml> [--snippets-dir <dir>]");
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
}
