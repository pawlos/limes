using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class AssemblyContextException : Exception
{
    public AssemblyContextException(string message) : base(message) { }
    public AssemblyContextException(string message, Exception inner) : base(message, inner) { }
}

public sealed class AssemblyContext : IDisposable
{
    public AssemblyDefinition Assembly { get; }

    private readonly Dictionary<string, MethodDefinition> _methodsByFullName;
    private readonly Dictionary<string, MethodDefinition> _methodsByShortSignature;

    private AssemblyContext(AssemblyDefinition asm)
    {
        Assembly = asm;

        _methodsByFullName = new Dictionary<string, MethodDefinition>(StringComparer.Ordinal);
        _methodsByShortSignature = new Dictionary<string, MethodDefinition>(StringComparer.Ordinal);

        foreach (var type in asm.MainModule.GetTypes())
        {
            foreach (var m in type.Methods)
            {
                _methodsByFullName[m.FullName] = m;
                var shortSig = BuildShortSignature(m);
                _methodsByShortSignature[shortSig] = m;
            }
        }
    }

    public static AssemblyContext Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new AssemblyContextException($"assembly not found: {path}");
        }

        var rp = new ReaderParameters
        {
            ReadSymbols = true,
            ReadWrite = false,
            InMemory = true,
        };

        AssemblyDefinition asm;
        try
        {
            asm = AssemblyDefinition.ReadAssembly(path, rp);
        }
        catch (Exception ex)
        {
            throw new AssemblyContextException(
                $"failed to load assembly with symbols at {path}: ensure a portable or Windows PDB sits next to the DLL. ({ex.Message})",
                ex);
        }

        if (!asm.MainModule.HasSymbols)
        {
            asm.Dispose();
            throw new AssemblyContextException(
                $"assembly loaded but no symbols were found for {Path.GetFileName(path)}: ensure a portable or Windows PDB sits next to the DLL.");
        }

        return new AssemblyContext(asm);
    }

    // Accepts either full Cecil signature ("ReturnType Namespace.Type::Method(Params)")
    // OR short signature ("Namespace.Type::Method(Params)" — return type elided) as the
    // rules file form.
    public MethodDefinition? FindMethod(string signature)
    {
        if (_methodsByFullName.TryGetValue(signature, out var full))
        {
            return full;
        }
        if (_methodsByShortSignature.TryGetValue(signature, out var sh))
        {
            return sh;
        }
        return null;
    }

    public IEnumerable<MethodDefinition> AllMethods() => _methodsByFullName.Values;

    public IEnumerable<string> AllSignatures() => _methodsByShortSignature.Keys;

    public SequencePoint? GetSequencePoint(MethodDefinition method, Instruction instruction)
    {
        var direct = method.DebugInformation.GetSequencePoint(instruction);
        if (direct is { IsHidden: false })
        {
            return direct;
        }

        // Fallback: walk backward to the nearest non-hidden sequence point.
        for (var cur = instruction.Previous; cur is not null; cur = cur.Previous)
        {
            var sp = method.DebugInformation.GetSequencePoint(cur);
            if (sp is { IsHidden: false })
            {
                return sp;
            }
        }
        return null;
    }

    public void Dispose() => Assembly.Dispose();

    private static string BuildShortSignature(MethodDefinition m)
    {
        var ps = new List<string>(m.Parameters.Count);
        foreach (var p in m.Parameters)
        {
            ps.Add(p.ParameterType.FullName);
        }
        return $"{m.DeclaringType.FullName}::{m.Name}({string.Join(",", ps)})";
    }
}
