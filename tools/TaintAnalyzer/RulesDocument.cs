using YamlDotNet.Core;
using YamlDotNet.Serialization;

namespace TaintAnalyzer;

public sealed class RulesDocumentException : Exception
{
    public RulesDocumentException(string message) : base(message) { }
    public RulesDocumentException(string message, Exception inner) : base(message, inner) { }
}

public sealed class RulesDocument
{
    [YamlMember(Alias = "vuln_id")] public string? VulnId { get; init; }
    [YamlMember(Alias = "source_methods")] public List<string>? SourceMethods { get; init; }

    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    public static RulesDocument Load(string yaml)
    {
        RulesDocument? doc;
        try
        {
            doc = s_deserializer.Deserialize<RulesDocument>(yaml);
        }
        catch (YamlException ex)
        {
            throw new RulesDocumentException($"malformed YAML: {ex.Message}", ex);
        }

        if (doc is null)
        {
            throw new RulesDocumentException("rules document is empty");
        }

        if (doc.SourceMethods is null || doc.SourceMethods.Count == 0)
        {
            var state = doc.SourceMethods is null ? "required" : "empty";
            throw new RulesDocumentException($"source_methods is {state}: at least one entry expected");
        }

        foreach (var sig in doc.SourceMethods)
        {
            ValidateSignatureShape(sig);
        }

        return doc;
    }

    // Signature form: "Namespace.Type::Method(Param1,Param2,...)" — no spaces, non-empty declaring type
    // and method name, balanced parens. Full Cecil-FullName compatibility (generic arity, grave accents)
    // is handled implicitly by Cecil's string comparison at lookup time — we only enforce the surface shape.
    private static void ValidateSignatureShape(string sig)
    {
        if (sig.Contains(' '))
        {
            throw new RulesDocumentException($"invalid signature '{sig}': no spaces allowed in source_methods entries");
        }

        int colon = sig.IndexOf("::", StringComparison.Ordinal);
        if (colon < 0)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': missing '::' between declaring type and method name");
        }
        if (colon == 0)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': empty declaring type before '::'");
        }

        int paren = sig.IndexOf('(', colon + 2);
        int lastParen = sig[^1] == ')' ? sig.Length - 1 : -1;
        if (paren < 0 || lastParen < 0 || lastParen <= paren)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': missing '(' / ')' bracketing the parameter list");
        }

        if (paren == colon + 2)
        {
            throw new RulesDocumentException($"invalid signature '{sig}': empty method name between '::' and '('");
        }
    }
}
