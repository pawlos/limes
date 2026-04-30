using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace TaintAnalyzer;

public sealed class RulesDocumentException : Exception
{
    public RulesDocumentException(string message) : base(message) { }
    public RulesDocumentException(string message, Exception inner) : base(message, inner) { }
}

// One source-method entry in rules.yaml. Backward-compatible with the v0 string form via the
// custom IYamlTypeConverter — a scalar entry is parsed as `{ Signature = scalar }`, a mapping
// entry parses both `signature:` and the optional `seed_this_fields:` list. The latter lets
// rules target a method like `ThriftCompactProtocolReader::ReadBinary()` whose attacker-
// controlled stream lives on `this._inputStream` rather than as a parameter — without it,
// the analyzer can't seed taint for parameterless instance methods.
public sealed class SourceMethodEntry
{
    public string Signature { get; init; } = "";
    public List<string>? SeedThisFields { get; init; }
    public List<string>? TaintFromExternalReturns { get; init; }

    // Convenience: callers (mostly tests) constructing a RulesDocument programmatically can
    // still write `new RulesDocument { SourceMethods = new() { "Ns.T::M()" } }` without
    // wrapping each string. Loader code parses YAML directly via the type converter.
    public static implicit operator SourceMethodEntry(string signature)
        => new() { Signature = signature };
}

public sealed class RulesDocument
{
    [YamlMember(Alias = "vuln_id")] public string? VulnId { get; init; }
    [YamlMember(Alias = "source_methods")] public List<SourceMethodEntry>? SourceMethods { get; init; }

    private static readonly IDeserializer s_deserializer = new DeserializerBuilder()
        .WithTypeConverter(new SourceMethodEntryConverter())
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
            // Surface our converter's actionable messages even though YamlDotNet wraps them.
            for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
            {
                if (inner is RulesDocumentException rdex) throw rdex;
            }
            throw new RulesDocumentException($"malformed YAML: {ex.Message}", ex);
        }
        catch (RulesDocumentException)
        {
            throw;
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

        foreach (var entry in doc.SourceMethods)
        {
            ValidateSignatureShape(entry.Signature);
            if (entry.SeedThisFields is { } seeds)
            {
                foreach (var field in seeds)
                {
                    if (string.IsNullOrWhiteSpace(field))
                    {
                        throw new RulesDocumentException(
                            $"invalid seed_this_fields entry for '{entry.Signature}': field name is empty or whitespace");
                    }
                }
            }
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
        int lastParen = sig.Length > 0 && sig[^1] == ')' ? sig.Length - 1 : -1;
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

internal sealed class SourceMethodEntryConverter : IYamlTypeConverter
{
    public bool Accepts(Type type) => type == typeof(SourceMethodEntry);

    public object? ReadYaml(IParser parser, Type type)
    {
        // Scalar form (back-compat): a bare string is the signature, no seed fields.
        if (parser.Current is Scalar scalar)
        {
            parser.MoveNext();
            return new SourceMethodEntry { Signature = scalar.Value };
        }

        // Mapping form: signature + optional seed_this_fields.
        if (parser.Current is MappingStart)
        {
            parser.MoveNext();
            string? signature = null;
            List<string>? seedFields = null;
            List<string>? taintFromExternalReturns = null;

            while (parser.Current is not MappingEnd)
            {
                if (parser.Current is not Scalar keyScalar)
                {
                    throw new RulesDocumentException("source_methods entry: expected mapping key as scalar");
                }
                var key = keyScalar.Value;
                parser.MoveNext();

                switch (key)
                {
                    case "signature":
                        if (parser.Current is not Scalar valueScalar)
                        {
                            throw new RulesDocumentException("source_methods entry: 'signature' must be a scalar string");
                        }
                        signature = valueScalar.Value;
                        parser.MoveNext();
                        break;

                    case "seed_this_fields":
                        if (parser.Current is not SequenceStart)
                        {
                            throw new RulesDocumentException("source_methods entry: 'seed_this_fields' must be a list");
                        }
                        parser.MoveNext();
                        seedFields = new List<string>();
                        while (parser.Current is not SequenceEnd)
                        {
                            if (parser.Current is not Scalar fieldScalar)
                            {
                                throw new RulesDocumentException("source_methods entry: 'seed_this_fields' entries must be scalar strings");
                            }
                            seedFields.Add(fieldScalar.Value);
                            parser.MoveNext();
                        }
                        parser.MoveNext();
                        break;

                    case "taint_from_external_returns":
                        if (parser.Current is not SequenceStart)
                        {
                            throw new RulesDocumentException("source_methods entry: 'taint_from_external_returns' must be a list");
                        }
                        parser.MoveNext();
                        taintFromExternalReturns = new List<string>();
                        while (parser.Current is not SequenceEnd)
                        {
                            if (parser.Current is not Scalar extRetScalar)
                            {
                                throw new RulesDocumentException("source_methods entry: 'taint_from_external_returns' entries must be scalar strings");
                            }
                            taintFromExternalReturns.Add(extRetScalar.Value);
                            parser.MoveNext();
                        }
                        parser.MoveNext();
                        break;

                    default:
                        // Unknown key: skip the value to keep the parser in sync. Matches the
                        // top-level `IgnoreUnmatchedProperties` policy.
                        parser.SkipThisAndNestedEvents();
                        break;
                }
            }
            parser.MoveNext();

            if (signature is null)
            {
                throw new RulesDocumentException("source_methods entry: object form requires 'signature' field");
            }
            return new SourceMethodEntry { Signature = signature, SeedThisFields = seedFields, TaintFromExternalReturns = taintFromExternalReturns };
        }

        throw new RulesDocumentException(
            $"source_methods entry: expected scalar string or mapping, got {parser.Current?.GetType().Name ?? "<null>"}");
    }

    public void WriteYaml(IEmitter emitter, object? value, Type type)
        => throw new NotSupportedException("rules.yaml is read-only from the analyzer");
}
