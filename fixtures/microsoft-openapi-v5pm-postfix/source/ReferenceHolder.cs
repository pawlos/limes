using System;
using System.Collections.Generic;

// Minimal faithful reproduction of Microsoft.OpenApi's BaseOpenApiReferenceHolder
// (GHSA-v5pm-xwqc-g5wc / CVE-2026-49451, CWE-674). POSTFIX = patched (2.7.5 / 3.5.4):
// target resolution threads a visited HashSet through the recursion and throws on a cycle,
// so a circular reference terminates instead of overflowing the stack.
namespace Microsoft.OpenApi.Models.References
{
    public abstract class BaseOpenApiReferenceHolder
    {
        public BaseOpenApiReferenceHolder Reference;
        public object Target;

        public object RecursiveTarget => ResolveTarget(new HashSet<BaseOpenApiReferenceHolder>());

        public object ResolveTarget(HashSet<BaseOpenApiReferenceHolder> visited)
        {
            if (!visited.Add(this))
                throw new InvalidOperationException("Circular reference detected while resolving reference");
            if (Reference != null)
                return Reference.ResolveTarget(visited);
            return Target;
        }
    }

    public class OpenApiSchemaReference : BaseOpenApiReferenceHolder
    {
    }
}
