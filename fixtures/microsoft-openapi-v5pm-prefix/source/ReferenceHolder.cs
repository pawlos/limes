using System;

// Minimal faithful reproduction of Microsoft.OpenApi's BaseOpenApiReferenceHolder
// (GHSA-v5pm-xwqc-g5wc / CVE-2026-49451, CWE-674). PREFIX = vulnerable (<= 2.7.4 / <= 3.5.3):
// RecursiveTarget resolves a $ref by walking the reference chain with no cycle guard, so a
// circular reference (A -> B -> A) overflows the stack.
namespace Microsoft.OpenApi.Models.References
{
    public abstract class BaseOpenApiReferenceHolder
    {
        public BaseOpenApiReferenceHolder Reference;
        public object Target;

        public object RecursiveTarget
        {
            get
            {
                if (Reference != null)
                    return Reference.RecursiveTarget;
                return Target;
            }
        }
    }

    public class OpenApiSchemaReference : BaseOpenApiReferenceHolder
    {
    }
}
