using Mono.Cecil;

namespace TaintAnalyzer;

public static class AsyncStateMachineResolver
{
    private const string AttributeFullName =
        "System.Runtime.CompilerServices.AsyncStateMachineAttribute";

    public sealed record Resolution(MethodDefinition Method, bool RedirectedFromAsync);

    public static Resolution Resolve(MethodDefinition source)
    {
        foreach (var ca in source.CustomAttributes)
        {
            if (ca.AttributeType.FullName == AttributeFullName)
            {
                throw new NotImplementedException("async redirect — implemented in Task 3");
            }
        }
        return new Resolution(source, false);
    }
}
