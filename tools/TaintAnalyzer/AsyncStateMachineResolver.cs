using Mono.Cecil;
using System.Linq;

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
            if (ca.AttributeType.FullName != AttributeFullName) continue;
            if (ca.ConstructorArguments.Count == 0) continue;

            var typeArg = ca.ConstructorArguments[0];
            if (typeArg.Value is not TypeReference smTypeRef) continue;

            var smType = smTypeRef.Resolve()
                ?? throw new InvalidOperationException(
                    $"async state machine type unresolvable for {source.FullName}");

            var moveNext = smType.Methods.FirstOrDefault(m => m.Name == "MoveNext")
                ?? throw new InvalidOperationException(
                    $"async state machine {smType.FullName} has no MoveNext");

            return new Resolution(moveNext, true);
        }
        return new Resolution(source, false);
    }
}
