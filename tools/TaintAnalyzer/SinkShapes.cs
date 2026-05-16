using Mono.Cecil;
using Mono.Cecil.Cil;

namespace TaintAnalyzer;

public sealed class SinkMatch
{
    public required SinkKind Kind { get; init; }
    public required SinkApi Api { get; init; }
    public required string SizeProvenance { get; init; }
}

public static class SinkShapes
{
    public static SinkMatch? MatchNewArr(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Newarr) return null;
        if (stack.Depth == 0) return null;

        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.NewArray,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    public static SinkMatch? MatchArrayPoolRent(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "Rent") return null;
        if (!mr.DeclaringType.FullName.StartsWith("System.Buffers.ArrayPool`", StringComparison.Ordinal))
        {
            return null;
        }
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.Int32") return null;

        if (stack.Depth < 2) return null;
        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.ArrayPoolRent,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    // BinaryReader.ReadBytes(int) allocates a managed byte[] of exactly `count` bytes.
    // Matches callvirt or call on System.IO.BinaryReader::ReadBytes(Int32) when the count arg is tainted.
    public static SinkMatch? MatchBinaryReaderReadBytes(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "ReadBytes") return null;
        if (mr.DeclaringType.FullName != "System.IO.BinaryReader") return null;
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.Int32") return null;

        if (stack.Depth < 2) return null;
        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.NewArray,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    public static SinkMatch? MatchReadOnlySpanSlice(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "Slice") return null;
        if (!mr.DeclaringType.FullName.StartsWith("System.ReadOnlySpan`", StringComparison.Ordinal))
        {
            return null;
        }

        // Slice(int32) — one-arg overload (start only)
        // Slice(int32, int32) — two-arg overload (start + length)
        int argCount = mr.Parameters.Count;
        if (argCount is not (1 or 2)) return null;
        if (stack.Depth < argCount + 1) return null;   // +1 for receiver

        // Stack layout for Slice(int, int) at the call: [receiver, start, length] with length at Peek(0).
        // We iterate Peek(0) → Peek(argCount-1), so length is inspected before start. The first tainted
        // slot wins; its provenance becomes `SizeProvenance`. Either arg tainted qualifies as a sink.
        StackSlot? taintedSlot = null;
        for (int i = 0; i < argCount; i++)
        {
            var slot = stack.Peek(i);
            if (slot.Tainted)
            {
                taintedSlot = slot;
                break;
            }
        }

        if (taintedSlot is null) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SpanAccess,
            Api = SinkApi.SpanSlice,
            SizeProvenance = taintedSlot.Value.Provenance,
        };
    }

    public static SinkMatch? MatchReadOnlySpanIndex(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "get_Item") return null;
        if (!mr.DeclaringType.FullName.StartsWith("System.ReadOnlySpan`", StringComparison.Ordinal))
        {
            return null;
        }
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.Int32") return null;

        if (stack.Depth < 2) return null;   // receiver + index
        var indexSlot = stack.Peek(0);
        if (!indexSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SpanAccess,
            Api = SinkApi.SpanIndex,
            SizeProvenance = indexSlot.Provenance,
        };
    }

    public static SinkMatch? MatchLocalloc(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Localloc) return null;
        if (stack.Depth == 0) return null;

        var sizeSlot = stack.Peek(0);
        if (!sizeSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = SinkApi.Stackalloc,
            SizeProvenance = sizeSlot.Provenance,
        };
    }

    // Unconditional sink for unbounded HTTP response reads.
    // Only methods that materialize the ENTIRE response body into a managed buffer are listed.
    // Stream-returning overloads (ReadAsStreamAsync, GetStreamAsync) are intentionally excluded:
    // they return a Stream handle without allocating a large buffer at the call site — the
    // danger is downstream if the stream is read without a bound, which is captured by other
    // sinks (e.g. MatchNewArray). Adding stream overloads here would cause false positives on
    // bounded-read patterns (e.g. HttpClientHelpers.GetResponseBodyAsString with a 4 MiB cap).
    public static SinkMatch? MatchHttpRead(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt)) return null;
        var mr = (MethodReference)instruction.Operand;
        var typeName = mr.DeclaringType.Name;
        var methodName = mr.Name;

        SinkApi? api = (typeName, methodName) switch
        {
            ("HttpContent", "ReadAsStringAsync" or "ReadAsByteArrayAsync")
                => SinkApi.HttpContentRead,
            ("HttpClient", "GetStringAsync" or "GetByteArrayAsync")
                => SinkApi.HttpClientRead,
            _ => null,
        };
        if (api is null) return null;

        // Retrieve receiver for provenance: receiver is paramCount slots from top.
        int paramCount = mr.Parameters.Count;
        if (stack.Depth < paramCount + 1) return null;
        var receiver = stack.Peek(paramCount);
        var provenance = receiver.Tainted ? receiver.Provenance : mr.DeclaringType.Name;

        return new SinkMatch
        {
            Kind = SinkKind.Allocation,
            Api = api.Value,
            SizeProvenance = provenance,
        };
    }

    // SQL injection sink: tainted string assigned to IDbCommand.CommandText.
    // Matches `callvirt System.Data.IDbCommand::set_CommandText(string)` OR a setter
    // on a class that implements IDbCommand. Resolve-failure fallback (Task 8) accepts
    // declaring types under known DB-provider namespaces whose names end in `Command`.
    public static SinkMatch? MatchCommandTextSetter(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (mr.Name != "set_CommandText") return null;
        if (mr.Parameters.Count != 1) return null;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return null;

        var declaring = mr.DeclaringType;
        var resolved = declaring.Resolve();
        if (resolved is not null)
        {
            if (!ImplementsIDbCommand(resolved)) return null;
        }
        else
        {
            if (!MatchesDbProviderHeuristic(declaring)) return null;
        }

        if (stack.Depth < 2) return null;    // receiver + value
        var valueSlot = stack.Peek(0);
        if (!valueSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SqlInjection,
            Api = SinkApi.SqlCommandText,
            SizeProvenance = valueSlot.Provenance,
        };
    }

    private static bool ImplementsIDbCommand(TypeDefinition td)
    {
        const string Target = "System.Data.IDbCommand";

        // Walk the base chain and check interface implementations on each.
        var current = td;
        while (current is not null)
        {
            if (current.FullName == Target) return true;
            foreach (var iface in current.Interfaces)
            {
                var ir = iface.InterfaceType;
                if (ir.FullName == Target) return true;
                // Interface inheritance — resolve and check transitively.
                var iresolved = ir.Resolve();
                if (iresolved is not null && ImplementsIDbCommandViaInterface(iresolved, Target)) return true;
            }
            var baseType = current.BaseType;
            current = baseType?.Resolve();
        }
        return false;
    }

    // Fallback when MethodReference.Resolve() returns null (declaring type's assembly
    // not loaded). Accepts known ADO.NET provider namespaces with type names ending
    // in "Command". Trades a small FP risk for the ability to scan apps that reference
    // DB providers without us loading the provider assembly.
    private static bool MatchesDbProviderHeuristic(TypeReference tr)
    {
        var typeName = tr.Name ?? "";
        if (!typeName.EndsWith("Command", StringComparison.Ordinal)) return false;

        var ns = tr.Namespace ?? "";
        return ns.StartsWith("System.Data.", StringComparison.Ordinal)
            || ns.StartsWith("Npgsql", StringComparison.Ordinal)
            || ns.StartsWith("MySql", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.Data.", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.EntityFrameworkCore.", StringComparison.Ordinal);
    }

    private static bool ImplementsIDbCommandViaInterface(TypeDefinition iface, string target)
    {
        if (iface.FullName == target) return true;
        foreach (var parent in iface.Interfaces)
        {
            var pr = parent.InterfaceType;
            if (pr.FullName == target) return true;
            var presolved = pr.Resolve();
            if (presolved is not null && ImplementsIDbCommandViaInterface(presolved, target)) return true;
        }
        return false;
    }
}
