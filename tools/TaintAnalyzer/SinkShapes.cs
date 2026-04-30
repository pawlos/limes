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

    // Milestone-H: unconditional sink for unbounded HTTP response reads.
    // Fires on any call to the listed methods regardless of receiver taint — the call itself
    // is the dangerous operation. Noise is controlled by source-entry selection in rules.yaml.
    public static SinkMatch? MatchHttpRead(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt)) return null;
        var mr = (MethodReference)instruction.Operand;
        var typeName = mr.DeclaringType.Name;
        var methodName = mr.Name;

        SinkApi? api = (typeName, methodName) switch
        {
            ("HttpContent", "ReadAsStringAsync" or "ReadAsByteArrayAsync" or "ReadAsStreamAsync")
                => SinkApi.HttpContentRead,
            ("HttpClient", "GetStringAsync" or "GetByteArrayAsync" or "GetStreamAsync")
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
}
