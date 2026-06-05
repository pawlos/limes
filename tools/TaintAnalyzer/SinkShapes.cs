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

    // Shared signature-level recognition of a SQL-sink call site (no stack inspection).
    // Used by BOTH the runtime sink matchers below AND SqlSinkReachability's static gate,
    // so the two cannot drift. A "SQL sink" is either IDbCommand.set_CommandText(string)
    // or ICommandBuilder.AppendWithParameters(string, ...).
    public static bool IsSqlSinkCall(MethodReference mr)
        => IsCommandTextSetterCall(mr) || IsCommandBuilderAppendCall(mr);

    private static bool IsCommandTextSetterCall(MethodReference mr)
    {
        if (mr.Name != "set_CommandText") return false;
        if (mr.Parameters.Count != 1) return false;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;

        var declaring = mr.DeclaringType;
        var resolved = declaring.Resolve();
        return resolved is not null
            ? ImplementsIDbCommand(resolved)
            : MatchesDbProviderHeuristic(declaring);
    }

    private static bool IsCommandBuilderAppendCall(MethodReference mr)
    {
        if (mr.Name != "AppendWithParameters") return false;
        if (mr.Parameters.Count < 1) return false;
        if (mr.Parameters[0].ParameterType.FullName != "System.String") return false;

        var declaring = mr.DeclaringType;
        TypeDefinition? resolved;
        try { resolved = declaring.Resolve(); }
        catch (AssemblyResolutionException) { resolved = null; }
        return resolved is not null
            ? ImplementsCommandBuilder(resolved)
            : MatchesCommandBuilderHeuristic(declaring);
    }

    // SQL injection sink: tainted string assigned to IDbCommand.CommandText.
    // Matches `callvirt System.Data.IDbCommand::set_CommandText(string)` OR a setter
    // on a class that implements IDbCommand. Resolve-failure fallback accepts
    // declaring types under known DB-provider namespaces whose names end in `Command`.
    public static SinkMatch? MatchCommandTextSetter(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (!IsCommandTextSetterCall(mr)) return null;

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

    // Phase 1 walker primitive: tainted value flowing into
    // DefaultInterpolatedStringHandler.AppendFormatted taints the handler local.
    // Subsequent ToStringAndClear() on that local picks up taint via the existing
    // HandleCall over-approximation (the byref-receiver lands in the call's bitmask).
    //
    // Returns true if the call was handled here; the caller (TaintWalker.HandleCall)
    // should early-return after a true result, skipping default external-call
    // dispatch (which would no-op for this call anyway, but avoids redundant work).
    public static bool TryHandleInterpolatedStringAppend(
        MethodReference callee,
        Instruction call,
        StackSlot[] argSlots,
        TaintState state)
    {
        if (callee.DeclaringType.FullName != "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler") return false;
        if (callee.Name != "AppendFormatted") return false;
        if (argSlots.Length == 0) return false;

        // The value-arg is argSlots[0]. If it's untainted, nothing to propagate.
        var valueSlot = argSlots[0];
        if (!valueSlot.Tainted) return false;

        // Walk back from the call site to find the receiver's pusher (the ldloca that
        // pushed the address of the handler local). We use net stack-balance tracking
        // rather than naive instruction-counting: when an arg is itself produced by a
        // transformer like `ldfld` (pops 1, pushes 1), walking back paramCount steps
        // would land on the consumed-then-popped operand instead of the receiver.
        // Net cumulative (push - pop) reaches totalPushers exactly at the receiver pusher.
        int totalPushers = callee.Parameters.Count + (callee.HasThis ? 1 : 0);
        var cur = call.Previous;
        Instruction? receiverPusher = null;
        int balance = 0;

        while (cur is not null)
        {
            if (cur.OpCode.Code == Code.Nop) { cur = cur.Previous; continue; }
            balance += ComputeStackPushes(cur) - ComputeStackPops(cur);
            if (balance >= totalPushers)
            {
                receiverPusher = cur;
                break;
            }
            cur = cur.Previous;
        }

        if (receiverPusher is null) return false;
        if (receiverPusher.OpCode.Code != Code.Ldloca && receiverPusher.OpCode.Code != Code.Ldloca_S) return false;
        if (receiverPusher.Operand is not VariableDefinition vd) return false;

        var prov = $"InterpolatedString({valueSlot.Provenance})";
        state.Locals[vd.Index] = StackSlot.TaintedWith(prov);
        return true;
    }

    private static int ComputeStackPushes(Instruction ins)
    {
        if (ins.Operand is MethodReference mr &&
            (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt
             || ins.OpCode.Code == Code.Calli || ins.OpCode.Code == Code.Newobj))
        {
            if (ins.OpCode.Code == Code.Newobj) return 1;
            return mr.ReturnType.FullName == "System.Void" ? 0 : 1;
        }
        return ins.OpCode.StackBehaviourPush switch
        {
            StackBehaviour.Push0 => 0,
            StackBehaviour.Push1 => 1,
            StackBehaviour.Push1_push1 => 2,
            StackBehaviour.Pushi => 1,
            StackBehaviour.Pushi8 => 1,
            StackBehaviour.Pushr4 => 1,
            StackBehaviour.Pushr8 => 1,
            StackBehaviour.Pushref => 1,
            _ => 0,
        };
    }

    private static int ComputeStackPops(Instruction ins)
    {
        if (ins.Operand is MethodReference mr &&
            (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt
             || ins.OpCode.Code == Code.Calli || ins.OpCode.Code == Code.Newobj))
        {
            int pops = mr.Parameters.Count;
            if (mr.HasThis && ins.OpCode.Code != Code.Newobj) pops += 1;
            if (ins.OpCode.Code == Code.Calli) pops += 1;  // function pointer
            return pops;
        }
        return ins.OpCode.StackBehaviourPop switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 => 1,
            StackBehaviour.Popi => 1,
            StackBehaviour.Popref => 1,
            StackBehaviour.Pop1_pop1 => 2,
            StackBehaviour.Popi_popi => 2,
            StackBehaviour.Popi_pop1 => 2,
            StackBehaviour.Popi_popi8 => 2,
            StackBehaviour.Popref_pop1 => 2,
            StackBehaviour.Popref_popi => 2,
            StackBehaviour.Popi_popi_popi => 3,
            StackBehaviour.Popref_popi_popi => 3,
            StackBehaviour.Popref_popi_popi8 => 3,
            StackBehaviour.Popref_popi_popr4 => 3,
            StackBehaviour.Popref_popi_popr8 => 3,
            StackBehaviour.Popref_popi_popref => 3,
            _ => 0,
        };
    }

    // T2.1 sink: tainted string flowing into Weasel.Postgresql.ICommandBuilder::AppendWithParameters.
    // Marten 8.36's FullTextWhereFragment.Apply emits SQL through this method, NOT through
    // IDbCommand.set_CommandText. Read-only on state; mirrors MatchCommandTextSetter shape.
    public static SinkMatch? MatchCommandBuilderAppend(Instruction instruction, SymbolicStack stack)
    {
        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) return null;
        if (instruction.Operand is not MethodReference mr) return null;
        if (!IsCommandBuilderAppendCall(mr)) return null;

        // Stack layout: [receiver, arg0, arg1, …, argN-1] with argN-1 at Peek(0).
        // The SQL string (arg0) is at Peek(paramCount - 1).
        int paramCount = mr.Parameters.Count;
        int peekOffset = paramCount - 1;
        if (stack.Depth < paramCount + 1) return null;
        var sqlSlot = stack.Peek(peekOffset);
        if (!sqlSlot.Tainted) return null;

        return new SinkMatch
        {
            Kind = SinkKind.SqlInjection,
            Api = SinkApi.SqlCommandBuilderAppend,
            SizeProvenance = sqlSlot.Provenance,
        };
    }

    private static bool ImplementsCommandBuilder(TypeDefinition td)
    {
        const string Target = "Weasel.Postgresql.ICommandBuilder";
        const string TargetFake = "Weasel.Postgresql.IFakeCommandBuilder";  // test fixture

        var current = td;
        while (current is not null)
        {
            if (current.FullName == Target || current.FullName == TargetFake) return true;
            foreach (var iface in current.Interfaces)
            {
                var ir = iface.InterfaceType;
                if (ir.FullName == Target || ir.FullName == TargetFake) return true;
                TypeDefinition? iresolved;
                try { iresolved = ir.Resolve(); }
                catch (AssemblyResolutionException) { iresolved = null; }
                if (iresolved is not null && (iresolved.FullName == Target || iresolved.FullName == TargetFake)) return true;
            }
            var baseType = current.BaseType;
            try { current = baseType?.Resolve(); }
            catch (AssemblyResolutionException) { current = null; }
        }
        return false;
    }

    private static bool MatchesCommandBuilderHeuristic(TypeReference tr)
    {
        var ns = tr.Namespace ?? "";
        if (!ns.StartsWith("Weasel.Postgresql", StringComparison.Ordinal)) return false;

        var typeName = tr.Name ?? "";
        return typeName.Contains("Command", StringComparison.Ordinal);
    }
}
