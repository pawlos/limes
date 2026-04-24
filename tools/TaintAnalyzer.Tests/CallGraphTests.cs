using Mono.Cecil;
using Mono.Cecil.Cil;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class CallGraphTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    private static MethodDefinition M(AssemblyContext ctx, string shortSig) =>
        ctx.FindMethod(shortSig) ?? throw new InvalidOperationException($"missing fixture: {shortSig}");

    [Fact]
    public void ResolveCallSite_DirectCall_EmitsDirectDispatch()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::DirectCall()");
        var call = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Call &&
            i.Operand is MethodReference mr && mr.Name == "Identity");

        var dispatch = CallGraph.ResolveCallSite(m, call, receiverStaticType: null, ctx);

        dispatch.Kind.ShouldBe("direct");
        dispatch.ClosureBoundary.ShouldBeFalse();
        dispatch.ResolvedTargets.ShouldBeEmpty();  // direct calls: spec convention is empty list
    }

    [Fact]
    public void ResolveCallSite_VirtualCall_WithNarrowedSealedLocal_ResolvesToOneTarget()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ReadViaNarrowedLocal(System.Byte[])");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "Read");

        // Receiver flow-type: the local is typed as TaintAnalyzer.Tests.Fixtures.BufferedReader.
        var bufferedReader = ctx.Assembly.MainModule.GetType("TaintAnalyzer.Tests.Fixtures.BufferedReader");
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: bufferedReader, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.StaticType.ShouldBe("TaintAnalyzer.Tests.Fixtures.BufferedReader");
        dispatch.ClosureBoundary.ShouldBeFalse();
        dispatch.ResolvedTargets.ShouldHaveSingleItem();
        dispatch.ResolvedTargets[0].ShouldContain("BufferedReader::Read");
    }

    [Fact]
    public void ResolveCallSite_VirtualCall_AbstractReceiver_CHAClosureWithinAssembly()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ReadViaAbstract(TaintAnalyzer.Tests.Fixtures.Reader,System.Byte[])");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "Read");

        var reader = ctx.Assembly.MainModule.GetType("TaintAnalyzer.Tests.Fixtures.Reader");
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: reader, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.ClosureBoundary.ShouldBeFalse();  // abstract base + all descendants are sealed → closure complete within assembly
        dispatch.ResolvedTargets.Count.ShouldBe(2);
        dispatch.ResolvedTargets.ShouldContain(s => s.Contains("BufferedReader::Read"));
        dispatch.ResolvedTargets.ShouldContain(s => s.Contains("NetworkReader::Read"));
    }

    [Fact]
    public void ResolveCallSite_ExternalAssemblyCall_SetsClosureBoundary()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::ExternalVirtualCall(System.IO.Stream)");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "ReadByte");

        // Receiver flow-type could not be narrowed — pass the call-site's declaring type.
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: null, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.ClosureBoundary.ShouldBeTrue();
        dispatch.ResolvedTargets.ShouldBeEmpty();   // nothing within analyzed assembly
    }

    [Fact]
    public void ResolveCallSite_VirtualCall_NonSealedNonAbstractReceiver_SetsClosureBoundary()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = M(ctx, "TaintAnalyzer.Tests.Fixtures.CallGraphFixtures::CallViaOpenBase(System.Int32)");
        var callvirt = m.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Callvirt &&
            i.Operand is MethodReference mr && mr.Name == "Compute");

        var openBase = ctx.Assembly.MainModule.GetType("TaintAnalyzer.Tests.Fixtures.OpenBase");
        var dispatch = CallGraph.ResolveCallSite(m, callvirt, receiverStaticType: openBase, ctx);

        dispatch.Kind.ShouldBe("virtual");
        dispatch.ClosureBoundary.ShouldBeTrue();                       // external subclass possible
        dispatch.ResolvedTargets.ShouldContain(s => s.Contains("OpenBase::Compute"));  // its own virtual method
    }
}
