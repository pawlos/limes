using System.Linq;
using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class AssemblyContextTests
{
    // Path relative to the test assembly's output dir. Task 1's csproj copies
    // the fixture DLL+PDB to `Fixtures/` under the test bin.
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Load_ReadsAssemblyWithSymbols()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        ctx.Assembly.ShouldNotBeNull();
        ctx.Assembly.MainModule.HasSymbols.ShouldBeTrue();
    }

    [Fact]
    public void FindMethod_ByShortSignature_ReturnsDefinition()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Short form: "Namespace.Type::Method(Params)" — return type elided. This is the form
        // rules files use.
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");

        m.ShouldNotBeNull();
        m!.Name.ShouldBe("Identity");
    }

    [Fact]
    public void FindMethod_ByCecilFullName_ReturnsDefinition()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        // Cecil's actual MethodReference.FullName shape: "<ReturnType> <Namespace.Type>::<Method>(<Params>)".
        // AssemblyContext._methodsByFullName indexes by this form.
        var m = ctx.FindMethod("System.Int32 TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");

        m.ShouldNotBeNull();
        m!.Name.ShouldBe("Identity");
    }

    [Fact]
    public void FindMethod_UnknownSignature_ReturnsNull()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::DoesNotExist(System.Int32)").ShouldBeNull();
    }

    [Fact]
    public void SequencePoints_AvailableForUserMethod()
    {
        using var ctx = AssemblyContext.Load(FixturePath);
        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.SimpleShapes::Identity(System.Int32)");
        m.ShouldNotBeNull();

        var anyWithPoint = false;
        foreach (var ins in m!.Body.Instructions)
        {
            if (m.DebugInformation.GetSequencePoint(ins) is { } sp && !sp.IsHidden)
            {
                sp.Document.Url.ShouldContain("Fixtures.cs");
                sp.StartLine.ShouldBeGreaterThan(0);
                anyWithPoint = true;
                break;
            }
        }
        anyWithPoint.ShouldBeTrue();
    }

    [Fact]
    public void Load_MissingPdb_Throws()
    {
        // Copy the fixture DLL to a temp path, do NOT copy its PDB, and confirm Load throws.
        var tmpDir = Path.Combine(Path.GetTempPath(), "TaintAnalyzerTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpDir);
        try
        {
            var dllCopy = Path.Combine(tmpDir, "noSymbols.dll");
            File.Copy(FixturePath, dllCopy);

            var ex = Should.Throw<AssemblyContextException>(() => AssemblyContext.Load(dllCopy));
            ex.Message.ShouldContain("symbols");
            ex.Message.ShouldContain("noSymbols.dll");
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }

    [Fact]
    public void FindMethod_InParamByRef_StripsModreqFromShortSignature()
    {
        // `in int` compiles to "System.Int32& modreq(System.Runtime.InteropServices.InAttribute)".
        // BuildShortSignature must strip the modifier so the user writes "System.Int32&" in
        // rules.yaml (no spaces, no Cecil-internal knowledge required).
        using var ctx = AssemblyContext.Load(FixturePath);

        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.InParamFixtures::SumByRef(System.Int32&,System.Int32&)");

        m.ShouldNotBeNull("in-param method must be findable using plain T& without modreq");
        m!.Name.ShouldBe("SumByRef");
    }

    [Fact]
    public void FindMethod_InParamReferenceType_StripsModreqFromShortSignature()
    {
        using var ctx = AssemblyContext.Load(FixturePath);

        var m = ctx.FindMethod("TaintAnalyzer.Tests.Fixtures.InParamFixtures::StringLength(System.String&)");

        m.ShouldNotBeNull();
        m!.Name.ShouldBe("StringLength");
    }

    [Fact]
    public void AllSignatures_ContainsNoSpaces()
    {
        // Guard: no short signature in the lookup table may contain a space.
        // If any modreq slips through, rules.yaml validation will reject entries that
        // try to target those methods.
        using var ctx = AssemblyContext.Load(FixturePath);

        var withSpaces = ctx.AllSignatures().Where(s => s.Contains(' ')).ToList();
        withSpaces.ShouldBeEmpty("short signatures must not contain spaces (modreq not stripped?)");
    }
}
