using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class SqliScanProfileTests
{
    private static string FixturePath =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "TaintAnalyzer.Tests.Fixtures.dll");

    [Fact]
    public void Default_StringSourceTypes_ContainsString()
    {
        EnumeratorConfig.Default.StringSourceTypes.ShouldContain("System.String");
    }
}
