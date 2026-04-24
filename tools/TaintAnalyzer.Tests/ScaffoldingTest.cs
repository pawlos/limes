using Shouldly;

namespace TaintAnalyzer.Tests;

public class ScaffoldingTest
{
    [Fact]
    public void ScaffoldingCompiles() => true.ShouldBeTrue();
}
