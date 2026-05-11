using Shouldly;
using TaintAnalyzer;

namespace TaintAnalyzer.Tests;

public class GlobMatcherTests
{
    [Theory]
    [InlineData("*", "anything")]
    [InlineData("*", "")]
    [InlineData("foo", "foo")]
    [InlineData("*Reader", "XmlReader")]
    [InlineData("*Reader", "Reader")]
    [InlineData("System.*", "System.IO")]
    [InlineData("System.*", "System.Collections.Generic")]
    [InlineData("*Test*", "MyTestClass")]
    [InlineData("*Test*", "TestSuite")]
    [InlineData("*Test*", "Test")]
    public void Matches_TrueCases(string pattern, string input)
    {
        GlobMatcher.Matches(pattern, input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("foo", "bar")]
    [InlineData("*Reader", "Readable")]
    [InlineData("*Reader", "ReaderWriter")]
    [InlineData("System.*", "Microsoft.IO")]
    public void Matches_FalseCases(string pattern, string input)
    {
        GlobMatcher.Matches(pattern, input).ShouldBeFalse();
    }
}
