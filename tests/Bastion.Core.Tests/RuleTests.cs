using System.Text;
using Bastion.Core.Scanning;
using Bastion.Core.Signatures;

namespace Bastion.Core.Tests;

public class RuleTests
{
    private static bool Matches(string rule, byte[] content) =>
        RuleParser.Parse(rule).Single().IsMatch(FileScanContext.FromBytes("test.bin", content));

    private static byte[] Bytes(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void TextStringMatches()
    {
        const string rule = """rule a { strings: $x = "hello" condition: $x }""";
        Assert.True(Matches(rule, Bytes("say hello world")));
        Assert.False(Matches(rule, Bytes("say HELLO world")));
    }

    [Fact]
    public void NoCaseAndWide()
    {
        Assert.True(Matches("""rule a { strings: $x = "hello" nocase condition: $x }""", Bytes("HeLLo")));
        Assert.True(Matches("""rule a { strings: $x = "hi" wide condition: $x }""", Encoding.Unicode.GetBytes("oh hi there")));
        Assert.False(Matches("""rule a { strings: $x = "hi" wide condition: $x }""", Bytes("oh hi there")));
        Assert.True(Matches("""rule a { strings: $x = "hi" ascii wide condition: $x }""", Bytes("oh hi there")));
    }

    [Fact]
    public void HexWithWildcards()
    {
        const string rule = "rule a { strings: $h = { 4D 5A ?? 00 FF } condition: $h }";
        Assert.True(Matches(rule, [0x01, 0x4D, 0x5A, 0x99, 0x00, 0xFF]));
        Assert.False(Matches(rule, [0x4D, 0x5A, 0x99, 0x01, 0xFF]));
    }

    [Fact]
    public void QuantifiersAndBooleanLogic()
    {
        const string rule = """
            rule a
            {
                meta:
                    description = "test"
                    severity = "high"
                strings:
                    $a1 = "one"
                    $a2 = "two"
                    $b = "three"
                condition:
                    (2 of ($a*) and not $b) or all of them
            }
            """;
        Assert.True(Matches(rule, Bytes("one two")));
        Assert.False(Matches(rule, Bytes("one three")));
        Assert.True(Matches(rule, Bytes("one two three")));
        Assert.Equal(Models.Severity.High, RuleParser.Parse(rule).Single().Severity);
    }

    [Fact]
    public void AnyOfThemAndFilesize()
    {
        const string rule = """rule a { strings: $a = "x" $b = "y" condition: any of them and filesize < 1KB }""";
        Assert.True(Matches(rule, Bytes("y")));
        Assert.False(Matches(rule, new byte[2048]));
    }

    [Fact]
    public void CommentsAndMultipleRules()
    {
        var rules = RuleParser.Parse("""
            // first
            rule a { condition: true }
            /* second
               rule */
            rule b : tag1 tag2 { condition: false }
            """);
        Assert.Equal(2, rules.Count);
        Assert.Equal(["tag1", "tag2"], rules[1].Tags);
    }

    [Fact]
    public void SyntaxErrorsReportLine()
    {
        var e = Assert.Throws<RuleParseException>(() => RuleParser.Parse("rule a {\n strings:\n $x = \"a\"\n condition: $x and\n}"));
        Assert.True(e.Line >= 4);
    }

    [Fact]
    public void ShippedRulesParse()
    {
        var dir = Path.Combine(Runtime.BastionPaths.DefaultSignatureDirectory(), "rules");
        var set = new RuleSet();
        set.LoadDirectories(dir);
        Assert.Empty(set.Errors);
        Assert.True(set.Count >= 1);
    }
}
