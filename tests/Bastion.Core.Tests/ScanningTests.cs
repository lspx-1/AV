using System.Text;
using Bastion.Core.Heuristics;
using Bastion.Core.Models;
using Bastion.Core.Platform;
using Bastion.Core.Scanning;
using Bastion.Core.Signatures;

namespace Bastion.Core.Tests;

public class ScanningTests
{
    private static ScanEngine Engine(HashSignatureDb? hashes = null, RuleSet? rules = null) => new(
    [
        new HashDetector(hashes ?? new HashSignatureDb()),
        new RuleDetector(rules ?? new RuleSet()),
        new HeuristicDetector(() => Sensitivity.Medium, _ => SignatureState.Unsigned),
    ], () => new ScanOptions());

    [Fact]
    public void EicarIsDetectedByHashAndRule()
    {
        var hashes = new HashSignatureDb();
        hashes.LoadDirectory(Path.Combine(Runtime.BastionPaths.DefaultSignatureDirectory(), "hashes"));
        var rules = new RuleSet();
        rules.LoadDirectories(Path.Combine(Runtime.BastionPaths.DefaultSignatureDirectory(), "rules"));

        var file = Path.Combine(TestFiles.TempDir(), "eicar.com");
        File.WriteAllBytes(file, TestFiles.Eicar());

        var result = Engine(hashes, rules).ScanFile(file);
        Assert.True(result.IsMalicious);
        Assert.True(result.Verdict!.IsDefinitive);
        Assert.Contains(result.Detections, d => d.Detector == "Signatur");
        Assert.Contains(result.Detections, d => d.Detector == "Regel");
    }

    [Fact]
    public void CleanFileIsClean()
    {
        var file = Path.Combine(TestFiles.TempDir(), "notes.txt");
        File.WriteAllText(file, "Einkaufsliste: Milch, Brot");
        var result = Engine().ScanFile(file);
        Assert.False(result.IsMalicious);
        Assert.Equal(64, result.Sha256!.Length);
    }

    [Fact]
    public void ExcludedPathsAreSkipped()
    {
        var dir = TestFiles.TempDir();
        var file = Path.Combine(dir, "eicar.com");
        File.WriteAllBytes(file, TestFiles.Eicar());
        var rules = new RuleSet();
        rules.LoadDirectories(Path.Combine(Runtime.BastionPaths.DefaultSignatureDirectory(), "rules"));
        var engine = new ScanEngine([new RuleDetector(rules)], () => new ScanOptions { ExcludedPaths = [dir] });
        Assert.False(engine.ScanFile(file).IsMalicious);
    }

    [Theory]
    [InlineData("Rechnung.pdf.exe", true)]
    [InlineData("foto.jpg.scr", true)]
    [InlineData("setup.exe", false)]
    [InlineData("bericht.pdf", false)]
    [InlineData("archiv.tar.gz", false)]
    public void DoubleExtension(string name, bool expected) =>
        Assert.Equal(expected, HeuristicDetector.HasDoubleExtension(name));

    [Fact]
    public void RtloNameIsFlagged()
    {
        var context = FileScanContext.FromBytes("C:\\Users\\a\\Downloads\\Rechnung\u202Efdp.exe", Encoding.ASCII.GetBytes("plain"));
        var detections = new HeuristicDetector(() => Sensitivity.Medium, _ => SignatureState.Unsigned).Inspect(context).ToList();
        Assert.Single(detections);
    }

    [Fact]
    public void PeParserReadsRealAssembly()
    {
        var bytes = File.ReadAllBytes(typeof(object).Assembly.Location);
        var pe = PeFile.TryParse(bytes);
        Assert.NotNull(pe);
        Assert.True(pe!.IsDotNet);
        Assert.NotEmpty(pe.Sections);
    }

    [Fact]
    public void PeParserSurvivesGarbage()
    {
        var random = new Random(42);
        for (var i = 0; i < 200; i++)
        {
            var data = new byte[random.Next(0, 2048)];
            random.NextBytes(data);
            if (data.Length > 2) { data[0] = (byte)'M'; data[1] = (byte)'Z'; }
            _ = PeFile.TryParse(data); // must not throw
        }
    }

    [Fact]
    public void EntropyRange()
    {
        Assert.Equal(0, Entropy.Shannon(new byte[1000]));
        var random = new byte[100_000];
        new Random(1).NextBytes(random);
        Assert.True(Entropy.Shannon(random) > 7.9);
    }

    [Fact]
    public void HashDbParsesNamesAndComments()
    {
        var file = Path.Combine(TestFiles.TempDir(), "list.txt");
        File.WriteAllText(file, "# comment\n" + new string('a', 64) + " Trojan.Test\n" + new string('b', 64) + "\nnot-a-hash\n");
        var db = new HashSignatureDb();
        Assert.Equal(2, db.LoadFile(file));
        Assert.True(db.TryMatch(new string('A', 64), out var name));
        Assert.Equal("Trojan.Test", name);
    }
}
