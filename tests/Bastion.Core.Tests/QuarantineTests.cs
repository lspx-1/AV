using Bastion.Core.Quarantine;

namespace Bastion.Core.Tests;

public class QuarantineTests
{
    [Fact]
    public void AddRestoreDelete()
    {
        var dir = TestFiles.TempDir();
        var vault = new QuarantineVault(Path.Combine(dir, "vault"));
        var file = Path.Combine(dir, "bad.exe");
        File.WriteAllBytes(file, TestFiles.Eicar());

        var item = vault.Add(file, "abc", "EICAR-Test-File", "Test");
        Assert.False(File.Exists(file));
        Assert.Single(vault.Items);

        // The stored blob must not contain the original bytes.
        var blob = File.ReadAllBytes(Directory.GetFiles(Path.Combine(dir, "vault"), "*.bqf").Single());
        Assert.DoesNotContain("EICAR", System.Text.Encoding.ASCII.GetString(blob));

        var restored = vault.Restore(item.Id);
        Assert.Equal(file, restored);
        Assert.Equal(TestFiles.Eicar(), File.ReadAllBytes(file));
        Assert.Empty(vault.Items);

        var again = vault.Add(file, "abc", "EICAR-Test-File", "Test");
        vault.Delete(again.Id);
        Assert.Empty(vault.Items);
        Assert.Empty(Directory.GetFiles(Path.Combine(dir, "vault"), "*.bqf"));
    }

    [Fact]
    public void IndexSurvivesReload()
    {
        var dir = TestFiles.TempDir();
        var file = Path.Combine(dir, "x.bin");
        File.WriteAllText(file, "data");
        new QuarantineVault(Path.Combine(dir, "vault")).Add(file, "h", "Name", "Reason");
        var reloaded = new QuarantineVault(Path.Combine(dir, "vault"));
        Assert.Single(reloaded.Items);
        Assert.Equal("data", File.ReadAllText(reloaded.Restore(reloaded.Items[0].Id)));
    }
}
