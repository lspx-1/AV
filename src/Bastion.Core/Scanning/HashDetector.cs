using Bastion.Core.Models;
using Bastion.Core.Signatures;

namespace Bastion.Core.Scanning;

public sealed class HashDetector(HashSignatureDb db) : IDetector
{
    public string Name => "Signatur";

    public IEnumerable<Detection> Inspect(FileScanContext context)
    {
        if (db.TryMatch(context.Sha256, out var name))
            yield return new Detection(name, Name, Severity.High, 100, "SHA-256 ist als Schadsoftware bekannt") { IsDefinitive = true };
    }
}
