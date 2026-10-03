using Bastion.Core.Licensing;
using Bastion.Core.Runtime;

namespace Bastion.LicenseManager;

public sealed record IssuedLicense
{
    public LicenseDocument Document { get; init; } = new();
    public string Token { get; init; } = "";
    public string? Note { get; init; }
}

/// <summary>Local list of all licenses issued with this tool (licenses.json next to the key).</summary>
public sealed class LicenseRegistry
{
    private static readonly string FilePath = Path.Combine(KeyStore.Folder, "licenses.json");
    private readonly List<IssuedLicense> _items = JsonStore.LoadOrDefault<List<IssuedLicense>>(FilePath);

    public IReadOnlyList<IssuedLicense> Items => _items.OrderByDescending(i => i.Document.IssuedAt).ToList();

    public void Add(IssuedLicense license)
    {
        _items.Add(license);
        Save();
    }

    public void Remove(IssuedLicense license)
    {
        _items.Remove(license);
        Save();
    }

    private void Save() => JsonStore.Save(FilePath, _items);
}
