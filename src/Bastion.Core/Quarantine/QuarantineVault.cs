using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Bastion.Core.Runtime;

namespace Bastion.Core.Quarantine;

public sealed record QuarantineItem
{
    public Guid Id { get; init; }
    public string OriginalPath { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public long Size { get; init; }
    public string DetectionName { get; init; } = "";
    public string Reason { get; init; } = "";
    public DateTimeOffset QuarantinedAt { get; init; }

    /// <summary>The original could not be deleted (in use) and will be removed on the next restart.</summary>
    public bool PendingDeleteOnReboot { get; init; }
}

/// <summary>
/// Stores quarantined files encrypted with AES-256-GCM so they cannot be executed or picked up by other scanners.
/// The vault key is protected with DPAPI (machine scope) on Windows.
/// </summary>
public sealed class QuarantineVault
{
    private const string Magic = "BQF1";
    private readonly string _dir;
    private readonly string _indexFile;
    private readonly byte[] _key;
    private readonly Lock _lock = new();
    private List<QuarantineItem> _items;

    public QuarantineVault(string directory)
    {
        _dir = directory;
        Directory.CreateDirectory(_dir);
        _indexFile = Path.Combine(_dir, "index.json");
        _key = LoadOrCreateKey(Path.Combine(_dir, "vault.key"));
        _items = JsonStore.LoadOrDefault<List<QuarantineItem>>(_indexFile);
    }

    public IReadOnlyList<QuarantineItem> Items
    {
        get
        {
            lock (_lock)
                return _items.OrderByDescending(i => i.QuarantinedAt).ToList();
        }
    }

    public QuarantineItem Add(string path, string sha256, string detectionName, string reason)
    {
        var data = File.ReadAllBytes(path);
        var id = Guid.NewGuid();
        File.WriteAllBytes(ItemPath(id), Encrypt(data));

        var pending = false;
        try
        {
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            pending = OperatingSystem.IsWindows() && MoveFileEx(path, null, 0x4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
            if (!pending)
            {
                File.Delete(ItemPath(id));
                throw;
            }
        }

        var item = new QuarantineItem
        {
            Id = id,
            OriginalPath = path,
            Sha256 = sha256,
            Size = data.LongLength,
            DetectionName = detectionName,
            Reason = reason,
            QuarantinedAt = DateTimeOffset.Now,
            PendingDeleteOnReboot = pending,
        };
        lock (_lock)
        {
            _items.Add(item);
            Save();
        }
        return item;
    }

    /// <summary>Restores the file. Returns the path it was written to (a new name if the original exists).</summary>
    public string Restore(Guid id)
    {
        var item = Find(id);
        var target = item.OriginalPath;
        if (File.Exists(target))
            target = Path.Combine(Path.GetDirectoryName(target)!, Path.GetFileNameWithoutExtension(target) + " (wiederhergestellt)" + Path.GetExtension(target));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllBytes(target, Decrypt(File.ReadAllBytes(ItemPath(id))));
        Remove(id);
        return target;
    }

    public void Delete(Guid id)
    {
        Find(id);
        Remove(id);
    }

    private QuarantineItem Find(Guid id)
    {
        lock (_lock)
            return _items.FirstOrDefault(i => i.Id == id) ?? throw new KeyNotFoundException("Eintrag nicht in der Quarantäne gefunden.");
    }

    private void Remove(Guid id)
    {
        var file = ItemPath(id);
        if (File.Exists(file))
            File.Delete(file);
        lock (_lock)
        {
            _items.RemoveAll(i => i.Id == id);
            Save();
        }
    }

    private void Save() => JsonStore.Save(_indexFile, _items);

    private string ItemPath(Guid id) => Path.Combine(_dir, id.ToString("N") + ".bqf");

    internal byte[] Encrypt(byte[] plain)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(_key, 16))
            aes.Encrypt(nonce, plain, cipher, tag);
        var output = new byte[4 + 12 + 16 + cipher.Length];
        System.Text.Encoding.ASCII.GetBytes(Magic).CopyTo(output, 0);
        nonce.CopyTo(output, 4);
        tag.CopyTo(output, 16);
        cipher.CopyTo(output, 32);
        return output;
    }

    internal byte[] Decrypt(byte[] blob)
    {
        if (blob.Length < 32 || System.Text.Encoding.ASCII.GetString(blob, 0, 4) != Magic)
            throw new InvalidDataException("Quarantänedatei ist beschädigt.");
        var plain = new byte[blob.Length - 32];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(blob.AsSpan(4, 12), blob.AsSpan(32), blob.AsSpan(16, 16), plain);
        return plain;
    }

    private static byte[] LoadOrCreateKey(string path)
    {
        if (File.Exists(path))
            return Unprotect(File.ReadAllBytes(path));
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, Protect(key));
        return key;
    }

    private static byte[] Protect(byte[] data) =>
        OperatingSystem.IsWindows() ? ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine) : data;

    private static byte[] Unprotect(byte[] data) =>
        OperatingSystem.IsWindows() ? ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine) : data;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string existing, string? newName, int flags);
}
