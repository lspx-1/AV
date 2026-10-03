using System.Collections.Concurrent;

namespace Bastion.Core.Signatures;

/// <summary>
/// SHA-256 hashes of known malicious files. Files are plain text: one hash per line,
/// optionally followed by whitespace and a detection name. Lines starting with # are comments.
/// </summary>
public sealed class HashSignatureDb
{
    private readonly ConcurrentDictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);

    public int Count => _hashes.Count;

    public DateTimeOffset? LastLoaded { get; private set; }

    public void LoadDirectory(string directory)
    {
        if (!Directory.Exists(directory))
            return;
        foreach (var file in Directory.EnumerateFiles(directory, "*.txt", SearchOption.AllDirectories))
            LoadFile(file);
        LastLoaded = DateTimeOffset.Now;
    }

    public int LoadFile(string path)
    {
        var defaultName = "Malware." + Path.GetFileNameWithoutExtension(path);
        var added = 0;
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;
            var parts = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            var hash = parts[0].Trim('"');
            if (!IsSha256(hash))
                continue;
            if (_hashes.TryAdd(hash, parts.Length > 1 ? parts[1].Trim() : defaultName))
                added++;
        }
        return added;
    }

    public void Add(string sha256, string name) => _hashes[sha256] = name;

    public bool TryMatch(string sha256, out string name) => _hashes.TryGetValue(sha256, out name!);

    public static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);
}
