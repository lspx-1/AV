namespace Bastion.Core.Updates;

public sealed record UpdateResult(bool Success, int NewHashes, int NewIps, string Message);

/// <summary>Downloads public threat feeds (abuse.ch MalwareBazaar hashes and Feodo Tracker C2 IPs).</summary>
public sealed class SignatureUpdater(HttpClient http)
{
    public async Task<UpdateResult> UpdateAsync(string hashDir, IEnumerable<string> hashFeeds, string ipDir, IEnumerable<string> ipFeeds, CancellationToken ct)
    {
        Directory.CreateDirectory(hashDir);
        Directory.CreateDirectory(ipDir);
        var errors = new List<string>();
        var hashes = 0;
        var ips = 0;
        var i = 0;
        foreach (var url in hashFeeds)
        {
            var (ok, lines) = await DownloadAsync(url, Path.Combine(hashDir, $"feed-{i++}.txt"), ct);
            if (ok) hashes += lines; else errors.Add(url);
        }
        i = 0;
        foreach (var url in ipFeeds)
        {
            var (ok, lines) = await DownloadAsync(url, Path.Combine(ipDir, $"feed-{i++}.txt"), ct);
            if (ok) ips += lines; else errors.Add(url);
        }
        return errors.Count == 0
            ? new UpdateResult(true, hashes, ips, $"Signaturen aktualisiert: {hashes:N0} Hashes, {ips:N0} Steuerserver-Adressen.")
            : new UpdateResult(hashes + ips > 0, hashes, ips, $"Teilweise aktualisiert. Nicht erreichbar: {string.Join(", ", errors)}");
    }

    private async Task<(bool Ok, int Lines)> DownloadAsync(string url, string target, CancellationToken ct)
    {
        try
        {
            var text = await http.GetStringAsync(url, ct);
            var count = text.Split('\n').Count(l => l.Length > 0 && l[0] != '#');
            if (count == 0)
                return (false, 0);
            var tmp = target + ".tmp";
            await File.WriteAllTextAsync(tmp, $"# Quelle: {url}\n# Stand: {DateTimeOffset.Now:O}\n" + text, ct);
            File.Move(tmp, target, overwrite: true);
            return (true, count);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            return (false, 0);
        }
    }
}
