using System.Collections.Concurrent;
using System.Net;

namespace Bastion.Core.Network;

/// <summary>IP addresses of known malware command-and-control servers (e.g. abuse.ch Feodo Tracker).</summary>
public sealed class IpBlocklist
{
    private readonly ConcurrentDictionary<string, string> _ips = new();

    public int Count => _ips.Count;

    public void LoadDirectory(string directory)
    {
        if (!Directory.Exists(directory))
            return;
        foreach (var file in Directory.EnumerateFiles(directory, "*.txt"))
            LoadFile(file);
    }

    public void LoadFile(string path)
    {
        var source = Path.GetFileNameWithoutExtension(path);
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;
            var ip = line.Split([' ', '\t', ',', ';'], 2)[0];
            if (IPAddress.TryParse(ip, out var parsed))
                _ips[parsed.ToString()] = source;
        }
    }

    public void Add(string ip, string source) => _ips[ip] = source;

    public bool TryMatch(IPAddress address, out string source) =>
        _ips.TryGetValue(address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString(), out source!);
}
