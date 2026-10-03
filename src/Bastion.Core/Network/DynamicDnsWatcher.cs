using System.Net;
using System.Runtime.InteropServices;

namespace Bastion.Core.Network;

/// <summary>
/// Knows which public IP addresses belong to dynamic-DNS names (duckdns.org, no-ip, ddns.net, ...). Remote-access
/// trojans like these because the operator can move the server without rebuilding the malware. The TCP table only
/// has IP addresses, so the names are taken from the Windows DNS cache and resolved again.
/// </summary>
public sealed class DynamicDnsWatcher
{
    private static readonly string[] Suffixes =
    [
        "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "noip.com", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
        "servebeer.com", "serveftp.com", "servegame.com", "serveminecraft.net", "myftp.biz", "myftp.org", "myvnc.com",
        "redirectme.net", "systes.net", "3utilities.com", "bounceme.net", "freedynamicdns.org", "gotdns.ch", "dyndns.org",
        "dyndns.biz", "dynu.net", "ddnsking.com", "chickenkiller.com", "ignorelist.com", "strangled.net", "webhop.me", "ngrok.io",
        "ngrok-free.app", "ply.gg", "playit.gg",
    ];

    private readonly Func<IEnumerable<string>> _cacheNames;
    private readonly Func<string, IReadOnlyList<IPAddress>> _resolve;
    private readonly TimeSpan _interval;
    private readonly Lock _lock = new();
    private Dictionary<IPAddress, string> _hosts = new();
    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
    private int _busy;

    public DynamicDnsWatcher(Func<IEnumerable<string>>? cacheNames = null, Func<string, IReadOnlyList<IPAddress>>? resolve = null, TimeSpan? interval = null)
    {
        _cacheNames = cacheNames ?? ReadWindowsDnsCache;
        _resolve = resolve ?? ResolveSafe;
        _interval = interval ?? TimeSpan.FromMinutes(2);
    }

    public static bool IsDynamicDns(string host)
    {
        host = host.TrimEnd('.');
        return Suffixes.Any(s => host.Equals(s, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + s, StringComparison.OrdinalIgnoreCase));
    }

    public string? HostFor(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        lock (_lock)
            return _hosts.GetValueOrDefault(address);
    }

    /// <summary>Starts a refresh in the background if one is due. Never blocks the caller (DNS can be slow).</summary>
    public void RefreshIfDue(DateTimeOffset now)
    {
        if (now - _lastRefresh < _interval || Interlocked.Exchange(ref _busy, 1) == 1)
            return;
        _lastRefresh = now;
        _ = Task.Run(() =>
        {
            try
            {
                Refresh();
            }
            catch (Exception)
            {
                // The DNS cache is a best-effort source.
            }
            finally
            {
                Volatile.Write(ref _busy, 0);
            }
        });
    }

    /// <summary>Synchronous refresh (used by the background task and by tests).</summary>
    public void Refresh()
    {
        var map = new Dictionary<IPAddress, string>();
        foreach (var name in _cacheNames().Where(IsDynamicDns).Distinct(StringComparer.OrdinalIgnoreCase).Take(200))
        {
            foreach (var ip in _resolve(name))
                map[ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip] = name;
        }
        lock (_lock)
            _hosts = map;
    }

    private static IReadOnlyList<IPAddress> ResolveSafe(string host)
    {
        try
        {
            return Dns.GetHostAddresses(host);
        }
        catch (Exception)
        {
            return [];
        }
    }

    // DNS_CACHE_ENTRY { next, name, type, dataLength, flags }. dnsapi owns the memory and offers no documented way to
    // free the chain, so it is only read; with one call every two minutes the amount is negligible.
    private static IEnumerable<string> ReadWindowsDnsCache()
    {
        if (!OperatingSystem.IsWindows())
            return [];
        var names = new List<string>();
        try
        {
            if (!DnsGetCacheDataTable(out var entry))
                return names;
            for (var i = 0; entry != IntPtr.Zero && i < 20_000; i++)
            {
                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(entry, IntPtr.Size));
                if (!string.IsNullOrEmpty(name))
                    names.Add(name);
                entry = Marshal.ReadIntPtr(entry);
            }
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or AccessViolationException)
        {
        }
        return names;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DnsGetCacheDataTable(out IntPtr table);
}
