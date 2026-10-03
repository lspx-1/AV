using Bastion.Core.Platform;

namespace Bastion.Core.Network;

/// <summary>Polls the TCP table, tracks new connections and runs the remote-access analysis.</summary>
public sealed class NetworkMonitor(
    RemoteAccessAnalyzer analyzer,
    BeaconDetector beacons,
    Func<IReadOnlyList<TcpConnection>>? source = null,
    Func<int, (string Name, string? Path)>? processResolver = null)
{
    private readonly Func<IReadOnlyList<TcpConnection>> _source = source ?? TcpTable.Read;
    private readonly Dictionary<TcpConnection, DateTimeOffset> _known = new();
    private readonly Dictionary<int, (string Name, string? Path)> _processes = new();
    private readonly HashSet<string> _reported = new();
    private readonly Lock _lock = new();
    private IReadOnlyList<ConnectionView> _current = [];

    public IReadOnlyList<ConnectionView> Current => _current;

    /// <summary>Takes one snapshot. Returns findings that have not been reported before.</summary>
    public IReadOnlyList<NetworkFinding> Poll(DateTimeOffset now)
    {
        var connections = _source();
        var views = new List<ConnectionView>(connections.Count);
        var fresh = new List<NetworkFinding>();
        lock (_lock)
        {
            var alive = new HashSet<TcpConnection>();
            foreach (var c in connections)
            {
                if (c.State is TcpState.TimeWait or TcpState.Closed or TcpState.DeleteTcb || c.ProcessId <= 4)
                    continue;
                alive.Add(c);
                var (name, path) = Process(c.ProcessId);
                if (!_known.TryGetValue(c, out var firstSeen))
                {
                    firstSeen = now;
                    _known[c] = now;
                    // A new local port to the same remote means a fresh connection attempt.
                    if (c.State is TcpState.Established or TcpState.SynSent && RemoteAccessAnalyzer.IsPublic(c.Remote.Address))
                        beacons.RecordConnection(path ?? name, c.Remote.Address.ToString(), now);
                }
                var (view, findings) = analyzer.Analyze(c, name, path, firstSeen);
                views.Add(view);
                foreach (var f in findings)
                {
                    if (_reported.Add(f.Key))
                        fresh.Add(f);
                }
            }
            foreach (var gone in _known.Keys.Where(k => !alive.Contains(k)).ToList())
                _known.Remove(gone);
            var pids = alive.Select(a => a.ProcessId).ToHashSet();
            foreach (var pid in _processes.Keys.Where(p => !pids.Contains(p)).ToList())
                _processes.Remove(pid);
        }
        beacons.Forget(now - TimeSpan.FromHours(3));
        _current = views
            .OrderByDescending(v => v.Risk)
            .ThenBy(v => v.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return fresh;
    }

    /// <summary>Allows a finding to be reported again (e.g. after the user dismissed it and it reappears later).</summary>
    public void ResetReported()
    {
        lock (_lock)
            _reported.Clear();
    }

    private (string Name, string? Path) Process(int pid)
    {
        if (_processes.TryGetValue(pid, out var info))
            return info;
        if (processResolver is not null)
            return _processes[pid] = processResolver(pid);
        var path = ProcessInfo.GetImagePath(pid);
        var name = path is not null ? Path.GetFileNameWithoutExtension(path) : ProcessInfo.GetName(pid) ?? $"PID {pid}";
        info = (name, path);
        _processes[pid] = info;
        return info;
    }
}
