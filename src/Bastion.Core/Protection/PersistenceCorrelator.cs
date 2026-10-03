using Bastion.Core.Models;

namespace Bastion.Core.Protection;

/// <summary>A program that both set itself up to start automatically and talks to the internet.</summary>
public sealed record PersistenceFinding(string ProgramPath, string AutostartTarget, string AutostartCommand, string Remote, int? ProcessId);

/// <summary>
/// Links two weak signals into a strong one: a new autostart entry for a program that also contacts the internet
/// is how a remote-access trojan survives a reboot and stays reachable. Neither the autostart guard nor the network
/// guard can see both halves, so they report here. Only unsigned programs count, and each program is reported once.
/// </summary>
public sealed class PersistenceCorrelator
{
    private readonly TimeSpan _window;
    private readonly Dictionary<string, (string Target, string Command, DateTimeOffset At)> _autostarts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string Remote, int? Pid, DateTimeOffset At)> _network = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    public PersistenceCorrelator(TimeSpan? window = null) => _window = window ?? TimeSpan.FromDays(3);

    public PersistenceFinding? NoteAutostart(string programPath, string target, string command, DateTimeOffset now)
    {
        lock (_lock)
        {
            Prune(now);
            _autostarts[programPath] = (target, command, now);
            return Check(programPath);
        }
    }

    public PersistenceFinding? NoteNetwork(string programPath, string remote, int? processId, DateTimeOffset now)
    {
        lock (_lock)
        {
            Prune(now);
            _network[programPath] = (remote, processId, now);
            return Check(programPath);
        }
    }

    private PersistenceFinding? Check(string path)
    {
        if (!_autostarts.TryGetValue(path, out var a) || !_network.TryGetValue(path, out var n) || !_reported.Add(path))
            return null;
        return new PersistenceFinding(path, a.Target, a.Command, n.Remote, n.Pid);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var k in _autostarts.Where(kv => now - kv.Value.At > _window).Select(kv => kv.Key).ToList())
            _autostarts.Remove(k);
        foreach (var k in _network.Where(kv => now - kv.Value.At > _window).Select(kv => kv.Key).ToList())
            _network.Remove(k);
    }

    public static SecurityEvent ToEvent(PersistenceFinding f) => new()
    {
        Category = EventCategory.Network,
        Severity = Severity.High,
        Title = "Verdacht auf Fernsteuerung: Autostart und Internet",
        Detail = $"{Path.GetFileName(f.ProgramPath)} hat sich gerade in den Autostart eingetragen ({f.AutostartCommand}) und verbindet sich mit {f.Remote}. " +
                 "Fernsteuerungs-Trojaner machen genau das, um nach einem Neustart weiter erreichbar zu sein. Das Programm ist nicht signiert.",
        // The target identifies the autostart entry, so "remove autostart" works from this event.
        Target = f.AutostartTarget,
        ProgramPath = f.ProgramPath,
        ProcessId = f.ProcessId,
        Actions = [EventActions.KillAndQuarantine, EventActions.RemoveAutostart, EventActions.BlockProgram, EventActions.Ignore],
    };
}
