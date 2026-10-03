using System.Diagnostics;
using System.Management;
using Bastion.Core.Models;
using Bastion.Core.Network;
using Bastion.Core.Platform;

namespace Bastion.Core.Protection;

/// <summary>
/// Checks every newly started process: scans its program file and looks for programs that disguise
/// themselves as Windows processes. Uses WMI process-start events (admin) with a polling fallback.
/// </summary>
public sealed class ProcessGuard(IProtectionContext context) : ProtectionModuleBase(context)
{
    private readonly HashSet<string> _checkedImages = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private ManagementEventWatcher? _watcher;
    private Timer? _pollTimer;
    private HashSet<int> _knownPids = [];
    private int _checkedToday;

    public override string Id => "process";
    public override string Name => "Prozess-Überwachung";
    public override string Description => "Bewertet jeden neu gestarteten Prozess.";
    public override string? Detail => $"{_checkedToday:N0} Prozesse geprüft";

    protected override void OnStart()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                _watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID FROM Win32_ProcessStartTrace"));
                _watcher.EventArrived += (_, e) =>
                {
                    Safe("Prozessereignis", () =>
                    {
                        var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                        ThreadPool.QueueUserWorkItem(_ => Safe("Prozessprüfung", () => Inspect(pid)));
                    });
                };
                _watcher.Start();
                return;
            }
            catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                // Not elevated: fall back to polling the process list.
                _watcher?.Dispose();
                _watcher = null;
                Context.Log($"WMI-Prozessereignisse nicht verfügbar ({e.Message}), nutze Abfrage alle 2 Sekunden.");
            }
        }
        _knownPids = Process.GetProcesses().Select(p => { using (p) return p.Id; }).ToHashSet();
        _pollTimer = new Timer(_ => Safe("Prozessliste", Poll), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    protected override void OnStop()
    {
        _watcher?.Stop();
        _watcher?.Dispose();
        _watcher = null;
        _pollTimer?.Dispose();
        _pollTimer = null;
    }

    private void Poll()
    {
        var now = Process.GetProcesses().Select(p => { using (p) return p.Id; }).ToHashSet();
        foreach (var pid in now.Where(p => !_knownPids.Contains(p)))
            Inspect(pid);
        _knownPids = now;
    }

    private void Inspect(int pid)
    {
        var path = ProcessInfo.GetImagePath(pid);
        if (path is null || !File.Exists(path))
            return;
        Interlocked.Increment(ref _checkedToday);
        if (path.StartsWith(Context.Paths.Root, StringComparison.OrdinalIgnoreCase))
            return;

        var name = Path.GetFileNameWithoutExtension(path);
        if (RemoteAccessAnalyzer.IsMasquerading(name, path))
        {
            Context.Raise(new SecurityEvent
            {
                Category = EventCategory.Process,
                Severity = Severity.High,
                Title = "Getarnter Prozess gestartet",
                Detail = $"{name}.exe trägt den Namen eines Windows-Prozesses, läuft aber aus {Path.GetDirectoryName(path)}.",
                Target = path,
                ProgramPath = path,
                ProcessId = pid,
                Actions = [EventActions.KillAndQuarantine, EventActions.Kill, EventActions.Ignore],
            });
        }

        lock (_lock)
        {
            // Scanning the same unchanged program on every start is wasted work.
            var key = path + "|" + File.GetLastWriteTimeUtc(path).Ticks;
            if (!_checkedImages.Add(key))
                return;
        }

        var result = Context.Engine.ScanFile(path);
        if (!result.IsMalicious)
            return;
        Context.HandleDetection(result, EventCategory.Process, pid);
    }
}
