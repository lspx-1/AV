using System.Collections.Concurrent;
using System.Threading.Channels;
using Bastion.Core.Heuristics;
using Bastion.Core.Models;
using Bastion.Core.Platform;

namespace Bastion.Core.Protection;

/// <summary>
/// Watches download, desktop, temp and AppData folders and scans new or changed files right away.
/// Without a kernel minifilter Bastion cannot block a file before it is opened, but it reacts within moments.
/// </summary>
public sealed class RealtimeFileGuard(IProtectionContext context) : ProtectionModuleBase(context)
{
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private Channel<string>? _queue;
    private CancellationTokenSource? _cts;
    private Task? _worker;
    private int _scannedToday;
    private DateOnly _day = DateOnly.FromDateTime(DateTime.Now);

    public override string Id => "realtime";
    public override string Name => "Echtzeit-Dateiwächter";
    public override string Description => "Prüft neue Dateien in Downloads, Desktop, Temp und AppData sofort.";
    public override string? Detail => $"{ScannedToday:N0} Dateien heute geprüft";

    public int ScannedToday
    {
        get
        {
            RollDay();
            return _scannedToday;
        }
    }

    protected override void OnStart()
    {
        _cts = new CancellationTokenSource();
        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest });

        foreach (var (dir, recursive, onlyExecutables) in WatchedFolders())
        {
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = recursive,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                };
                void OnEvent(string path)
                {
                    if (onlyExecutables && !HeuristicDetector.IsExecutableType(path))
                        return;
                    Enqueue(path);
                }
                w.Created += (_, e) => Safe("Dateiereignis", () => OnEvent(e.FullPath));
                w.Changed += (_, e) => Safe("Dateiereignis", () => OnEvent(e.FullPath));
                w.Renamed += (_, e) => Safe("Dateiereignis", () => OnEvent(e.FullPath));
                w.Error += (_, e) => Context.Log($"Dateiwächter-Puffer übergelaufen in {dir}: {e.GetException().Message}");
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException)
            {
                Context.Log($"Ordner kann nicht überwacht werden: {dir} ({e.Message})");
            }
        }
        _worker = Task.Run(() => WorkAsync(_cts.Token));
    }

    protected override void OnStop()
    {
        foreach (var w in _watchers)
            w.Dispose();
        _watchers.Clear();
        _cts?.Cancel();
        _queue?.Writer.TryComplete();
        try
        {
            _worker?.Wait(2000);
        }
        catch (AggregateException)
        {
        }
    }

    private IEnumerable<(string Dir, bool Recursive, bool OnlyExecutables)> WatchedFolders()
    {
        foreach (var d in KnownFolders.ForAllUsers("Downloads")) yield return (d, true, false);
        foreach (var d in KnownFolders.ForAllUsers("Desktop")) yield return (d, true, false);
        foreach (var d in KnownFolders.ForAllUsers("AppData", "Local", "Temp")) yield return (d, true, true);
        foreach (var d in KnownFolders.ForAllUsers("AppData", "Roaming")) yield return (d, true, true);
        foreach (var d in KnownFolders.ForAllUsers("AppData", "Local")) yield return (d, false, true);
        var winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
        if (Directory.Exists(winTemp)) yield return (winTemp, true, true);
        var publicDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments);
        if (Directory.Exists(publicDir)) yield return (Path.GetDirectoryName(publicDir)!, true, true);
        foreach (var extra in Context.Settings.ExtraWatchedFolders.Where(Directory.Exists))
            yield return (extra, true, false);
    }

    internal void Enqueue(string path)
    {
        if (path.StartsWith(Context.Paths.Root, StringComparison.OrdinalIgnoreCase))
            return;
        // Collapse bursts of change events for the same file (downloads write in many chunks).
        var now = DateTime.UtcNow;
        if (_pending.TryGetValue(path, out var last) && now - last < TimeSpan.FromSeconds(2))
            return;
        _pending[path] = now;
        _queue?.Writer.TryWrite(path);
    }

    private async Task WorkAsync(CancellationToken ct)
    {
        var reader = _queue!.Reader;
        while (await reader.WaitToReadAsync(ct).ConfigureAwait(false))
        {
            while (reader.TryRead(out var path))
            {
                // Give the writer a moment to finish, then scan.
                await Task.Delay(750, ct).ConfigureAwait(false);
                _pending.TryRemove(path, out _);
                if (!File.Exists(path))
                    continue;
                if (Context.ComplementaryModeActive && !HeuristicDetector.IsExecutableType(path))
                    continue; // the other AV covers documents and archives
                if (!await WaitUntilReadableAsync(path, ct).ConfigureAwait(false))
                    continue;

                // One bad file must not stop real-time protection for everything after it.
                Safe($"Scan von {path}", () =>
                {
                    var result = Context.Engine.ScanFile(path);
                    RollDay();
                    Interlocked.Increment(ref _scannedToday);
                    if (result.IsMalicious)
                        Context.HandleDetection(result, EventCategory.Realtime);
                });
            }
        }
    }

    private static async Task<bool> WaitUntilReadableAsync(string path, CancellationToken ct)
    {
        for (var i = 0; i < 20; i++)
        {
            try
            {
                using var _ = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                return true;
            }
            catch (IOException)
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                return false;
            }
        }
        return false;
    }

    private void RollDay()
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        if (today != _day)
        {
            _day = today;
            _scannedToday = 0;
        }
    }
}
