using System.Text.Json;
using Bastion.Core.Models;

namespace Bastion.Core.Runtime;

/// <summary>Keeps recent events in memory and appends them to a daily JSON-lines log.</summary>
public sealed class EventJournal
{
    private const int MaxInMemory = 5000;
    private readonly string _dir;
    private readonly LinkedList<SecurityEvent> _events = new();
    private readonly Lock _lock = new();

    public EventJournal(string logDirectory)
    {
        _dir = logDirectory;
        LoadRecent();
    }

    public event Action<SecurityEvent>? Added;
    public event Action<SecurityEvent>? Updated;

    public void Add(SecurityEvent e)
    {
        lock (_lock)
        {
            _events.AddFirst(e);
            while (_events.Count > MaxInMemory)
                _events.RemoveLast();
            Append(e);
        }
        Notify(Added, e);
    }

    // A failing listener (e.g. a broken pipe connection) must not break the module that raised the event.
    private static void Notify(Action<SecurityEvent>? handler, SecurityEvent e)
    {
        if (handler is null)
            return;
        foreach (var h in handler.GetInvocationList().Cast<Action<SecurityEvent>>())
        {
            try
            {
                h(e);
            }
            catch (Exception)
            {
            }
        }
    }

    public SecurityEvent? Find(Guid id)
    {
        lock (_lock)
            return _events.FirstOrDefault(e => e.Id == id);
    }

    public void Resolve(SecurityEvent e, string resolution)
    {
        lock (_lock)
        {
            e.Resolution = resolution;
            e.Actions = [];
            Append(e);
        }
        Notify(Updated, e);
    }

    public IReadOnlyList<SecurityEvent> Recent(int max)
    {
        lock (_lock)
            return _events.Take(max).ToList();
    }

    /// <summary>Drops everything that is not an open finding, in memory and on disk.</summary>
    public int Clear()
    {
        lock (_lock)
        {
            var keep = _events.Where(e => !e.IsResolved && e.Actions.Count > 0).ToList();
            var removed = _events.Count - keep.Count;
            _events.Clear();
            foreach (var e in keep)
                _events.AddLast(e);
            try
            {
                if (Directory.Exists(_dir))
                {
                    foreach (var file in Directory.EnumerateFiles(_dir, "events-*.jsonl"))
                        File.Delete(file);
                    // Re-write the open findings (oldest first) so they survive a restart.
                    foreach (var e in keep.AsEnumerable().Reverse())
                        Append(e);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
            return removed;
        }
    }

    public int OpenThreats()
    {
        lock (_lock)
            return _events.Count(e => !e.IsResolved && e.Severity >= Severity.Medium && e.Actions.Count > 0);
    }

    private void Append(SecurityEvent e)
    {
        try
        {
            var file = Path.Combine(_dir, $"events-{DateTime.Now:yyyy-MM-dd}.jsonl");
            File.AppendAllText(file, JsonSerializer.Serialize(e, JsonStore.Options).Replace("\r", "").Replace("\n", "") + "\n");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Logging must never take protection down.
        }
    }

    private void LoadRecent()
    {
        if (!Directory.Exists(_dir))
            return;
        var byId = new Dictionary<Guid, SecurityEvent>();
        foreach (var file in Directory.EnumerateFiles(_dir, "events-*.jsonl").OrderByDescending(f => f).Take(14).Reverse())
        {
            foreach (var line in File.ReadLines(file))
            {
                try
                {
                    var e = JsonSerializer.Deserialize<SecurityEvent>(line, JsonStore.Options);
                    if (e is not null)
                        byId[e.Id] = e; // later lines (resolutions) win
                }
                catch (JsonException)
                {
                }
            }
        }
        foreach (var e in byId.Values.OrderByDescending(e => e.Timestamp).Take(MaxInMemory))
            _events.AddLast(e);

        // Old log files are not needed forever.
        foreach (var old in Directory.EnumerateFiles(_dir, "events-*.jsonl").OrderByDescending(f => f).Skip(90))
            File.Delete(old);
    }
}
