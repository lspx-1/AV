namespace Bastion.Core.Network;

/// <summary>
/// Detects "beaconing": a program that contacts the same server again and again in very regular
/// intervals, as remote-control malware does when it polls its operator for commands.
/// </summary>
public sealed class BeaconDetector
{
    private readonly Dictionary<(string Program, string Remote), List<DateTimeOffset>> _starts = new();
    private readonly Lock _lock = new();

    public int MinConnections { get; init; } = 6;
    public TimeSpan MinInterval { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan MaxInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Maximum coefficient of variation (stddev / mean) of the intervals. Humans and normal apps are far less regular.</summary>
    public double MaxJitter { get; init; } = 0.15;

    public void RecordConnection(string program, string remote, DateTimeOffset at)
    {
        lock (_lock)
        {
            if (!_starts.TryGetValue((program, remote), out var list))
                _starts[(program, remote)] = list = [];
            list.Add(at);
            if (list.Count > 50)
                list.RemoveAt(0);
        }
    }

    public BeaconResult? Evaluate(string program, string remote)
    {
        List<DateTimeOffset> times;
        lock (_lock)
        {
            if (!_starts.TryGetValue((program, remote), out var list) || list.Count < MinConnections)
                return null;
            times = [.. list];
        }
        var intervals = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).ToArray();
        var mean = intervals.Average();
        if (mean < MinInterval.TotalSeconds || mean > MaxInterval.TotalSeconds)
            return null;
        var std = Math.Sqrt(intervals.Sum(x => (x - mean) * (x - mean)) / intervals.Length);
        var jitter = std / mean;
        return jitter <= MaxJitter ? new BeaconResult(TimeSpan.FromSeconds(mean), jitter, times.Count) : null;
    }

    public void Forget(DateTimeOffset olderThan)
    {
        lock (_lock)
        {
            foreach (var key in _starts.Where(kv => kv.Value[^1] < olderThan).Select(kv => kv.Key).ToList())
                _starts.Remove(key);
        }
    }
}

public sealed record BeaconResult(TimeSpan Interval, double Jitter, int Connections);
