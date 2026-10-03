namespace Bastion.Core.Models;

public sealed record ModuleStatus(
    string Id,
    string Name,
    string Description,
    bool Enabled,
    bool Running,
    string? Detail,
    bool RequiresPro = false);

public sealed record StatusSnapshot
{
    public bool Protected { get; init; }
    public int ActiveThreats { get; init; }
    public IReadOnlyList<ModuleStatus> Modules { get; init; } = [];
    public DateTimeOffset? LastScan { get; init; }
    public string? LastScanSummary { get; init; }
    public DateTimeOffset? SignaturesUpdated { get; init; }
    public int SignatureCount { get; init; }
    public int RuleCount { get; init; }
    public int FilesScannedToday { get; init; }
    public int QuarantineCount { get; init; }
    public IReadOnlyList<string> OtherAntivirusProducts { get; init; } = [];
    public bool ComplementaryModeActive { get; init; }
    public bool RunningAsService { get; init; }
    public bool IsElevated { get; init; }
    public string Version { get; init; } = "";
    public ScanProgress? CurrentScan { get; init; }
}

public sealed record ScanRequest(ScanKind Kind, IReadOnlyList<string>? Paths = null);

public sealed record ScanProgress
{
    public Guid ScanId { get; init; }
    public ScanKind Kind { get; init; }
    public bool Running { get; init; }
    public bool Cancelled { get; init; }
    public int FilesScanned { get; init; }

    /// <summary>Total files if known (quick and custom scans), otherwise null.</summary>
    public int? FilesTotal { get; init; }
    public int Threats { get; init; }
    public string? CurrentPath { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? FinishedAt { get; init; }
    public List<FileScanSummary> Findings { get; init; } = [];

    public double? Percent => FilesTotal is > 0 ? Math.Min(100.0, FilesScanned * 100.0 / FilesTotal.Value) : null;
}

public sealed record FileScanSummary(string Path, string DetectionName, Severity Severity, string Reason, bool Quarantined, Guid? EventId);
