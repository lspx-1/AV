using Bastion.Core.Models;

namespace Bastion.Core.Runtime;

public sealed class BastionSettings
{
    public Dictionary<string, bool> Modules { get; set; } = new();

    public Sensitivity HeuristicSensitivity { get; set; } = Sensitivity.Medium;

    /// <summary>Move definitive signature hits to quarantine without asking.</summary>
    public bool AutoQuarantineSignatures { get; set; } = true;

    /// <summary>Move heuristic detections to quarantine without asking.</summary>
    public bool AutoQuarantineHeuristics { get; set; }

    /// <summary>Kill a malicious process that the process guard detects.</summary>
    public bool KillMaliciousProcesses { get; set; } = true;

    /// <summary>When a ransomware canary is touched, stop suspicious recently started processes.</summary>
    public bool RansomwareEmergencyStop { get; set; } = true;

    public ComplementaryMode ComplementaryMode { get; set; } = ComplementaryMode.Auto;

    public List<string> ExcludedPaths { get; set; } = [];
    public List<string> ExcludedHashes { get; set; } = [];
    public List<string> ExtraWatchedFolders { get; set; } = [];

    /// <summary>Files larger than this are only hash-checked, not content-scanned.</summary>
    public long MaxContentScanBytes { get; set; } = 64L * 1024 * 1024;

    public bool AutoUpdateSignatures { get; set; } = true;
    public List<string> HashFeedUrls { get; set; } = ["https://bazaar.abuse.ch/export/txt/sha256/recent/"];
    public List<string> IpFeedUrls { get; set; } = ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"];

    /// <summary>Pro: run a quick scan on a schedule.</summary>
    public bool ScheduledScanEnabled { get; set; }
    public int ScheduledScanHour { get; set; } = 12;

    /// <summary>Base URL of the license server, e.g. https://license.example.com. Empty = offline licensing only.</summary>
    public string LicenseServerUrl { get; set; } = "";

    public string Language { get; set; } = "de";

    public bool IsModuleEnabled(string id) => !Modules.TryGetValue(id, out var on) || on;
}
