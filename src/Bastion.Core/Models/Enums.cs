namespace Bastion.Core.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum EventCategory
{
    System,
    Scan,
    Realtime,
    Process,
    Network,
    Autostart,
    Hosts,
    Ransomware,
    Quarantine,
    Update,
    License,
}

public enum ScanKind
{
    Quick,
    Full,
    Custom,
}

public enum Sensitivity
{
    Low,
    Medium,
    High,
}

/// <summary>How Bastion behaves when another antivirus product is active.</summary>
public enum ComplementaryMode
{
    /// <summary>Detect other AV products via Windows Security Center and adapt automatically.</summary>
    Auto,
    /// <summary>Always run in complementary mode (no duplicate on-access content scanning).</summary>
    On,
    /// <summary>Always run the full real-time scanner.</summary>
    Off,
}
