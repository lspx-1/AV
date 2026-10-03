namespace Bastion.Core.Licensing;

public enum LicensePlan
{
    Free,
    Pro,
}

public static class LicenseFeatures
{
    public const string ScheduledScans = "scheduled-scans";
    public const string CustomRules = "custom-rules";
    public const string HourlyUpdates = "hourly-updates";

    public static readonly string[] Pro = [ScheduledScans, CustomRules, HourlyUpdates];
}

/// <summary>The signed content of a license. Issued by the license server or the KeyGen tool.</summary>
public sealed record LicenseDocument
{
    public int Version { get; init; } = 1;
    public string LicenseId { get; init; } = "";
    public string Key { get; init; } = "";
    public LicensePlan Plan { get; init; } = LicensePlan.Pro;
    public string Licensee { get; init; } = "";
    public string? Email { get; init; }
    public int Seats { get; init; } = 1;
    public DateTimeOffset IssuedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>When set, the license only works on this device (online activation binds it).</summary>
    public string? DeviceId { get; init; }

    /// <summary>Number of devices currently activated, as reported by the server.</summary>
    public int? ActivatedSeats { get; init; }

    public IReadOnlyList<string> Features { get; init; } = [];
}

public enum LicenseState
{
    Free,
    Active,
    Expired,
    WrongDevice,
    Invalid,
    Revoked,
}

public sealed record LicenseStatus
{
    public LicenseState State { get; init; }
    public LicensePlan Plan { get; init; }
    public string? Licensee { get; init; }
    public string? MaskedKey { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public int Seats { get; init; }
    public int? ActivatedSeats { get; init; }
    public string DeviceId { get; init; } = "";
    public string DeviceName { get; init; } = "";
    public DateTimeOffset? LastValidated { get; init; }
    public bool OnlineActivation { get; init; }
    public bool ServerConfigured { get; init; }
    public bool PublicKeyConfigured { get; init; }
    public IReadOnlyList<string> Features { get; init; } = [];
    public string? Message { get; init; }

    public bool IsPro => State == LicenseState.Active && Plan == LicensePlan.Pro;
}

public sealed record LicenseOperationResult(bool Success, string Message, LicenseStatus Status);
