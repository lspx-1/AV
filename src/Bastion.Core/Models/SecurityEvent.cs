namespace Bastion.Core.Models;

/// <summary>Something Bastion observed or did. Shown in the history and as notifications.</summary>
public sealed class SecurityEvent
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public Severity Severity { get; init; }
    public EventCategory Category { get; init; }
    public string Title { get; init; } = "";
    public string? Detail { get; init; }

    /// <summary>File, registry value or endpoint the event refers to.</summary>
    public string? Target { get; init; }

    public int? ProcessId { get; init; }

    /// <summary>Name of the detected threat, if any (e.g. "Heur.Suspicious.Score70").</summary>
    public string? ThreatName { get; init; }

    /// <summary>Program file involved, e.g. the process behind a network connection.</summary>
    public string? ProgramPath { get; init; }

    /// <summary>Actions the user can still take, e.g. "quarantine", "kill", "removeAutostart", "block", "ignore".</summary>
    public List<string> Actions { get; set; } = [];

    /// <summary>What has been done about this event, e.g. "Quarantined".</summary>
    public string? Resolution { get; set; }

    public bool IsResolved => Resolution is not null;
}

public static class EventActions
{
    public const string Quarantine = "quarantine";
    public const string Kill = "kill";
    public const string KillAndQuarantine = "killAndQuarantine";
    public const string RemoveAutostart = "removeAutostart";
    public const string BlockRemote = "blockRemote";
    public const string BlockProgram = "blockProgram";
    public const string RestoreHosts = "restoreHosts";
    public const string Ignore = "ignore";
    public const string Exclude = "exclude";
}
