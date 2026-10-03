using Bastion.Core.Models;

namespace Bastion.Core.Network;

public enum ConnectionRisk
{
    None,
    Info,
    Suspicious,
    Dangerous,
}

public sealed record ConnectionView
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ProcessPath { get; init; }
    public bool? Signed { get; init; }
    public string LocalEndpoint { get; init; } = "";
    public string RemoteEndpoint { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public string State { get; init; } = "";
    public bool IsListening { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public ConnectionRisk Risk { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

public sealed record NetworkFinding(
    string Key,
    Severity Severity,
    string Title,
    string Detail,
    int ProcessId,
    string? ProcessPath,
    string? RemoteAddress);
