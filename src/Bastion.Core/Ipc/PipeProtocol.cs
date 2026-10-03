using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Core.Ipc;

/// <summary>Newline-delimited JSON messages exchanged over the named pipe.</summary>
public sealed class PipeMessage
{
    [JsonPropertyName("id")] public long? Id { get; set; }
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("args")] public JsonElement[]? Args { get; set; }
    [JsonPropertyName("ok")] public bool? Ok { get; set; }
    [JsonPropertyName("result")] public JsonElement? Result { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("event")] public string? Event { get; set; }
    [JsonPropertyName("data")] public JsonElement? Data { get; set; }
}

public static class PipeEvents
{
    public const string SecurityEvent = "securityEvent";
    public const string ScanProgress = "scanProgress";
    public const string License = "license";
}
