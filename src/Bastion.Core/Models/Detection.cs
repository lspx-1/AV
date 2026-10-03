namespace Bastion.Core.Models;

/// <summary>A single finding produced by a detector for one file.</summary>
public sealed record Detection(
    string Name,
    string Detector,
    Severity Severity,
    int Score,
    string Reason)
{
    /// <summary>True for signature (hash/rule) hits that are considered definitive.</summary>
    public bool IsDefinitive { get; init; }
}

public sealed record FileScanResult(
    string Path,
    string? Sha256,
    long Size,
    IReadOnlyList<Detection> Detections,
    string? Error = null)
{
    public bool IsMalicious => Verdict is not null;

    /// <summary>The most important detection, or null if the file is considered clean.</summary>
    public Detection? Verdict { get; init; }

    public static FileScanResult Failed(string path, string error) => new(path, null, 0, [], error);
}
