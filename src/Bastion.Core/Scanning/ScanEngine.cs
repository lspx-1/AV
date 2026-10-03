using Bastion.Core.Models;

namespace Bastion.Core.Scanning;

/// <summary>Runs all detectors against a file and decides on a verdict.</summary>
public sealed class ScanEngine(IReadOnlyList<IDetector> detectors, Func<ScanOptions> options)
{
    private int _filesScanned;

    public int FilesScanned => _filesScanned;

    public FileScanResult ScanFile(string path)
    {
        var opts = options();
        if (opts.IsExcluded(path))
            return new FileScanResult(path, null, 0, []);

        FileScanContext context;
        try
        {
            context = FileScanContext.Load(path, opts.MaxContentBytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return FileScanResult.Failed(path, e.Message);
        }
        return Scan(context, opts);
    }

    public FileScanResult Scan(FileScanContext context, ScanOptions? opts = null)
    {
        opts ??= options();
        Interlocked.Increment(ref _filesScanned);
        if (opts.ExcludedHashes.Contains(context.Sha256))
            return new FileScanResult(context.Path, context.Sha256, context.Size, []);

        var detections = new List<Detection>();
        foreach (var detector in detectors)
        {
            try
            {
                detections.AddRange(detector.Inspect(context));
            }
            catch (Exception e)
            {
                // One faulty detector must not break the scan of this file.
                System.Diagnostics.Debug.WriteLine($"{detector.Name} failed on {context.Path}: {e}");
            }
        }

        var verdict = detections
            .OrderByDescending(d => d.IsDefinitive)
            .ThenByDescending(d => d.Severity)
            .ThenByDescending(d => d.Score)
            .FirstOrDefault();
        return new FileScanResult(context.Path, context.Sha256, context.Size, detections) { Verdict = verdict };
    }
}

public sealed class ScanOptions
{
    public long MaxContentBytes { get; init; } = 64L * 1024 * 1024;
    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];
    public IReadOnlySet<string> ExcludedHashes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public bool IsExcluded(string path) =>
        ExcludedPaths.Any(ex => path.StartsWith(ex, StringComparison.OrdinalIgnoreCase));
}
