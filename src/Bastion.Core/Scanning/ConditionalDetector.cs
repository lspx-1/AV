using Bastion.Core.Models;

namespace Bastion.Core.Scanning;

/// <summary>Runs the inner detector only while <paramref name="enabled"/> returns true.</summary>
public sealed class ConditionalDetector(IDetector inner, Func<bool> enabled) : IDetector
{
    public string Name => inner.Name;

    public IEnumerable<Detection> Inspect(FileScanContext context) => enabled() ? inner.Inspect(context) : [];
}
