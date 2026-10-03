using Bastion.Core.Models;

namespace Bastion.Core.Scanning;

public interface IDetector
{
    string Name { get; }

    IEnumerable<Detection> Inspect(FileScanContext context);
}
