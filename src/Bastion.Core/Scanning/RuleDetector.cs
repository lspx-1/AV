using Bastion.Core.Models;
using Bastion.Core.Signatures;

namespace Bastion.Core.Scanning;

public sealed class RuleDetector(RuleSet rules) : IDetector
{
    public string Name => "Regel";

    public IEnumerable<Detection> Inspect(FileScanContext context)
    {
        foreach (var rule in rules.Match(context))
        {
            yield return new Detection(rule.Name, Name, rule.Severity, rule.Severity >= Severity.High ? 100 : 60, rule.Description ?? "Regel hat angeschlagen")
            {
                IsDefinitive = rule.Severity >= Severity.High,
            };
        }
    }
}
