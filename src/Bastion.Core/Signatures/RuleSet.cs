using Bastion.Core.Scanning;

namespace Bastion.Core.Signatures;

public sealed class RuleSet
{
    private volatile IReadOnlyList<Rule> _rules = [];

    public int Count => _rules.Count;

    public IReadOnlyList<string> Errors { get; private set; } = [];

    public void LoadDirectories(params string[] directories)
    {
        var rules = new List<Rule>();
        var errors = new List<string>();
        foreach (var dir in directories.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.yar", SearchOption.AllDirectories)
                         .Concat(Directory.EnumerateFiles(dir, "*.yara", SearchOption.AllDirectories)))
            {
                try
                {
                    rules.AddRange(RuleParser.Parse(File.ReadAllText(file)));
                }
                catch (RuleParseException e)
                {
                    errors.Add($"{Path.GetFileName(file)}: {e.Message}");
                }
            }
        }
        _rules = rules;
        Errors = errors;
    }

    public void Add(IEnumerable<Rule> rules) => _rules = [.. _rules, .. rules];

    public IEnumerable<Rule> Match(FileScanContext context)
    {
        foreach (var rule in _rules)
        {
            if (rule.IsMatch(context))
                yield return rule;
        }
    }
}
