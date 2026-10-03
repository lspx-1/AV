using Bastion.Core.Models;
using Bastion.Core.Scanning;

namespace Bastion.Core.Signatures;

/// <summary>A compiled content rule (YARA-compatible subset, see docs/rules.md).</summary>
public sealed class Rule
{
    public required string Name { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = [];
    public IReadOnlyDictionary<string, string> Meta { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<RuleString> Strings { get; init; } = [];
    public required RuleExpr Condition { get; init; }

    public string? Description => Meta.GetValueOrDefault("description");

    public Severity Severity =>
        Enum.TryParse<Severity>(Meta.GetValueOrDefault("severity"), ignoreCase: true, out var s) ? s : Severity.Medium;

    public bool IsMatch(FileScanContext context)
    {
        var hits = new Dictionary<string, bool>(StringComparer.Ordinal);
        bool Hit(string id)
        {
            if (!hits.TryGetValue(id, out var hit))
            {
                var str = Strings.FirstOrDefault(s => s.Id == id);
                hit = str is not null && str.IsFoundIn(context);
                hits[id] = hit;
            }
            return hit;
        }
        return Condition.Evaluate(new RuleEvalContext(context, Strings, Hit));
    }
}

public sealed record RuleEvalContext(FileScanContext File, IReadOnlyList<RuleString> Strings, Func<string, bool> IsHit);

public sealed class RuleString
{
    public required string Id { get; init; }

    /// <summary>Byte patterns; a value of -1 is a wildcard. Any pattern matching counts as a hit.</summary>
    public required IReadOnlyList<short[]> Patterns { get; init; }

    public bool NoCase { get; init; }

    public bool IsFoundIn(FileScanContext context)
    {
        var haystack = NoCase ? context.LowerContent : context.Content;
        foreach (var pattern in Patterns)
        {
            if (Contains(haystack, pattern))
                return true;
        }
        return false;
    }

    internal static bool Contains(ReadOnlySpan<byte> haystack, short[] pattern)
    {
        if (pattern.Length == 0 || pattern.Length > haystack.Length)
            return false;

        // Find the longest run without wildcards and use the vectorised IndexOf on it.
        int bestStart = 0, bestLen = 0;
        for (int i = 0; i < pattern.Length;)
        {
            if (pattern[i] < 0) { i++; continue; }
            var start = i;
            while (i < pattern.Length && pattern[i] >= 0) i++;
            if (i - start > bestLen) { bestStart = start; bestLen = i - start; }
        }
        if (bestLen == 0)
            return true; // all wildcards

        Span<byte> anchor = bestLen <= 256 ? stackalloc byte[bestLen] : new byte[bestLen];
        for (var i = 0; i < bestLen; i++)
            anchor[i] = (byte)pattern[bestStart + i];

        var searchFrom = bestStart;
        while (searchFrom <= haystack.Length - (pattern.Length - bestStart))
        {
            var idx = haystack[searchFrom..].IndexOf(anchor);
            if (idx < 0)
                return false;
            var anchorPos = searchFrom + idx;
            var begin = anchorPos - bestStart;
            if (begin + pattern.Length <= haystack.Length && MatchesAt(haystack, begin, pattern))
                return true;
            searchFrom = anchorPos + 1;
        }
        return false;
    }

    private static bool MatchesAt(ReadOnlySpan<byte> haystack, int at, short[] pattern)
    {
        for (var i = 0; i < pattern.Length; i++)
        {
            if (pattern[i] >= 0 && haystack[at + i] != pattern[i])
                return false;
        }
        return true;
    }
}
