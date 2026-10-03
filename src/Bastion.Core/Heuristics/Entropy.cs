namespace Bastion.Core.Heuristics;

public static class Entropy
{
    /// <summary>Shannon entropy in bits per byte (0..8). Packed or encrypted data is close to 8.</summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
            counts[b]++;
        double entropy = 0;
        double len = data.Length;
        foreach (var c in counts)
        {
            if (c == 0)
                continue;
            var p = c / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
