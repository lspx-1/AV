using System.Security.Cryptography;

namespace Bastion.Core.Licensing;

/// <summary>
/// Human-typable license key: BSTN-XXXX-XXXX-XXXX-XXXX using Crockford Base32 (no I, L, O, U).
/// 15 random characters plus one checksum character catch typos before contacting a server.
/// </summary>
public static class LicenseKey
{
    public const string Prefix = "BSTN";
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public static string Generate()
    {
        Span<char> body = stackalloc char[15];
        for (var i = 0; i < body.Length; i++)
            body[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        return Format(new string(body) + Checksum(body));
    }

    /// <summary>Normalizes user input (lowercase, missing dashes, O/I/L confusion). Returns null if invalid.</summary>
    public static string? Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;
        var chars = input.ToUpperInvariant()
            .Replace('O', '0').Replace('I', '1').Replace('L', '1')
            .Where(c => c != '-' && !char.IsWhiteSpace(c))
            .ToArray();
        var s = new string(chars);
        if (s.StartsWith("BSTN", StringComparison.Ordinal))
            s = s[4..];
        if (s.Length != 16 || s.Any(c => !Alphabet.Contains(c)))
            return null;
        return Checksum(s.AsSpan(0, 15)) == s[15] ? Format(s) : null;
    }

    public static bool IsValid(string? input) => Normalize(input) is not null;

    /// <summary>Shows only the first and last block, e.g. BSTN-7Q4M-••••-••••-K2XR.</summary>
    public static string Mask(string key)
    {
        var parts = key.Split('-');
        return parts.Length == 5 ? $"{parts[0]}-{parts[1]}-••••-••••-{parts[4]}" : key;
    }

    private static string Format(string sixteen) =>
        $"{Prefix}-{sixteen[..4]}-{sixteen[4..8]}-{sixteen[8..12]}-{sixteen[12..16]}";

    private static char Checksum(ReadOnlySpan<char> body)
    {
        var sum = 0;
        for (var i = 0; i < body.Length; i++)
            sum = (sum * 31 + Alphabet.IndexOf(body[i]) + i) % Alphabet.Length;
        return Alphabet[sum];
    }
}
