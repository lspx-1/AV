using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bastion.Core.Runtime;

namespace Bastion.Core.Licensing;

/// <summary>
/// Signs and verifies license tokens: base64url(json) + "." + base64url(ECDSA P-256 / SHA-256 signature).
/// The app only ships the public key, so tokens cannot be forged without the private key.
/// </summary>
public static class LicenseCodec
{
    public static string Sign(LicenseDocument document, ECDsa privateKey)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(document, JsonStore.Options);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Base64Url(payload) + "." + Base64Url(signature);
    }

    public static bool TryVerify(string token, ECDsa publicKey, out LicenseDocument? document)
    {
        document = null;
        var parts = token.Trim().Split('.');
        if (parts.Length != 2)
            return false;
        try
        {
            var payload = FromBase64Url(parts[0]);
            var signature = FromBase64Url(parts[1]);
            if (!publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                return false;
            document = JsonSerializer.Deserialize<LicenseDocument>(payload, JsonStore.Options);
            return document is not null;
        }
        catch (Exception e) when (e is FormatException or JsonException or CryptographicException)
        {
            return false;
        }
    }

    public static ECDsa CreateKeyPair() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static ECDsa ImportPem(string pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key;
    }

    /// <summary>The public key embedded at build time (src/Bastion.Core/Licensing/license-public-key.pem), if any.</summary>
    public static ECDsa? LoadEmbeddedPublicKey()
    {
        using var stream = typeof(LicenseCodec).Assembly.GetManifestResourceStream("Bastion.LicensePublicKey");
        if (stream is null)
            return null;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var pem = reader.ReadToEnd();
        return pem.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal) ? ImportPem(pem) : null;
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}
