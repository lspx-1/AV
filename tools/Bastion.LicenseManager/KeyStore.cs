using System.Security.Cryptography;
using System.Text;
using Bastion.Core.Licensing;

namespace Bastion.LicenseManager;

/// <summary>
/// Holds the signing key pair. The private key is stored encrypted for the current Windows user (DPAPI)
/// in %APPDATA%\Bastion License Manager. Export it for backups; never commit or share it.
/// </summary>
public sealed class KeyStore
{
    public static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Bastion License Manager");

    private static readonly string PrivateFile = Path.Combine(Folder, "private-key.dpapi");
    public static readonly string PublicFile = Path.Combine(Folder, LicenseCodec.InstalledKeyFileName);

    private ECDsa? _key;

    public KeyStore()
    {
        Directory.CreateDirectory(Folder);
        if (File.Exists(PrivateFile))
        {
            try
            {
                var pem = Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(PrivateFile), null, DataProtectionScope.CurrentUser));
                _key = LicenseCodec.ImportPem(pem);
            }
            catch (CryptographicException)
            {
                // Created by another Windows user or corrupted: the user must import the backup.
                _key = null;
            }
        }
    }

    public bool HasKey => _key is not null;

    public string? PublicPem => _key?.ExportSubjectPublicKeyInfoPem();

    /// <summary>Short fingerprint to compare keys at a glance, e.g. "3F2A 9C01 7B44 E0D2".</summary>
    public string? Fingerprint
    {
        get
        {
            if (_key is null)
                return null;
            var hex = Convert.ToHexString(SHA256.HashData(_key.ExportSubjectPublicKeyInfo()), 0, 8);
            return string.Join(' ', Enumerable.Range(0, 4).Select(i => hex.Substring(i * 4, 4)));
        }
    }

    public void CreateNew() => Store(LicenseCodec.CreateKeyPair());

    /// <summary>Imports a private key PEM (e.g. keys\license-private.pem from bastion-keygen).</summary>
    public void ImportPrivatePem(string pem)
    {
        if (!pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            throw new InvalidDataException("Die Datei enthält keinen privaten Schlüssel. Wähle license-private.pem (nicht den öffentlichen Schlüssel).");
        ECDsa key;
        try
        {
            key = LicenseCodec.ImportPem(pem);
            key.SignData([1], HashAlgorithmName.SHA256); // proves it is a usable private key
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new InvalidDataException("Der Schlüssel konnte nicht gelesen werden: " + e.Message);
        }
        Store(key);
    }

    public void ExportPrivatePem(string path)
    {
        if (_key is null)
            throw new InvalidOperationException("Es ist noch kein Schlüssel vorhanden.");
        File.WriteAllText(path, _key.ExportECPrivateKeyPem());
    }

    public void ExportPublicPem(string path) =>
        File.WriteAllText(path, PublicPem ?? throw new InvalidOperationException("Es ist noch kein Schlüssel vorhanden."));

    public string Sign(LicenseDocument document) =>
        LicenseCodec.Sign(document, _key ?? throw new InvalidOperationException("Erstelle oder importiere zuerst einen Schlüssel."));

    private void Store(ECDsa key)
    {
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(key.ExportECPrivateKeyPem()), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(PrivateFile, encrypted);
        File.WriteAllText(PublicFile, key.ExportSubjectPublicKeyInfoPem());
        _key?.Dispose();
        _key = key;
    }
}
