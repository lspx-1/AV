using System.Globalization;
using Bastion.Core.Licensing;

// Bastion KeyGen: creates the signing key pair and issues license keys and signed license files.
// The private key stays on your machine (keys/ is git-ignored). Only the public key goes into the app.

var repoRoot = FindRepoRoot();
var keysDir = Path.Combine(repoRoot, "keys");
var privatePath = Path.Combine(keysDir, "license-private.pem");
var publicPath = Path.Combine(repoRoot, "src", "Bastion.Core", "Licensing", "license-public-key.pem");

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintHelp();
    return 0;
}

try
{
    return args[0] switch
    {
        "init" => Init(args.Contains("--force")),
        "key" => NewKey(),
        "issue" => Issue(ParseOptions(args.Skip(1).ToArray())),
        "verify" => Verify(args.Length > 1 ? args[1] : throw new ArgumentException("Pfad zur .bastionlic-Datei fehlt.")),
        _ => throw new ArgumentException($"Unbekannter Befehl: {args[0]}"),
    };
}
catch (Exception e) when (e is ArgumentException or IOException or FormatException)
{
    Console.Error.WriteLine("Fehler: " + e.Message);
    return 1;
}

int Init(bool force)
{
    if (File.Exists(privatePath) && !force)
    {
        Console.Error.WriteLine($"Es gibt schon einen privaten Schlüssel: {privatePath}");
        Console.Error.WriteLine("Mit --force wird er ersetzt. Achtung: Alle bisher ausgestellten Lizenzen werden dann ungültig.");
        return 1;
    }
    Directory.CreateDirectory(keysDir);
    using var key = LicenseCodec.CreateKeyPair();
    File.WriteAllText(privatePath, key.ExportECPrivateKeyPem());
    File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine("Schlüsselpaar erstellt.");
    Console.WriteLine($"  Privat (geheim halten, nie committen): {privatePath}");
    Console.WriteLine($"  Öffentlich (wird in die App eingebaut): {publicPath}");
    Console.WriteLine("Baue die App neu, damit sie den öffentlichen Schlüssel enthält.");
    return 0;
}

int NewKey()
{
    Console.WriteLine(LicenseKey.Generate());
    return 0;
}

int Issue(Dictionary<string, string> o)
{
    if (!File.Exists(privatePath))
        throw new ArgumentException("Kein privater Schlüssel gefunden. Führe zuerst 'init' aus.");
    using var key = LicenseCodec.ImportPem(File.ReadAllText(privatePath));

    var licenseKey = o.TryGetValue("key", out var k) ? LicenseKey.Normalize(k) ?? throw new ArgumentException("Ungültiger --key.") : LicenseKey.Generate();
    var days = o.TryGetValue("days", out var d) ? int.Parse(d, CultureInfo.InvariantCulture) : 365;
    var doc = new LicenseDocument
    {
        LicenseId = Guid.NewGuid().ToString("N"),
        Key = licenseKey,
        Plan = Enum.Parse<LicensePlan>(o.GetValueOrDefault("plan", "Pro"), ignoreCase: true),
        Licensee = o.TryGetValue("name", out var n) ? n : throw new ArgumentException("--name fehlt."),
        Email = o.GetValueOrDefault("email"),
        Seats = o.TryGetValue("seats", out var s) ? int.Parse(s, CultureInfo.InvariantCulture) : 1,
        IssuedAt = DateTimeOffset.UtcNow,
        ExpiresAt = days > 0 ? DateTimeOffset.UtcNow.AddDays(days) : null,
        DeviceId = o.GetValueOrDefault("device"),
        Features = LicenseFeatures.Pro,
    };
    var token = LicenseCodec.Sign(doc, key);
    var output = o.GetValueOrDefault("out", $"{licenseKey}.bastionlic");
    File.WriteAllText(output, token);
    Console.WriteLine($"Lizenzschlüssel: {licenseKey}");
    Console.WriteLine($"Lizenzdatei:     {Path.GetFullPath(output)}");
    Console.WriteLine($"Gültig bis:      {(doc.ExpiresAt is { } e ? e.ToLocalTime().ToString("dd.MM.yyyy", CultureInfo.InvariantCulture) : "unbegrenzt")}");
    return 0;
}

int Verify(string path)
{
    var pem = File.Exists(publicPath) ? File.ReadAllText(publicPath) : throw new ArgumentException("Kein öffentlicher Schlüssel gefunden.");
    using var key = LicenseCodec.ImportPem(pem);
    if (!LicenseCodec.TryVerify(File.ReadAllText(path), key, out var doc) || doc is null)
    {
        Console.Error.WriteLine("UNGÜLTIG: Signatur stimmt nicht.");
        return 2;
    }
    Console.WriteLine($"Gültig. {doc.Plan} für {doc.Licensee}, Schlüssel {doc.Key}, {doc.Seats} Geräte, bis {doc.ExpiresAt?.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture) ?? "unbegrenzt"}.");
    return 0;
}

static Dictionary<string, string> ParseOptions(string[] a)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < a.Length; i++)
    {
        if (!a[i].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException($"Unerwartetes Argument: {a[i]}");
        var name = a[i][2..];
        result[name] = i + 1 < a.Length && !a[i + 1].StartsWith("--", StringComparison.Ordinal) ? a[++i] : "true";
    }
    return result;
}

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(Environment.CurrentDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Bastion.sln")))
        dir = dir.Parent;
    return dir?.FullName ?? Environment.CurrentDirectory;
}

static void PrintHelp() => Console.WriteLine("""
    Bastion KeyGen

      init [--force]          Erstellt das Schlüsselpaar (keys/license-private.pem, Public Key in Bastion.Core)
      key                     Erzeugt einen neuen Lizenzschlüssel (BSTN-XXXX-XXXX-XXXX-XXXX)
      issue --name "Name"     Stellt eine signierte Lizenzdatei aus
            [--email a@b.de] [--plan Pro] [--seats 3] [--days 365 | 0 = unbegrenzt]
            [--key BSTN-...] [--device <Geräte-ID>] [--out datei.bastionlic]
      verify <datei>          Prüft eine Lizenzdatei

    Beispiel:
      dotnet run --project tools/Bastion.KeyGen -- issue --name "Max Muster" --seats 3
    """);
