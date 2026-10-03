namespace Bastion.Core.Runtime;

/// <summary>Where Bastion stores its data. The service uses ProgramData, the standalone app uses LocalAppData.</summary>
public sealed class BastionPaths
{
    public BastionPaths(string root, string signaturesDirectory)
    {
        Root = root;
        Signatures = signaturesDirectory;
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Quarantine);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(UserSignatures);
    }

    public string Root { get; }

    /// <summary>Signatures shipped with the program (read only).</summary>
    public string Signatures { get; }

    /// <summary>Downloaded feeds and the user's own rules.</summary>
    public string UserSignatures => Path.Combine(Root, "Signatures");
    public string Quarantine => Path.Combine(Root, "Quarantine");
    public string Logs => Path.Combine(Root, "Logs");
    public string SettingsFile => Path.Combine(Root, "settings.json");
    public string LicenseFile => Path.Combine(Root, "license.dat");
    public string StateFile => Path.Combine(Root, "state.json");
    public string AutostartBaseline => Path.Combine(Root, "autostart-baseline.json");
    public string HostsBackup => Path.Combine(Root, "hosts.backup");

    public static BastionPaths ForService()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bastion");
        return new BastionPaths(root, DefaultSignatureDirectory());
    }

    public static BastionPaths ForStandaloneApp()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bastion");
        return new BastionPaths(root, DefaultSignatureDirectory());
    }

    public static string DefaultSignatureDirectory()
    {
        // Installed layout: <install>\signatures. Dev layout: walk up to the repository root.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "signatures");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        return Path.Combine(AppContext.BaseDirectory, "signatures");
    }
}
