using System.Net;
using Bastion.Core.Models;
using Bastion.Core.Platform;

namespace Bastion.Core.Protection;

/// <summary>
/// Watches the hosts file. Malware edits it to redirect banking sites or to block security updates.
/// Keeps a known-good copy that the user can restore.
/// </summary>
public sealed class HostsGuard(IProtectionContext context) : ProtectionModuleBase(context)
{
    private static readonly string[] SensitiveDomains =
    [
        "microsoft.com", "windowsupdate.com", "update.microsoft.com", "google.com", "paypal.com", "amazon.", "apple.com",
        "bitdefender.", "eset.", "kaspersky.", "avast.", "avg.com", "malwarebytes.", "norton", "mcafee.", "sophos.", "virustotal.com",
        "sparkasse", "volksbank", "deutsche-bank", "commerzbank", "ing.de", "dkb.de", "postbank", "comdirect", "n26.com",
    ];

    private FileSystemWatcher? _watcher;
    private string _lastContent = "";
    private DateTime _lastChange;

    public override string Id => "hosts";
    public override string Name => "Hosts-Datei-Schutz";
    public override string Description => "Erkennt Umleitungen von Banken, Windows Update und Sicherheitsseiten.";
    public override string? Detail => _lastChange == default ? "Unverändert seit Start" : $"Letzte Änderung {_lastChange:dd.MM.yyyy HH:mm}";

    protected override void OnStart()
    {
        var hosts = KnownFolders.HostsFile();
        if (!File.Exists(hosts))
            throw new FileNotFoundException("Hosts-Datei nicht gefunden.", hosts);
        _lastContent = File.ReadAllText(hosts);
        if (!File.Exists(Context.Paths.HostsBackup) && FindSuspicious(_lastContent).Count == 0)
            File.WriteAllText(Context.Paths.HostsBackup, _lastContent);

        foreach (var line in FindSuspicious(_lastContent))
            Report(line, isNew: false);

        _watcher = new FileSystemWatcher(Path.GetDirectoryName(hosts)!, "hosts")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
        };
        _watcher.Changed += (_, _) => OnChanged(hosts);
        _watcher.Created += (_, _) => OnChanged(hosts);
        _watcher.Renamed += (_, _) => OnChanged(hosts);
        _watcher.EnableRaisingEvents = true;
    }

    protected override void OnStop()
    {
        _watcher?.Dispose();
        _watcher = null;
    }

    private void OnChanged(string hosts)
    {
        Thread.Sleep(300);
        string content;
        try
        {
            content = File.ReadAllText(hosts);
        }
        catch (IOException)
        {
            return;
        }
        if (content == _lastContent)
            return;
        var before = FindSuspicious(_lastContent).ToHashSet();
        _lastContent = content;
        _lastChange = DateTime.Now;
        var suspicious = FindSuspicious(content).Where(l => !before.Contains(l)).ToList();
        if (suspicious.Count == 0)
        {
            Context.Raise(new SecurityEvent
            {
                Category = EventCategory.Hosts,
                Severity = Severity.Info,
                Title = "Hosts-Datei wurde geändert",
                Detail = "Keine verdächtigen Umleitungen gefunden.",
                Target = hosts,
            });
            File.WriteAllText(Context.Paths.HostsBackup, content);
            return;
        }
        foreach (var line in suspicious)
            Report(line, isNew: true);
    }

    private void Report(string line, bool isNew) => Context.Raise(new SecurityEvent
    {
        Category = EventCategory.Hosts,
        Severity = Severity.High,
        Title = isNew ? "Verdächtige Umleitung in der Hosts-Datei" : "Hosts-Datei enthält eine verdächtige Umleitung",
        Detail = $"Eintrag: {line}. Damit können Webseiten gefälscht oder Sicherheitsupdates blockiert werden.",
        Target = KnownFolders.HostsFile(),
        Actions = File.Exists(Context.Paths.HostsBackup) ? [EventActions.RestoreHosts, EventActions.Ignore] : [EventActions.Ignore],
    });

    /// <summary>Lines that send a well-known domain somewhere other than localhost.</summary>
    public static List<string> FindSuspicious(string content)
    {
        var result = new List<string>();
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Split('#')[0].Trim();
            if (line.Length == 0)
                continue;
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out _))
                continue;
            foreach (var host in parts.Skip(1))
            {
                if (SensitiveDomains.Any(d => host.Contains(d, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Add(line);
                    break;
                }
            }
        }
        return result;
    }

    public static (bool Ok, string Message) RestoreBackup(string backup)
    {
        try
        {
            if (!File.Exists(backup))
                return (false, "Keine Sicherung der Hosts-Datei vorhanden.");
            File.Copy(backup, KnownFolders.HostsFile(), overwrite: true);
            return (true, "Hosts-Datei aus der Sicherung wiederhergestellt.");
        }
        catch (Exception e)
        {
            return (false, "Wiederherstellen fehlgeschlagen: " + e.Message);
        }
    }
}
