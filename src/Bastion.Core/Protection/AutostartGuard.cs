using Bastion.Core.Models;
using Bastion.Core.Platform;
using Bastion.Core.Runtime;
using Microsoft.Win32;

namespace Bastion.Core.Protection;

public sealed record AutostartEntry(string Location, string Name, string Command)
{
    public string Key => $"{Location}|{Name}";

    /// <summary>The program file the entry starts, if it can be determined.</summary>
    public string? ProgramPath => AutostartGuard.ExtractPath(Command);
}

/// <summary>
/// Remembers all autostart entries (Run keys, startup folders, scheduled tasks) and reports new ones.
/// Malware almost always creates one to survive a restart.
/// </summary>
public sealed class AutostartGuard(IProtectionContext context) : ProtectionModuleBase(context)
{
    private static readonly string[] RunKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    private Timer? _timer;
    private Dictionary<string, AutostartEntry> _baseline = new();
    private int _newEntries;

    public override string Id => "autostart";
    public override string Name => "Autostart-Wächter";
    public override string Description => "Meldet neue Autostart-Einträge, geplante Aufgaben und Startordner-Dateien.";
    public override string? Detail => _newEntries == 0 ? $"{_baseline.Count} Einträge bekannt" : $"{_newEntries} neue Einträge zur Prüfung";

    protected override void OnStart()
    {
        var stored = JsonStore.LoadOrDefault<List<AutostartEntry>>(Context.Paths.AutostartBaseline);
        _baseline = stored.GroupBy(e => e.Key).ToDictionary(g => g.Key, g => g.First());
        if (_baseline.Count == 0)
        {
            // First run: everything that exists now is the trusted starting point.
            _baseline = Snapshot().GroupBy(e => e.Key).ToDictionary(g => g.Key, g => g.First());
            Save();
        }
        _timer = new Timer(_ => Safe("Autostart-Prüfung", Check), null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(10));
    }

    protected override void OnStop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void Check()
    {
        var current = Snapshot().GroupBy(e => e.Key).ToDictionary(g => g.Key, g => g.First());
        foreach (var (key, entry) in current)
        {
            if (_baseline.TryGetValue(key, out var known) && known.Command == entry.Command)
                continue;
            _newEntries++;
            _baseline[key] = entry;
            Report(entry);
        }
        foreach (var removed in _baseline.Keys.Where(k => !current.ContainsKey(k)).ToList())
            _baseline.Remove(removed);
        Save();
    }

    private void Report(AutostartEntry entry)
    {
        var program = entry.ProgramPath;
        if (program is not null && File.Exists(program))
        {
            var result = Context.Engine.ScanFile(program);
            if (result.IsMalicious)
            {
                var ev = Context.HandleDetection(result, EventCategory.Autostart);
                ev?.Actions.Insert(0, EventActions.RemoveAutostart);
                return;
            }
        }

        var trusted = program is not null && File.Exists(program) && Authenticode.Check(program) == SignatureState.Signed;
        Context.Raise(new SecurityEvent
        {
            Category = EventCategory.Autostart,
            Severity = trusted ? Severity.Info : Severity.Medium,
            Title = trusted ? "Neuer Autostart-Eintrag (signiert)" : "Neuer Autostart-Eintrag",
            Detail = $"„{entry.Name}“ startet ab jetzt automatisch: {entry.Command}" +
                     (trusted ? "" : ". Das Programm ist nicht signiert. Wenn du es nicht gerade installiert hast, entferne den Eintrag."),
            Target = entry.Location + "\\" + entry.Name,
            Actions = trusted ? [EventActions.Ignore, EventActions.RemoveAutostart] : [EventActions.RemoveAutostart, EventActions.Ignore],
        });
    }

    private void Save() => JsonStore.Save(Context.Paths.AutostartBaseline, _baseline.Values.ToList());

    public static IEnumerable<AutostartEntry> Snapshot()
    {
        if (!OperatingSystem.IsWindows())
            yield break;

        foreach (var (root, label) in Hives())
        {
            foreach (var path in RunKeys)
            {
                foreach (var entry in ReadRunKey(root, label, path))
                    yield return entry;
            }
            if (root is var r && label.StartsWith("HKU", StringComparison.Ordinal))
                r.Dispose();
        }

        var startupDirs = KnownFolders.ForAllUsers("AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup").ToList();
        var common = KnownFolders.StartupFolderCommon();
        if (common.Length > 0 && Directory.Exists(common))
            startupDirs.Add(common);
        foreach (var dir in startupDirs)
        {
            foreach (var file in SafeFiles(dir, SearchOption.TopDirectoryOnly))
            {
                if (!file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    yield return new AutostartEntry(dir, Path.GetFileName(file), file);
            }
        }

        var tasks = Path.Combine(Environment.SystemDirectory, "Tasks");
        foreach (var file in SafeFiles(tasks, SearchOption.AllDirectories))
        {
            if (file.Contains(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
                continue;
            yield return new AutostartEntry("Geplante Aufgaben", Path.GetRelativePath(tasks, file), TaskCommand(file));
        }
    }

    private static List<AutostartEntry> ReadRunKey(RegistryKey root, string label, string path)
    {
        var list = new List<AutostartEntry>();
        try
        {
            using var key = root.OpenSubKey(path);
            if (key is null)
                return list;
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string cmd)
                    list.Add(new AutostartEntry($@"{label}\{path}", name, cmd));
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // A user hive we may not read; skip it.
        }
        return list;
    }

    private static IEnumerable<(RegistryKey Root, string Label)> Hives()
    {
        yield return (Registry.LocalMachine, "HKLM");
        yield return (Registry.CurrentUser, "HKCU");
        // The service runs as SYSTEM: also look at every logged-on user's hive.
        string[] users;
        try
        {
            users = Registry.Users.GetSubKeyNames();
        }
        catch (Exception)
        {
            yield break;
        }
        foreach (var sid in users.Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith("_Classes", StringComparison.Ordinal)))
        {
            RegistryKey? key = null;
            try
            {
                key = Registry.Users.OpenSubKey(sid);
            }
            catch (Exception)
            {
            }
            if (key is not null)
                yield return (key, $@"HKU\{sid}");
        }
    }

    private static string TaskCommand(string taskFile)
    {
        try
        {
            var xml = File.ReadAllText(taskFile);
            var start = xml.IndexOf("<Command>", StringComparison.OrdinalIgnoreCase);
            var end = xml.IndexOf("</Command>", StringComparison.OrdinalIgnoreCase);
            if (start >= 0 && end > start)
            {
                var cmd = xml[(start + 9)..end].Trim();
                var argsStart = xml.IndexOf("<Arguments>", StringComparison.OrdinalIgnoreCase);
                var argsEnd = xml.IndexOf("</Arguments>", StringComparison.OrdinalIgnoreCase);
                if (argsStart >= 0 && argsEnd > argsStart)
                    cmd += " " + xml[(argsStart + 11)..argsEnd].Trim();
                return System.Net.WebUtility.HtmlDecode(cmd);
            }
        }
        catch (Exception)
        {
        }
        return taskFile;
    }

    private static IEnumerable<string> SafeFiles(string dir, SearchOption option)
    {
        try
        {
            return Directory.Exists(dir) ? Directory.GetFiles(dir, "*", option) : [];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>Extracts the program path from a command line like <c>"C:\x\a.exe" -arg</c> or <c>C:\x\a.exe -arg</c>.</summary>
    public static string? ExtractPath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;
        var cmd = Environment.ExpandEnvironmentVariables(command.Trim());
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            return end > 1 ? cmd[1..end] : null;
        }
        if (File.Exists(cmd))
            return cmd;
        var exe = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? cmd[..(exe + 4)] : cmd.Split(' ')[0];
    }

    /// <summary>Removes an autostart entry identified by its event target ("location\name").</summary>
    public static (bool Ok, string Message) Remove(string target)
    {
        if (!OperatingSystem.IsWindows())
            return (false, "Nur unter Windows verfügbar.");
        var split = target.LastIndexOf('\\');
        if (split < 0)
            return (false, "Unbekannter Eintrag.");
        var location = target[..split];
        var name = target[(split + 1)..];
        try
        {
            if (location == "Geplante Aufgaben")
            {
                var file = Path.Combine(Environment.SystemDirectory, "Tasks", name);
                using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("schtasks", $"/Delete /TN \"\\{name}\" /F") { CreateNoWindow = true, UseShellExecute = false })!;
                p.WaitForExit(10_000);
                return p.ExitCode == 0 || !File.Exists(file) ? (true, "Geplante Aufgabe entfernt.") : (false, "Geplante Aufgabe konnte nicht entfernt werden.");
            }
            if (Directory.Exists(location))
            {
                File.Delete(Path.Combine(location, name));
                return (true, "Datei aus dem Autostart-Ordner entfernt.");
            }
            var hiveEnd = location.IndexOf('\\');
            var hive = location[..hiveEnd];
            var subPath = location[(hiveEnd + 1)..];
            RegistryKey root = hive switch
            {
                "HKLM" => Registry.LocalMachine,
                "HKCU" => Registry.CurrentUser,
                _ => Registry.Users,
            };
            if (hive.StartsWith("HKU", StringComparison.Ordinal))
                subPath = location[(location.IndexOf('\\') + 1)..];
            using var key = root.OpenSubKey(subPath, writable: true);
            if (key is null)
                return (false, "Registrierungsschlüssel nicht gefunden.");
            key.DeleteValue(name, throwOnMissingValue: false);
            return (true, "Autostart-Eintrag entfernt.");
        }
        catch (Exception e)
        {
            return (false, "Entfernen fehlgeschlagen: " + e.Message);
        }
    }
}
