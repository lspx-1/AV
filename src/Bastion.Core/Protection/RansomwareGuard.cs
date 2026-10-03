using System.Diagnostics;
using System.Text;
using Bastion.Core.Models;
using Bastion.Core.Platform;

namespace Bastion.Core.Protection;

/// <summary>
/// Places hidden decoy files in document and picture folders. Nobody opens them, so any change
/// is a strong sign of ransomware encrypting files. On a hit Bastion raises an alarm and can stop
/// recently started, unsigned programs from user folders.
/// </summary>
public sealed class RansomwareGuard(IProtectionContext context) : ProtectionModuleBase(context)
{
    // Names sort first and last so encryption that walks folders alphabetically hits them early.
    private static readonly (string Name, string Content)[] Decoys =
    [
        ("!000_Bastion_Kontoauszuege.docx", "Bastion Ransomware-Köder. Bitte nicht ändern oder löschen."),
        ("~zzz_Bastion_Steuer_2025.xlsx", "Bastion Ransomware-Köder. Bitte nicht ändern oder löschen."),
    ];

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly HashSet<string> _decoyPaths = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastAlarm;
    private bool _restoring;

    public override string Id => "ransomware";
    public override string Name => "Ransomware-Köder";
    public override string Description => "Versteckte Köderdateien schlagen Alarm, sobald etwas sie verschlüsselt.";
    public override string? Detail => $"{_decoyPaths.Count} Köder aktiv";

    protected override void OnStart()
    {
        var folders = KnownFolders.ForAllUsers("Documents")
            .Concat(KnownFolders.ForAllUsers("Pictures"))
            .Concat(KnownFolders.ForAllUsers("Desktop"))
            .ToList();
        foreach (var folder in folders)
        {
            foreach (var (name, content) in Decoys)
            {
                var path = Path.Combine(folder, name);
                try
                {
                    WriteDecoy(path, content);
                    _decoyPaths.Add(path);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    Context.Log($"Köder konnte nicht angelegt werden: {path} ({e.Message})");
                }
            }
            try
            {
                var w = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                };
                w.Changed += (_, e) => Safe("Köder-Prüfung", () => OnTouched(e.FullPath));
                w.Deleted += (_, e) => Safe("Köder-Prüfung", () => OnTouched(e.FullPath));
                w.Renamed += (_, e) => Safe("Köder-Prüfung", () => OnTouched(e.OldFullPath));
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception e) when (e is ArgumentException or IOException)
            {
                Context.Log($"Ordner kann nicht überwacht werden: {folder} ({e.Message})");
            }
        }
    }

    protected override void OnStop()
    {
        foreach (var w in _watchers)
            w.Dispose();
        _watchers.Clear();
        foreach (var path in _decoyPaths)
        {
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
        }
        _decoyPaths.Clear();
    }

    private static void WriteDecoy(string path, string content)
    {
        if (File.Exists(path))
            File.SetAttributes(path, FileAttributes.Normal);
        File.WriteAllText(path, content, Encoding.UTF8);
        File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
    }

    private void OnTouched(string path)
    {
        if (_restoring || !_decoyPaths.Contains(path))
            return;
        // One alarm per burst; ransomware touches many files within seconds.
        if (DateTime.UtcNow - _lastAlarm < TimeSpan.FromSeconds(30))
            return;
        _lastAlarm = DateTime.UtcNow;

        var stopped = Context.Settings.RansomwareEmergencyStop ? EmergencyStop() : [];
        Context.Raise(new SecurityEvent
        {
            Category = EventCategory.Ransomware,
            Severity = Severity.Critical,
            Title = "Möglicher Ransomware-Angriff",
            Detail = $"Eine Köderdatei wurde verändert: {path}. " +
                     (stopped.Count > 0
                         ? $"Bastion hat {stopped.Count} verdächtige Programme gestoppt: {string.Join(", ", stopped)}. "
                         : "") +
                     "Trenne den PC vom Netzwerk, wenn du nicht selbst an dieser Datei gearbeitet hast, und starte einen vollständigen Scan.",
            Target = path,
        });

        _restoring = true;
        try
        {
            var decoy = Decoys.FirstOrDefault(d => path.EndsWith(d.Name, StringComparison.OrdinalIgnoreCase));
            if (decoy.Name is not null)
                WriteDecoy(path, decoy.Content);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
        finally
        {
            _restoring = false;
        }
    }

    /// <summary>Stops unsigned programs from user folders that started within the last 15 minutes.</summary>
    private List<string> EmergencyStop()
    {
        var stopped = new List<string>();
        var cutoff = DateTime.Now - TimeSpan.FromMinutes(15);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id <= 4 || process.Id == Environment.ProcessId)
                        continue;
                    var path = ProcessInfo.GetImagePath(process.Id);
                    if (path is null || !KnownFolders.IsUserWritableLocation(path))
                        continue;
                    if (ProcessInfo.GetStartTime(process.Id) is not { } start || start < cutoff)
                        continue;
                    if (Authenticode.Check(path) == SignatureState.Signed)
                        continue;
                    if (ProcessInfo.TryKill(process.Id, out _))
                        stopped.Add(Path.GetFileName(path));
                }
                catch (Exception)
                {
                    // Process exited or access denied; continue with the next one.
                }
            }
        }
        return stopped;
    }
}
