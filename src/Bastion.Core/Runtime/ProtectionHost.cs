using System.Diagnostics;
using System.Security.Principal;
using Bastion.Core.Heuristics;
using Bastion.Core.Ipc;
using Bastion.Core.Licensing;
using Bastion.Core.Models;
using Bastion.Core.Network;
using Bastion.Core.Platform;
using Bastion.Core.Protection;
using Bastion.Core.Quarantine;
using Bastion.Core.Scanning;
using Bastion.Core.Signatures;
using Bastion.Core.Updates;
using Microsoft.Extensions.Logging;

namespace Bastion.Core.Runtime;

/// <summary>
/// The protection engine: owns signatures, scanner, quarantine, license and all protection modules.
/// Hosted by the Windows service, or directly by the app when the service is not installed.
/// </summary>
public sealed class ProtectionHost : IBastionBackend, IProtectionContext, IDisposable
{
    public const string HeuristicsModuleId = "heuristics";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    private readonly ILogger? _logger;
    private readonly HashSignatureDb _hashes = new();
    private readonly RuleSet _rules = new();
    private readonly IpBlocklist _ipBlocklist = new();
    private readonly EventJournal _journal;
    private readonly Dictionary<string, IProtectionModule> _modules = new();
    private readonly NetworkMonitor _networkMonitor;
    private readonly Lock _scanLock = new();
    private readonly List<Timer> _timers = [];
    private HostState _state;
    private BastionSettings _settings;
    private IReadOnlyList<string> _otherAv = [];
    private ScanProgress? _scan;
    private CancellationTokenSource? _scanCts;
    private DateTime _lastProgressEvent;

    public ProtectionHost(BastionPaths paths, bool runningAsService, ILogger? logger = null)
    {
        Paths = paths;
        RunningAsService = runningAsService;
        _logger = logger;
        _settings = JsonStore.LoadOrDefault<BastionSettings>(paths.SettingsFile);
        _state = JsonStore.LoadOrDefault<HostState>(paths.StateFile);
        _journal = new EventJournal(paths.Logs);
        _journal.Added += e => EventRaised?.Invoke(e);
        _journal.Updated += e => EventRaised?.Invoke(e);

        Vault = new QuarantineVault(paths.Quarantine);
        License = new LicenseManager(paths.LicenseFile, LicenseCodec.LoadPublicKey(), CreateLicenseClient);
        License.Changed += s =>
        {
            LicenseChanged?.Invoke(s);
            ReloadSignatures();
        };

        Engine = new ScanEngine(
        [
            new HashDetector(_hashes),
            new RuleDetector(_rules),
            new ConditionalDetector(new HeuristicDetector(() => _settings.HeuristicSensitivity), () => _settings.IsModuleEnabled(HeuristicsModuleId)),
        ], () => new ScanOptions
        {
            MaxContentBytes = _settings.MaxContentScanBytes,
            ExcludedPaths = _settings.ExcludedPaths,
            ExcludedHashes = _settings.ExcludedHashes.ToHashSet(StringComparer.OrdinalIgnoreCase),
        });

        var beacons = new BeaconDetector();
        _networkMonitor = new NetworkMonitor(new RemoteAccessAnalyzer(_ipBlocklist, beacons, Authenticode.Check), beacons);

        foreach (var module in new IProtectionModule[]
                 {
                     new RealtimeFileGuard(this),
                     new ProcessGuard(this),
                     new NetworkGuard(this, _networkMonitor),
                     new AutostartGuard(this),
                     new RansomwareGuard(this),
                     new HostsGuard(this),
                 })
        {
            _modules[module.Id] = module;
        }
    }

    public event Action<SecurityEvent>? EventRaised;
    public event Action<ScanProgress>? ScanProgressChanged;
    public event Action<LicenseStatus>? LicenseChanged;

    public BastionPaths Paths { get; }
    public ScanEngine Engine { get; }
    public QuarantineVault Vault { get; }
    public LicenseManager License { get; }
    public bool RunningAsService { get; }
    public BastionSettings Settings => _settings;

    public bool ComplementaryModeActive => _settings.ComplementaryMode switch
    {
        ComplementaryMode.On => true,
        ComplementaryMode.Off => false,
        _ => _otherAv.Count > 0,
    };

    public void Start()
    {
        ReloadSignatures();
        _otherAv = AntivirusProducts.ActiveThirdParty();
        foreach (var module in _modules.Values.Where(m => _settings.IsModuleEnabled(m.Id)))
            module.Start();

        Raise(new SecurityEvent
        {
            Category = EventCategory.System,
            Severity = Severity.Info,
            Title = "Bastion gestartet",
            Detail = $"{_modules.Values.Count(m => m.Running)} Schutzmodule aktiv, {_hashes.Count:N0} Signaturen, {_rules.Count} Regeln." +
                     (_otherAv.Count > 0 ? $" Ergänzungsmodus neben {string.Join(", ", _otherAv)}." : ""),
        });

        _timers.Add(new Timer(_ => Safe("Virenschutz-Erkennung", () => _otherAv = AntivirusProducts.ActiveThirdParty()), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5)));
        _timers.Add(new Timer(_ => Safe("Signatur-Update", () => _ = AutoUpdateAsync()), null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(30)));
        _timers.Add(new Timer(_ => Safe("Lizenzprüfung", () => _ = License.RefreshAsync()), null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(6)));
        _timers.Add(new Timer(_ => Safe("Geplanter Scan", ScheduledScanTick), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10)));
    }

    private void Safe(string what, Action action)
    {
        try
        {
            action();
        }
        catch (Exception e)
        {
            Log($"{what} fehlgeschlagen: {e.GetType().Name}: {e.Message}");
        }
    }

    public void Dispose()
    {
        foreach (var t in _timers)
            t.Dispose();
        _scanCts?.Cancel();
        foreach (var m in _modules.Values)
            m.Dispose();
    }

    // ---------------------------------------------------------------- signatures

    public void ReloadSignatures()
    {
        var shipped = Paths.Signatures;
        _hashes.LoadDirectory(Path.Combine(shipped, "hashes"));
        _hashes.LoadDirectory(Path.Combine(Paths.UserSignatures, "hashes"));
        _ipBlocklist.LoadDirectory(Path.Combine(shipped, "ip-blocklist"));
        _ipBlocklist.LoadDirectory(Path.Combine(Paths.UserSignatures, "ip-blocklist"));

        var ruleDirs = new List<string> { Path.Combine(shipped, "rules") };
        var customRules = Path.Combine(Paths.UserSignatures, "custom-rules");
        Directory.CreateDirectory(customRules);
        if (License.HasFeature(LicenseFeatures.CustomRules))
            ruleDirs.Add(customRules);
        _rules.LoadDirectories([.. ruleDirs]);
        foreach (var error in _rules.Errors)
            Log("Regel-Fehler: " + error);
    }

    private async Task AutoUpdateAsync()
    {
        if (!_settings.AutoUpdateSignatures)
            return;
        var interval = License.HasFeature(LicenseFeatures.HourlyUpdates) ? TimeSpan.FromHours(1) : TimeSpan.FromDays(7);
        if (_state.SignaturesUpdated is { } last && DateTimeOffset.Now - last < interval)
            return;
        await UpdateSignaturesAsync();
    }

    public async Task<UpdateResult> UpdateSignaturesAsync()
    {
        var result = await new SignatureUpdater(Http).UpdateAsync(
            Path.Combine(Paths.UserSignatures, "hashes"), _settings.HashFeedUrls,
            Path.Combine(Paths.UserSignatures, "ip-blocklist"), _settings.IpFeedUrls,
            CancellationToken.None);
        if (result.Success)
        {
            _state = _state with { SignaturesUpdated = DateTimeOffset.Now };
            SaveState();
            ReloadSignatures();
        }
        Raise(new SecurityEvent
        {
            Category = EventCategory.Update,
            Severity = result.Success ? Severity.Info : Severity.Low,
            Title = result.Success ? "Signaturen aktualisiert" : "Signatur-Update fehlgeschlagen",
            Detail = result.Message,
        });
        return result;
    }

    // ---------------------------------------------------------------- IProtectionContext

    public void Raise(SecurityEvent securityEvent)
    {
        _journal.Add(securityEvent);
        Log($"[{securityEvent.Severity}] {securityEvent.Title}: {securityEvent.Detail}");
    }

    public SecurityEvent? HandleDetection(FileScanResult result, EventCategory category, int? processId = null)
    {
        var verdict = result.Verdict;
        if (verdict is null)
            return null;

        var autoQuarantine = verdict.IsDefinitive ? _settings.AutoQuarantineSignatures : _settings.AutoQuarantineHeuristics;
        string? resolution = null;
        var detail = $"{verdict.Reason} (erkannt durch {verdict.Detector}).";

        if (autoQuarantine)
        {
            if (processId is { } pid && _settings.KillMaliciousProcesses)
            {
                ProcessInfo.TryKill(pid, out _);
                Thread.Sleep(300);
            }
            try
            {
                Vault.Add(result.Path, result.Sha256 ?? "", verdict.Name, verdict.Reason);
                resolution = "In Quarantäne verschoben";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                detail += $" Verschieben in die Quarantäne fehlgeschlagen: {e.Message}";
            }
        }

        var actions = new List<string>();
        if (resolution is null)
        {
            if (processId is not null)
                actions.Add(EventActions.KillAndQuarantine);
            else
                actions.Add(EventActions.Quarantine);
            actions.Add(EventActions.Exclude);
            actions.Add(EventActions.Ignore);
        }

        var ev = new SecurityEvent
        {
            Category = category,
            Severity = verdict.Severity,
            Title = resolution is null ? $"Bedrohung gefunden: {verdict.Name}" : $"Bedrohung entfernt: {verdict.Name}",
            Detail = detail,
            Target = result.Path,
            ProgramPath = result.Path,
            ProcessId = processId,
            ThreatName = verdict.Name,
            Actions = actions,
            Resolution = resolution,
        };
        Raise(ev);
        return ev;
    }

    public void Log(string message)
    {
        _logger?.LogInformation("{Message}", message);
        try
        {
            File.AppendAllText(Path.Combine(Paths.Logs, "bastion.log"), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}\n");
        }
        catch (IOException)
        {
        }
    }

    // ---------------------------------------------------------------- status & modules

    public Task<StatusSnapshot> GetStatusAsync()
    {
        var modules = _modules.Values.Select(m => new ModuleStatus(m.Id, m.Name, m.Description, _settings.IsModuleEnabled(m.Id), m.Running, m.Running ? m.Detail : "Ausgeschaltet"))
            .Append(new ModuleStatus(HeuristicsModuleId, "Heuristik", "Erkennt unbekannte Schadsoftware an verdächtigen Merkmalen.",
                _settings.IsModuleEnabled(HeuristicsModuleId), _settings.IsModuleEnabled(HeuristicsModuleId),
                $"Empfindlichkeit: {SensitivityLabel(_settings.HeuristicSensitivity)}"))
            .ToList();
        var openThreats = _journal.OpenThreats();
        return Task.FromResult(new StatusSnapshot
        {
            Protected = modules.All(m => m.Enabled && m.Running) && openThreats == 0,
            ActiveThreats = openThreats,
            Modules = modules,
            LastScan = _state.LastScan,
            LastScanSummary = _state.LastScanSummary,
            SignaturesUpdated = _state.SignaturesUpdated ?? _hashes.LastLoaded,
            SignatureCount = _hashes.Count + _ipBlocklist.Count,
            RuleCount = _rules.Count,
            FilesScannedToday = (_modules["realtime"] as RealtimeFileGuard)?.ScannedToday ?? 0,
            QuarantineCount = Vault.Items.Count,
            OtherAntivirusProducts = _otherAv,
            ComplementaryModeActive = ComplementaryModeActive,
            RunningAsService = RunningAsService,
            IsElevated = IsElevated(),
            Version = AppInfo.Version,
            CurrentScan = _scan,
        });
    }

    public Task SetModuleEnabledAsync(string moduleId, bool enabled)
    {
        _settings.Modules[moduleId] = enabled;
        SaveSettings();
        if (_modules.TryGetValue(moduleId, out var module))
        {
            if (enabled) module.Start();
            else module.Stop();
        }
        if (!enabled)
        {
            Raise(new SecurityEvent
            {
                Category = EventCategory.System,
                Severity = Severity.Low,
                Title = "Schutzmodul ausgeschaltet",
                Detail = $"{ModuleName(moduleId)} wurde ausgeschaltet.",
            });
        }
        return Task.CompletedTask;
    }

    private string ModuleName(string id) => _modules.TryGetValue(id, out var m) ? m.Name : id == HeuristicsModuleId ? "Heuristik" : id;

    private static string SensitivityLabel(Sensitivity s) => s switch
    {
        Sensitivity.Low => "Niedrig",
        Sensitivity.High => "Hoch",
        _ => "Mittel",
    };

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ---------------------------------------------------------------- scanning

    public Task<ScanProgress> StartScanAsync(ScanRequest request)
    {
        lock (_scanLock)
        {
            if (_scan is { Running: true })
                return Task.FromResult(_scan);
            _scanCts = new CancellationTokenSource();
            _scan = new ScanProgress { ScanId = Guid.NewGuid(), Kind = request.Kind, Running = true, StartedAt = DateTimeOffset.Now };
        }
        var ct = _scanCts.Token;
        var scan = _scan;
        _ = Task.Run(() => RunScan(scan, request, ct), ct);
        ScanProgressChanged?.Invoke(scan);
        return Task.FromResult(scan);
    }

    public Task CancelScanAsync()
    {
        _scanCts?.Cancel();
        return Task.CompletedTask;
    }

    private void RunScan(ScanProgress scan, ScanRequest request, CancellationToken ct)
    {
        var findings = new List<FileScanSummary>();
        var scanned = 0;
        var threats = 0;
        string? current = null;
        var cancelled = false;

        void Report(bool force = false)
        {
            if (!force && DateTime.UtcNow - _lastProgressEvent < TimeSpan.FromMilliseconds(250))
                return;
            _lastProgressEvent = DateTime.UtcNow;
            List<FileScanSummary> snapshot;
            lock (findings)
                snapshot = [.. findings];
            _scan = scan with { FilesScanned = scanned, Threats = threats, CurrentPath = current, Findings = snapshot };
            ScanProgressChanged?.Invoke(_scan);
        }

        try
        {
            var files = ScanTargets.Enumerate(request, Paths.Root);
            if (request.Kind != ScanKind.Full)
            {
                var list = files.ToList();
                scan = scan with { FilesTotal = list.Count };
                files = list;
            }

            Parallel.ForEach(files, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount / 2) }, path =>
            {
                current = path;
                FileScanResult result;
                try
                {
                    result = Engine.ScanFile(path);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    Log($"Scan von {path} fehlgeschlagen: {e.Message}");
                    return;
                }
                Interlocked.Increment(ref scanned);
                if (result.IsMalicious)
                {
                    Interlocked.Increment(ref threats);
                    var ev = HandleDetection(result, EventCategory.Scan);
                    lock (findings)
                        findings.Add(new FileScanSummary(path, result.Verdict!.Name, result.Verdict.Severity, result.Verdict.Reason, ev?.Resolution is not null, ev?.Id));
                }
                Report();
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        catch (Exception e)
        {
            Log("Scan abgebrochen: " + e);
        }

        var duration = DateTimeOffset.Now - scan.StartedAt;
        current = null;
        Report(force: true);
        _scan = _scan! with { Running = false, Cancelled = cancelled, FinishedAt = DateTimeOffset.Now };
        ScanProgressChanged?.Invoke(_scan);

        var kind = request.Kind switch { ScanKind.Quick => "Schnellscan", ScanKind.Full => "Vollständiger Scan", _ => "Benutzerdefinierter Scan" };
        var summary = $"{scanned:N0} Dateien in {duration:mm\\:ss} min, {threats} Funde";
        if (!cancelled)
        {
            _state = _state with { LastScan = DateTimeOffset.Now, LastScanSummary = $"{kind}: {summary}" };
            SaveState();
        }
        Raise(new SecurityEvent
        {
            Category = EventCategory.Scan,
            Severity = threats > 0 ? Severity.Medium : Severity.Info,
            Title = cancelled ? $"{kind} abgebrochen" : threats > 0 ? $"{kind} abgeschlossen, {threats} Funde" : $"{kind} ohne Funde",
            Detail = summary,
        });
    }

    private void ScheduledScanTick()
    {
        if (!_settings.ScheduledScanEnabled || !License.HasFeature(LicenseFeatures.ScheduledScans))
            return;
        if (DateTime.Now.Hour != _settings.ScheduledScanHour)
            return;
        if (_state.LastScan is { } last && last.Date == DateTime.Today)
            return;
        _ = StartScanAsync(new ScanRequest(ScanKind.Quick));
    }

    // ---------------------------------------------------------------- events & actions

    public Task<IReadOnlyList<SecurityEvent>> GetEventsAsync(int max) => Task.FromResult(_journal.Recent(max));

    public Task<ActionResult> ExecuteEventActionAsync(Guid eventId, string action)
    {
        var ev = _journal.Find(eventId);
        if (ev is null)
            return Task.FromResult(new ActionResult(false, "Ereignis nicht gefunden."));
        if (ev.IsResolved)
            return Task.FromResult(new ActionResult(false, "Dieses Ereignis ist bereits erledigt."));

        ActionResult result = action switch
        {
            EventActions.Quarantine => QuarantineFile(ev.ProgramPath ?? ev.Target, ev.ThreatName ?? ev.Title, ev.Detail),
            EventActions.Kill => Kill(ev.ProcessId),
            EventActions.KillAndQuarantine => KillAndQuarantine(ev),
            EventActions.RemoveAutostart => ToResult(AutostartGuard.Remove(ev.Target ?? "")),
            EventActions.BlockRemote => ToResult(Firewall.BlockRemoteAddress(ev.Target ?? "")),
            EventActions.BlockProgram => ToResult(Firewall.BlockProgram(ev.ProgramPath ?? "")),
            EventActions.RestoreHosts => ToResult(HostsGuard.RestoreBackup(Paths.HostsBackup)),
            EventActions.Exclude => Exclude(ev.ProgramPath ?? ev.Target),
            EventActions.Ignore => new ActionResult(true, "Ignoriert"),
            _ => new ActionResult(false, $"Unbekannte Aktion: {action}"),
        };
        if (result.Success)
            _journal.Resolve(ev, result.Message);
        return Task.FromResult(result);
    }

    private static ActionResult ToResult((bool Ok, string Message) r) => new(r.Ok, r.Message);

    private ActionResult KillAndQuarantine(SecurityEvent ev)
    {
        var kill = Kill(ev.ProcessId);
        var path = ev.ProgramPath ?? ev.Target;
        if (path is null || !File.Exists(path))
            return kill;
        Thread.Sleep(300);
        var q = QuarantineFile(path, ev.ThreatName ?? ev.Title, ev.Detail);
        return new ActionResult(q.Success, kill.Success ? "Prozess beendet und " + q.Message.ToLowerInvariant() : q.Message);
    }

    private static ActionResult Kill(int? pid)
    {
        if (pid is null)
            return new ActionResult(false, "Kein Prozess angegeben.");
        return ProcessInfo.TryKill(pid.Value, out var error)
            ? new ActionResult(true, "Prozess beendet")
            : new ActionResult(false, "Prozess konnte nicht beendet werden: " + error);
    }

    private ActionResult QuarantineFile(string? path, string name, string? reason)
    {
        if (path is null || !File.Exists(path))
            return new ActionResult(false, "Die Datei existiert nicht mehr.");
        try
        {
            var context = FileScanContext.Load(path, 0);
            Vault.Add(path, context.Sha256, name, reason ?? "");
            return new ActionResult(true, "In Quarantäne verschoben");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new ActionResult(false, "Verschieben fehlgeschlagen: " + e.Message);
        }
    }

    private ActionResult Exclude(string? path)
    {
        if (path is null)
            return new ActionResult(false, "Kein Pfad angegeben.");
        if (!_settings.ExcludedPaths.Contains(path, StringComparer.OrdinalIgnoreCase))
            _settings.ExcludedPaths.Add(path);
        SaveSettings();
        return new ActionResult(true, "Als Ausnahme hinzugefügt");
    }

    // ---------------------------------------------------------------- quarantine

    public Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync() => Task.FromResult(Vault.Items);

    public Task<ActionResult> RestoreQuarantineAsync(Guid id, bool addExclusion)
    {
        try
        {
            var item = Vault.Items.FirstOrDefault(i => i.Id == id);
            var target = Vault.Restore(id);
            if (addExclusion && item is not null && !_settings.ExcludedHashes.Contains(item.Sha256, StringComparer.OrdinalIgnoreCase))
            {
                _settings.ExcludedHashes.Add(item.Sha256);
                SaveSettings();
            }
            Raise(new SecurityEvent { Category = EventCategory.Quarantine, Severity = Severity.Low, Title = "Datei wiederhergestellt", Target = target });
            return Task.FromResult(new ActionResult(true, $"Wiederhergestellt nach {target}"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or KeyNotFoundException or InvalidDataException)
        {
            return Task.FromResult(new ActionResult(false, e.Message));
        }
    }

    public Task<ActionResult> DeleteQuarantineAsync(Guid id)
    {
        try
        {
            Vault.Delete(id);
            return Task.FromResult(new ActionResult(true, "Endgültig gelöscht"));
        }
        catch (Exception e) when (e is IOException or KeyNotFoundException)
        {
            return Task.FromResult(new ActionResult(false, e.Message));
        }
    }

    // ---------------------------------------------------------------- network

    public Task<IReadOnlyList<ConnectionView>> GetConnectionsAsync()
    {
        if (!_modules["network"].Running)
            _networkMonitor.Poll(DateTimeOffset.Now);
        return Task.FromResult(_networkMonitor.Current);
    }

    public Task<ActionResult> KillProcessAsync(int pid) => Task.FromResult(Kill(pid));

    public Task<ActionResult> BlockRemoteAsync(string ip) => Task.FromResult(ToResult(Firewall.BlockRemoteAddress(ip)));

    public Task<ActionResult> BlockProgramAsync(string path) => Task.FromResult(ToResult(Firewall.BlockProgram(path)));

    // ---------------------------------------------------------------- settings

    public Task<BastionSettings> GetSettingsAsync() => Task.FromResult(_settings);

    public Task SaveSettingsAsync(BastionSettings settings)
    {
        var rulesChanged = settings.LicenseServerUrl != _settings.LicenseServerUrl;
        _settings = settings;
        SaveSettings();
        foreach (var module in _modules.Values)
        {
            var enabled = _settings.IsModuleEnabled(module.Id);
            if (enabled && !module.Running) module.Start();
            if (!enabled && module.Running) module.Stop();
        }
        if (rulesChanged)
            LicenseChanged?.Invoke(License.Status);
        return Task.CompletedTask;
    }

    private void SaveSettings() => JsonStore.Save(Paths.SettingsFile, _settings);

    private void SaveState() => JsonStore.Save(Paths.StateFile, _state);

    // ---------------------------------------------------------------- license

    private ILicenseServerClient? CreateLicenseClient() =>
        string.IsNullOrWhiteSpace(_settings?.LicenseServerUrl) ? null : new HttpLicenseServerClient(Http, _settings.LicenseServerUrl);

    public Task<LicenseStatus> GetLicenseAsync() => Task.FromResult(License.Status);

    public Task<LicenseOperationResult> ActivateLicenseAsync(string key) => License.ActivateAsync(key);

    public Task<LicenseOperationResult> ImportLicenseAsync(string token) => Task.FromResult(License.ImportToken(token));

    public Task<LicenseOperationResult> DeactivateLicenseAsync() => License.DeactivateAsync();

    public Task<LicenseOperationResult> RefreshLicenseAsync() => License.RefreshAsync(force: true);

    private sealed record HostState
    {
        public DateTimeOffset? LastScan { get; init; }
        public string? LastScanSummary { get; init; }
        public DateTimeOffset? SignaturesUpdated { get; init; }
    }
}
