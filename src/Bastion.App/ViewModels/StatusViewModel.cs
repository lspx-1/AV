using System.Collections.ObjectModel;
using System.Windows.Threading;
using Bastion.App.Services;
using Bastion.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public enum ProtectionState
{
    Protected,
    Limited,
    Threat,
}

public sealed partial class StatusViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;
    private readonly DispatcherTimer _timer;

    public StatusViewModel(BackendSession session, ISnackbarService snackbar)
    {
        _session = session;
        _snackbar = snackbar;
        _session.EventRaised += e => _ = RefreshAsync();
        _session.ScanProgressChanged += OnScanProgress;
        _session.Reconnected += () => _ = RefreshAsync();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    [ObservableProperty] private ProtectionState _state = ProtectionState.Protected;
    [ObservableProperty] private string _headline = "Wird geladen…";
    [ObservableProperty] private string _subline = "";
    [ObservableProperty] private string _signaturesText = "–";
    [ObservableProperty] private string _scannedTodayText = "–";
    [ObservableProperty] private int _quarantineCount;
    [ObservableProperty] private string? _complementaryText;
    [ObservableProperty] private string _modeText = "";
    [ObservableProperty] private bool _isServiceMode = true;
    [ObservableProperty] private bool _scanRunning;
    [ObservableProperty] private double _scanPercent;
    [ObservableProperty] private bool _scanIndeterminate;
    [ObservableProperty] private string? _scanText;
    [ObservableProperty] private bool _isUpdating;

    public ObservableCollection<ModuleItemViewModel> Modules { get; } = [];
    public ObservableCollection<EventItemViewModel> RecentEvents { get; } = [];

    public bool IsProtected => State == ProtectionState.Protected;
    public bool IsLimited => State == ProtectionState.Limited;
    public bool IsThreat => State == ProtectionState.Threat;

    partial void OnStateChanged(ProtectionState value)
    {
        OnPropertyChanged(nameof(IsProtected));
        OnPropertyChanged(nameof(IsLimited));
        OnPropertyChanged(nameof(IsThreat));
    }

    public void Start()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    public void Stop() => _timer.Stop();

    public async Task RefreshAsync()
    {
        StatusSnapshot status;
        IReadOnlyList<SecurityEvent> events;
        try
        {
            status = await _session.Backend.GetStatusAsync();
            events = await _session.Backend.GetEventsAsync(6);
        }
        catch (Exception)
        {
            return; // reconnect in progress
        }

        ModeText = _session.ModeText;
        IsServiceMode = _session.IsServiceMode;
        var off = status.Modules.Count(m => !m.Enabled);
        State = status.ActiveThreats > 0 ? ProtectionState.Threat : off > 0 ? ProtectionState.Limited : ProtectionState.Protected;
        Headline = State switch
        {
            ProtectionState.Threat => status.ActiveThreats == 1 ? "1 Bedrohung braucht deine Entscheidung" : $"{status.ActiveThreats} Bedrohungen brauchen deine Entscheidung",
            ProtectionState.Limited => "Schutz eingeschränkt",
            _ => "Du bist geschützt",
        };
        Subline = State switch
        {
            ProtectionState.Threat => "Öffne den Verlauf und entscheide, was mit den Funden passieren soll.",
            ProtectionState.Limited => off == 1 ? "1 Schutzmodul ist ausgeschaltet. Schalte es wieder ein, um voll geschützt zu sein."
                                                : $"{off} Schutzmodule sind ausgeschaltet. Schalte sie wieder ein, um voll geschützt zu sein.",
            _ => status.LastScan is { } last ? $"Alle Schutzmodule laufen. Zuletzt geprüft {Helpers.Format.Time(last)}." : "Alle Schutzmodule laufen. Starte einen ersten Schnellscan.",
        };
        SignaturesText = status.SignaturesUpdated is { } updated ? $"{updated.ToLocalTime():dd.MM.yyyy} · {status.SignatureCount:N0}" : $"{status.SignatureCount:N0}";
        ScannedTodayText = $"{status.FilesScannedToday:N0} Dateien";
        QuarantineCount = status.QuarantineCount;
        ComplementaryText = status.ComplementaryModeActive && status.OtherAntivirusProducts.Count > 0
            ? $"{string.Join(", ", status.OtherAntivirusProducts)} erkannt. Bastion ergänzt den Schutz und scannt Dateien nicht doppelt."
            : null;

        foreach (var m in status.Modules)
        {
            var item = Modules.FirstOrDefault(x => x.Id == m.Id);
            if (item is null)
            {
                item = new ModuleItemViewModel(m.Id, SetModuleAsync);
                Modules.Add(item);
            }
            item.Update(m);
        }

        RecentEvents.Clear();
        foreach (var e in events.Where(e => e.Category != EventCategory.System || e.Severity > Severity.Info).Take(5))
            RecentEvents.Add(new EventItemViewModel(e, _session, _snackbar));

        if (status.CurrentScan is { Running: true } scan)
            OnScanProgress(scan);
    }

    private async Task SetModuleAsync(string id, bool enabled)
    {
        try
        {
            await _session.Backend.SetModuleEnabledAsync(id, enabled);
        }
        catch (Exception e)
        {
            _snackbar.Show("Fehler", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
        await RefreshAsync();
    }

    private void OnScanProgress(ScanProgress p)
    {
        ScanRunning = p.Running;
        ScanIndeterminate = p.Percent is null;
        ScanPercent = p.Percent ?? 0;
        ScanText = p.Running
            ? $"{(p.Percent is { } pct ? $"{pct:0} % · " : "")}{p.FilesScanned:N0} Dateien · {p.CurrentPath}"
            : p.Cancelled ? "Scan abgebrochen" : $"Fertig. {p.FilesScanned:N0} Dateien geprüft, {(p.Threats == 0 ? "nichts gefunden" : $"{p.Threats} Funde")}.";
    }

    [RelayCommand]
    private Task QuickScanAsync() => StartScanAsync(ScanKind.Quick);

    [RelayCommand]
    private Task FullScanAsync() => StartScanAsync(ScanKind.Full);

    private async Task StartScanAsync(ScanKind kind)
    {
        try
        {
            var progress = await _session.Backend.StartScanAsync(new ScanRequest(kind));
            OnScanProgress(progress);
        }
        catch (Exception e)
        {
            _snackbar.Show("Scan konnte nicht starten", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
    }

    [RelayCommand]
    private async Task CancelScanAsync() => await _session.Backend.CancelScanAsync();

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        IsUpdating = true;
        try
        {
            var result = await _session.Backend.UpdateSignaturesAsync();
            _snackbar.Show(result.Success ? "Signaturen aktualisiert" : "Update fehlgeschlagen", result.Message,
                result.Success ? ControlAppearance.Success : ControlAppearance.Caution, null, TimeSpan.FromSeconds(5));
        }
        catch (Exception e)
        {
            _snackbar.Show("Update fehlgeschlagen", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
        finally
        {
            IsUpdating = false;
        }
        await RefreshAsync();
    }
}
