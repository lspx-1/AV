using System.Collections.ObjectModel;
using Bastion.App.Services;
using Bastion.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class ScanViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;

    public ScanViewModel(BackendSession session, ISnackbarService snackbar)
    {
        _session = session;
        _snackbar = snackbar;
        _session.ScanProgressChanged += OnProgress;
    }

    [ObservableProperty] private bool _running;
    [ObservableProperty] private bool _indeterminate;
    [ObservableProperty] private double _percent;
    [ObservableProperty] private string _kindText = "";
    [ObservableProperty] private string? _currentPath;
    [ObservableProperty] private string _counterText = "";
    [ObservableProperty] private string? _resultText;

    public ObservableCollection<string> CustomPaths { get; } = [];
    public ObservableCollection<ScanFindingViewModel> Findings { get; } = [];

    private void OnProgress(ScanProgress p)
    {
        Running = p.Running;
        Indeterminate = p.Running && p.Percent is null;
        Percent = p.Percent ?? (p.Running ? 0 : 100);
        KindText = p.Kind switch { ScanKind.Quick => "Schnellscan", ScanKind.Full => "Vollständiger Scan", _ => "Benutzerdefinierter Scan" };
        CurrentPath = p.Running ? p.CurrentPath : null;
        CounterText = $"{p.FilesScanned:N0}{(p.FilesTotal is { } t ? $" von {t:N0}" : "")} Dateien · {p.Threats} Funde · {(DateTimeOffset.Now - p.StartedAt):mm\\:ss}";
        ResultText = p.Running ? null
            : p.Cancelled ? "Scan abgebrochen."
            : p.Threats == 0 ? $"Fertig. {p.FilesScanned:N0} Dateien geprüft, nichts gefunden."
            : $"Fertig. {p.Threats} Bedrohungen gefunden.";
        foreach (var f in p.Findings.Where(f => Findings.All(x => x.Path != f.Path)))
            Findings.Add(new ScanFindingViewModel(f, _session, _snackbar));
    }

    [RelayCommand]
    private Task QuickAsync() => StartAsync(new ScanRequest(ScanKind.Quick));

    [RelayCommand]
    private Task FullAsync() => StartAsync(new ScanRequest(ScanKind.Full));

    [RelayCommand]
    private Task CustomAsync()
    {
        if (CustomPaths.Count == 0)
        {
            _snackbar.Show("Keine Ordner gewählt", "Füge zuerst einen Ordner oder eine Datei hinzu.", ControlAppearance.Caution, null, TimeSpan.FromSeconds(4));
            return Task.CompletedTask;
        }
        return StartAsync(new ScanRequest(ScanKind.Custom, [.. CustomPaths]));
    }

    public Task ScanPathsAsync(IReadOnlyList<string> paths) => StartAsync(new ScanRequest(ScanKind.Custom, paths));

    private async Task StartAsync(ScanRequest request)
    {
        Findings.Clear();
        ResultText = null;
        try
        {
            OnProgress(await _session.Backend.StartScanAsync(request));
        }
        catch (Exception e)
        {
            _snackbar.Show("Scan konnte nicht starten", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
    }

    [RelayCommand]
    private async Task CancelAsync() => await _session.Backend.CancelScanAsync();

    [RelayCommand]
    private void AddFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Ordner für den Scan wählen", Multiselect = true };
        if (dialog.ShowDialog() == true)
            foreach (var f in dialog.FolderNames.Where(f => !CustomPaths.Contains(f)))
                CustomPaths.Add(f);
    }

    [RelayCommand]
    private void AddFile()
    {
        var dialog = new OpenFileDialog { Title = "Dateien für den Scan wählen", Multiselect = true };
        if (dialog.ShowDialog() == true)
            foreach (var f in dialog.FileNames.Where(f => !CustomPaths.Contains(f)))
                CustomPaths.Add(f);
    }

    [RelayCommand]
    private void RemovePath(string path) => CustomPaths.Remove(path);
}

public sealed partial class ScanFindingViewModel(FileScanSummary finding, BackendSession session, ISnackbarService snackbar) : ObservableObject
{
    public string Path { get; } = finding.Path;
    public string Name { get; } = finding.DetectionName;
    public string Reason { get; } = finding.Reason;
    public Severity Severity { get; } = finding.Severity;

    [ObservableProperty] private string? _resolution = finding.Quarantined ? "In Quarantäne verschoben" : null;

    public bool CanAct => Resolution is null && finding.EventId is not null;

    partial void OnResolutionChanged(string? value) => OnPropertyChanged(nameof(CanAct));

    [RelayCommand]
    private Task QuarantineAsync() => RunAsync(EventActions.Quarantine);

    [RelayCommand]
    private Task IgnoreAsync() => RunAsync(EventActions.Ignore);

    private async Task RunAsync(string action)
    {
        if (finding.EventId is not { } id)
            return;
        var result = await session.Backend.ExecuteEventActionAsync(id, action);
        if (result.Success)
            Resolution = result.Message;
        else
            snackbar.Show("Nicht möglich", result.Message, ControlAppearance.Caution, null, TimeSpan.FromSeconds(4));
    }
}
