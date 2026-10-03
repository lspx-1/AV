using System.Collections.ObjectModel;
using Bastion.App.Services;
using Bastion.Core.Models;
using Bastion.Core.Runtime;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;
    private readonly UiSettings _ui;
    private BastionSettings? _settings;
    private bool _loading;

    public SettingsViewModel(BackendSession session, ISnackbarService snackbar, UiSettings ui)
    {
        _session = session;
        _snackbar = snackbar;
        _ui = ui;
    }

    public IReadOnlyList<string> Themes { get; } = ["System", "Hell", "Dunkel"];
    public IReadOnlyList<string> Backdrops { get; } = ["Glas (Acrylic)", "Mica", "Keiner"];
    public IReadOnlyList<string> Sensitivities { get; } = ["Niedrig", "Mittel", "Hoch"];
    public IReadOnlyList<string> ComplementaryModes { get; } = ["Automatisch", "Immer ergänzen", "Nie (voller Scan)"];

    [ObservableProperty] private int _themeIndex;
    [ObservableProperty] private int _backdropIndex;
    [ObservableProperty] private int _sensitivityIndex = 1;
    [ObservableProperty] private int _complementaryIndex;
    [ObservableProperty] private bool _autoQuarantineSignatures;
    [ObservableProperty] private bool _autoQuarantineHeuristics;
    [ObservableProperty] private bool _killMaliciousProcesses;
    [ObservableProperty] private bool _ransomwareEmergencyStop;
    [ObservableProperty] private bool _autoUpdateSignatures;
    [ObservableProperty] private bool _scheduledScanEnabled;
    [ObservableProperty] private int _scheduledScanHour = 12;
    [ObservableProperty] private bool _isPro;
    [ObservableProperty] private string _licenseServerUrl = "";
    [ObservableProperty] private bool _startWithWindows;
    [ObservableProperty] private bool _explorerContextMenu;
    [ObservableProperty] private bool _showNotifications;
    [ObservableProperty] private bool _closeToTray;
    [ObservableProperty] private string _serviceState = "";
    [ObservableProperty] private string _modeText = "";
    [ObservableProperty] private string _dataFolder = "";
    [ObservableProperty] private bool _dirty;

    public string Version => AppInfo.Version;
    public IReadOnlyList<int> Hours { get; } = Enumerable.Range(0, 24).ToList();
    public ObservableCollection<string> Exclusions { get; } = [];

    public async Task RefreshAsync()
    {
        _loading = true;
        try
        {
            _settings = await _session.Backend.GetSettingsAsync();
            IsPro = (await _session.Backend.GetLicenseAsync()).IsPro;
        }
        catch (Exception)
        {
            _loading = false;
            return;
        }
        ThemeIndex = (int)_ui.Theme;
        BackdropIndex = (int)_ui.Backdrop;
        ShowNotifications = _ui.ShowNotifications;
        CloseToTray = _ui.CloseToTray;
        SensitivityIndex = (int)_settings.HeuristicSensitivity;
        ComplementaryIndex = (int)_settings.ComplementaryMode;
        AutoQuarantineSignatures = _settings.AutoQuarantineSignatures;
        AutoQuarantineHeuristics = _settings.AutoQuarantineHeuristics;
        KillMaliciousProcesses = _settings.KillMaliciousProcesses;
        RansomwareEmergencyStop = _settings.RansomwareEmergencyStop;
        AutoUpdateSignatures = _settings.AutoUpdateSignatures;
        ScheduledScanEnabled = _settings.ScheduledScanEnabled;
        ScheduledScanHour = _settings.ScheduledScanHour;
        LicenseServerUrl = _settings.LicenseServerUrl;
        Exclusions.Clear();
        foreach (var e in _settings.ExcludedPaths)
            Exclusions.Add(e);
        StartWithWindows = WindowsIntegration.StartWithWindows;
        ExplorerContextMenu = WindowsIntegration.ExplorerContextMenu;
        ServiceState = WindowsIntegration.ServiceState();
        ModeText = _session.ModeText;
        DataFolder = _session.IsServiceMode
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bastion")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bastion");
        Dirty = false;
        _loading = false;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loading || e.PropertyName is nameof(Dirty) or nameof(ServiceState) or nameof(ModeText) or nameof(DataFolder) or nameof(IsPro))
            return;
        switch (e.PropertyName)
        {
            // UI-only preferences apply immediately.
            case nameof(ThemeIndex):
                _ui.Theme = (ThemeChoice)ThemeIndex;
                _ui.Save();
                App.ApplyTheme(_ui);
                return;
            case nameof(BackdropIndex):
                _ui.Backdrop = (BackdropChoice)BackdropIndex;
                _ui.Save();
                App.ApplyTheme(_ui);
                return;
            case nameof(ShowNotifications):
                _ui.ShowNotifications = ShowNotifications;
                _ui.Save();
                return;
            case nameof(CloseToTray):
                _ui.CloseToTray = CloseToTray;
                _ui.Save();
                return;
            case nameof(StartWithWindows):
                WindowsIntegration.StartWithWindows = StartWithWindows;
                return;
            case nameof(ExplorerContextMenu):
                WindowsIntegration.ExplorerContextMenu = ExplorerContextMenu;
                return;
        }
        Dirty = true;
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (_settings is null)
            return;
        _settings.HeuristicSensitivity = (Sensitivity)SensitivityIndex;
        _settings.ComplementaryMode = (ComplementaryMode)ComplementaryIndex;
        _settings.AutoQuarantineSignatures = AutoQuarantineSignatures;
        _settings.AutoQuarantineHeuristics = AutoQuarantineHeuristics;
        _settings.KillMaliciousProcesses = KillMaliciousProcesses;
        _settings.RansomwareEmergencyStop = RansomwareEmergencyStop;
        _settings.AutoUpdateSignatures = AutoUpdateSignatures;
        _settings.ScheduledScanEnabled = ScheduledScanEnabled && IsPro;
        _settings.ScheduledScanHour = ScheduledScanHour;
        _settings.LicenseServerUrl = LicenseServerUrl.Trim();
        _settings.ExcludedPaths = [.. Exclusions];
        try
        {
            await _session.Backend.SaveSettingsAsync(_settings);
            Dirty = false;
            _snackbar.Show("Gespeichert", "Die Einstellungen sind aktiv.", ControlAppearance.Success, null, TimeSpan.FromSeconds(3));
        }
        catch (Exception e)
        {
            _snackbar.Show("Speichern fehlgeschlagen", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
    }

    [RelayCommand]
    private void AddExclusionFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Ordner als Ausnahme wählen" };
        if (dialog.ShowDialog() == true && !Exclusions.Contains(dialog.FolderName))
        {
            Exclusions.Add(dialog.FolderName);
            Dirty = true;
        }
    }

    [RelayCommand]
    private void AddExclusionFile()
    {
        var dialog = new OpenFileDialog { Title = "Datei als Ausnahme wählen" };
        if (dialog.ShowDialog() == true && !Exclusions.Contains(dialog.FileName))
        {
            Exclusions.Add(dialog.FileName);
            Dirty = true;
        }
    }

    [RelayCommand]
    private void RemoveExclusion(string path)
    {
        Exclusions.Remove(path);
        Dirty = true;
    }

    [RelayCommand]
    private void OpenDataFolder() => WindowsIntegration.OpenFolder(DataFolder);
}
