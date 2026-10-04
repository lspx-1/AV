using System.Collections.ObjectModel;
using Bastion.App.Services;
using Bastion.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class HistoryViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;
    private readonly IContentDialogService _dialogs;
    private List<EventItemViewModel> _all = [];

    public HistoryViewModel(BackendSession session, ISnackbarService snackbar, IContentDialogService dialogs)
    {
        _dialogs = dialogs;
        _session = session;
        _snackbar = snackbar;
        _session.EventRaised += OnEvent;
    }

    public IReadOnlyList<string> Filters { get; } = ["Alle", "Offen", "Bedrohungen", "Netzwerk", "Autostart", "Scans", "System"];

    [ObservableProperty] private string _filter = "Alle";
    [ObservableProperty] private string _search = "";

    public ObservableCollection<EventItemViewModel> Events { get; } = [];

    [RelayCommand]
    private async Task ClearAsync()
    {
        try
        {
            var dialog = new ContentDialog
            {
                Title = "Verlauf löschen?",
                Content = "„Alles löschen“ entfernt jeden Eintrag. „Nur Erledigte“ lässt offene Funde stehen, über die du noch entscheiden musst.",
                PrimaryButtonText = "Alles löschen",
                SecondaryButtonText = "Nur Erledigte",
                CloseButtonText = "Abbrechen",
                DefaultButton = ContentDialogButton.Close,
            };
            var choice = await _dialogs.ShowAsync(dialog, CancellationToken.None);
            if (choice is not (ContentDialogResult.Primary or ContentDialogResult.Secondary))
                return;
            var removed = await _session.Backend.ClearHistoryAsync(includeOpen: choice == ContentDialogResult.Primary);
            _snackbar.Show("Verlauf gelöscht", $"{removed} Einträge entfernt.", ControlAppearance.Success, null, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            (System.Windows.Application.Current as App)?.LogError(ex);
            var hint = ex.Message.Contains("Unbekannte Methode", StringComparison.Ordinal)
                ? "Der installierte Bastion-Dienst ist älter als die App. Bitte mit dem neuen Installer aktualisieren."
                : ex.Message;
            _snackbar.Show("Verlauf konnte nicht gelöscht werden", hint, ControlAppearance.Danger, null, TimeSpan.FromSeconds(6));
            return;
        }
        await RefreshAsync();
    }

    partial void OnFilterChanged(string value) => Apply();
    partial void OnSearchChanged(string value) => Apply();

    public async Task RefreshAsync()
    {
        IReadOnlyList<SecurityEvent> events;
        try
        {
            events = await _session.Backend.GetEventsAsync(600);
        }
        catch (Exception)
        {
            return;
        }
        _all = events.Select(e => new EventItemViewModel(e, _session, _snackbar)).ToList();
        Apply();
    }

    private void OnEvent(SecurityEvent e)
    {
        var existing = _all.FirstOrDefault(x => x.Id == e.Id);
        if (existing is not null)
        {
            existing.Update(e);
            return;
        }
        _all.Insert(0, new EventItemViewModel(e, _session, _snackbar));
        Apply();
    }

    private void Apply()
    {
        IEnumerable<EventItemViewModel> q = Filter switch
        {
            "Offen" => _all.Where(e => e.HasActions),
            "Bedrohungen" => _all.Where(e => e.Severity >= Severity.Medium),
            "Netzwerk" => _all.Where(e => e.CategoryValue == EventCategory.Network),
            "Autostart" => _all.Where(e => e.CategoryValue is EventCategory.Autostart or EventCategory.Hosts),
            "Scans" => _all.Where(e => e.CategoryValue is EventCategory.Scan or EventCategory.Realtime or EventCategory.Process),
            "System" => _all.Where(e => e.CategoryValue is EventCategory.System or EventCategory.Update or EventCategory.License or EventCategory.Quarantine),
            _ => _all,
        };
        if (!string.IsNullOrWhiteSpace(Search))
            q = q.Where(e => e.Title.Contains(Search, StringComparison.OrdinalIgnoreCase)
                             || (e.Detail?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false)
                             || (e.Target?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false));
        Events.Clear();
        foreach (var e in q.Take(300))
            Events.Add(e);
    }
}
