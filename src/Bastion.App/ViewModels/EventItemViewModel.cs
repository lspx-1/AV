using System.Collections.ObjectModel;
using Bastion.App.Helpers;
using Bastion.App.Services;
using Bastion.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class EventItemViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;

    public EventItemViewModel(SecurityEvent e, BackendSession session, ISnackbarService snackbar)
    {
        _session = session;
        _snackbar = snackbar;
        Update(e);
    }

    public Guid Id { get; private set; }

    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string? _detail;
    [ObservableProperty] private string? _target;
    [ObservableProperty] private string _time = "";
    [ObservableProperty] private string _category = "";
    [ObservableProperty] private Severity _severity;
    [ObservableProperty] private string? _resolution;
    [ObservableProperty] private bool _busy;

    public DateTimeOffset Timestamp { get; private set; }
    public EventCategory CategoryValue { get; private set; }

    public ObservableCollection<EventActionViewModel> Actions { get; } = [];

    public bool HasActions => Actions.Count > 0;

    public string Meta => $"{Time} · {Category}";

    public void Update(SecurityEvent e)
    {
        Id = e.Id;
        Timestamp = e.Timestamp;
        CategoryValue = e.Category;
        Title = e.Title;
        Detail = e.Detail;
        Target = e.Target;
        Time = Format.Time(e.Timestamp);
        Category = Format.Category(e.Category);
        Severity = e.Severity;
        Resolution = e.Resolution;
        Actions.Clear();
        foreach (var a in e.Actions)
            Actions.Add(new EventActionViewModel(a, Format.Action(a), Format.IsPrimaryAction(a), ExecuteCommand));
        OnPropertyChanged(nameof(HasActions));
        OnPropertyChanged(nameof(Meta));
    }

    [RelayCommand]
    private async Task ExecuteAsync(string action)
    {
        Busy = true;
        try
        {
            var result = await _session.Backend.ExecuteEventActionAsync(Id, action);
            _snackbar.Show(result.Success ? "Erledigt" : "Nicht möglich", result.Message,
                result.Success ? ControlAppearance.Success : ControlAppearance.Caution, null, TimeSpan.FromSeconds(4));
            if (result.Success)
            {
                Resolution = result.Message;
                Actions.Clear();
                OnPropertyChanged(nameof(HasActions));
            }
        }
        catch (Exception ex)
        {
            _snackbar.Show("Fehler", ex.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
        finally
        {
            Busy = false;
        }
    }
}

public sealed record EventActionViewModel(string Action, string Label, bool IsPrimary, IAsyncRelayCommand<string> Command)
{
    public ControlAppearance Appearance => IsPrimary ? ControlAppearance.Primary : ControlAppearance.Secondary;
}
