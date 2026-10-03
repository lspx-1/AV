using Bastion.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Bastion.App.ViewModels;

public sealed partial class ModuleItemViewModel(string id, Func<string, bool, Task> setEnabled) : ObservableObject
{
    private bool _suppress;

    public string Id { get; } = id;

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private string? _detail;
    [ObservableProperty] private bool _enabled;
    [ObservableProperty] private bool _running;

    public bool IsOff => !Enabled;

    public void Update(ModuleStatus status)
    {
        _suppress = true;
        Name = status.Name;
        Description = status.Description;
        Detail = status.Enabled ? status.Detail : "Ausgeschaltet";
        Enabled = status.Enabled;
        Running = status.Running;
        _suppress = false;
        OnPropertyChanged(nameof(IsOff));
    }

    partial void OnEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(IsOff));
        if (_suppress)
            return;
        Detail = value ? "Wird gestartet…" : "Ausgeschaltet";
        _ = setEnabled(Id, value);
    }
}
