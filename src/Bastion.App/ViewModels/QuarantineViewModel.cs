using System.Collections.ObjectModel;
using Bastion.App.Helpers;
using Bastion.App.Services;
using Bastion.Core.Quarantine;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class QuarantineViewModel(BackendSession session, ISnackbarService snackbar, IContentDialogService dialogs) : ObservableObject
{
    [ObservableProperty] private int _count;

    public ObservableCollection<QuarantineItemViewModel> Items { get; } = [];

    public async Task RefreshAsync()
    {
        IReadOnlyList<QuarantineItem> items;
        try
        {
            items = await session.Backend.GetQuarantineAsync();
        }
        catch (Exception)
        {
            return;
        }
        Items.Clear();
        foreach (var i in items)
            Items.Add(new QuarantineItemViewModel(i, this));
        Count = Items.Count;
    }

    internal async Task RestoreAsync(QuarantineItemViewModel item)
    {
        var dialog = new ContentDialog
        {
            Title = "Datei wiederherstellen?",
            Content = $"„{item.FileName}“ wurde als {item.Detection} erkannt. Stelle sie nur wieder her, wenn du sicher bist, dass sie harmlos ist.\n\nDie Datei wird künftig nicht mehr gemeldet.",
            PrimaryButtonText = "Wiederherstellen",
            CloseButtonText = "Abbrechen",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialogs.ShowAsync(dialog, CancellationToken.None) != ContentDialogResult.Primary)
            return;
        var result = await session.Backend.RestoreQuarantineAsync(item.Id, addExclusion: true);
        Report(result);
        await RefreshAsync();
    }

    internal async Task DeleteAsync(QuarantineItemViewModel item)
    {
        var result = await session.Backend.DeleteQuarantineAsync(item.Id);
        Report(result);
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task DeleteAllAsync()
    {
        if (Items.Count == 0)
            return;
        var dialog = new ContentDialog
        {
            Title = "Alle endgültig löschen?",
            Content = $"{Items.Count} Dateien werden unwiderruflich gelöscht.",
            PrimaryButtonText = "Alle löschen",
            CloseButtonText = "Abbrechen",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialogs.ShowAsync(dialog, CancellationToken.None) != ContentDialogResult.Primary)
            return;
        foreach (var item in Items.ToList())
            await session.Backend.DeleteQuarantineAsync(item.Id);
        snackbar.Show("Quarantäne geleert", "Alle Dateien wurden gelöscht.", ControlAppearance.Success, null, TimeSpan.FromSeconds(4));
        await RefreshAsync();
    }

    private void Report(Bastion.Core.Ipc.ActionResult result) =>
        snackbar.Show(result.Success ? "Erledigt" : "Nicht möglich", result.Message,
            result.Success ? ControlAppearance.Success : ControlAppearance.Caution, null, TimeSpan.FromSeconds(4));
}

public sealed partial class QuarantineItemViewModel(QuarantineItem item, QuarantineViewModel owner) : ObservableObject
{
    public Guid Id => item.Id;
    public string FileName => Path.GetFileName(item.OriginalPath);
    public string OriginalPath => item.OriginalPath;
    public string Detection => item.DetectionName;
    public string Reason => item.Reason;
    public string Meta => $"{Format.Time(item.QuarantinedAt)} · {Format.Size(item.Size)}{(item.PendingDeleteOnReboot ? " · wird beim Neustart entfernt" : "")}";

    [RelayCommand]
    private Task RestoreAsync() => owner.RestoreAsync(this);

    [RelayCommand]
    private Task DeleteAsync() => owner.DeleteAsync(this);
}
