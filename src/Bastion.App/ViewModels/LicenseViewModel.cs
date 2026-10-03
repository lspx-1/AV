using Bastion.App.Services;
using Bastion.Core.Licensing;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class LicenseViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly IContentDialogService _dialogs;

    public LicenseViewModel(BackendSession session, IContentDialogService dialogs)
    {
        _session = session;
        _dialogs = dialogs;
        _session.LicenseChanged += Apply;
    }

    [ObservableProperty] private bool _isPro;
    [ObservableProperty] private string _planBadge = "FREE";
    [ObservableProperty] private string _planTitle = "Bastion Free";
    [ObservableProperty] private string _planSubtitle = "";
    [ObservableProperty] private string? _licensee;
    [ObservableProperty] private string? _maskedKey;
    [ObservableProperty] private string? _validUntil;
    [ObservableProperty] private string? _seatsText;
    [ObservableProperty] private string _deviceText = "";
    [ObservableProperty] private string? _lastCheck;
    [ObservableProperty] private bool _hasLicense;
    [ObservableProperty] private string _keyInput = "";
    [ObservableProperty] private string? _message;
    [ObservableProperty] private bool _messageIsError;
    [ObservableProperty] private bool _busy;
    [ObservableProperty] private bool _serverConfigured;
    [ObservableProperty] private bool _publicKeyMissing;
    [ObservableProperty] private string _keyLabel = "Lizenzschlüssel eingeben";

    public async Task RefreshAsync()
    {
        try
        {
            Apply(await _session.Backend.GetLicenseAsync());
        }
        catch (Exception)
        {
        }
    }

    private void Apply(LicenseStatus s)
    {
        IsPro = s.IsPro;
        HasLicense = s.State != LicenseState.Free;
        ServerConfigured = s.ServerConfigured;
        PublicKeyMissing = !s.PublicKeyConfigured;
        PlanBadge = s.IsPro ? "PRO" : "FREE";
        PlanTitle = s.IsPro ? "Bastion Pro" : "Bastion Free";
        PlanSubtitle = s.State switch
        {
            LicenseState.Active => s.ExpiresAt is { } e ? $"Aktiv bis {e.ToLocalTime():dd.MM.yyyy} · Danke für deine Unterstützung." : "Unbegrenzt gültig · Danke für deine Unterstützung.",
            LicenseState.Expired => s.Message ?? "Die Lizenz ist abgelaufen.",
            LicenseState.Revoked => s.Message ?? "Die Lizenz wurde widerrufen.",
            LicenseState.WrongDevice => "Die Lizenz gehört zu einem anderen Gerät.",
            LicenseState.Invalid => "Die gespeicherte Lizenz ist ungültig.",
            _ => "Voller Schutz. Pro schaltet Komfortfunktionen frei und unterstützt das Projekt.",
        };
        Licensee = s.Licensee;
        MaskedKey = s.MaskedKey;
        ValidUntil = s.ExpiresAt is { } exp ? $"{exp.ToLocalTime():dd.MM.yyyy} ({Math.Max(0, (int)(exp - DateTimeOffset.Now).TotalDays)} Tage)" : HasLicense ? "unbegrenzt" : null;
        SeatsText = HasLicense ? s.ActivatedSeats is { } used ? $"{used} von {s.Seats} aktiviert" : $"bis zu {s.Seats}" : null;
        DeviceText = $"{s.DeviceName} · {s.DeviceId}";
        LastCheck = s.LastValidated is { } v ? $"{Helpers.Format.Time(v)}{(s.OnlineActivation ? " · online bestätigt" : " · Lizenzdatei")}" : null;
        KeyLabel = HasLicense ? "Anderen Schlüssel eingeben" : "Lizenzschlüssel eingeben";
    }

    private void Show(LicenseOperationResult result)
    {
        Message = result.Message;
        MessageIsError = !result.Success;
        Apply(result.Status);
    }

    private void ShowError(Exception e)
    {
        Message = e is IOException ? "Die Datei konnte nicht gelesen werden: " + e.Message : e.Message;
        MessageIsError = true;
    }

    partial void OnKeyInputChanged(string value)
    {
        // Format as BSTN-XXXX-XXXX-XXXX-XXXX while typing.
        var raw = new string(value.ToUpperInvariant().Where(char.IsLetterOrDigit).Take(20).ToArray());
        var formatted = string.Join("-", Enumerable.Range(0, (raw.Length + 3) / 4).Select(i => raw.Substring(i * 4, Math.Min(4, raw.Length - i * 4))));
        if (formatted != value)
            KeyInput = formatted;
    }

    [RelayCommand]
    private async Task ActivateAsync()
    {
        Busy = true;
        try
        {
            var result = await _session.Backend.ActivateLicenseAsync(KeyInput);
            Show(result);
            if (result.Success)
                KeyInput = "";
        }
        catch (Exception e)
        {
            ShowError(e);
        }
        finally
        {
            Busy = false;
        }
    }

    [RelayCommand]
    private async Task ImportFileAsync()
    {
        var dialog = new OpenFileDialog { Title = "Lizenzdatei öffnen", Filter = "Bastion-Lizenz (*.bastionlic)|*.bastionlic|Alle Dateien (*.*)|*.*" };
        if (dialog.ShowDialog() != true)
            return;
        Busy = true;
        try
        {
            Show(await _session.Backend.ImportLicenseAsync(await File.ReadAllTextAsync(dialog.FileName)));
        }
        catch (Exception e)
        {
            ShowError(e);
        }
        finally
        {
            Busy = false;
        }
    }

    [RelayCommand]
    private async Task DeactivateAsync()
    {
        var dialog = new ContentDialog
        {
            Title = "Lizenz auf diesem Gerät deaktivieren?",
            Content = "Pro-Funktionen werden auf diesem PC abgeschaltet. Der Gerätplatz wird frei, sodass du die Lizenz auf einem anderen PC nutzen kannst. Der Virenschutz bleibt vollständig aktiv.",
            PrimaryButtonText = "Deaktivieren",
            CloseButtonText = "Abbrechen",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await _dialogs.ShowAsync(dialog, CancellationToken.None) != ContentDialogResult.Primary)
            return;
        Busy = true;
        try
        {
            Show(await _session.Backend.DeactivateLicenseAsync());
        }
        catch (Exception e)
        {
            ShowError(e);
        }
        finally
        {
            Busy = false;
        }
    }

    [RelayCommand]
    private async Task CheckAsync()
    {
        Busy = true;
        try
        {
            Show(await _session.Backend.RefreshLicenseAsync());
        }
        catch (Exception e)
        {
            ShowError(e);
        }
        finally
        {
            Busy = false;
        }
    }
}
