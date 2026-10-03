using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using Bastion.Core.Licensing;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace Bastion.LicenseManager;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly KeyStore _keys = new();
    private readonly LicenseRegistry _registry = new();

    public MainViewModel()
    {
        RefreshKey();
        RefreshList();
    }

    // ------------------------------------------------------------ status line

    [ObservableProperty] private string? _message;
    [ObservableProperty] private bool _messageIsError;

    private void Ok(string text)
    {
        Message = text;
        MessageIsError = false;
    }

    private void Error(string text)
    {
        Message = text;
        MessageIsError = true;
    }

    // ------------------------------------------------------------ key

    [ObservableProperty] private bool _hasKey;
    [ObservableProperty] private string? _fingerprint;
    [ObservableProperty] private string? _publicPem;
    [ObservableProperty] private int _selectedTab;

    public string KeyFolder => KeyStore.Folder;

    private void RefreshKey()
    {
        HasKey = _keys.HasKey;
        Fingerprint = _keys.Fingerprint;
        PublicPem = _keys.PublicPem;
        IssueCommand.NotifyCanExecuteChanged();
        if (!HasKey)
            SelectedTab = 2;
    }

    [RelayCommand]
    private void CreateKey()
    {
        if (_keys.HasKey && MessageBox.Show(
                "Es gibt schon einen Schlüssel. Ein neuer Schlüssel macht ALLE bisher ausgestellten Lizenzen ungültig.\n\nWirklich einen neuen erstellen?",
                "Neuen Schlüssel erstellen", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        _keys.CreateNew();
        RefreshKey();
        Ok("Neuer Schlüssel erstellt. Sichere ihn jetzt mit „Sicherung exportieren“ und installiere ihn danach in Bastion.");
    }

    [RelayCommand]
    private void ImportKey()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Privaten Schlüssel importieren (license-private.pem)",
            Filter = "PEM-Schlüssel (*.pem)|*.pem|Alle Dateien (*.*)|*.*",
        };
        if (dialog.ShowDialog() != true)
            return;
        try
        {
            _keys.ImportPrivatePem(File.ReadAllText(dialog.FileName));
            RefreshKey();
            Ok("Schlüssel importiert. Lizenzen, die mit diesem Schlüssel erstellt wurden, bleiben gültig.");
        }
        catch (Exception e) when (e is InvalidDataException or IOException)
        {
            Error(e.Message);
        }
    }

    [RelayCommand]
    private void ExportBackup()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Privaten Schlüssel sichern",
            FileName = "license-private.pem",
            Filter = "PEM-Schlüssel (*.pem)|*.pem",
        };
        if (dialog.ShowDialog() != true)
            return;
        try
        {
            _keys.ExportPrivatePem(dialog.FileName);
            Ok("Gesichert. Bewahre die Datei offline auf (USB-Stick, Passwort-Manager) und gib sie niemandem.");
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            Error(e.Message);
        }
    }

    [RelayCommand]
    private void CopyPublicKey()
    {
        if (PublicPem is null)
            return;
        Clipboard.SetText(PublicPem);
        Ok("Öffentlicher Schlüssel kopiert.");
    }

    /// <summary>Runs setup-licensing.ps1 with admin rights to put the public key into C:\Program Files\Bastion.</summary>
    [RelayCommand]
    private void InstallIntoBastion()
    {
        if (!_keys.HasKey)
        {
            Error("Erstelle oder importiere zuerst einen Schlüssel.");
            return;
        }
        var script = Path.Combine(AppContext.BaseDirectory, "setup-licensing.ps1");
        if (!File.Exists(script))
        {
            Error($"setup-licensing.ps1 fehlt neben dem Programm ({AppContext.BaseDirectory}).");
            return;
        }
        try
        {
            using var process = Process.Start(new ProcessStartInfo("powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -NoExit -File \"{script}\" -PublicKey \"{KeyStore.PublicFile}\"")
            {
                UseShellExecute = true,
                Verb = "runas", // asks for admin rights
            });
            Ok("Ein Administrator-Fenster installiert den Schlüssel in Bastion. Danach kannst du es schließen.");
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Error("Abgebrochen. Für die Installation in Bastion werden Administratorrechte gebraucht.");
        }
    }

    // ------------------------------------------------------------ issue

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(IssueCommand))]
    private string _licensee = "";

    [ObservableProperty] private string _email = "";
    [ObservableProperty] private double _seats = 3;
    [ObservableProperty] private bool _unlimited = true;
    [ObservableProperty] private double _days = 365;
    [ObservableProperty] private string _deviceId = "";
    [ObservableProperty] private string _note = "";
    [ObservableProperty] private string? _lastKey;
    [ObservableProperty] private string? _lastFile;

    private bool CanIssue() => HasKey && !string.IsNullOrWhiteSpace(Licensee);

    [RelayCommand(CanExecute = nameof(CanIssue))]
    private void Issue()
    {
        var device = DeviceId.Trim().ToLowerInvariant();
        if (device.Length > 0 && (device.Length != 16 || !device.All(Uri.IsHexDigit)))
        {
            Error("Die Geräte-ID hat 16 Zeichen (0-9, a-f). Du findest sie in Bastion unten auf der Lizenz-Seite. Leer lassen für beliebige Geräte.");
            return;
        }
        var document = new LicenseDocument
        {
            LicenseId = Guid.NewGuid().ToString("N"),
            Key = LicenseKey.Generate(),
            Plan = LicensePlan.Pro,
            Licensee = Licensee.Trim(),
            Email = string.IsNullOrWhiteSpace(Email) ? null : Email.Trim(),
            Seats = Math.Max(1, (int)Seats),
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = Unlimited ? null : DateTimeOffset.UtcNow.AddDays(Math.Max(1, (int)Days)),
            DeviceId = device.Length > 0 ? device : null,
            Features = LicenseFeatures.Pro,
        };
        var license = new IssuedLicense { Document = document, Token = _keys.Sign(document), Note = string.IsNullOrWhiteSpace(Note) ? null : Note.Trim() };
        _registry.Add(license);
        RefreshList();

        LastKey = document.Key;
        LastFile = SaveLicenseFile(license);
        if (LastFile is not null)
            Ok($"Lizenz für {document.Licensee} erstellt und gespeichert.");
        else
            Ok($"Lizenz für {document.Licensee} erstellt. Du kannst die Datei jederzeit unter „Ausgestellt“ speichern.");
        Licensee = "";
        Email = "";
        DeviceId = "";
        Note = "";
    }

    private static string? SaveLicenseFile(IssuedLicense license)
    {
        var name = string.Concat(license.Document.Licensee.Split(Path.GetInvalidFileNameChars())).Replace(' ', '_');
        var dialog = new SaveFileDialog
        {
            Title = "Lizenzdatei speichern",
            FileName = $"{name}_{license.Document.Key}.bastionlic",
            Filter = "Bastion-Lizenz (*.bastionlic)|*.bastionlic",
        };
        if (dialog.ShowDialog() != true)
            return null;
        File.WriteAllText(dialog.FileName, license.Token);
        return dialog.FileName;
    }

    [RelayCommand]
    private void CopyLastKey()
    {
        if (LastKey is null)
            return;
        Clipboard.SetText(LastKey);
        Ok("Lizenzschlüssel kopiert.");
    }

    [RelayCommand]
    private void OpenLastFolder()
    {
        if (LastFile is not null)
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{LastFile}\"") { UseShellExecute = true });
    }

    // ------------------------------------------------------------ list

    [ObservableProperty] private string _search = "";

    public ObservableCollection<IssuedLicenseViewModel> Licenses { get; } = [];

    partial void OnSearchChanged(string value) => RefreshList();

    private void RefreshList()
    {
        Licenses.Clear();
        foreach (var l in _registry.Items.Where(l => string.IsNullOrWhiteSpace(Search)
                     || l.Document.Licensee.Contains(Search, StringComparison.OrdinalIgnoreCase)
                     || (l.Document.Email?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false)
                     || l.Document.Key.Contains(Search, StringComparison.OrdinalIgnoreCase)
                     || (l.Note?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false)))
        {
            Licenses.Add(new IssuedLicenseViewModel(l, this));
        }
        OnPropertyChanged(nameof(LicenseCount));
    }

    public int LicenseCount => _registry.Items.Count;

    internal void SaveFile(IssuedLicense license)
    {
        var path = SaveLicenseFile(license);
        if (path is not null)
            Ok($"Gespeichert: {path}");
    }

    internal void CopyKey(IssuedLicense license)
    {
        Clipboard.SetText(license.Document.Key);
        Ok("Lizenzschlüssel kopiert.");
    }

    internal void Delete(IssuedLicense license)
    {
        if (MessageBox.Show($"Lizenz von {license.Document.Licensee} aus der Liste entfernen?\n\nAchtung: Bereits verteilte Lizenzdateien bleiben gültig, solange es keinen Lizenzserver gibt.",
                "Aus Liste entfernen", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        _registry.Remove(license);
        RefreshList();
    }

    internal void Renew(IssuedLicense license)
    {
        // Same key and customer, one more year from today (or from the old expiry if still running).
        var start = license.Document.ExpiresAt is { } exp && exp > DateTimeOffset.UtcNow ? exp : DateTimeOffset.UtcNow;
        var document = license.Document with { LicenseId = Guid.NewGuid().ToString("N"), IssuedAt = DateTimeOffset.UtcNow, ExpiresAt = start.AddDays(365) };
        var renewed = new IssuedLicense { Document = document, Token = _keys.Sign(document), Note = license.Note };
        _registry.Add(renewed);
        RefreshList();
        SaveFile(renewed);
    }
}

public sealed class IssuedLicenseViewModel(IssuedLicense license, MainViewModel owner)
{
    public string Licensee => license.Document.Licensee;
    public string Key => license.Document.Key;
    public string Details =>
        string.Join(" · ", new[]
        {
            license.Document.Email,
            $"{license.Document.Seats} Geräte",
            license.Document.ExpiresAt is { } e ? $"bis {e.ToLocalTime():dd.MM.yyyy}" : "unbegrenzt",
            license.Document.DeviceId is { } d ? $"Gerät {d}" : null,
            $"erstellt {license.Document.IssuedAt.ToLocalTime():dd.MM.yyyy}",
        }.Where(s => !string.IsNullOrEmpty(s)));
    public string? Note => license.Note;
    public bool Expired => license.Document.ExpiresAt is { } e && e < DateTimeOffset.UtcNow;
    public bool HasExpiry => license.Document.ExpiresAt is not null;

    public IRelayCommand SaveCommand { get; } = new RelayCommand(() => owner.SaveFile(license));
    public IRelayCommand CopyCommand { get; } = new RelayCommand(() => owner.CopyKey(license));
    public IRelayCommand RenewCommand { get; } = new RelayCommand(() => owner.Renew(license));
    public IRelayCommand DeleteCommand { get; } = new RelayCommand(() => owner.Delete(license));
}
