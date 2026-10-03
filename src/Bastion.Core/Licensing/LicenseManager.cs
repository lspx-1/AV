using System.Security.Cryptography;
using Bastion.Core.Runtime;

namespace Bastion.Core.Licensing;

/// <summary>
/// Keeps track of the license on this device. Works offline with signed license files and,
/// when a license server URL is configured, with online activation, validation and deactivation.
/// </summary>
public sealed class LicenseManager
{
    /// <summary>How long an online-activated license keeps working without reaching the server.</summary>
    public static readonly TimeSpan OfflineGrace = TimeSpan.FromDays(30);

    /// <summary>How often an online-activated license is re-validated.</summary>
    public static readonly TimeSpan RevalidateEvery = TimeSpan.FromDays(1);

    private readonly string _file;
    private readonly ECDsa? _publicKey;
    private readonly Func<ILicenseServerClient?> _server;
    private readonly string _deviceId;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private StoredLicense _stored;

    public LicenseManager(string file, ECDsa? publicKey, Func<ILicenseServerClient?> server, string? deviceId = null)
    {
        _file = file;
        _publicKey = publicKey;
        _server = server;
        _deviceId = deviceId ?? DeviceId.Current;
        _stored = JsonStore.LoadOrDefault<StoredLicense>(file);
    }

    public event Action<LicenseStatus>? Changed;

    public LicenseStatus Status => Evaluate(null);

    public bool HasFeature(string feature) => Status is { IsPro: true } s && s.Features.Contains(feature);

    /// <summary>Activates a key online. Without a server, tells the user to import a license file instead.</summary>
    public async Task<LicenseOperationResult> ActivateAsync(string key, CancellationToken ct = default)
    {
        var normalized = LicenseKey.Normalize(key);
        if (normalized is null)
            return Fail("Der Schlüssel ist ungültig. Er beginnt mit BSTN und hat 5 Blöcke mit je 4 Zeichen. Prüfe ihn auf Tippfehler.");
        var server = _server();
        if (server is null)
            return Fail("Es ist kein Lizenzserver eingerichtet. Importiere stattdessen die Lizenzdatei (.bastionlic), die du erhalten hast.");

        await _gate.WaitAsync(ct);
        try
        {
            ServerLicenseResponse response;
            try
            {
                response = await server.ActivateAsync(normalized, _deviceId, DeviceId.Name, ct);
            }
            catch (LicenseServerException e)
            {
                return Fail(e.Message + " Prüfe deine Internetverbindung und versuche es erneut.");
            }
            if (!response.Ok || response.Token is null)
                return Fail(response.Message ?? "Der Server hat die Aktivierung abgelehnt.");
            return Store(response.Token, online: true, "Lizenz aktiviert. Pro-Funktionen sind freigeschaltet.");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Imports a signed license token (content of a .bastionlic file). Works fully offline.</summary>
    public LicenseOperationResult ImportToken(string token)
    {
        _gate.Wait();
        try
        {
            return Store(token.Trim(), online: false, "Lizenzdatei importiert. Pro-Funktionen sind freigeschaltet.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<LicenseOperationResult> DeactivateAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var doc = Current();
            var message = "Lizenz auf diesem Gerät entfernt.";
            if (doc is not null && _stored.Online && _server() is { } server)
            {
                try
                {
                    var response = await server.DeactivateAsync(doc.Key, _deviceId, ct);
                    message = response.Ok ? "Lizenz auf diesem Gerät deaktiviert. Der Gerätplatz ist wieder frei." : response.Message ?? message;
                }
                catch (LicenseServerException)
                {
                    message = "Lizenz lokal entfernt. Der Server war nicht erreichbar, der Gerätplatz wird dort erst später frei.";
                }
            }
            _stored = new StoredLicense();
            if (File.Exists(_file))
                File.Delete(_file);
            var status = Evaluate(message);
            Changed?.Invoke(status);
            return new LicenseOperationResult(true, message, status);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Re-validates an online license if it is due (or <paramref name="force"/>).</summary>
    public async Task<LicenseOperationResult> RefreshAsync(bool force = false, CancellationToken ct = default)
    {
        var doc = Current();
        if (doc is null || !_stored.Online)
            return new LicenseOperationResult(true, "Lizenzstatus ist aktuell.", Status);
        if (!force && _stored.LastValidated is { } last && DateTimeOffset.Now - last < RevalidateEvery)
            return new LicenseOperationResult(true, "Lizenzstatus ist aktuell.", Status);
        var server = _server();
        if (server is null)
            return new LicenseOperationResult(true, "Kein Lizenzserver eingerichtet.", Status);

        await _gate.WaitAsync(ct);
        try
        {
            ServerLicenseResponse response;
            try
            {
                response = await server.ValidateAsync(doc.Key, _deviceId, ct);
            }
            catch (LicenseServerException e)
            {
                return new LicenseOperationResult(false, e.Message + " Die Lizenz bleibt bis zu 30 Tage offline gültig.", Status);
            }
            if (response.Status is "revoked" or "unknown" or "deactivated")
            {
                _stored = _stored with { Revoked = true, LastValidated = DateTimeOffset.Now };
                JsonStore.Save(_file, _stored);
                var revoked = Evaluate(response.Message ?? "Die Lizenz wurde vom Server widerrufen.");
                Changed?.Invoke(revoked);
                return new LicenseOperationResult(false, revoked.Message!, revoked);
            }
            if (response.Ok && response.Token is not null)
                return Store(response.Token, online: true, "Lizenzstatus ist aktuell.");
            _stored = _stored with { LastValidated = DateTimeOffset.Now };
            JsonStore.Save(_file, _stored);
            return new LicenseOperationResult(true, "Lizenzstatus ist aktuell.", Status);
        }
        finally
        {
            _gate.Release();
        }
    }

    private LicenseOperationResult Store(string token, bool online, string successMessage)
    {
        if (_publicKey is null)
            return Fail("Bastion hat noch keinen Lizenz-Prüfschlüssel. Installiere ihn mit dem Bastion License Manager („In Bastion installieren“) oder mit scripts\\setup-licensing.ps1.");
        if (!LicenseCodec.TryVerify(token, _publicKey, out var doc) || doc is null)
            return Fail("Die Lizenz ist beschädigt oder nicht echt (Signatur stimmt nicht).");
        if (doc.DeviceId is not null && doc.DeviceId != _deviceId)
            return Fail("Diese Lizenz gehört zu einem anderen Gerät.");
        if (doc.ExpiresAt is { } exp && exp < DateTimeOffset.Now)
            return Fail($"Diese Lizenz ist am {exp:dd.MM.yyyy} abgelaufen.");

        _stored = new StoredLicense { Token = token, Online = online, LastValidated = DateTimeOffset.Now };
        JsonStore.Save(_file, _stored);
        var status = Evaluate(successMessage);
        Changed?.Invoke(status);
        return new LicenseOperationResult(true, successMessage, status);
    }

    private LicenseDocument? Current()
    {
        if (_stored.Token is null || _publicKey is null)
            return null;
        return LicenseCodec.TryVerify(_stored.Token, _publicKey, out var doc) ? doc : null;
    }

    private LicenseStatus Evaluate(string? message)
    {
        var baseStatus = new LicenseStatus
        {
            State = LicenseState.Free,
            Plan = LicensePlan.Free,
            DeviceId = _deviceId,
            DeviceName = DeviceId.Name,
            ServerConfigured = _server() is not null,
            PublicKeyConfigured = _publicKey is not null,
            Message = message,
        };
        if (_stored.Token is null)
            return baseStatus;

        var doc = Current();
        if (doc is null)
            return baseStatus with { State = LicenseState.Invalid, Message = message ?? "Die gespeicherte Lizenz ist ungültig." };

        var status = baseStatus with
        {
            Plan = doc.Plan,
            Licensee = doc.Licensee,
            MaskedKey = LicenseKey.Mask(doc.Key),
            ExpiresAt = doc.ExpiresAt,
            Seats = doc.Seats,
            ActivatedSeats = doc.ActivatedSeats,
            LastValidated = _stored.LastValidated,
            OnlineActivation = _stored.Online,
            Features = doc.Features.Count > 0 ? doc.Features : doc.Plan == LicensePlan.Pro ? LicenseFeatures.Pro : [],
        };

        if (_stored.Revoked)
            return status with { State = LicenseState.Revoked, Message = message ?? "Die Lizenz wurde widerrufen." };
        if (doc.DeviceId is not null && doc.DeviceId != _deviceId)
            return status with { State = LicenseState.WrongDevice, Message = message ?? "Die Lizenz gehört zu einem anderen Gerät." };
        if (doc.ExpiresAt is { } exp && exp < DateTimeOffset.Now)
            return status with { State = LicenseState.Expired, Message = message ?? $"Die Lizenz ist am {exp:dd.MM.yyyy} abgelaufen." };
        if (_stored.Online && _stored.LastValidated is { } last && DateTimeOffset.Now - last > OfflineGrace)
            return status with { State = LicenseState.Expired, Message = message ?? "Die Lizenz konnte seit 30 Tagen nicht online bestätigt werden. Verbinde das Gerät mit dem Internet." };
        return status with { State = LicenseState.Active };
    }

    private LicenseOperationResult Fail(string message) => new(false, message, Evaluate(message));

    private sealed record StoredLicense
    {
        public string? Token { get; init; }
        public bool Online { get; init; }
        public bool Revoked { get; init; }
        public DateTimeOffset? LastValidated { get; init; }
    }
}
