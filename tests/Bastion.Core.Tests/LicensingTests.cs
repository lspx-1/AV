using Bastion.Core.Licensing;

namespace Bastion.Core.Tests;

public class LicensingTests
{
    [Fact]
    public void GeneratedKeysAreValidAndFormatted()
    {
        for (var i = 0; i < 100; i++)
        {
            var key = LicenseKey.Generate();
            Assert.Matches("^BSTN(-[0-9A-Z]{4}){4}$", key);
            Assert.Equal(key, LicenseKey.Normalize(key));
        }
    }

    [Fact]
    public void NormalizeAcceptsSloppyInputAndRejectsTypos()
    {
        var key = LicenseKey.Generate();
        Assert.Equal(key, LicenseKey.Normalize(key.ToLowerInvariant().Replace("-", " ")));

        var chars = key.ToCharArray();
        var last = chars.Length - 2;
        chars[last] = chars[last] == '7' ? '8' : '7';
        Assert.Null(LicenseKey.Normalize(new string(chars)));
        Assert.Null(LicenseKey.Normalize("BSTN-1234"));
        Assert.Null(LicenseKey.Normalize(""));
    }

    [Fact]
    public void MaskHidesMiddleBlocks()
    {
        Assert.Equal("BSTN-7Q4M-••••-••••-K2XR", LicenseKey.Mask("BSTN-7Q4M-AAAA-BBBB-K2XR"));
    }

    [Fact]
    public void SignedTokenVerifiesAndTamperingIsDetected()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var token = LicenseCodec.Sign(Doc(), key);
        Assert.True(LicenseCodec.TryVerify(token, key, out var doc));
        Assert.Equal("Max Muster", doc!.Licensee);

        var parts = token.Split('.');
        var forged = parts[0][..^2] + (parts[0][^2] == 'A' ? "B" : "A") + parts[0][^1] + "." + parts[1];
        Assert.False(LicenseCodec.TryVerify(forged, key, out _));

        using var otherKey = LicenseCodec.CreateKeyPair();
        Assert.False(LicenseCodec.TryVerify(token, otherKey, out _));
        Assert.False(LicenseCodec.TryVerify("not-a-token", key, out _));
    }

    [Fact]
    public async Task ImportedLicenseUnlocksProAndDeactivationRemovesIt()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var manager = new LicenseManager(Path.Combine(TestFiles.TempDir(), "license.dat"), key, () => null, "device-1");
        Assert.Equal(LicenseState.Free, manager.Status.State);

        var result = manager.ImportToken(LicenseCodec.Sign(Doc(), key));
        Assert.True(result.Success, result.Message);
        Assert.True(manager.Status.IsPro);
        Assert.True(manager.HasFeature(LicenseFeatures.ScheduledScans));

        var off = await manager.DeactivateAsync();
        Assert.True(off.Success);
        Assert.Equal(LicenseState.Free, manager.Status.State);
    }

    [Fact]
    public void LicenseSurvivesRestart()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var file = Path.Combine(TestFiles.TempDir(), "license.dat");
        new LicenseManager(file, key, () => null, "device-1").ImportToken(LicenseCodec.Sign(Doc(), key));
        Assert.True(new LicenseManager(file, key, () => null, "device-1").Status.IsPro);
    }

    [Fact]
    public void ExpiredOrForeignDeviceLicensesAreRejected()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var manager = new LicenseManager(Path.Combine(TestFiles.TempDir(), "license.dat"), key, () => null, "device-1");

        Assert.False(manager.ImportToken(LicenseCodec.Sign(Doc() with { ExpiresAt = DateTimeOffset.Now.AddDays(-1) }, key)).Success);
        Assert.False(manager.ImportToken(LicenseCodec.Sign(Doc() with { DeviceId = "device-2" }, key)).Success);
        Assert.True(manager.ImportToken(LicenseCodec.Sign(Doc() with { DeviceId = "device-1" }, key)).Success);
    }

    [Fact]
    public async Task WithoutServerActivationAsksForLicenseFile()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var manager = new LicenseManager(Path.Combine(TestFiles.TempDir(), "license.dat"), key, () => null, "device-1");
        var result = await manager.ActivateAsync(LicenseKey.Generate());
        Assert.False(result.Success);
        Assert.Contains("Lizenzdatei", result.Message);
    }

    [Fact]
    public async Task OnlineActivationDeactivationAndRevocation()
    {
        using var key = LicenseCodec.CreateKeyPair();
        var server = new FakeServer(key);
        var manager = new LicenseManager(Path.Combine(TestFiles.TempDir(), "license.dat"), key, () => server, "device-1");

        var activation = await manager.ActivateAsync(server.Key);
        Assert.True(activation.Success, activation.Message);
        Assert.True(manager.Status.IsPro);
        Assert.True(manager.Status.OnlineActivation);
        Assert.Equal(1, server.ActiveDevices);

        server.Revoked = true;
        var refresh = await manager.RefreshAsync(force: true);
        Assert.False(refresh.Success);
        Assert.Equal(LicenseState.Revoked, manager.Status.State);

        server.Revoked = false;
        await manager.ActivateAsync(server.Key);
        await manager.DeactivateAsync();
        Assert.Equal(0, server.ActiveDevices);
    }

    private static LicenseDocument Doc() => new()
    {
        LicenseId = "test",
        Key = LicenseKey.Generate(),
        Licensee = "Max Muster",
        Seats = 3,
        IssuedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
    };

    private sealed class FakeServer(System.Security.Cryptography.ECDsa key) : ILicenseServerClient
    {
        private readonly HashSet<string> _devices = [];

        public string Key { get; } = LicenseKey.Generate();
        public bool Revoked { get; set; }
        public int ActiveDevices => _devices.Count;

        public Task<ServerLicenseResponse> ActivateAsync(string key, string deviceId, string deviceName, CancellationToken ct)
        {
            if (key != Key) return Task.FromResult(new ServerLicenseResponse(false, null, "unknown", "Unbekannter Schlüssel"));
            _devices.Add(deviceId);
            return Task.FromResult(new ServerLicenseResponse(true, Token(deviceId), "active", null));
        }

        public Task<ServerLicenseResponse> ValidateAsync(string key, string deviceId, CancellationToken ct) =>
            Task.FromResult(Revoked
                ? new ServerLicenseResponse(false, null, "revoked", "Widerrufen")
                : new ServerLicenseResponse(true, Token(deviceId), "active", null));

        public Task<ServerLicenseResponse> DeactivateAsync(string key, string deviceId, CancellationToken ct)
        {
            _devices.Remove(deviceId);
            return Task.FromResult(new ServerLicenseResponse(true, null, "deactivated", null));
        }

        private string Token(string deviceId) => LicenseCodec.Sign(new LicenseDocument
        {
            LicenseId = "srv",
            Key = Key,
            Licensee = "Server Kunde",
            Seats = 3,
            ActivatedSeats = _devices.Count,
            DeviceId = deviceId,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365),
        }, key);
    }
}

public class InstalledPublicKeyTests
{
    [Fact]
    public void PublicKeyIsLoadedFromInstallFolder()
    {
        var dir = TestFiles.TempDir();
        Assert.Null(LicenseCodec.LoadPublicKey(dir));

        using var key = LicenseCodec.CreateKeyPair();
        File.WriteAllText(Path.Combine(dir, LicenseCodec.InstalledKeyFileName), key.ExportSubjectPublicKeyInfoPem());
        using var loaded = LicenseCodec.LoadPublicKey(dir);
        Assert.NotNull(loaded);

        var token = LicenseCodec.Sign(new LicenseDocument { Key = LicenseKey.Generate(), Licensee = "A", IssuedAt = DateTimeOffset.UtcNow }, key);
        Assert.True(LicenseCodec.TryVerify(token, loaded!, out _));
    }

    [Fact]
    public void PrivateKeyFileIsNotAcceptedAsPublicKey()
    {
        var dir = TestFiles.TempDir();
        using var key = LicenseCodec.CreateKeyPair();
        File.WriteAllText(Path.Combine(dir, LicenseCodec.InstalledKeyFileName), key.ExportECPrivateKeyPem());
        Assert.Null(LicenseCodec.LoadPublicKey(dir));
    }
}
