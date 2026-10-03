using System.Net.Http.Json;
using Bastion.Core.Runtime;

namespace Bastion.Core.Licensing;

/// <summary>Talks to the license server. The API is documented in docs/licensing-api.md.</summary>
public interface ILicenseServerClient
{
    Task<ServerLicenseResponse> ActivateAsync(string key, string deviceId, string deviceName, CancellationToken ct);
    Task<ServerLicenseResponse> ValidateAsync(string key, string deviceId, CancellationToken ct);
    Task<ServerLicenseResponse> DeactivateAsync(string key, string deviceId, CancellationToken ct);
}

public sealed record ServerLicenseResponse(bool Ok, string? Token, string? Status, string? Message);

public sealed class LicenseServerException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class HttpLicenseServerClient(HttpClient http, string baseUrl) : ILicenseServerClient
{
    private readonly string _baseUrl = baseUrl.TrimEnd('/');

    public Task<ServerLicenseResponse> ActivateAsync(string key, string deviceId, string deviceName, CancellationToken ct) =>
        PostAsync("activate", new { key, deviceId, deviceName, appVersion = AppInfo.Version }, ct);

    public Task<ServerLicenseResponse> ValidateAsync(string key, string deviceId, CancellationToken ct) =>
        PostAsync("validate", new { key, deviceId, appVersion = AppInfo.Version }, ct);

    public Task<ServerLicenseResponse> DeactivateAsync(string key, string deviceId, CancellationToken ct) =>
        PostAsync("deactivate", new { key, deviceId }, ct);

    private async Task<ServerLicenseResponse> PostAsync(string action, object body, CancellationToken ct)
    {
        try
        {
            using var response = await http.PostAsJsonAsync($"{_baseUrl}/api/v1/licenses/{action}", body, JsonStore.Options, ct);
            var result = await response.Content.ReadFromJsonAsync<ServerLicenseResponse>(JsonStore.Options, ct);
            return result ?? new ServerLicenseResponse(false, null, null, $"Leere Antwort vom Server ({(int)response.StatusCode}).");
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            throw new LicenseServerException("Lizenzserver nicht erreichbar.", e);
        }
    }
}
