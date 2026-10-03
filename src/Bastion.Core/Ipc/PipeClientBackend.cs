using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Bastion.Core.Licensing;
using Bastion.Core.Models;
using Bastion.Core.Network;
using Bastion.Core.Quarantine;
using Bastion.Core.Runtime;
using Bastion.Core.Updates;

namespace Bastion.Core.Ipc;

/// <summary>Talks to the Bastion service over the named pipe.</summary>
/// <summary>The Bastion service is not reachable right now. The app reconnects on its own.</summary>
public sealed class ServiceUnavailableException()
    : Exception("Die Verbindung zum Bastion-Dienst ist kurz unterbrochen. Bastion verbindet sich gerade neu – versuch es in ein paar Sekunden noch einmal.");

public sealed class PipeClientBackend : IBastionBackend, IDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly SemaphoreSlim _write = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement?>> _pending = new();
    private long _nextId;

    private PipeClientBackend(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        _ = Task.Run(ReadLoopAsync);
    }

    public event Action<SecurityEvent>? EventRaised;
    public event Action<ScanProgress>? ScanProgressChanged;
    public event Action<LicenseStatus>? LicenseChanged;

    /// <summary>Raised when the connection to the service is lost.</summary>
    public event Action? Disconnected;

    public bool IsConnected => _pipe.IsConnected;

    /// <summary>Connects to the service. Returns null if it is not running or refuses this client.</summary>
    public static async Task<PipeClientBackend?> TryConnectAsync(TimeSpan timeout)
    {
        var pipe = new NamedPipeClientStream(".", AppInfo.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            using var cts = new CancellationTokenSource(timeout);
            await pipe.ConnectAsync(cts.Token);
            var client = new PipeClientBackend(pipe);
            // The server drops untrusted clients right after connecting; verify with a real call.
            await client.CallAsync<StatusSnapshot>(nameof(GetStatusAsync)).WaitAsync(timeout);
            return client;
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or TimeoutException or UnauthorizedAccessException or InvalidOperationException or ServiceUnavailableException)
        {
            pipe.Dispose();
            return null;
        }
    }

    public void Dispose()
    {
        _pipe.Dispose();
        _write.Dispose();
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (true)
            {
                var line = await _reader.ReadLineAsync();
                if (line is null)
                    break;
                var message = JsonSerializer.Deserialize<PipeMessage>(line, JsonStore.Options);
                if (message is null)
                    continue;
                if (message.Event is not null && message.Data is { } data)
                {
                    switch (message.Event)
                    {
                        case PipeEvents.SecurityEvent:
                            EventRaised?.Invoke(data.Deserialize<SecurityEvent>(JsonStore.Options)!);
                            break;
                        case PipeEvents.ScanProgress:
                            ScanProgressChanged?.Invoke(data.Deserialize<ScanProgress>(JsonStore.Options)!);
                            break;
                        case PipeEvents.License:
                            LicenseChanged?.Invoke(data.Deserialize<LicenseStatus>(JsonStore.Options)!);
                            break;
                    }
                    continue;
                }
                if (message.Id is { } id && _pending.TryRemove(id, out var tcs))
                {
                    if (message.Ok == true)
                        tcs.TrySetResult(message.Result);
                    else
                        tcs.TrySetException(new InvalidOperationException(message.Error ?? "Unbekannter Fehler im Dienst."));
                }
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or JsonException)
        {
        }
        foreach (var tcs in _pending.Values)
            tcs.TrySetException(new IOException("Verbindung zum Bastion-Dienst getrennt."));
        _pending.Clear();
        Disconnected?.Invoke();
    }

    private async Task<T> CallAsync<T>(string method, params object?[] args)
    {
        var id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonElement?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        var request = new PipeMessage
        {
            Id = id,
            Method = method,
            Args = args.Select(a => JsonSerializer.SerializeToElement(a, JsonStore.Options)).ToArray(),
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, JsonStore.CompactOptions) + "\n");
        await _write.WaitAsync();
        try
        {
            await _pipe.WriteAsync(bytes);
            await _pipe.FlushAsync();
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException)
        {
            _pending.TryRemove(id, out _);
            // The service went away (restart or crash). Close our end so the read loop reports the disconnect.
            _pipe.Dispose();
            throw new ServiceUnavailableException();
        }
        finally
        {
            _write.Release();
        }
        JsonElement? result;
        try
        {
            result = await tcs.Task;
        }
        catch (IOException)
        {
            throw new ServiceUnavailableException();
        }
        return result is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } r ? r.Deserialize<T>(JsonStore.Options)! : default!;
    }

    private Task CallAsync(string method, params object?[] args) => CallAsync<object?>(method, args);

    public Task<StatusSnapshot> GetStatusAsync() => CallAsync<StatusSnapshot>(nameof(GetStatusAsync));
    public Task SetModuleEnabledAsync(string moduleId, bool enabled) => CallAsync(nameof(SetModuleEnabledAsync), moduleId, enabled);
    public Task<ScanProgress> StartScanAsync(ScanRequest request) => CallAsync<ScanProgress>(nameof(StartScanAsync), request);
    public Task CancelScanAsync() => CallAsync(nameof(CancelScanAsync));
    public Task<IReadOnlyList<SecurityEvent>> GetEventsAsync(int max) => List<SecurityEvent>(nameof(GetEventsAsync), max);
    public Task<ActionResult> ExecuteEventActionAsync(Guid eventId, string action) => CallAsync<ActionResult>(nameof(ExecuteEventActionAsync), eventId, action);
    public Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync() => List<QuarantineItem>(nameof(GetQuarantineAsync));
    public Task<ActionResult> RestoreQuarantineAsync(Guid id, bool addExclusion) => CallAsync<ActionResult>(nameof(RestoreQuarantineAsync), id, addExclusion);
    public Task<ActionResult> DeleteQuarantineAsync(Guid id) => CallAsync<ActionResult>(nameof(DeleteQuarantineAsync), id);
    public Task<IReadOnlyList<ConnectionView>> GetConnectionsAsync() => List<ConnectionView>(nameof(GetConnectionsAsync));
    public Task<ActionResult> KillProcessAsync(int pid) => CallAsync<ActionResult>(nameof(KillProcessAsync), pid);
    public Task<ActionResult> BlockRemoteAsync(string ip) => CallAsync<ActionResult>(nameof(BlockRemoteAsync), ip);
    public Task<ActionResult> BlockProgramAsync(string path) => CallAsync<ActionResult>(nameof(BlockProgramAsync), path);
    public Task<BastionSettings> GetSettingsAsync() => CallAsync<BastionSettings>(nameof(GetSettingsAsync));
    public Task SaveSettingsAsync(BastionSettings settings) => CallAsync(nameof(SaveSettingsAsync), settings);
    public Task<LicenseStatus> GetLicenseAsync() => CallAsync<LicenseStatus>(nameof(GetLicenseAsync));
    public Task<LicenseOperationResult> ActivateLicenseAsync(string key) => CallAsync<LicenseOperationResult>(nameof(ActivateLicenseAsync), key);
    public Task<LicenseOperationResult> ImportLicenseAsync(string token) => CallAsync<LicenseOperationResult>(nameof(ImportLicenseAsync), token);
    public Task<LicenseOperationResult> DeactivateLicenseAsync() => CallAsync<LicenseOperationResult>(nameof(DeactivateLicenseAsync));
    public Task<LicenseOperationResult> RefreshLicenseAsync() => CallAsync<LicenseOperationResult>(nameof(RefreshLicenseAsync));
    public Task<UpdateResult> UpdateSignaturesAsync() => CallAsync<UpdateResult>(nameof(UpdateSignaturesAsync));

    private async Task<IReadOnlyList<T>> List<T>(string method, params object?[] args) =>
        await CallAsync<List<T>>(method, args) ?? [];
}
