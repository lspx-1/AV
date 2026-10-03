using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Bastion.Core.Licensing;
using Bastion.Core.Models;
using Bastion.Core.Platform;
using Bastion.Core.Runtime;

namespace Bastion.Core.Ipc;

/// <summary>
/// Exposes a <see cref="IBastionBackend"/> over a named pipe. Only the Bastion app from the
/// service's own (admin-protected) install folder may connect, so malware running as the user
/// cannot switch protection off through the pipe.
/// </summary>
public sealed class PipeServer(IBastionBackend backend, Action<string> log) : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Connection> _connections = [];
    private readonly Lock _lock = new();

    /// <summary>For development only: accept clients from any folder (set BASTION_ALLOW_ANY_CLIENT=1).</summary>
    public bool AllowAnyClient { get; init; } = Environment.GetEnvironmentVariable("BASTION_ALLOW_ANY_CLIENT") == "1";

    public void Start()
    {
        backend.EventRaised += e => Broadcast(PipeEvents.SecurityEvent, e);
        backend.ScanProgressChanged += p => Broadcast(PipeEvents.ScanProgress, p);
        backend.LicenseChanged += l => Broadcast(PipeEvents.License, l);
        _ = Task.Run(AcceptLoopAsync);
    }

    public void Dispose()
    {
        _cts.Cancel();
        lock (_lock)
        {
            foreach (var c in _connections)
                c.Pipe.Dispose();
        }
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception e)
            {
                log("Pipe-Fehler: " + e.Message);
                await Task.Delay(1000);
                continue;
            }

            if (!AllowAnyClient && !IsTrustedClient(pipe, out var reason))
            {
                log("Pipe-Verbindung abgelehnt: " + reason);
                pipe.Dispose();
                continue;
            }

            var connection = new Connection(pipe);
            lock (_lock)
                _connections.Add(connection);
            _ = Task.Run(() => ServeAsync(connection));
        }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        if (!OperatingSystem.IsWindows())
            return new NamedPipeServerStream(AppInfo.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(AppInfo.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    private static bool IsTrustedClient(NamedPipeServerStream pipe, out string reason)
    {
        reason = "";
        if (!OperatingSystem.IsWindows())
            return true;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
        {
            reason = "Client-Prozess unbekannt";
            return false;
        }
        var path = ProcessInfo.GetImagePath((int)pid);
        var installDir = Path.GetFullPath(AppContext.BaseDirectory);
        if (path is null || !Path.GetFullPath(path).StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
        {
            reason = $"{path ?? $"PID {pid}"} liegt nicht im Bastion-Installationsordner";
            return false;
        }
        return true;
    }

    private async Task ServeAsync(Connection connection)
    {
        using var reader = new StreamReader(connection.Pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        try
        {
            while (!_cts.IsCancellationRequested && connection.Pipe.IsConnected)
            {
                var line = await reader.ReadLineAsync(_cts.Token);
                if (line is null)
                    break;
                PipeMessage? request;
                try
                {
                    request = JsonSerializer.Deserialize<PipeMessage>(line, JsonStore.Options);
                }
                catch (JsonException)
                {
                    continue;
                }
                if (request?.Method is null)
                    continue;
                _ = Task.Run(async () =>
                {
                    var response = new PipeMessage { Id = request.Id };
                    try
                    {
                        var result = await DispatchAsync(request.Method, request.Args ?? []);
                        response.Ok = true;
                        response.Result = JsonSerializer.SerializeToElement(result, JsonStore.Options);
                    }
                    catch (Exception e)
                    {
                        response.Ok = false;
                        response.Error = e.Message;
                    }
                    await connection.SendAsync(response);
                });
            }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            lock (_lock)
                _connections.Remove(connection);
            connection.Pipe.Dispose();
        }
    }

    private async Task<object?> DispatchAsync(string method, JsonElement[] args)
    {
        T Arg<T>(int i) => args[i].Deserialize<T>(JsonStore.Options)!;
        return method switch
        {
            nameof(IBastionBackend.GetStatusAsync) => await backend.GetStatusAsync(),
            nameof(IBastionBackend.SetModuleEnabledAsync) => await Done(backend.SetModuleEnabledAsync(Arg<string>(0), Arg<bool>(1))),
            nameof(IBastionBackend.StartScanAsync) => await backend.StartScanAsync(Arg<ScanRequest>(0)),
            nameof(IBastionBackend.CancelScanAsync) => await Done(backend.CancelScanAsync()),
            nameof(IBastionBackend.GetEventsAsync) => await backend.GetEventsAsync(Arg<int>(0)),
            nameof(IBastionBackend.ExecuteEventActionAsync) => await backend.ExecuteEventActionAsync(Arg<Guid>(0), Arg<string>(1)),
            nameof(IBastionBackend.ClearHistoryAsync) => await backend.ClearHistoryAsync(),
            nameof(IBastionBackend.GetQuarantineAsync) => await backend.GetQuarantineAsync(),
            nameof(IBastionBackend.RestoreQuarantineAsync) => await backend.RestoreQuarantineAsync(Arg<Guid>(0), Arg<bool>(1)),
            nameof(IBastionBackend.DeleteQuarantineAsync) => await backend.DeleteQuarantineAsync(Arg<Guid>(0)),
            nameof(IBastionBackend.GetConnectionsAsync) => await backend.GetConnectionsAsync(),
            nameof(IBastionBackend.KillProcessAsync) => await backend.KillProcessAsync(Arg<int>(0)),
            nameof(IBastionBackend.BlockRemoteAsync) => await backend.BlockRemoteAsync(Arg<string>(0)),
            nameof(IBastionBackend.BlockProgramAsync) => await backend.BlockProgramAsync(Arg<string>(0)),
            nameof(IBastionBackend.GetSettingsAsync) => await backend.GetSettingsAsync(),
            nameof(IBastionBackend.SaveSettingsAsync) => await Done(backend.SaveSettingsAsync(Arg<BastionSettings>(0))),
            nameof(IBastionBackend.GetLicenseAsync) => await backend.GetLicenseAsync(),
            nameof(IBastionBackend.ActivateLicenseAsync) => await backend.ActivateLicenseAsync(Arg<string>(0)),
            nameof(IBastionBackend.ImportLicenseAsync) => await backend.ImportLicenseAsync(Arg<string>(0)),
            nameof(IBastionBackend.DeactivateLicenseAsync) => await backend.DeactivateLicenseAsync(),
            nameof(IBastionBackend.RefreshLicenseAsync) => await backend.RefreshLicenseAsync(),
            nameof(IBastionBackend.UpdateSignaturesAsync) => await backend.UpdateSignaturesAsync(),
            _ => throw new InvalidOperationException($"Unbekannte Methode {method}"),
        };
    }

    private static async Task<object?> Done(Task task)
    {
        await task;
        return null;
    }

    private void Broadcast(string name, object data)
    {
        PipeMessage message;
        try
        {
            message = new PipeMessage { Event = name, Data = JsonSerializer.SerializeToElement(data, JsonStore.Options) };
        }
        catch (Exception e)
        {
            log($"Ereignis {name} konnte nicht gesendet werden: {e.Message}");
            return;
        }
        List<Connection> targets;
        lock (_lock)
            targets = [.. _connections];
        foreach (var c in targets)
            _ = c.SendAsync(message);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    private sealed class Connection(NamedPipeServerStream pipe)
    {
        private readonly SemaphoreSlim _write = new(1, 1);

        public NamedPipeServerStream Pipe { get; } = pipe;

        public async Task SendAsync(PipeMessage message)
        {
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message, JsonStore.CompactOptions) + "\n");
            await _write.WaitAsync();
            try
            {
                await Pipe.WriteAsync(bytes);
                await Pipe.FlushAsync();
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException)
            {
            }
            finally
            {
                _write.Release();
            }
        }
    }
}
