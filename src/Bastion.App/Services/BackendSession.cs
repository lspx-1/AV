using System.Windows;
using Bastion.Core.Ipc;
using Bastion.Core.Licensing;
using Bastion.Core.Models;
using Bastion.Core.Runtime;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Bastion.App.Services;

/// <summary>
/// Connects the UI to the protection engine: the Bastion service if it runs, otherwise an
/// in-process engine (app mode, protection only while the app runs). Events arrive on the UI thread.
/// </summary>
public sealed partial class BackendSession : ObservableObject, IDisposable
{
    private IBastionBackend? _backend;
    private ProtectionHost? _localHost;
    private PipeClientBackend? _pipe;

    [ObservableProperty]
    private bool _isServiceMode;

    [ObservableProperty]
    private string _modeText = "Verbinde…";

    public event Action<SecurityEvent>? EventRaised;
    public event Action<ScanProgress>? ScanProgressChanged;
    public event Action<LicenseStatus>? LicenseChanged;

    /// <summary>Raised after the backend changed (first connection, reconnect or fallback).</summary>
    public event Action? Reconnected;

    public IBastionBackend Backend => _backend ?? throw new InvalidOperationException("Noch nicht verbunden.");

    public async Task ConnectAsync()
    {
        // Skip the pipe timeout when the service is not installed at all.
        _pipe = WindowsIntegration.ServiceState() == "Nicht installiert"
            ? null
            : await PipeClientBackend.TryConnectAsync(TimeSpan.FromSeconds(2));
        if (_pipe is not null)
        {
            _pipe.Disconnected += OnPipeDisconnected;
            Attach(_pipe);
            IsServiceMode = true;
            ModeText = "Bastion-Dienst aktiv";
        }
        else
        {
            // Starting the modules takes a moment; keep the window responsive.
            _localHost ??= await Task.Run(CreateLocalHost);
            Attach(_localHost);
            IsServiceMode = false;
            ModeText = "App-Modus: Schutz nur, solange Bastion läuft";
        }
        Reconnected?.Invoke();
    }

    private static ProtectionHost CreateLocalHost()
    {
        var host = new ProtectionHost(BastionPaths.ForStandaloneApp(), runningAsService: false);
        host.Start();
        return host;
    }

    private void Attach(IBastionBackend backend)
    {
        if (_backend is not null)
        {
            _backend.EventRaised -= OnEvent;
            _backend.ScanProgressChanged -= OnScan;
            _backend.LicenseChanged -= OnLicense;
        }
        _backend = backend;
        backend.EventRaised += OnEvent;
        backend.ScanProgressChanged += OnScan;
        backend.LicenseChanged += OnLicense;
    }

    private void OnEvent(SecurityEvent e) => Ui(() => EventRaised?.Invoke(e));
    private void OnScan(ScanProgress p) => Ui(() => ScanProgressChanged?.Invoke(p));
    private void OnLicense(LicenseStatus s) => Ui(() => LicenseChanged?.Invoke(s));

    private void OnPipeDisconnected()
    {
        Ui(async () =>
        {
            ModeText = "Verbindung zum Dienst verloren, verbinde neu…";
            for (var attempt = 0; attempt < 5; attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(3));
                var pipe = await PipeClientBackend.TryConnectAsync(TimeSpan.FromSeconds(2));
                if (pipe is not null)
                {
                    _pipe?.Dispose();
                    _pipe = pipe;
                    pipe.Disconnected += OnPipeDisconnected;
                    Attach(pipe);
                    ModeText = "Bastion-Dienst aktiv";
                    Reconnected?.Invoke();
                    return;
                }
            }
            // The service is gone: keep the user protected with the in-process engine.
            await ConnectAsync();
        });
    }

    private static void Ui(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.InvokeAsync(action);
    }

    public void Dispose()
    {
        _pipe?.Dispose();
        _localHost?.Dispose();
    }
}
