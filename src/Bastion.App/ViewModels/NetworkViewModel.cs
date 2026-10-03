using System.Collections.ObjectModel;
using System.Windows.Threading;
using Bastion.App.Services;
using Bastion.Core.Ipc;
using Bastion.Core.Network;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Bastion.App.ViewModels;

public sealed partial class NetworkViewModel : ObservableObject
{
    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;
    private readonly DispatcherTimer _timer;
    private IReadOnlyList<ConnectionView> _all = [];

    public NetworkViewModel(BackendSession session, ISnackbarService snackbar)
    {
        _session = session;
        _snackbar = snackbar;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    [ObservableProperty] private bool _onlyNotable;
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private int _riskyCount;
    [ObservableProperty] private int _programCount;
    [ObservableProperty] private int _connectionCount;
    [ObservableProperty] private int _listeningCount;

    public ObservableCollection<ConnectionItemViewModel> Connections { get; } = [];

    partial void OnOnlyNotableChanged(bool value) => Apply();
    partial void OnSearchChanged(string value) => Apply();

    public void Start()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    public void Stop() => _timer.Stop();

    public async Task RefreshAsync()
    {
        try
        {
            _all = await _session.Backend.GetConnectionsAsync();
        }
        catch (Exception)
        {
            return;
        }
        RiskyCount = _all.Count(c => c.Risk >= ConnectionRisk.Suspicious);
        ProgramCount = _all.Select(c => c.ProcessPath ?? c.ProcessName).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        ConnectionCount = _all.Count(c => !c.IsListening);
        ListeningCount = _all.Count(c => c.IsListening);
        Summary = RiskyCount == 0
            ? "Keine verdächtigen Verbindungen. Bastion achtet auf Steuerserver, regelmäßiges Nachfragen (Beaconing), getarnte Prozesse und offene Hintertüren."
            : $"{RiskyCount} Verbindungen sehen verdächtig aus. Prüfe sie unten.";
        Apply();
    }

    private void Apply()
    {
        var filtered = _all.Where(c => !OnlyNotable || c.Risk > ConnectionRisk.None)
            .Where(c => string.IsNullOrWhiteSpace(Search)
                        || c.ProcessName.Contains(Search, StringComparison.OrdinalIgnoreCase)
                        || c.RemoteEndpoint.Contains(Search, StringComparison.OrdinalIgnoreCase)
                        || (c.ProcessPath?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false))
            .Take(400)
            .ToList();

        // Update in place so the list does not jump while the user reads it.
        for (var i = 0; i < filtered.Count; i++)
        {
            if (i < Connections.Count)
                Connections[i].Update(filtered[i]);
            else
                Connections.Add(new ConnectionItemViewModel(filtered[i], this));
        }
        while (Connections.Count > filtered.Count)
            Connections.RemoveAt(Connections.Count - 1);
    }

    internal async Task RunAsync(Func<IBastionBackend, Task<ActionResult>> call)
    {
        try
        {
            var result = await call(_session.Backend);
            _snackbar.Show(result.Success ? "Erledigt" : "Nicht möglich", result.Message,
                result.Success ? ControlAppearance.Success : ControlAppearance.Caution, null, TimeSpan.FromSeconds(4));
        }
        catch (Exception e)
        {
            _snackbar.Show("Fehler", e.Message, ControlAppearance.Danger, null, TimeSpan.FromSeconds(5));
        }
        await RefreshAsync();
    }
}

public sealed partial class ConnectionItemViewModel : ObservableObject
{
    private readonly NetworkViewModel _owner;

    public ConnectionItemViewModel(ConnectionView view, NetworkViewModel owner)
    {
        _owner = owner;
        Update(view);
    }

    [ObservableProperty] private ConnectionView _view = null!;

    public string Process => $"{View.ProcessName}  ·  PID {View.ProcessId}";
    public string Endpoint => View.IsListening ? $"wartet an {View.LocalEndpoint}" : $"→ {View.RemoteEndpoint}";
    public string SignedText => View.Signed switch { true => "signiert", false => "nicht signiert", _ => "" };
    public string Reasons => string.Join(" · ", View.Reasons);
    public bool HasReasons => View.Reasons.Count > 0;
    public bool CanBlockRemote => !View.IsListening && !string.IsNullOrEmpty(View.RemoteAddress);
    public bool CanBlockProgram => View.ProcessPath is not null;

    public void Update(ConnectionView view)
    {
        View = view;
        OnPropertyChanged(nameof(Process));
        OnPropertyChanged(nameof(Endpoint));
        OnPropertyChanged(nameof(SignedText));
        OnPropertyChanged(nameof(Reasons));
        OnPropertyChanged(nameof(HasReasons));
        OnPropertyChanged(nameof(CanBlockRemote));
        OnPropertyChanged(nameof(CanBlockProgram));
    }

    [RelayCommand]
    private Task KillAsync() => _owner.RunAsync(b => b.KillProcessAsync(View.ProcessId));

    [RelayCommand]
    private Task BlockRemoteAsync() => _owner.RunAsync(b => b.BlockRemoteAsync(View.RemoteAddress));

    [RelayCommand]
    private Task BlockProgramAsync() => _owner.RunAsync(b => b.BlockProgramAsync(View.ProcessPath!));

    [RelayCommand]
    private void OpenLocation()
    {
        if (View.ProcessPath is not null)
            WindowsIntegration.OpenFolder(View.ProcessPath);
    }
}
