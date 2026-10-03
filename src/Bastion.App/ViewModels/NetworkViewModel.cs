using System.Collections.ObjectModel;
using System.Text;
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
    private const int MaxRows = 250;

    private readonly BackendSession _session;
    private readonly ISnackbarService _snackbar;
    private readonly IContentDialogService _dialogs;
    private readonly DispatcherTimer _timer;
    private IReadOnlyList<ConnectionView> _all = [];
    private string _lastSignature = "";
    private bool _refreshing;

    public NetworkViewModel(BackendSession session, ISnackbarService snackbar, IContentDialogService dialogs)
    {
        _session = session;
        _snackbar = snackbar;
        _dialogs = dialogs;
        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(4) };
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    [ObservableProperty] private bool _onlyNotable;
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _summary = "Verbindungen werden geladen…";
    [ObservableProperty] private int _riskyCount;
    [ObservableProperty] private int _programCount;
    [ObservableProperty] private int _connectionCount;
    [ObservableProperty] private int _listeningCount;
    [ObservableProperty] private string? _hiddenText;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyCanExecuteChangedFor(nameof(KillCommand), nameof(BlockRemoteCommand), nameof(BlockProgramCommand), nameof(OpenLocationCommand))]
    private ConnectionItemViewModel? _selected;

    public bool HasSelection => Selected is not null;

    public ObservableCollection<ConnectionItemViewModel> Connections { get; } = [];

    partial void OnOnlyNotableChanged(bool value) => Apply(force: true);
    partial void OnSearchChanged(string value) => Apply(force: true);

    public void Start()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    public void Stop() => _timer.Stop();

    public async Task RefreshAsync()
    {
        if (_refreshing)
            return;
        _refreshing = true;
        try
        {
            _all = await _session.Backend.GetConnectionsAsync();
            RiskyCount = _all.Count(c => c.Risk >= ConnectionRisk.Suspicious);
            ProgramCount = _all.Select(c => c.ProcessPath ?? c.ProcessName).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            ConnectionCount = _all.Count(c => !c.IsListening);
            ListeningCount = _all.Count(c => c.IsListening);
            Summary = RiskyCount == 0
                ? "Keine verdächtigen Verbindungen. Bastion achtet auf Steuerserver, regelmäßiges Nachfragen (Beaconing), getarnte Prozesse und offene Hintertüren."
                : $"{RiskyCount} Verbindungen sehen verdächtig aus. Wähle eine aus, um sie zu beenden oder zu blockieren.";
            Apply(force: false);
        }
        catch (Exception)
        {
            // The service may be restarting; the next tick tries again.
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void Apply(bool force)
    {
        var matching = _all.Where(c => !OnlyNotable || c.Risk > ConnectionRisk.None)
            .Where(c => string.IsNullOrWhiteSpace(Search)
                        || c.ProcessName.Contains(Search, StringComparison.OrdinalIgnoreCase)
                        || c.RemoteEndpoint.Contains(Search, StringComparison.OrdinalIgnoreCase)
                        || (c.ProcessPath?.Contains(Search, StringComparison.OrdinalIgnoreCase) ?? false))
            .ToList();
        var shown = matching.Take(MaxRows).ToList();
        HiddenText = matching.Count > MaxRows ? $"{matching.Count - MaxRows} weitere ausgeblendet. Nutze die Suche, um sie zu finden." : null;

        // Only touch the list when something actually changed; redrawing hundreds of rows costs a lot.
        var signature = Signature(shown);
        if (!force && signature == _lastSignature)
            return;
        _lastSignature = signature;

        var selectedKey = Selected?.Key;
        var sameOrder = shown.Count == Connections.Count && shown.Select(Key).SequenceEqual(Connections.Select(c => c.Key));
        if (sameOrder)
        {
            for (var i = 0; i < shown.Count; i++)
                Connections[i].Update(shown[i]);
        }
        else
        {
            Connections.Clear();
            foreach (var c in shown)
                Connections.Add(new ConnectionItemViewModel(c));
            Selected = selectedKey is null ? null : Connections.FirstOrDefault(c => c.Key == selectedKey);
        }
    }

    internal static string Key(ConnectionView c) => $"{c.ProcessId}|{c.LocalEndpoint}|{c.RemoteEndpoint}";

    private static string Signature(IEnumerable<ConnectionView> views)
    {
        var sb = new StringBuilder();
        foreach (var v in views)
            sb.Append(Key(v)).Append('|').Append(v.State).Append('|').Append((int)v.Risk).Append(';');
        return sb.ToString();
    }

    private bool CanAct() => Selected is not null;
    private bool CanBlockRemote() => Selected?.CanBlockRemote == true;
    private bool CanBlockProgram() => Selected?.CanBlockProgram == true;

    [RelayCommand(CanExecute = nameof(CanAct))]
    private async Task KillAsync()
    {
        var target = Selected;
        if (target is null)
            return;
        var dialog = new ContentDialog
        {
            Title = $"{target.View.ProcessName} beenden?",
            Content = "Ungespeicherte Daten in diesem Programm gehen verloren. Wichtige Windows-Prozesse beendet Bastion grundsätzlich nicht.",
            PrimaryButtonText = "Beenden",
            CloseButtonText = "Abbrechen",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await _dialogs.ShowAsync(dialog, CancellationToken.None) != ContentDialogResult.Primary)
            return;
        await RunAsync(b => b.KillProcessAsync(target.View.ProcessId));
    }

    [RelayCommand(CanExecute = nameof(CanBlockRemote))]
    private Task BlockRemoteAsync() => RunAsync(b => b.BlockRemoteAsync(Selected!.View.RemoteAddress));

    [RelayCommand(CanExecute = nameof(CanBlockProgram))]
    private Task BlockProgramAsync() => RunAsync(b => b.BlockProgramAsync(Selected!.View.ProcessPath!));

    [RelayCommand(CanExecute = nameof(CanBlockProgram))]
    private void OpenLocation()
    {
        if (Selected?.View.ProcessPath is { } path)
            WindowsIntegration.OpenFolder(path);
    }

    private async Task RunAsync(Func<IBastionBackend, Task<ActionResult>> call)
    {
        if (Selected is null)
            return;
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

/// <summary>One row in the connection list. Display only; actions live on the page for the selected row.</summary>
public sealed partial class ConnectionItemViewModel : ObservableObject
{
    public ConnectionItemViewModel(ConnectionView view)
    {
        Key = NetworkViewModel.Key(view);
        _view = view;
    }

    public string Key { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Process), nameof(Endpoint), nameof(SignedText), nameof(Reasons), nameof(HasReasons), nameof(CanBlockRemote), nameof(CanBlockProgram))]
    private ConnectionView _view;

    public string Process => $"{View.ProcessName}  ·  PID {View.ProcessId}";
    public string Endpoint => View.IsListening ? $"wartet an {View.LocalEndpoint}" : $"→ {View.RemoteEndpoint}";
    public string SignedText => View.Signed switch { true => "signiert", false => "nicht signiert", _ => "" };
    public string Reasons => string.Join(" · ", View.Reasons);
    public bool HasReasons => View.Reasons.Count > 0;
    public bool CanBlockRemote => !View.IsListening && !string.IsNullOrEmpty(View.RemoteAddress);
    public bool CanBlockProgram => View.ProcessPath is not null;

    public void Update(ConnectionView view) => View = view;
}
