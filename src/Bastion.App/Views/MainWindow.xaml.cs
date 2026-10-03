using System.ComponentModel;
using System.Windows;
using System.Windows.Media.Imaging;
using Bastion.App.Services;
using Bastion.App.ViewModels;
using Bastion.App.Views.Pages;
using Bastion.Core.Models;
using Wpf.Ui;
using Wpf.Ui.Controls;
using Wpf.Ui.Tray.Controls;

namespace Bastion.App.Views;

public partial class MainWindow : FluentWindow
{
    private static readonly BitmapImage OkIcon = new(new Uri("pack://application:,,,/Assets/bastion.ico"));
    private static readonly BitmapImage WarnIcon = new(new Uri("pack://application:,,,/Assets/bastion-warning.ico"));

    private readonly UiSettings _ui;
    private readonly StatusViewModel _status;
    private bool _exiting;
    private bool _themeApplied;

    public MainWindow(IServiceProvider services, ISnackbarService snackbar, IContentDialogService dialogs, UiSettings ui, StatusViewModel status)
    {
        _ui = ui;
        _status = status;
        InitializeComponent();

        RootNavigation.SetServiceProvider(services);
        snackbar.SetSnackbarPresenter(SnackbarPresenter);
        dialogs.SetDialogHost(RootContentDialog);

        Loaded += (_, _) =>
        {
            if (!_themeApplied)
            {
                _themeApplied = true;
                App.ApplyTheme(_ui);
            }
            if (RootNavigation.SelectedItem is null)
                RootNavigation.Navigate(typeof(StatusPage));
        };
        _status.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(StatusViewModel.State))
                UpdateTray();
        };
    }

    /// <summary>Starts in the tray only (autostart). The window must load once so the tray icon registers.</summary>
    public void StartHidden()
    {
        Opacity = 0;
        ShowInTaskbar = false;
        Show();
        Hide();
        ShowInTaskbar = true;
        Opacity = 1;
    }

    public void ShowAndActivate()
    {
        if (!IsVisible)
            Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    public void Navigate(Type page) => RootNavigation.Navigate(page);

    private void UpdateTray()
    {
        var ok = _status.State == ProtectionState.Protected;
        TrayIcon.Icon = ok ? OkIcon : WarnIcon;
        TrayIcon.TooltipText = $"Bastion: {_status.Headline}";
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_exiting && _ui.CloseToTray)
        {
            // Protection keeps running; the window just goes to the tray.
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnClosing(e);
    }

    public void ExitApplication()
    {
        _exiting = true;
        TrayIcon.Unregister();
        Close();
        Application.Current.Shutdown();
    }

    private void TrayIcon_LeftClick(NotifyIcon sender, RoutedEventArgs e) => ShowAndActivate();

    private void TrayOpen_Click(object sender, RoutedEventArgs e) => ShowAndActivate();

    private void TrayQuickScan_Click(object sender, RoutedEventArgs e)
    {
        ShowAndActivate();
        Navigate(typeof(StatusPage));
        _status.QuickScanCommand.Execute(null);
    }

    private void TrayExit_Click(object sender, RoutedEventArgs e) => ExitApplication();
}
