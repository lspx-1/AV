using System.Windows;
using System.Windows.Threading;
using Bastion.App.Services;
using Bastion.App.ViewModels;
using Bastion.App.Views;
using Bastion.App.Views.Pages;
using Microsoft.Extensions.DependencyInjection;
using Wpf.Ui;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Bastion.App;

public partial class App : Application
{
    private SingleInstance? _instance;
    private ServiceProvider? _services;

    public static IServiceProvider Services => ((App)Current)._services ?? throw new InvalidOperationException("App not started.");

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _instance = new SingleInstance();
        if (!_instance.IsFirst)
        {
            // Bastion already runs: hand over the arguments (e.g. "--scan C:\file") and quit.
            SingleInstance.Send(e.Args);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogError(args.Exception);
            args.SetObserved();
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogError((Exception)args.ExceptionObject);
        _services = ConfigureServices();

        var window = _services.GetRequiredService<MainWindow>();
        if (e.Args.Contains("--minimized"))
            window.StartHidden();
        else
            window.Show();

        await _services.GetRequiredService<BackendSession>().ConnectAsync();
        _services.GetRequiredService<NotificationService>().Start();

        HandleArguments(e.Args);
        _instance.ArgumentsReceived += args => Dispatcher.InvokeAsync(() => HandleArguments(args, activate: true));
        _instance.Listen();
    }

    private static ServiceProvider ConfigureServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(UiSettings.Load());
        services.AddSingleton<BackendSession>();
        services.AddSingleton<ISnackbarService, SnackbarService>();
        services.AddSingleton<IContentDialogService, ContentDialogService>();
        services.AddSingleton<NotificationService>();
        services.AddSingleton<MainWindow>();

        services.AddSingleton<StatusViewModel>();
        services.AddSingleton<ScanViewModel>();
        services.AddSingleton<NetworkViewModel>();
        services.AddSingleton<QuarantineViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<LicenseViewModel>();
        services.AddSingleton<SettingsViewModel>();

        services.AddSingleton<StatusPage>();
        services.AddSingleton<ScanPage>();
        services.AddSingleton<NetworkPage>();
        services.AddSingleton<QuarantinePage>();
        services.AddSingleton<HistoryPage>();
        services.AddSingleton<LicensePage>();
        services.AddSingleton<SettingsPage>();
        return services.BuildServiceProvider();
    }

    private void HandleArguments(string[] args, bool activate = false)
    {
        var window = Services.GetRequiredService<MainWindow>();
        var scanIndex = Array.IndexOf(args, "--scan");
        if (scanIndex >= 0 && scanIndex + 1 < args.Length)
        {
            window.ShowAndActivate();
            window.Navigate(typeof(ScanPage));
            _ = Services.GetRequiredService<ScanViewModel>().ScanPathsAsync([args[scanIndex + 1]]);
            return;
        }
        if (activate && !args.Contains("--minimized"))
            window.ShowAndActivate();
    }

    public static void ApplyTheme(UiSettings ui)
    {
        var backdrop = ui.Backdrop switch
        {
            BackdropChoice.Mica => WindowBackdropType.Mica,
            BackdropChoice.None => WindowBackdropType.None,
            _ => WindowBackdropType.Acrylic,
        };
        var window = Services.GetRequiredService<MainWindow>();
        if (ui.Theme == ThemeChoice.System)
        {
            ApplicationThemeManager.ApplySystemTheme(false);
            SystemThemeWatcher.Watch(window, backdrop, false);
        }
        else
        {
            SystemThemeWatcher.UnWatch(window);
            ApplicationThemeManager.Apply(ui.Theme == ThemeChoice.Light ? ApplicationTheme.Light : ApplicationTheme.Dark, backdrop, false);
        }
        window.WindowBackdropType = backdrop;
        GlassTheme.Apply(ui, backdrop);

        if (!_themeHooked)
        {
            // Windows switched between light and dark: recolour the glass layers.
            _themeHooked = true;
            ApplicationThemeManager.Changed += (_, _) => Current.Dispatcher.InvokeAsync(() => GlassTheme.Apply(ui, window.WindowBackdropType));
        }
    }

    private static bool _themeHooked;

    private DateTime _lastErrorShown;
    private int _errorsLogged;

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        LogError(e.Exception);
        // An error that repeats on every layout pass must not flood the screen with messages.
        if (DateTime.UtcNow - _lastErrorShown < TimeSpan.FromSeconds(10))
            return;
        _lastErrorShown = DateTime.UtcNow;
        try
        {
            Services.GetRequiredService<ISnackbarService>().Show("Unerwarteter Fehler", Describe(e.Exception), ControlAppearance.Danger, null, TimeSpan.FromSeconds(6));
        }
        catch (Exception)
        {
            // Never crash while reporting a crash.
        }
    }

    /// <summary>Message plus exception type and the first stack frame, so a screenshot is enough to locate the bug.</summary>
    private static string Describe(Exception exception)
    {
        var frame = exception.StackTrace?.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
        return $"{exception.GetType().Name}: {exception.Message}" + (frame is null ? "" : $"\n{frame}");
    }

    /// <summary>Writes to %LocalAppData%\Bastion\app-errors.log (at most 200 entries per run).</summary>
    public void LogError(Exception exception)
    {
        if (Interlocked.Increment(ref _errorsLogged) > 200)
            return;
        try
        {
            var log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bastion", "app-errors.log");
            Directory.CreateDirectory(Path.GetDirectoryName(log)!);
            File.AppendAllText(log, $"{DateTime.Now:O} {exception}\n\n");
        }
        catch (Exception)
        {
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }
}
