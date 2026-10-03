using System.Windows;
using System.Windows.Media;
using Bastion.App.Views;
using Bastion.App.Views.Pages;
using Bastion.Core.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Bastion.App.Services;

/// <summary>Shows a toast for events the user should know about, even when the window is hidden.</summary>
public sealed class NotificationService(BackendSession session, UiSettings ui, IServiceProvider services)
{
    private DateTime _lastToast;

    public void Start() => session.EventRaised += OnEvent;

    private void OnEvent(SecurityEvent e)
    {
        if (!ui.ShowNotifications || e.Resolution is not null && e.Severity < Severity.Medium)
            return;
        var important = e.Severity >= Severity.Medium
                        || e.Category == EventCategory.Network && e.Severity == Severity.Info && e.Title.EndsWith("ist aktiv", StringComparison.Ordinal);
        if (!important)
            return;
        // Avoid a wall of toasts during a scan that finds many files.
        if (DateTime.UtcNow - _lastToast < TimeSpan.FromSeconds(2))
            return;
        _lastToast = DateTime.UtcNow;

        var accent = (Brush)Application.Current.FindResource(e.Severity >= Severity.High ? "BadBrush" : e.Severity == Severity.Medium ? "WarnBrush" : "InfoBrush");
        var toast = new ToastWindow(e.Title, e.Detail ?? "", accent, TimeSpan.FromSeconds(e.Severity >= Severity.High ? 10 : 6), () =>
        {
            var window = services.GetRequiredService<MainWindow>();
            window.ShowAndActivate();
            window.Navigate(typeof(HistoryPage));
        });
        toast.Show();
    }
}
