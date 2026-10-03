using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Bastion.App.Views;

/// <summary>Small notification in the bottom-right corner, like Windows toasts, for important events.</summary>
public partial class ToastWindow : Window
{
    private readonly DispatcherTimer _timer;
    private readonly Action _onClick;

    public ToastWindow(string title, string message, Brush accent, TimeSpan duration, Action onClick)
    {
        InitializeComponent();
        _onClick = onClick;
        TitleText.Text = title;
        MessageText.Text = message;
        Accent.Background = accent;
        _timer = new DispatcherTimer { Interval = duration };
        _timer.Tick += (_, _) => FadeOut();
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth - 8;
            Top = area.Bottom - ActualHeight - 8;
            BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
            _timer.Start();
        };
        MouseEnter += (_, _) => _timer.Stop();
        MouseLeave += (_, _) => _timer.Start();
    }

    private void FadeOut()
    {
        _timer.Stop();
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(220));
        fade.Completed += (_, _) => Close();
        BeginAnimation(OpacityProperty, fade);
    }

    private void Body_Click(object sender, MouseButtonEventArgs e)
    {
        _onClick();
        FadeOut();
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        FadeOut();
    }
}
