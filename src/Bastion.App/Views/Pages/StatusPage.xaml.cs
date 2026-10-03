using System.Windows.Controls;
using System.Windows.Media.Animation;
using Bastion.App.ViewModels;

namespace Bastion.App.Views.Pages;

public partial class StatusPage : Page
{
    public StatusPage(StatusViewModel viewModel)
    {
        DataContext = viewModel;
        InitializeComponent();
        Loaded += (_, _) =>
        {
            viewModel.Start();
            ((Storyboard)Resources["Breathe"]).Begin(this, true);
        };
        Unloaded += (_, _) => viewModel.Stop();
    }
}
