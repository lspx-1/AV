using System.Windows.Controls;
using Bastion.App.ViewModels;

namespace Bastion.App.Views.Pages;

public partial class NetworkPage : Page
{
    public NetworkPage(NetworkViewModel viewModel)
    {
        DataContext = viewModel;
        InitializeComponent();
        Loaded += (_, _) => viewModel.Start();
        Unloaded += (_, _) => viewModel.Stop();
    }
}
