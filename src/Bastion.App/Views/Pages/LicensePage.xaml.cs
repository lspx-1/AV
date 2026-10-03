using System.Windows.Controls;
using Bastion.App.ViewModels;

namespace Bastion.App.Views.Pages;

public partial class LicensePage : Page
{
    public LicensePage(LicenseViewModel viewModel)
    {
        DataContext = viewModel;
        InitializeComponent();
        Loaded += async (_, _) => await viewModel.RefreshAsync();
    }
}
