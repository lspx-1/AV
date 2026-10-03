using System.Windows.Controls;
using Bastion.App.ViewModels;

namespace Bastion.App.Views.Pages;

public partial class ScanPage : Page
{
    public ScanPage(ScanViewModel viewModel)
    {
        DataContext = viewModel;
        InitializeComponent();
    }
}
