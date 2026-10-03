using System.Windows.Controls;
using Bastion.App.ViewModels;

namespace Bastion.App.Views.Pages;

public partial class HistoryPage : Page
{
    public HistoryPage(HistoryViewModel viewModel)
    {
        DataContext = viewModel;
        InitializeComponent();
        Loaded += async (_, _) => await viewModel.RefreshAsync();
    }
}
