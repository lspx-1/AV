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

    // The view model reformats the key (adds dashes); keep the caret at the end while typing.
    private void KeyBox_TextChanged(object sender, TextChangedEventArgs e) => KeyBox.CaretIndex = KeyBox.Text.Length;
}
