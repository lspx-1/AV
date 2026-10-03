using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Bastion.LicenseManager;

public static class Converters
{
    public static readonly IValueConverter Not = new Lambda(v => v is not true);
    public static readonly IValueConverter FalseToVisible = new Lambda(v => v is true ? Visibility.Collapsed : Visibility.Visible);
    public static readonly IValueConverter NotNullToVisible = new Lambda(v => v is null or "" ? Visibility.Collapsed : Visibility.Visible);

    private sealed class Lambda(Func<object?, object> convert) : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => convert(value);

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
    }
}
