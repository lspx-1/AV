using System.Windows;
using System.Windows.Media;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Bastion.App.Services;

/// <summary>
/// Colours the translucent window. Acrylic alone looks washed out on bright wallpapers, so Bastion lays a
/// tinted layer and two soft accent glows over it and uses its own teal accent instead of the Windows one.
/// </summary>
public static class GlassTheme
{
    public static readonly Color Accent = Color.FromRgb(0x1D, 0x8F, 0xB0);

    public static void Apply(UiSettings ui, WindowBackdropType backdrop)
    {
        var theme = ApplicationThemeManager.GetAppTheme();
        var dark = theme != ApplicationTheme.Light;
        ApplicationAccentColorManager.Apply(Accent, theme, false, false);

        // 0 = clear glass, 100 = almost opaque. Without a backdrop the tint must be fully opaque.
        var strength = backdrop == WindowBackdropType.None ? 1.0 : Math.Clamp(ui.GlassTint, 0, 100) / 100.0;
        var tintAlpha = dark ? 0.35 + 0.6 * strength : 0.25 + 0.65 * strength;
        var resources = Application.Current.Resources;

        resources["BastionTintBrush"] = Frozen(new SolidColorBrush(dark
            ? WithAlpha(Color.FromRgb(0x0A, 0x13, 0x1A), tintAlpha)
            : WithAlpha(Color.FromRgb(0xEE, 0xF3, 0xF6), tintAlpha)));
        resources["BastionGlowABrush"] = Glow(dark ? Color.FromRgb(0x2A, 0xA7, 0xC9) : Color.FromRgb(0x5C, 0xC3, 0xDE), dark ? 0.34 : 0.30, new Point(0.12, 0.1), 0.7, 0.8);
        resources["BastionGlowBBrush"] = Glow(dark ? Color.FromRgb(0x3A, 0x5B, 0xD9) : Color.FromRgb(0x9F, 0xB4, 0xF5), dark ? 0.25 : 0.28, new Point(0.95, 0.95), 0.65, 0.7);
        resources["BastionPanelBrush"] = Frozen(new SolidColorBrush(dark ? Color.FromArgb(0x1A, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0xB8, 0xFF, 0xFF, 0xFF)));
        resources["BastionPanelStrokeBrush"] = Frozen(new SolidColorBrush(dark ? Color.FromArgb(0x24, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0x1F, 0x10, 0x30, 0x40)));
        resources["BastionOrbBrush"] = Frozen(new SolidColorBrush(dark ? Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0xE0, 0xFF, 0xFF, 0xFF)));
    }

    private static Color WithAlpha(Color c, double alpha) => Color.FromArgb((byte)Math.Round(255 * Math.Clamp(alpha, 0, 1)), c.R, c.G, c.B);

    private static Brush Glow(Color color, double alpha, Point center, double rx, double ry)
    {
        var brush = new RadialGradientBrush { Center = center, GradientOrigin = center, RadiusX = rx, RadiusY = ry };
        brush.GradientStops.Add(new GradientStop(WithAlpha(color, alpha), 0));
        brush.GradientStops.Add(new GradientStop(WithAlpha(color, 0), 1));
        return Frozen(brush);
    }

    private static T Frozen<T>(T freezable) where T : Freezable
    {
        freezable.Freeze();
        return freezable;
    }
}
