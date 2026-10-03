using Bastion.Core.Runtime;

namespace Bastion.App.Services;

public enum ThemeChoice
{
    System,
    Light,
    Dark,
}

public enum BackdropChoice
{
    Acrylic,
    Mica,
    None,
}

/// <summary>Per-user UI preferences (the engine settings live in the service).</summary>
public sealed class UiSettings
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bastion", "ui.json");

    public ThemeChoice Theme { get; set; } = ThemeChoice.System;
    public BackdropChoice Backdrop { get; set; } = BackdropChoice.Acrylic;
    /// <summary>How strongly the glass is tinted: 0 = very transparent, 100 = nearly solid.</summary>
    public int GlassTint { get; set; } = 55;

    public bool ShowNotifications { get; set; } = true;
    public bool CloseToTray { get; set; } = true;

    public static UiSettings Load() => JsonStore.LoadOrDefault<UiSettings>(FilePath);

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        JsonStore.Save(FilePath, this);
    }
}
