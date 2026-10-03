using Bastion.Core.Models;

namespace Bastion.App.Helpers;

public static class Format
{
    public static string Time(DateTimeOffset t)
    {
        var local = t.ToLocalTime();
        if (local.Date == DateTime.Today)
            return $"heute, {local:HH:mm}";
        if (local.Date == DateTime.Today.AddDays(-1))
            return $"gestern, {local:HH:mm}";
        return local.ToString("dd.MM.yyyy, HH:mm");
    }

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024:0.#} MB",
        _ => $"{bytes / 1024.0 / 1024 / 1024:0.##} GB",
    };

    public static string Category(EventCategory c) => c switch
    {
        EventCategory.Scan => "Scan",
        EventCategory.Realtime => "Echtzeitschutz",
        EventCategory.Process => "Prozesse",
        EventCategory.Network => "Netzwerk",
        EventCategory.Autostart => "Autostart",
        EventCategory.Hosts => "Hosts-Datei",
        EventCategory.Ransomware => "Ransomware",
        EventCategory.Quarantine => "Quarantäne",
        EventCategory.Update => "Update",
        EventCategory.License => "Lizenz",
        _ => "System",
    };

    public static string Action(string action) => action switch
    {
        EventActions.Quarantine => "In Quarantäne",
        EventActions.Kill => "Prozess beenden",
        EventActions.KillAndQuarantine => "Beenden und Quarantäne",
        EventActions.RemoveAutostart => "Eintrag entfernen",
        EventActions.BlockRemote => "Adresse blockieren",
        EventActions.BlockProgram => "Programm blockieren",
        EventActions.RestoreHosts => "Hosts wiederherstellen",
        EventActions.Exclude => "Als Ausnahme",
        EventActions.Ignore => "Ignorieren",
        _ => action,
    };

    /// <summary>Destructive or protective actions get the primary button style.</summary>
    public static bool IsPrimaryAction(string action) =>
        action is EventActions.Quarantine or EventActions.KillAndQuarantine or EventActions.RemoveAutostart or EventActions.RestoreHosts;
}
