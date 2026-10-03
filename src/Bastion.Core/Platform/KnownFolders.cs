namespace Bastion.Core.Platform;

/// <summary>Resolves per-user folders for all local profiles (the service runs as SYSTEM).</summary>
public static class KnownFolders
{
    private static readonly string[] SkipProfiles = ["Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount"];

    public static IEnumerable<string> UserProfiles()
    {
        var current = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!OperatingSystem.IsWindows())
        {
            if (current.Length > 0)
                yield return current;
            yield break;
        }

        var usersRoot = Path.GetDirectoryName(current);
        // When running as SYSTEM the profile lives under System32\config\systemprofile.
        if (usersRoot is null || usersRoot.Contains("system32", StringComparison.OrdinalIgnoreCase))
            usersRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Users");

        if (!Directory.Exists(usersRoot))
            yield break;
        foreach (var dir in Directory.EnumerateDirectories(usersRoot))
        {
            var name = Path.GetFileName(dir);
            if (SkipProfiles.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            if (Directory.Exists(Path.Combine(dir, "AppData")))
                yield return dir;
        }
    }

    public static IEnumerable<string> ForAllUsers(params string[] relative)
    {
        foreach (var profile in UserProfiles())
        {
            var path = Path.Combine([profile, .. relative]);
            if (Directory.Exists(path))
                yield return path;
        }
    }

    /// <summary>Folders an ordinary user can write to. Programs running from here deserve more scrutiny.</summary>
    public static bool IsUserWritableLocation(string path)
    {
        if (string.IsNullOrEmpty(path))
            return false;
        var p = path.Replace('/', '\\');
        return p.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) && !p.Contains(@"\ProgramData\Microsoft\", StringComparison.OrdinalIgnoreCase);
    }

    public static string StartupFolderCommon() =>
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

    public static string HostsFile() =>
        Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
}
