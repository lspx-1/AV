using System.Diagnostics;
using Bastion.Core.Models;
using Bastion.Core.Platform;

namespace Bastion.Core.Scanning;

/// <summary>Decides which files a quick, full or custom scan visits.</summary>
public static class ScanTargets
{
    private static readonly EnumerationOptions Recursive = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
    };

    private static readonly EnumerationOptions TopLevel = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
    };

    public static IEnumerable<string> Enumerate(ScanRequest request, string excludeRoot)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var source = request.Kind switch
        {
            ScanKind.Quick => Quick(),
            ScanKind.Full => Full(),
            _ => Custom(request.Paths ?? []),
        };
        foreach (var file in source)
        {
            if (file.StartsWith(excludeRoot, StringComparison.OrdinalIgnoreCase))
                continue; // never scan our own quarantine
            if (seen.Add(file))
                yield return file;
        }
    }

    /// <summary>Places where malware typically lands or starts from.</summary>
    public static IEnumerable<string> Quick()
    {
        foreach (var path in RunningProcessImages())
            yield return path;

        foreach (var dir in KnownFolders.ForAllUsers("Downloads").Concat(KnownFolders.ForAllUsers("Desktop")))
            foreach (var f in SafeEnumerate(dir, Recursive))
                yield return f;

        foreach (var dir in KnownFolders.ForAllUsers("AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
            foreach (var f in SafeEnumerate(dir, TopLevel))
                yield return f;

        var common = KnownFolders.StartupFolderCommon();
        if (common.Length > 0)
            foreach (var f in SafeEnumerate(common, TopLevel))
                yield return f;

        // Executables directly inside Temp and AppData (not the whole tree, which is huge).
        foreach (var dir in KnownFolders.ForAllUsers("AppData", "Local", "Temp")
                     .Concat(KnownFolders.ForAllUsers("AppData", "Roaming"))
                     .Concat(KnownFolders.ForAllUsers("AppData", "Local")))
        {
            foreach (var f in SafeEnumerate(dir, TopLevel))
                yield return f;
            foreach (var sub in SafeEnumerateDirs(dir))
                foreach (var f in SafeEnumerate(sub, TopLevel).Where(Heuristics.HeuristicDetector.IsExecutableType))
                    yield return f;
        }
    }

    public static IEnumerable<string> Full()
    {
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable))
            foreach (var f in SafeEnumerate(drive.RootDirectory.FullName, Recursive))
                yield return f;
    }

    public static IEnumerable<string> Custom(IEnumerable<string> paths)
    {
        foreach (var p in paths)
        {
            if (File.Exists(p))
                yield return Path.GetFullPath(p);
            else if (Directory.Exists(p))
                foreach (var f in SafeEnumerate(p, Recursive))
                    yield return f;
        }
    }

    public static IEnumerable<string> RunningProcessImages()
    {
        foreach (var process in Process.GetProcesses())
        {
            string? path;
            try
            {
                path = ProcessInfo.GetImagePath(process.Id);
            }
            finally
            {
                process.Dispose();
            }
            if (path is not null && File.Exists(path))
                yield return path;
        }
    }

    private static IEnumerable<string> SafeEnumerate(string dir, EnumerationOptions options)
    {
        try
        {
            return Directory.EnumerateFiles(dir, "*", options);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static IEnumerable<string> SafeEnumerateDirs(string dir)
    {
        try
        {
            return Directory.EnumerateDirectories(dir, "*", TopLevel);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
