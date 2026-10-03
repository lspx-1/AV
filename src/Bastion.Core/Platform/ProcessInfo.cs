using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Bastion.Core.Platform;

public static class ProcessInfo
{
    /// <summary>Full image path of a process. Works for most processes, including elevated ones, when running as admin.</summary>
    public static string? GetImagePath(int pid)
    {
        if (pid <= 4)
            return null;
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.MainModule?.FileName;
            }
            catch (Exception)
            {
                return null;
            }
        }

        var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (handle == IntPtr.Zero)
            return null;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public static string? GetName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static DateTime? GetStartTime(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Windows processes whose termination crashes or locks the system. Bastion never ends these.</summary>
    private static readonly string[] ProtectedNames =
    [
        "system", "registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso", "svchost",
        "dwm", "fontdrvhost", "sihost", "ctfmon", "memcompression", "secure system", "msmpeng", "nissrv",
    ];

    /// <summary>
    /// True if ending the process could crash Windows (blue screen) or lock the user out:
    /// processes marked critical by Windows, core system processes and Bastion itself.
    /// </summary>
    public static bool IsProtected(int pid, out string reason)
    {
        reason = "";
        if (pid <= 4)
        {
            reason = "Das ist ein Kernprozess von Windows.";
            return true;
        }
        if (pid == Environment.ProcessId)
        {
            reason = "Bastion beendet sich nicht selbst.";
            return true;
        }
        if (!OperatingSystem.IsWindows())
            return false;

        var path = GetImagePath(pid);
        var name = path is not null ? Path.GetFileNameWithoutExtension(path) : GetName(pid) ?? "";
        var inWindows = path is null || Authenticode.IsInWindowsDirectory(path);
        if (inWindows && ProtectedNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            reason = $"{name} ist ein wichtiger Windows-Prozess. Ihn zu beenden würde Windows abstürzen lassen.";
            return true;
        }

        var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                if (IsProcessCritical(handle, out var critical) && critical)
                {
                    reason = $"{name} ist von Windows als kritisch markiert. Ihn zu beenden würde einen Bluescreen auslösen.";
                    return true;
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        return false;
    }

    public static bool TryKill(int pid, out string? error)
    {
        if (IsProtected(pid, out var reason))
        {
            error = reason;
            return false;
        }
        try
        {
            using var p = Process.GetProcessById(pid);
            // Only this process: ending its whole tree could take down unrelated programs (e.g. everything started from Explorer).
            p.Kill(entireProcessTree: false);
            p.WaitForExit(3000);
            error = null;
            return true;
        }
        catch (Exception e)
        {
            error = e.Message;
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessCritical(IntPtr process, out bool critical);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
