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

    public static bool TryKill(int pid, out string? error)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
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
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
