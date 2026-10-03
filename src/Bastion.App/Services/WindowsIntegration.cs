using System.Diagnostics;
using System.ServiceProcess;
using Bastion.Core.Runtime;
using Microsoft.Win32;

namespace Bastion.App.Services;

/// <summary>Start with Windows, Explorer context menu and service status. All per-user, no admin needed.</summary>
public static class WindowsIntegration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "Bastion";
    private static readonly string[] ContextMenuKeys = [@"Software\Classes\*\shell\BastionScan", @"Software\Classes\Directory\shell\BastionScan"];

    public static string ExecutablePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "Bastion.exe");

    public static bool StartWithWindows
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(RunValue) is string;
        }
        set
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (value)
                key.SetValue(RunValue, $"\"{ExecutablePath}\" --minimized");
            else
                key.DeleteValue(RunValue, throwOnMissingValue: false);
        }
    }

    public static bool ExplorerContextMenu
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(ContextMenuKeys[0]);
            return key is not null;
        }
        set
        {
            foreach (var path in ContextMenuKeys)
            {
                if (!value)
                {
                    Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
                    continue;
                }
                using var key = Registry.CurrentUser.CreateSubKey(path);
                key.SetValue("", "Mit Bastion scannen");
                key.SetValue("Icon", $"\"{ExecutablePath}\",0");
                using var command = key.CreateSubKey("command");
                command.SetValue("", $"\"{ExecutablePath}\" --scan \"%1\"");
            }
        }
    }

    public static string ServiceState()
    {
        try
        {
            using var service = new ServiceController(AppInfo.ServiceName);
            return service.Status switch
            {
                ServiceControllerStatus.Running => "Läuft",
                ServiceControllerStatus.Stopped => "Gestoppt",
                ServiceControllerStatus.StartPending => "Startet",
                ServiceControllerStatus.StopPending => "Stoppt",
                _ => service.Status.ToString(),
            };
        }
        catch (InvalidOperationException)
        {
            return "Nicht installiert";
        }
    }

    public static void OpenFolder(string path)
    {
        var target = File.Exists(path) ? $"/select,\"{path}\"" : $"\"{(Directory.Exists(path) ? path : Path.GetDirectoryName(path))}\"";
        Process.Start(new ProcessStartInfo("explorer.exe", target) { UseShellExecute = true });
    }
}
