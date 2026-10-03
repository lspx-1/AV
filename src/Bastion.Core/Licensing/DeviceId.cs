using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Bastion.Core.Licensing;

/// <summary>Stable, anonymous identifier of this Windows installation (hash of the MachineGuid).</summary>
public static class DeviceId
{
    public static string Current { get; } = Compute();

    public static string Name => Environment.MachineName;

    private static string Compute()
    {
        string? guid = null;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                guid = key?.GetValue("MachineGuid") as string;
            }
            catch (Exception)
            {
                // fall through
            }
        }
        guid ??= Environment.MachineName;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("bastion-device:" + guid));
        return Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }
}
