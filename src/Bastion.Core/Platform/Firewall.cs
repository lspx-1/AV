using System.Diagnostics;
using System.Net;

namespace Bastion.Core.Platform;

/// <summary>Creates Windows Firewall rules via netsh. Requires administrator rights (the service has them).</summary>
public static class Firewall
{
    public const string RulePrefix = "Bastion Block";

    public static (bool Ok, string Message) BlockRemoteAddress(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed))
            return (false, "Ungültige IP-Adresse.");
        var name = $"{RulePrefix} {parsed}";
        return Run($"advfirewall firewall add rule name=\"{name}\" dir=out action=block remoteip={parsed}",
                   $"Ausgehende Verbindungen zu {parsed} werden jetzt blockiert.");
    }

    public static (bool Ok, string Message) BlockProgram(string path)
    {
        if (!File.Exists(path) || path.Contains('"'))
            return (false, "Programm nicht gefunden.");
        var name = $"{RulePrefix} {Path.GetFileName(path)}";
        return Run($"advfirewall firewall add rule name=\"{name}\" dir=out action=block program=\"{path}\"",
                   $"{Path.GetFileName(path)} darf keine Verbindungen mehr aufbauen.");
    }

    private static (bool Ok, string Message) Run(string arguments, string success)
    {
        if (!OperatingSystem.IsWindows())
            return (false, "Nur unter Windows verfügbar.");
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            })!;
            p.WaitForExit(10_000);
            return p.ExitCode == 0 ? (true, success) : (false, "Firewall-Regel konnte nicht angelegt werden. Dafür sind Administratorrechte nötig.");
        }
        catch (Exception e)
        {
            return (false, e.Message);
        }
    }
}
