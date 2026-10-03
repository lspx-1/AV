using System.Net;
using System.Net.Sockets;
using Bastion.Core.Models;
using Bastion.Core.Platform;

namespace Bastion.Core.Network;

/// <summary>
/// Looks at which programs talk to the network and flags patterns typical for remote-access trojans (RATs):
/// contact with known command servers, regular "beaconing", hidden listeners in user folders, programs
/// disguised as Windows processes and script hosts talking to the internet. It also points out legitimate
/// remote-support tools, because scammers misuse them.
/// </summary>
public sealed class RemoteAccessAnalyzer(IpBlocklist blocklist, BeaconDetector beacons, Func<string, SignatureState> signatureCheck)
{
    private static readonly string[] SystemProcessNames =
        ["svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit", "taskhostw", "spoolsv", "dllhost", "conhost", "explorer", "sihost", "fontdrvhost"];

    private static readonly string[] ScriptHosts = ["powershell", "pwsh", "wscript", "cscript", "mshta"];

    private static readonly (string Process, string Product)[] RemoteSupportTools =
    [
        ("teamviewer", "TeamViewer"), ("anydesk", "AnyDesk"), ("rustdesk", "RustDesk"), ("screenconnect.clientservice", "ScreenConnect"),
        ("splashtopstreamer", "Splashtop"), ("ultraviewer_desktop", "UltraViewer"), ("logmein", "LogMeIn"), ("remoting_host", "Chrome Remotedesktop"),
        ("quickassist", "Windows-Remotehilfe"), ("supremo", "Supremo"),
    ];

    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            return false;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal || ip.IsIPv6Multicast);
        var b = ip.GetAddressBytes();
        return !(b[0] == 10
                 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                 || (b[0] == 192 && b[1] == 168)
                 || (b[0] == 169 && b[1] == 254)
                 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                 || b[0] >= 224);
    }

    /// <summary>True if a program uses the name of a core Windows process but runs from somewhere else.</summary>
    public static bool IsMasquerading(string processName, string? path)
    {
        if (path is null || !SystemProcessNames.Contains(processName, StringComparer.OrdinalIgnoreCase))
            return false;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (windows.Length == 0)
            return false;
        return !path.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public (ConnectionView View, IReadOnlyList<NetworkFinding> Findings) Analyze(TcpConnection connection, string processName, string? path, DateTimeOffset firstSeen)
    {
        var reasons = new List<string>();
        var findings = new List<NetworkFinding>();
        var risk = ConnectionRisk.None;
        var listening = connection.State == TcpState.Listen;
        var remote = connection.Remote.Address;
        var remoteText = listening ? "" : connection.Remote.ToString();
        var programKey = path ?? processName;

        var signature = path is null ? SignatureState.Unknown
            : Authenticode.IsInWindowsDirectory(path) ? SignatureState.Signed
            : signatureCheck(path);
        var untrusted = signature is SignatureState.Unsigned or SignatureState.Invalid;
        var userFolder = path is not null && KnownFolders.IsUserWritableLocation(path);

        void Raise(ConnectionRisk level, string reason)
        {
            reasons.Add(reason);
            if (level > risk)
                risk = level;
        }

        if (!listening && blocklist.TryMatch(remote, out var source))
        {
            Raise(ConnectionRisk.Dangerous, $"Ziel ist ein bekannter Steuerserver für Schadsoftware ({source})");
            findings.Add(new NetworkFinding($"c2:{programKey}:{remote}", Severity.Critical,
                "Verbindung zu bekanntem Steuerserver",
                $"{processName} ist mit {remote} verbunden. Diese Adresse steht auf der Blockliste {source}.",
                connection.ProcessId, path, remote.ToString()));
        }

        if (IsMasquerading(processName, path))
        {
            Raise(ConnectionRisk.Dangerous, "Gibt sich als Windows-Prozess aus, läuft aber aus einem anderen Ordner");
            findings.Add(new NetworkFinding($"masq:{programKey}", Severity.High,
                "Getarnter Prozess mit Netzwerkzugriff",
                $"{processName}.exe läuft aus {path} statt aus dem Windows-Ordner und nutzt das Netzwerk.",
                connection.ProcessId, path, remoteText));
        }

        if (!listening && IsPublic(remote))
        {
            var beacon = beacons.Evaluate(programKey, remote.ToString());
            if (beacon is not null && (untrusted || userFolder))
            {
                Raise(ConnectionRisk.Dangerous, $"Meldet sich regelmäßig alle {beacon.Interval.TotalSeconds:0} s beim selben Server");
                findings.Add(new NetworkFinding($"beacon:{programKey}:{remote}", Severity.High,
                    "Verdacht auf Fernsteuerungs-Trojaner (RAT)",
                    $"{processName} baut alle {beacon.Interval.TotalSeconds:0} Sekunden eine Verbindung zu {remote} auf ({beacon.Connections} Mal). " +
                    "So fragen ferngesteuerte Schadprogramme nach neuen Befehlen.",
                    connection.ProcessId, path, remote.ToString()));
            }

            if (ScriptHosts.Contains(processName, StringComparer.OrdinalIgnoreCase))
            {
                Raise(ConnectionRisk.Suspicious, "Skript-Programm baut eine Internetverbindung auf");
                findings.Add(new NetworkFinding($"script:{processName}:{remote}", Severity.Medium,
                    "Skript verbindet sich mit dem Internet",
                    $"{processName} ist mit {remote} verbunden. Skripte, die Daten nachladen, sind ein häufiger Infektionsweg.",
                    connection.ProcessId, path, remote.ToString()));
            }
            else if (untrusted && userFolder)
            {
                Raise(ConnectionRisk.Info, "Unsigniertes Programm aus einem Benutzerordner");
            }
        }

        if (listening && untrusted && userFolder && !IPAddress.IsLoopback(connection.Local.Address))
        {
            Raise(ConnectionRisk.Suspicious, $"Wartet auf eingehende Verbindungen an Port {connection.Local.Port}");
            findings.Add(new NetworkFinding($"listen:{programKey}:{connection.Local.Port}", Severity.Medium,
                "Unbekanntes Programm öffnet einen Port",
                $"{processName} aus {path} wartet an Port {connection.Local.Port} auf Verbindungen von außen. Hintertüren arbeiten so.",
                connection.ProcessId, path, null));
        }

        var tool = RemoteSupportTools.FirstOrDefault(t => processName.StartsWith(t.Process, StringComparison.OrdinalIgnoreCase));
        if (tool.Product is not null && connection.State == TcpState.Established && IsPublic(remote))
        {
            Raise(ConnectionRisk.Info, $"Fernwartung ({tool.Product}) ist verbunden");
            findings.Add(new NetworkFinding($"rat-tool:{tool.Product}", Severity.Info,
                $"{tool.Product} ist aktiv",
                $"Eine Fernwartungssitzung über {tool.Product} läuft. Wenn du sie nicht selbst gestartet hast oder dich jemand am Telefon dazu aufgefordert hat, beende sie sofort.",
                connection.ProcessId, path, remote.ToString()));
        }

        var view = new ConnectionView
        {
            ProcessId = connection.ProcessId,
            ProcessName = processName,
            ProcessPath = path,
            Signed = signature switch { SignatureState.Signed => true, SignatureState.Unknown => null, _ => false },
            LocalEndpoint = connection.Local.ToString(),
            RemoteEndpoint = remoteText,
            RemoteAddress = listening ? "" : remote.ToString(),
            State = connection.State.ToString(),
            IsListening = listening,
            FirstSeen = firstSeen,
            Risk = risk,
            Reasons = reasons,
        };
        return (view, findings);
    }
}
