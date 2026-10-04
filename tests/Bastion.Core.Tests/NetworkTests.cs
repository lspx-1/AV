using System.Net;
using Bastion.Core.Models;
using Bastion.Core.Network;
using Bastion.Core.Platform;

namespace Bastion.Core.Tests;

public class NetworkTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.20.1.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.3.3", false)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("::1", false)]
    public void PublicAddressDetection(string ip, bool expected) =>
        Assert.Equal(expected, RemoteAccessAnalyzer.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public void RegularIntervalsAreBeaconing()
    {
        var detector = new BeaconDetector();
        var t = DateTimeOffset.Now;
        for (var i = 0; i < 8; i++)
            detector.RecordConnection("evil.exe", "203.0.113.5", t.AddSeconds(i * 30 + (i % 2)));
        var result = detector.Evaluate("evil.exe", "203.0.113.5");
        Assert.NotNull(result);
        Assert.InRange(result!.Interval.TotalSeconds, 29, 31);
    }

    [Fact]
    public void IrregularIntervalsAreNotBeaconing()
    {
        var detector = new BeaconDetector();
        var t = DateTimeOffset.Now;
        int[] offsets = [0, 7, 60, 64, 200, 260, 500, 505];
        foreach (var o in offsets)
            detector.RecordConnection("browser.exe", "203.0.113.5", t.AddSeconds(o));
        Assert.Null(detector.Evaluate("browser.exe", "203.0.113.5"));
    }

    [Fact]
    public void JitteredIntervalsWithOutlierAreBeaconing()
    {
        var detector = new BeaconDetector();
        var t = DateTimeOffset.Now;
        // ~60 s with +-25 % jitter and one missed poll
        double[] gaps = [52, 71, 58, 66, 49, 130, 63, 55];
        var at = 0.0;
        detector.RecordConnection("rat.exe", "203.0.113.9", t);
        foreach (var g in gaps)
            detector.RecordConnection("rat.exe", "203.0.113.9", t.AddSeconds(at += g));
        var result = detector.Evaluate("rat.exe", "203.0.113.9");
        Assert.NotNull(result);
        Assert.InRange(result!.Interval.TotalSeconds, 50, 70);
    }

    [Fact]
    public void RatCapabilitiesNeedSeveralTraits()
    {
        var one = new HashSet<string> { "GetAsyncKeyState" };
        var several = new HashSet<string> { "GetAsyncKeyState", "BitBlt", "GetDC", "SendInput" };
        Assert.Single(Bastion.Core.Heuristics.HeuristicDetector.RatCapabilities(one));
        Assert.Equal(3, Bastion.Core.Heuristics.HeuristicDetector.RatCapabilities(several).Count);
    }

    private static TcpConnection Conn(string remote, int pid = 77, int port = 51000) =>
        new(new IPEndPoint(IPAddress.Parse("192.168.1.2"), port), new IPEndPoint(IPAddress.Parse(remote), 443), TcpState.Established, pid);

    [Fact]
    public void RenamedRemoteSupportToolIsFlagged()
    {
        var analyzer = new RemoteAccessAnalyzer(new IpBlocklist(), new BeaconDetector(), _ => SignatureState.Signed, null,
            _ => "AnyDesk|AnyDesk Software|AnyDesk|AnyDesk.exe|philandro Software GmbH");
        var (view, findings) = analyzer.Analyze(Conn("198.51.100.20"), "svchosts", @"C:\Users\a\AppData\Local\Temp\svchosts.exe", DateTimeOffset.Now);
        Assert.Equal(ConnectionRisk.Dangerous, view.Risk);
        Assert.Contains(findings, f => f.Key.StartsWith("rat-tool-renamed:", StringComparison.Ordinal) && f.Severity == Severity.High);
    }

    [Fact]
    public void InstalledSignedRemoteToolOnlyInforms()
    {
        var analyzer = new RemoteAccessAnalyzer(new IpBlocklist(), new BeaconDetector(), _ => SignatureState.Signed);
        var (view, findings) = analyzer.Analyze(Conn("198.51.100.20"), "AnyDesk", @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", DateTimeOffset.Now);
        Assert.Equal(ConnectionRisk.Info, view.Risk);
        Assert.All(findings, f => Assert.Equal(Severity.Info, f.Severity));
    }

    [Fact]
    public void PortableRemoteToolInUserFolderIsSuspicious()
    {
        var analyzer = new RemoteAccessAnalyzer(new IpBlocklist(), new BeaconDetector(), _ => SignatureState.Unsigned);
        var (_, findings) = analyzer.Analyze(Conn("198.51.100.20"), "AnyDesk", @"C:\Users\a\Downloads\AnyDesk.exe", DateTimeOffset.Now);
        Assert.Contains(findings, f => f.Key.StartsWith("rat-tool-portable:", StringComparison.Ordinal) && f.Severity == Severity.Medium);
    }

    [Theory]
    [InlineData("evil.duckdns.org", true)]
    [InlineData("duckdns.org", true)]
    [InlineData("host.ddns.net.", true)]
    [InlineData("example.com", false)]
    [InlineData("notduckdns.org", false)]
    public void DynamicDnsSuffixes(string host, bool expected) => Assert.Equal(expected, DynamicDnsWatcher.IsDynamicDns(host));

    [Fact]
    public void ConnectionToDynamicDnsHostIsReported()
    {
        var watcher = new DynamicDnsWatcher(() => ["c2.duckdns.org", "example.com"], _ => [IPAddress.Parse("198.51.100.30")]);
        watcher.Refresh();
        Assert.Equal("c2.duckdns.org", watcher.HostFor(IPAddress.Parse("198.51.100.30")));

        var analyzer = new RemoteAccessAnalyzer(new IpBlocklist(), new BeaconDetector(), _ => SignatureState.Unsigned, watcher);
        var (_, findings) = analyzer.Analyze(Conn("198.51.100.30"), "client", @"C:\Users\a\AppData\Roaming\client.exe", DateTimeOffset.Now);
        Assert.Contains(findings, f => f.Key.StartsWith("ddns:", StringComparison.Ordinal));
    }

    [Fact]
    public void AutostartPlusNetworkIsCorrelatedOnce()
    {
        var c = new Bastion.Core.Protection.PersistenceCorrelator();
        var now = DateTimeOffset.Now;
        Assert.Null(c.NoteNetwork(@"C:\Users\a\x.exe", "198.51.100.1:443", 5, now));
        var link = c.NoteAutostart(@"c:\users\a\X.EXE", @"HKCU\Run\x", "x.exe", now.AddSeconds(5));
        Assert.NotNull(link);
        Assert.Equal(5, link!.ProcessId);
        Assert.Null(c.NoteNetwork(@"C:\Users\a\x.exe", "198.51.100.1:443", 5, now.AddSeconds(10)));
    }

    [Fact]
    public void CorrelationExpiresAfterWindow()
    {
        var c = new Bastion.Core.Protection.PersistenceCorrelator(TimeSpan.FromHours(1));
        var now = DateTimeOffset.Now;
        c.NoteAutostart(@"C:\a.exe", @"HKCU\Run\a", "a.exe", now);
        Assert.Null(c.NoteNetwork(@"C:\a.exe", "198.51.100.1:443", 1, now.AddHours(2)));
    }

    [Fact]
    public void BlocklistedRemoteIsDangerous()
    {
        var blocklist = new IpBlocklist();
        blocklist.Add("203.0.113.66", "test-feed");
        var analyzer = new RemoteAccessAnalyzer(blocklist, new BeaconDetector(), _ => SignatureState.Signed);
        var connection = new TcpConnection(new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000), new IPEndPoint(IPAddress.Parse("203.0.113.66"), 443), TcpState.Established, 1234);

        var (view, findings) = analyzer.Analyze(connection, "updater", @"C:\Program Files\X\updater.exe", DateTimeOffset.Now);
        Assert.Equal(ConnectionRisk.Dangerous, view.Risk);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void MonitorReportsBeaconOnceForUnsignedProgram()
    {
        var blocklist = new IpBlocklist();
        var beacons = new BeaconDetector();
        var analyzer = new RemoteAccessAnalyzer(blocklist, beacons, _ => SignatureState.Unsigned);
        var port = 40000;
        var remote = new IPEndPoint(IPAddress.Parse("198.51.100.7"), 8443);
        var monitor = new NetworkMonitor(analyzer, beacons, () =>
            [new TcpConnection(new IPEndPoint(IPAddress.Parse("192.168.1.2"), port), remote, TcpState.Established, 4242)],
            _ => ("client", @"C:\Users\a\AppData\Roaming\client.exe"));

        var t = DateTimeOffset.Now;
        var findings = new List<NetworkFinding>();
        for (var i = 0; i < 10; i++)
        {
            port++; // every poll sees a fresh connection, like a program that reconnects every 20 s
            findings.AddRange(monitor.Poll(t.AddSeconds(i * 20)));
        }
        Assert.Single(findings, f => f.Key.StartsWith("beacon:", StringComparison.Ordinal));
    }

    [Fact]
    public void BlocklistParsesFeedFormat()
    {
        var file = Path.Combine(TestFiles.TempDir(), "feed.txt");
        File.WriteAllText(file, "# Feodo\n203.0.113.1\n198.51.100.2,botnet\nnonsense\n");
        var list = new IpBlocklist();
        list.LoadFile(file);
        Assert.Equal(2, list.Count);
        Assert.True(list.TryMatch(IPAddress.Parse("198.51.100.2"), out _));
    }
}
