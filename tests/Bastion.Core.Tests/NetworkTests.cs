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
