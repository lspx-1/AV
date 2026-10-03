using Bastion.Core.Protection;

namespace Bastion.Core.Tests;

public class GuardTests
{
    [Fact]
    public void HostsSuspiciousEntries()
    {
        const string hosts = """
            # Copyright (c) Microsoft
            127.0.0.1 localhost
            0.0.0.0 ads.example.com
            203.0.113.9 www.paypal.com
            0.0.0.0 update.microsoft.com # blocks updates
            """;
        var suspicious = HostsGuard.FindSuspicious(hosts);
        Assert.Equal(2, suspicious.Count);
        Assert.Contains(suspicious, l => l.Contains("paypal"));
    }

    [Fact]
    public void CoreAndOwnProcessesAreNeverKilled()
    {
        Assert.True(Platform.ProcessInfo.IsProtected(4, out _));
        Assert.True(Platform.ProcessInfo.IsProtected(Environment.ProcessId, out _));
        Assert.False(Platform.ProcessInfo.TryKill(Environment.ProcessId, out var error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --minimized", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Tools\\tool.exe /background", "C:\\Tools\\tool.exe")]
    public void AutostartPathExtraction(string command, string expected) =>
        Assert.Equal(expected, AutostartGuard.ExtractPath(command));
}
