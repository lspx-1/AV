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

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --minimized", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Tools\\tool.exe /background", "C:\\Tools\\tool.exe")]
    public void AutostartPathExtraction(string command, string expected) =>
        Assert.Equal(expected, AutostartGuard.ExtractPath(command));
}
