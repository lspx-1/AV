using Bastion.Core.Ipc;
using Bastion.Core.Runtime;

namespace Bastion.Service;

/// <summary>Runs the protection engine as a Windows service and serves the app over a named pipe.</summary>
public sealed class ProtectionWorker(ILogger<ProtectionWorker> logger) : BackgroundService
{
    private ProtectionHost? _host;
    private PipeServer? _pipe;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _host = new ProtectionHost(BastionPaths.ForService(), runningAsService: true, logger);
        _host.Start();
        _pipe = new PipeServer(_host, message => logger.LogInformation("{Message}", message));
        _pipe.Start();
        logger.LogInformation("Bastion-Dienst {Version} gestartet", AppInfo.Version);
        return Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _pipe?.Dispose();
        _host?.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
