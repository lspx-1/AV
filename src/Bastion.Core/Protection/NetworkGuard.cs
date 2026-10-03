using Bastion.Core.Models;
using Bastion.Core.Network;

namespace Bastion.Core.Protection;

/// <summary>Runs the network monitor every few seconds and turns findings into events.</summary>
public sealed class NetworkGuard(IProtectionContext context, NetworkMonitor monitor) : ProtectionModuleBase(context)
{
    private Timer? _timer;
    private int _busy;

    public override string Id => "network";
    public override string Name => "Netzwerk & RAT-Schutz";
    public override string Description => "Erkennt Fernsteuerungs-Trojaner, Steuerserver und verdächtige Verbindungen.";

    public override string? Detail
    {
        get
        {
            var current = monitor.Current;
            var risky = current.Count(c => c.Risk >= ConnectionRisk.Suspicious);
            return risky > 0 ? $"{risky} verdächtige Verbindungen" : $"{current.Count} Verbindungen, alle unauffällig";
        }
    }

    protected override void OnStart() =>
        _timer = new Timer(_ => Tick(), null, TimeSpan.Zero, TimeSpan.FromSeconds(3));

    protected override void OnStop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1)
            return;
        try
        {
            foreach (var finding in monitor.Poll(DateTimeOffset.Now))
            {
                var actions = new List<string>();
                if (finding.Severity >= Severity.Medium)
                {
                    actions.Add(finding.ProcessPath is not null ? EventActions.KillAndQuarantine : EventActions.Kill);
                    if (!string.IsNullOrEmpty(finding.RemoteAddress))
                        actions.Add(EventActions.BlockRemote);
                    if (finding.ProcessPath is not null)
                        actions.Add(EventActions.BlockProgram);
                }
                actions.Add(EventActions.Ignore);
                Context.Raise(new SecurityEvent
                {
                    Category = EventCategory.Network,
                    Severity = finding.Severity,
                    Title = finding.Title,
                    Detail = finding.Detail,
                    Target = string.IsNullOrEmpty(finding.RemoteAddress) ? finding.ProcessPath : finding.RemoteAddress,
                    ProcessId = finding.ProcessId,
                    ProgramPath = finding.ProcessPath,
                    Actions = actions,
                });
            }
        }
        catch (Exception e)
        {
            Context.Log("Netzwerkprüfung fehlgeschlagen: " + e.Message);
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }
}
