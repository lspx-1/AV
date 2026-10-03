using Bastion.Core.Models;
using Bastion.Core.Runtime;
using Bastion.Core.Scanning;

namespace Bastion.Core.Protection;

public interface IProtectionModule : IDisposable
{
    string Id { get; }
    string Name { get; }
    string Description { get; }
    bool Running { get; }

    /// <summary>Short live status for the UI, e.g. "214 Prozesse heute bewertet".</summary>
    string? Detail { get; }

    void Start();
    void Stop();
}

/// <summary>What protection modules may use from the host.</summary>
public interface IProtectionContext
{
    BastionSettings Settings { get; }
    BastionPaths Paths { get; }
    ScanEngine Engine { get; }

    /// <summary>True while another antivirus product handles on-access scanning.</summary>
    bool ComplementaryModeActive { get; }

    void Raise(SecurityEvent securityEvent);

    /// <summary>Reports a malicious scan result and applies the automatic response (quarantine etc.).</summary>
    SecurityEvent? HandleDetection(FileScanResult result, EventCategory category, int? processId = null);

    void Log(string message);
}

public abstract class ProtectionModuleBase(IProtectionContext context) : IProtectionModule
{
    protected IProtectionContext Context { get; } = context;

    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }
    public bool Running { get; private set; }
    public virtual string? Detail => null;

    public void Start()
    {
        if (Running)
            return;
        try
        {
            OnStart();
            Running = true;
        }
        catch (Exception e)
        {
            Context.Log($"{Name} konnte nicht starten: {e.Message}");
            Context.Raise(new SecurityEvent
            {
                Category = EventCategory.System,
                Severity = Severity.Low,
                Title = $"{Name} konnte nicht starten",
                Detail = e.Message,
            });
        }
    }

    public void Stop()
    {
        if (!Running)
            return;
        Running = false;
        try
        {
            OnStop();
        }
        catch (Exception e)
        {
            Context.Log($"{Name} konnte nicht sauber stoppen: {e.Message}");
        }
    }

    /// <summary>
    /// Runs a callback from a timer, file watcher or WMI event. An exception there would otherwise end the
    /// whole service process (and with it every connection to the app), so it is logged and swallowed.
    /// </summary>
    protected void Safe(string what, Action action)
    {
        try
        {
            action();
        }
        catch (Exception e)
        {
            Context.Log($"{Name}: {what} fehlgeschlagen: {e.GetType().Name}: {e.Message}");
        }
    }

    protected abstract void OnStart();
    protected abstract void OnStop();

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
