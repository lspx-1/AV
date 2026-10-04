using Bastion.Core.Licensing;
using Bastion.Core.Models;
using Bastion.Core.Network;
using Bastion.Core.Quarantine;
using Bastion.Core.Runtime;
using Bastion.Core.Updates;

namespace Bastion.Core.Ipc;

public sealed record ActionResult(bool Success, string Message);

/// <summary>
/// Everything the UI can ask of the protection engine. Implemented in-process by
/// <see cref="ProtectionHost"/> and over a named pipe by <see cref="PipeClientBackend"/>.
/// </summary>
public interface IBastionBackend
{
    event Action<SecurityEvent>? EventRaised;
    event Action<ScanProgress>? ScanProgressChanged;
    event Action<LicenseStatus>? LicenseChanged;

    Task<StatusSnapshot> GetStatusAsync();
    Task SetModuleEnabledAsync(string moduleId, bool enabled);

    Task<ScanProgress> StartScanAsync(ScanRequest request);
    Task CancelScanAsync();

    Task<IReadOnlyList<SecurityEvent>> GetEventsAsync(int max);
    Task<ActionResult> ExecuteEventActionAsync(Guid eventId, string action);
    /// <summary>
    /// Clears the history. With <paramref name="includeOpen"/> false, findings that still wait for a decision are kept.
    /// </summary>
    Task<int> ClearHistoryAsync(bool includeOpen);

    Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync();
    Task<ActionResult> RestoreQuarantineAsync(Guid id, bool addExclusion);
    Task<ActionResult> DeleteQuarantineAsync(Guid id);

    Task<IReadOnlyList<ConnectionView>> GetConnectionsAsync();
    Task<ActionResult> KillProcessAsync(int pid);
    Task<ActionResult> BlockRemoteAsync(string ip);
    Task<ActionResult> BlockProgramAsync(string path);

    Task<BastionSettings> GetSettingsAsync();
    Task SaveSettingsAsync(BastionSettings settings);

    Task<LicenseStatus> GetLicenseAsync();
    Task<LicenseOperationResult> ActivateLicenseAsync(string key);
    Task<LicenseOperationResult> ImportLicenseAsync(string token);
    Task<LicenseOperationResult> DeactivateLicenseAsync();
    Task<LicenseOperationResult> RefreshLicenseAsync();

    Task<UpdateResult> UpdateSignaturesAsync();
}
