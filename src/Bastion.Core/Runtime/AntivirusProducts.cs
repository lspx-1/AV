using System.Management;

namespace Bastion.Core.Runtime;

/// <summary>Lists other antivirus products registered with Windows Security Center (e.g. Bitdefender).</summary>
public static class AntivirusProducts
{
    public sealed record Product(string Name, bool RealtimeEnabled);

    public static IReadOnlyList<Product> Query()
    {
        if (!OperatingSystem.IsWindows())
            return [];
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            var list = new List<Product>();
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    var name = obj["displayName"]?.ToString() ?? "Unbekannt";
                    var state = Convert.ToUInt32(obj["productState"] ?? 0u);
                    // Byte 2 of productState: 0x10 = real-time protection on.
                    var realtime = ((state >> 8) & 0xF0) == 0x10;
                    list.Add(new Product(name, realtime));
                }
            }
            return list;
        }
        catch (Exception)
        {
            return [];
        }
    }

    /// <summary>Active third-party products. Microsoft Defender does not count: it steps back when another AV is present.</summary>
    public static IReadOnlyList<string> ActiveThirdParty() =>
        Query().Where(p => p.RealtimeEnabled && !p.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase))
               .Select(p => p.Name).Distinct().ToList();
}
