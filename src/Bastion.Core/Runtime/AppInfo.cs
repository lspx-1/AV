using System.Reflection;

namespace Bastion.Core.Runtime;

public static class AppInfo
{
    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public const string PipeName = "Bastion.Service.v1";
    public const string ServiceName = "BastionService";
}
