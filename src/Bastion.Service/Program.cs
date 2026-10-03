using Bastion.Core.Runtime;
using Bastion.Service;

// Last resort: write the reason of a crash to the log before Windows restarts the service.
AppDomain.CurrentDomain.UnhandledException += (_, e) =>
{
    try
    {
        var log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bastion", "Logs", "service-crash.log");
        Directory.CreateDirectory(Path.GetDirectoryName(log)!);
        File.AppendAllText(log, $"{DateTime.Now:O} {e.ExceptionObject}\n\n");
    }
    catch (Exception)
    {
    }
};
TaskScheduler.UnobservedTaskException += (_, e) => e.SetObserved();

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = AppInfo.ServiceName);
builder.Services.AddHostedService<ProtectionWorker>();
builder.Logging.AddEventLog(settings => settings.SourceName = "Bastion");

builder.Build().Run();
