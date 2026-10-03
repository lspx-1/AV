using Bastion.Core.Runtime;
using Bastion.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = AppInfo.ServiceName);
builder.Services.AddHostedService<ProtectionWorker>();
builder.Logging.AddEventLog(settings => settings.SourceName = "Bastion");

builder.Build().Run();
