using System.IO.Pipes;
using System.Text;

namespace Bastion.App.Services;

/// <summary>Ensures one app per user. A second start (e.g. "Mit Bastion scannen") hands its arguments to the first.</summary>
public sealed class SingleInstance : IDisposable
{
    private readonly string _pipeName = $"Bastion.App.{Environment.UserName}";
    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _cts = new();

    public SingleInstance()
    {
        _mutex = new Mutex(true, $@"Local\Bastion.App.{Environment.UserName}", out var created);
        IsFirst = created;
    }

    public bool IsFirst { get; }

    public event Action<string[]>? ArgumentsReceived;

    public void Listen() => _ = Task.Run(async () =>
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(_pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(_cts.Token);
                using var reader = new StreamReader(server, Encoding.UTF8);
                var text = await reader.ReadToEndAsync(_cts.Token);
                ArgumentsReceived?.Invoke(text.Split('\n', StringSplitOptions.RemoveEmptyEntries));
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
            }
        }
    });

    public static bool Send(string[] args)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", $"Bastion.App.{Environment.UserName}", PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect(2000);
            var bytes = Encoding.UTF8.GetBytes(string.Join('\n', args.Length == 0 ? ["--show"] : args));
            client.Write(bytes);
            return true;
        }
        catch (Exception e) when (e is IOException or TimeoutException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _mutex.Dispose();
    }
}
