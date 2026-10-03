using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Core.Runtime;

public static class JsonStore
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Single-line JSON for the pipe protocol.</summary>
    public static readonly JsonSerializerOptions CompactOptions = new(Options) { WriteIndented = false };

    public static T LoadOrDefault<T>(string path) where T : new()
    {
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options) ?? new T();
        }
        catch (Exception)
        {
            // A corrupt file must never stop protection; fall back to defaults.
        }
        return new T();
    }

    public static void Save<T>(string path, T value)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Options));
        File.Move(tmp, path, overwrite: true);
    }
}
