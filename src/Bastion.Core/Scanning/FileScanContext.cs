using System.Security.Cryptography;
using Bastion.Core.Heuristics;

namespace Bastion.Core.Scanning;

/// <summary>Everything detectors need to know about one file. The content is read once and shared.</summary>
public sealed class FileScanContext
{
    private PeFile? _pe;
    private bool _peParsed;
    private byte[]? _lower;

    private FileScanContext(string path, long size, string sha256, byte[] content)
    {
        Path = path;
        Size = size;
        Sha256 = sha256;
        Content = content;
    }

    public string Path { get; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long Size { get; }
    public string Sha256 { get; }

    /// <summary>The file content, or the first <c>maxContentBytes</c> of it.</summary>
    public byte[] Content { get; }

    public PeFile? Pe
    {
        get
        {
            if (!_peParsed)
            {
                _pe = PeFile.TryParse(Content);
                _peParsed = true;
            }
            return _pe;
        }
    }

    /// <summary>ASCII-lowercased copy of the content for case-insensitive rule strings.</summary>
    public byte[] LowerContent
    {
        get
        {
            if (_lower is null)
            {
                var copy = (byte[])Content.Clone();
                for (var i = 0; i < copy.Length; i++)
                {
                    if (copy[i] is >= (byte)'A' and <= (byte)'Z')
                        copy[i] = (byte)(copy[i] + 32);
                }
                _lower = copy;
            }
            return _lower;
        }
    }

    public static FileScanContext Load(string path, long maxContentBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        var size = stream.Length;
        var keep = (int)Math.Min(size, maxContentBytes);
        var content = new byte[keep];
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1 << 16];
        long offset = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.AppendData(buffer, 0, read);
            if (offset < keep)
            {
                var copy = (int)Math.Min(read, keep - offset);
                Buffer.BlockCopy(buffer, 0, content, (int)offset, copy);
            }
            offset += read;
        }
        return new FileScanContext(path, size, Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant(), content);
    }

    /// <summary>For tests and in-memory scanning.</summary>
    public static FileScanContext FromBytes(string path, byte[] content) =>
        new(path, content.Length, Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), content);
}
