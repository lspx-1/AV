using System.Buffers.Binary;
using System.Text;

namespace Bastion.Core.Heuristics;

public sealed record PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics)
{
    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
}

/// <summary>Minimal, bounds-checked parser for Portable Executable headers. Never throws on malformed input.</summary>
public sealed class PeFile
{
    public bool Is64Bit { get; private init; }
    public bool IsDll { get; private init; }
    public bool IsDotNet { get; private init; }
    public bool HasSignatureDirectory { get; private init; }
    public bool HasOverlay { get; private init; }
    public IReadOnlyList<PeSection> Sections { get; private init; } = [];
    public IReadOnlySet<string> ImportedFunctions { get; private init; } = new HashSet<string>();
    public IReadOnlySet<string> ImportedDlls { get; private init; } = new HashSet<string>();

    public static bool LooksLikePe(ReadOnlySpan<byte> data) =>
        data.Length > 0x40 && data[0] == (byte)'M' && data[1] == (byte)'Z';

    public static PeFile? TryParse(byte[] data)
    {
        try
        {
            return Parse(data);
        }
        catch (Exception e) when (e is ArgumentOutOfRangeException or IndexOutOfRangeException or OverflowException)
        {
            return null;
        }
    }

    private static PeFile? Parse(byte[] bytes)
    {
        ReadOnlySpan<byte> data = bytes;
        if (!LooksLikePe(data))
            return null;
        var peOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[0x3C..]);
        if (peOffset <= 0 || peOffset > data.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(data[peOffset..]) != 0x00004550)
            return null;

        var coff = peOffset + 4;
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 2)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 16)..]);
        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data[(coff + 18)..]);
        var optional = coff + 20;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(data[optional..]);
        var is64 = magic == 0x20B;
        if (magic != 0x10B && magic != 0x20B)
            return null;

        var dataDirOffset = optional + (is64 ? 112 : 96);
        var dirCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[(dataDirOffset - 4)..]);
        (uint Rva, uint Size) Dir(int index)
        {
            if (index >= dirCount || dataDirOffset + index * 8 + 8 > bytes.Length)
                return (0, 0);
            var at = dataDirOffset + index * 8;
            return (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + 4)));
        }

        var sections = new List<PeSection>();
        var sectionTable = optional + optionalSize;
        uint endOfRaw = 0;
        for (var i = 0; i < Math.Min(sectionCount, 96); i++)
        {
            var s = sectionTable + i * 40;
            if (s + 40 > data.Length)
                break;
            var name = Encoding.ASCII.GetString(data.Slice(s, 8)).TrimEnd('\0');
            var section = new PeSection(
                name,
                BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 12)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 8)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 20)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 16)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(data[(s + 36)..]));
            sections.Add(section);
            endOfRaw = Math.Max(endOfRaw, section.RawOffset + section.RawSize);
        }

        int RvaToOffset(uint rva)
        {
            foreach (var s in sections)
            {
                var size = Math.Max(s.VirtualSize, s.RawSize);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    var off = rva - s.VirtualAddress + s.RawOffset;
                    return off < bytes.Length ? (int)off : -1;
                }
            }
            return -1;
        }

        string ReadAscii(int offset)
        {
            if (offset < 0 || offset >= bytes.Length)
                return "";
            var end = offset;
            while (end < bytes.Length && end - offset < 256 && bytes[end] != 0)
                end++;
            return Encoding.ASCII.GetString(bytes, offset, end - offset);
        }

        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var import = Dir(1);
        var desc = import.Rva != 0 ? RvaToOffset(import.Rva) : -1;
        for (var d = 0; desc >= 0 && d < 512 && desc + 20 <= data.Length; d++, desc += 20)
        {
            var originalThunk = BinaryPrimitives.ReadUInt32LittleEndian(data[desc..]);
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data[(desc + 12)..]);
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data[(desc + 16)..]);
            if (nameRva == 0)
                break;
            dlls.Add(ReadAscii(RvaToOffset(nameRva)));
            var thunk = RvaToOffset(originalThunk != 0 ? originalThunk : firstThunk);
            var step = is64 ? 8 : 4;
            for (var n = 0; thunk >= 0 && n < 4096 && thunk + step <= data.Length; n++, thunk += step)
            {
                var value = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(data[thunk..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[thunk..]);
                if (value == 0)
                    break;
                var byOrdinal = is64 ? (value & 0x8000000000000000) != 0 : (value & 0x80000000) != 0;
                if (byOrdinal)
                    continue;
                var hint = RvaToOffset((uint)(value & 0x7FFFFFFF));
                if (hint >= 0)
                    functions.Add(ReadAscii(hint + 2));
            }
        }

        var security = Dir(4);
        return new PeFile
        {
            Is64Bit = is64,
            IsDll = (characteristics & 0x2000) != 0,
            IsDotNet = Dir(14).Rva != 0,
            HasSignatureDirectory = security.Rva != 0 && security.Size != 0,
            HasOverlay = endOfRaw > 0 && data.Length > endOfRaw + (security.Size > 0 ? security.Size : 0) + 512,
            Sections = sections,
            ImportedFunctions = functions,
            ImportedDlls = dlls,
        };
    }
}
