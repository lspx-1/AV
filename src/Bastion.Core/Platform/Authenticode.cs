using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Bastion.Core.Platform;

public enum SignatureState
{
    Unknown,
    Signed,
    Unsigned,
    Invalid,
}

/// <summary>Checks embedded Authenticode signatures via WinVerifyTrust. Results are cached per path and write time.</summary>
public static class Authenticode
{
    private static readonly ConcurrentDictionary<(string, DateTime), SignatureState> Cache = new();

    public static SignatureState Check(string path)
    {
        if (!OperatingSystem.IsWindows())
            return SignatureState.Unknown;
        DateTime stamp;
        try
        {
            stamp = File.GetLastWriteTimeUtc(path);
        }
        catch (Exception)
        {
            return SignatureState.Unknown;
        }
        return Cache.GetOrAdd((path.ToLowerInvariant(), stamp), _ => Verify(path));
    }

    /// <summary>
    /// Files below the Windows directory are mostly catalog-signed, which WinVerifyTrust on the file alone
    /// does not see. Bastion treats them as trusted for heuristics; hash signatures still apply.
    /// </summary>
    public static bool IsInWindowsDirectory(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return windows.Length > 0 && path.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static SignatureState Verify(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE (offline friendly)
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = filePtr,
                dwStateAction = 0,
                dwProvFlags = 0x00000080, // WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result switch
            {
                0 => SignatureState.Signed,
                unchecked((int)0x800B0100) => SignatureState.Unsigned, // TRUST_E_NOSIGNATURE
                unchecked((int)0x800B0003) => SignatureState.Unsigned, // TRUST_E_SUBJECT_FORM_UNKNOWN
                unchecked((int)0x80092009) => SignatureState.Unsigned, // CRYPT_E_FILE_ERROR / no signature found
                _ => SignatureState.Invalid,
            };
        }
        catch (Exception)
        {
            return SignatureState.Unknown;
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
