using System.Text;

namespace Bastion.Core.Tests;

internal static class TestFiles
{
    /// <summary>
    /// The EICAR test string, assembled at runtime so this source file itself is not flagged by antivirus software.
    /// </summary>
    public static byte[] Eicar() => Encoding.ASCII.GetBytes(
        string.Concat("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"));

    public static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "bastion-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
