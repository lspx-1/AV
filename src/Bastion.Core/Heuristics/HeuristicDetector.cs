using Bastion.Core.Models;
using Bastion.Core.Platform;
using Bastion.Core.Scanning;

namespace Bastion.Core.Heuristics;

/// <summary>
/// Scores suspicious traits of a file. Every trait adds points; the file is reported once the
/// total reaches the threshold for the configured sensitivity. Heuristics never act alone on
/// signed files or files in the Windows directory.
/// </summary>
public sealed class HeuristicDetector(Func<Sensitivity> sensitivity, Func<string, SignatureState>? signatureCheck = null) : IDetector
{
    private static readonly string[] ExecutableExtensions = [".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".dll", ".cpl"];
    private static readonly string[] DocumentExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar", ".7z"];
    private static readonly string[] PackerSections = ["UPX0", "UPX1", ".aspack", ".adata", ".nsp0", ".nsp1", ".petite", "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1"];

    private readonly Func<string, SignatureState> _signatureCheck = signatureCheck ?? Authenticode.Check;

    public string Name => "Heuristik";

    public static int Threshold(Sensitivity s) => s switch
    {
        Sensitivity.Low => 80,
        Sensitivity.High => 45,
        _ => 60,
    };

    public IEnumerable<Detection> Inspect(FileScanContext context)
    {
        var reasons = new List<string>();
        var score = 0;
        var fileName = context.FileName;

        // Disguised file names: "Rechnung.pdf.exe" or a right-to-left override character.
        if (fileName.Contains('‮'))
        {
            score += 70;
            reasons.Add("Dateiname enthält ein unsichtbares Umkehrzeichen (RTLO)");
        }
        if (HasDoubleExtension(fileName))
        {
            score += 50;
            reasons.Add("Doppelte Dateiendung täuscht ein Dokument vor");
        }

        var pe = context.Pe;
        if (pe is not null && !Authenticode.IsInWindowsDirectory(context.Path))
        {
            var signature = File.Exists(context.Path) ? _signatureCheck(context.Path) : SignatureState.Unknown;
            if (signature == SignatureState.Signed)
            {
                // A valid signature identifies the publisher; content heuristics are skipped.
                return Report(score, reasons);
            }
            if (signature == SignatureState.Invalid)
            {
                score += 30;
                reasons.Add("Digitale Signatur ist ungültig oder manipuliert");
            }

            var packed = pe.Sections.Any(s => PackerSections.Contains(s.Name, StringComparer.OrdinalIgnoreCase));
            if (packed)
            {
                score += 15;
                reasons.Add("Mit einem Packer komprimiert");
            }

            var execHighEntropy = pe.Sections.Where(s => s.IsExecutable && s.RawSize > 1024 && s.RawOffset + s.RawSize <= context.Content.Length)
                .Any(s => Entropy.Shannon(context.Content.AsSpan((int)s.RawOffset, (int)s.RawSize)) > 7.2);
            if (execHighEntropy)
            {
                score += 20;
                reasons.Add("Programmcode ist verschlüsselt oder verschleiert (hohe Entropie)");
            }

            if (pe.Sections.Any(s => s.IsExecutable && s.IsWritable))
            {
                score += 10;
                reasons.Add("Abschnitt ist gleichzeitig beschreibbar und ausführbar");
            }

            if (!pe.IsDotNet && pe.ImportedFunctions.Count is > 0 and < 6 && (packed || execHighEntropy))
            {
                score += 10;
                reasons.Add("Sehr wenige Importe (typisch für gepackte Programme)");
            }

            var imports = pe.ImportedFunctions;
            if (imports.Contains("WriteProcessMemory") && imports.Contains("CreateRemoteThread"))
            {
                score += 30;
                reasons.Add("Kann Code in andere Prozesse schreiben");
            }
            if (imports.Contains("SetWindowsHookExA") || imports.Contains("SetWindowsHookExW"))
            {
                if (imports.Contains("GetAsyncKeyState") || imports.Contains("GetKeyboardState"))
                {
                    score += 25;
                    reasons.Add("Kann Tastatureingaben mitlesen");
                }
            }

            var ratCapabilities = RatCapabilities(imports, pe.ImportedDlls);
            if (ratCapabilities.Count >= 2 && HasNetworkImports(pe))
            {
                score += ratCapabilities.Count >= 3 ? 45 : 30;
                reasons.Add($"Fernsteuerungs-Fähigkeiten und Netzwerkzugriff kombiniert ({string.Join(", ", ratCapabilities)})");
            }

            if (KnownFolders.IsUserWritableLocation(context.Path))
            {
                score += signature == SignatureState.Unsigned ? 10 : 5;
                reasons.Add("Unsigniertes Programm in einem Benutzerordner");
            }
        }

        return Report(score, reasons);
    }

    /// <summary>Capabilities that are typical for remote-access trojans (a harmless tool rarely needs several of them).</summary>
    public static IReadOnlyList<string> RatCapabilities(IReadOnlySet<string> imports, IReadOnlySet<string>? dlls = null)
    {
        var found = new List<string>();
        bool Any(params string[] names) => names.Any(imports.Contains);
        if (Any("GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookExA", "SetWindowsHookExW"))
            found.Add("Tastatur mitlesen");
        if (imports.Contains("BitBlt") && Any("GetDC", "GetWindowDC", "GetDesktopWindow"))
            found.Add("Bildschirm aufnehmen");
        if (Any("SendInput", "keybd_event", "mouse_event", "SetCursorPos"))
            found.Add("Eingaben simulieren");
        if (Any("capCreateCaptureWindowA", "capCreateCaptureWindowW") || (dlls?.Contains("avicap32.dll") ?? false))
            found.Add("Webcam");
        if (Any("waveInOpen", "waveInStart"))
            found.Add("Mikrofon");
        if (imports.Contains("GetClipboardData") && Any("SetClipboardViewer", "AddClipboardFormatListener"))
            found.Add("Zwischenablage überwachen");
        return found;
    }

    private static bool HasNetworkImports(PeFile pe) =>
        pe.ImportedDlls.Any(d => d.Equals("ws2_32.dll", StringComparison.OrdinalIgnoreCase)
                                 || d.Equals("wininet.dll", StringComparison.OrdinalIgnoreCase)
                                 || d.Equals("winhttp.dll", StringComparison.OrdinalIgnoreCase));

    private IEnumerable<Detection> Report(int score, List<string> reasons)
    {
        if (score < Threshold(sensitivity()))
            yield break;
        var severity = score >= 90 ? Severity.High : Severity.Medium;
        yield return new Detection($"Heur.Suspicious.Score{Math.Min(score, 100)}", Name, severity, score, string.Join("; ", reasons));
    }

    public static bool HasDoubleExtension(string fileName)
    {
        var ext = Path.GetExtension(fileName);
        if (!ExecutableExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
            return false;
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(fileName));
        return DocumentExtensions.Contains(inner, StringComparer.OrdinalIgnoreCase);
    }

    public static bool IsExecutableType(string path) =>
        ExecutableExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);
}
