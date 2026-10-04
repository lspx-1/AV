// Remote-access trojan (RAT) families. Strings are typical class/namespace names, mutex names and
// config keys that survive recompilation. Medium = reported, high = quarantined automatically.

rule RAT_AsyncRAT_Family : rat
{
    meta:
        description = "AsyncRAT / DcRAT / VenomRAT (.NET-Fernsteuerung)"
        severity = "high"
    strings:
        $a1 = "AsyncClient" ascii wide
        $a2 = "Anti_Analysis" ascii wide
        $a3 = "Pastebin" ascii wide
        $a4 = "Select * from Win32_ComputerSystem" ascii wide
        $a5 = "HWID" ascii wide
        $a6 = "MutexControl" ascii wide
        $a7 = "Plugin.Plugin" ascii wide
    condition:
        is_pe and 4 of them and filesize < 5MB
}

rule RAT_Quasar_Family : rat
{
    meta:
        description = "Quasar RAT (.NET-Fernsteuerung)"
        severity = "high"
    strings:
        $q1 = "Quasar.Common" ascii wide
        $q2 = "xClient" ascii wide
        $q3 = "Quasar Client Startup" ascii wide
        $q4 = "GetKeyloggerLogsResponse" ascii wide
        $q5 = "DoShellExecute" ascii wide
        $q6 = "DoAskElevate" ascii wide
    condition:
        is_pe and 2 of them and filesize < 5MB
}

rule RAT_njRAT_Family : rat
{
    meta:
        description = "njRAT / Bladabindi / NYAN CAT"
        severity = "high"
    strings:
        $n1 = "netsh firewall add allowedprogram" ascii wide nocase
        $n2 = "SEE_MASK_NOZONECHECKS" ascii wide
        $n3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $n4 = "Bladabindi" ascii wide
        $n5 = "[kl]" ascii wide
        $n6 = "cmd.exe /k ping 0 & del" ascii wide nocase
    condition:
        is_pe and ($n4 or ($n1 and $n2) or 3 of them) and filesize < 3MB
}

rule RAT_Remcos : rat
{
    meta:
        description = "Remcos RAT"
        severity = "high"
    strings:
        $r1 = "Remcos" ascii wide
        $r2 = "Breaking-Security.Net" ascii wide nocase
        $r3 = "Remcos_Mutex_Inj" ascii wide
        $r4 = "licence.dat" ascii wide nocase
        $r5 = "Uploading file to C&C" ascii wide
    condition:
        is_pe and 2 of them and filesize < 5MB
}

rule RAT_NanoCore : rat
{
    meta:
        description = "NanoCore RAT"
        severity = "high"
    strings:
        $c1 = "NanoCore.ClientPlugin" ascii wide
        $c2 = "NanoCore Client" ascii wide
        $c3 = "ClientPluginHost" ascii wide
        $c4 = "IClientNetwork" ascii wide
    condition:
        is_pe and 2 of them and filesize < 5MB
}

rule RAT_Generic_Capabilities : rat generic
{
    meta:
        description = "Fernsteuerungs-Funktionen in einem Programm (Tastatur, Bildschirm, Webcam, Shell)"
        severity = "medium"
    strings:
        $k1 = "keylogger" ascii wide nocase
        $k2 = "GetAsyncKeyState" ascii wide
        $s1 = "screenshot" ascii wide nocase
        $s2 = "webcam" ascii wide nocase
        $p1 = "remote shell" ascii wide nocase
        $p2 = "reverse shell" ascii wide nocase
        $p3 = "cmd.exe /c" ascii wide nocase
        $f1 = "file manager" ascii wide nocase
        $c2 = "heartbeat" ascii wide nocase
    condition:
        is_pe and 1 of ($k*) and 1 of ($s*) and 1 of ($p*) and 1 of ($f*, $c2) and filesize < 8MB
}
