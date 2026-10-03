// Bastion rules use a YARA-compatible subset. See docs/rules.md.

rule EICAR_Test_File : test
{
    meta:
        description = "EICAR-Testdatei (harmlos, zum Testen des Virenschutzes)"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar and filesize < 256
}
