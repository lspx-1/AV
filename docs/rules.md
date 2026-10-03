# Writing rules

Bastion's content rules use a subset of the [YARA](https://yara.readthedocs.io/) syntax, so most simple
YARA rules work unchanged. Put rule files (`*.yar`, `*.yara`) into:

* `signatures/rules/` – shipped with Bastion
* `%ProgramData%\Bastion\Signatures\custom-rules\` – your own rules (Pro)

## Example

```yara
rule Suspicious_Invoice_Dropper : downloader
{
    meta:
        description = "Rechnungs-Dokument, das ein Programm nachlädt"
        severity = "high"          // info, low, medium, high, critical
    strings:
        $url  = "http://" nocase
        $exe  = ".exe" ascii wide
        $hdr  = { D0 CF 11 E0 ?? ?? }
    condition:
        $hdr and all of ($url, $exe) and filesize < 5MB
}
```

## Supported

| Feature | Syntax |
|---|---|
| Text strings | `"text"` with escapes `\" \\ \n \t \xNN` |
| Modifiers | `ascii`, `wide` (UTF-16LE), `nocase` (`fullword` is accepted but ignored) |
| Hex strings | `{ 4D 5A ?? 00 }` with `??` wildcards |
| Boolean logic | `and`, `or`, `not`, parentheses |
| Quantifiers | `any of them`, `all of them`, `2 of them`, `1 of ($a*, $b)` |
| File checks | `is_pe`, `filesize < 10MB` (`KB`/`MB`, operators `< <= > >= == !=`) |
| Comments | `//` and `/* … */` |

Not supported (yet): regular expressions, jumps in hex strings (`[2-4]`), `at`/`in`, counts (`#a`),
modules (`pe.`, `math.`), imports and includes. Rules with unsupported syntax are skipped and
listed in `%ProgramData%\Bastion\Logs\bastion.log`.

## Severity

`high` and `critical` hits count as definitive and are quarantined automatically (if enabled).
`medium` and lower are reported and wait for the user's decision.
