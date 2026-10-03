<#
.SYNOPSIS
    Installs Bastion: copies the program, registers the Bastion service and starts it.
.DESCRIPTION
    Run from the unpacked release folder in an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Bastion"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BastionService'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Bitte PowerShell als Administrator starten.'
}

$source = $PSScriptRoot
if (-not (Test-Path (Join-Path $source 'Bastion.Service.exe'))) {
    Write-Error "Bastion.Service.exe nicht gefunden in $source. Starte das Skript aus dem entpackten Release-Ordner."
}

Write-Host 'Stoppe laufende Bastion-Instanzen ...'
$service = Get-Service $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
    try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20)) } catch { }
}
# The tray app runs in every logged-on session; end it and wait until its files are released.
$apps = Get-Process -Name Bastion, Bastion.Service -ErrorAction SilentlyContinue
if ($apps) {
    $apps | Stop-Process -Force -ErrorAction SilentlyContinue
    $apps | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
}

Write-Host "Kopiere Dateien nach ${InstallDir} ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$copied = $false
for ($attempt = 1; $attempt -le 5 -and -not $copied; $attempt++) {
    try {
        Copy-Item -Path (Join-Path $source '*') -Destination $InstallDir -Recurse -Force -ErrorAction Stop
        $copied = $true
    } catch {
        if ($attempt -eq 5) {
            # Do not leave the PC unprotected: start the previous version again before giving up.
            if (Get-Service $serviceName -ErrorAction SilentlyContinue) { Start-Service $serviceName -ErrorAction SilentlyContinue }
            Write-Error "Dateien sind noch in Benutzung: $($_.Exception.Message) Beende Bastion im Infobereich (Rechtsklick > Beenden) und starte das Skript erneut."
        }
        Get-Process -Name Bastion -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

# Program Files is admin-only, which the service relies on to trust the app that connects to it.
$serviceExe = Join-Path $InstallDir 'Bastion.Service.exe'
if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
    Write-Host 'Registriere den Bastion-Dienst ...'
    New-Service -Name $serviceName -BinaryPathName "`"$serviceExe`"" -DisplayName 'Bastion Antivirus' `
        -Description 'Echtzeitschutz von Bastion Antivirus.' -StartupType Automatic | Out-Null
}
# Restart automatically if the service crashes.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

# Data folder: only SYSTEM and administrators may change quarantine, settings and logs.
$data = Join-Path $env:ProgramData 'Bastion'
New-Item -ItemType Directory -Force -Path $data | Out-Null
icacls $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

Write-Host 'Starte den Dienst ...'
Start-Service $serviceName

# Tray app for every user at logon, plus a start menu entry.
$appExe = Join-Path $InstallDir 'Bastion.exe'
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Bastion' -Value "`"$appExe`" --minimized"
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Bastion.lnk'))
$link.TargetPath = $appExe
$link.WorkingDirectory = $InstallDir
$link.Description = 'Bastion Antivirus'
$link.Save()

Write-Host ''
Write-Host 'Bastion ist installiert und der Echtzeitschutz läuft.' -ForegroundColor Green
Start-Process $appExe
