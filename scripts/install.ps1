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

Write-Host 'Stoppe laufende Bastion-Instanzen…'
if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
}
Get-Process Bastion -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Kopiere Dateien nach $InstallDir…"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $InstallDir -Recurse -Force

# Program Files is admin-only, which the service relies on to trust the app that connects to it.
$serviceExe = Join-Path $InstallDir 'Bastion.Service.exe'
if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
    Write-Host 'Registriere den Bastion-Dienst…'
    New-Service -Name $serviceName -BinaryPathName "`"$serviceExe`"" -DisplayName 'Bastion Antivirus' `
        -Description 'Echtzeitschutz von Bastion Antivirus.' -StartupType Automatic | Out-Null
}
# Restart automatically if the service crashes.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

# Data folder: only SYSTEM and administrators may change quarantine, settings and logs.
$data = Join-Path $env:ProgramData 'Bastion'
New-Item -ItemType Directory -Force -Path $data | Out-Null
icacls $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

Write-Host 'Starte den Dienst…'
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
