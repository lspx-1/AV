<#
.SYNOPSIS
    Installs your license public key into Bastion, so it accepts the licenses you issue.
.DESCRIPTION
    The Bastion License Manager calls this script for you ("In Bastion installieren").
    Manually, in an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File .\setup-licensing.ps1 -PublicKey "C:\Pfad\license-public-key.pem"
    Only the PUBLIC key is installed. The private key never leaves the License Manager.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublicKey,
    [string]$InstallDir = "$env:ProgramFiles\Bastion"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BastionService'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Bitte PowerShell als Administrator starten.'
}

if (-not (Test-Path $PublicKey)) {
    Write-Error "Datei nicht gefunden: $PublicKey"
}
$pem = Get-Content -Raw $PublicKey
if ($pem -match 'PRIVATE KEY') {
    Write-Error 'Das ist der PRIVATE Schlüssel. Er darf nie in Bastion installiert oder weitergegeben werden. Nimm license-public-key.pem.'
}
if ($pem -notmatch 'BEGIN PUBLIC KEY') {
    Write-Error 'Die Datei enthält keinen öffentlichen Schlüssel (BEGIN PUBLIC KEY).'
}
if (-not (Test-Path (Join-Path $InstallDir 'Bastion.exe'))) {
    Write-Error "Bastion ist nicht in ${InstallDir} installiert. Installiere Bastion zuerst mit install.ps1."
}

$target = Join-Path $InstallDir 'license-public-key.pem'
Set-Content -Path $target -Value $pem.Trim() -Encoding Ascii
Write-Host "Öffentlicher Schlüssel installiert: ${target}"

if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Write-Host 'Starte den Bastion-Dienst neu ...'
    Restart-Service $serviceName -Force
}

# The tray app reads the key at start; restart it for the logged-on user if it runs.
$app = Join-Path $InstallDir 'Bastion.exe'
$running = Get-Process -Name Bastion -ErrorAction SilentlyContinue
if ($running) {
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    # Started through Explorer so the app runs as the normal user, not elevated.
    Start-Process explorer.exe -ArgumentList "`"$app`""
}

Write-Host ''
Write-Host 'Fertig. Bastion akzeptiert jetzt Lizenzen, die mit deinem Schlüssel ausgestellt wurden.' -ForegroundColor Green
