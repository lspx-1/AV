<#
.SYNOPSIS
    Removes Bastion. Quarantine, logs and settings in %ProgramData%\Bastion are kept unless -RemoveData is given.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Bastion",
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BastionService'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Bitte PowerShell als Administrator starten.'
}

Get-Process Bastion -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
}

Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Bastion' -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Bastion.lnk') -ErrorAction SilentlyContinue

# Firewall rules created from the network page.
Get-NetFirewallRule -DisplayName 'Bastion Block*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Start-Sleep -Seconds 1
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

if ($RemoveData) {
    Remove-Item (Join-Path $env:ProgramData 'Bastion') -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Daten und Quarantäne wurden gelöscht.'
} else {
    Write-Host "Quarantäne und Einstellungen bleiben in $env:ProgramData\Bastion erhalten (mit -RemoveData löschen)."
}
Write-Host 'Bastion wurde entfernt.' -ForegroundColor Green
