; Bastion Antivirus installer (Inno Setup 6)
; Built by GitHub Actions:  ISCC.exe /DAppVersion=0.2.1 /DSourceDir=..\publish\Bastion installer\Bastion.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish\Bastion"
#endif

#define AppName "Bastion Antivirus"
#define ServiceName "BastionService"

[Setup]
AppId={{6B1E3E52-6A5B-4C6E-9C1E-0B9A57A1B5A1}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=lspx-1
AppPublisherURL=https://github.com/lspx-1/AV
AppSupportURL=https://github.com/lspx-1/AV/issues
DefaultDirName={autopf}\Bastion
DefaultGroupName=Bastion
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\publish
OutputBaseFilename=Bastion-Setup-{#AppVersion}
SetupIconFile=..\src\Bastion.App\Assets\bastion.ico
UninstallDisplayIcon={app}\Bastion.exe
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
CloseApplications=force
RestartApplications=no

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
german.TaskAutostart=Bastion beim Anmelden im Infobereich starten (empfohlen)
english.TaskAutostart=Start Bastion in the notification area at sign-in (recommended)
german.TaskContextMenu=„Mit Bastion scannen“ im Explorer-Kontextmenü
english.TaskContextMenu=„Scan with Bastion“ in the Explorer context menu
german.ScanWithBastion=Mit Bastion scannen
english.ScanWithBastion=Scan with Bastion
german.LaunchBastion=Bastion jetzt öffnen
english.LaunchBastion=Open Bastion now
german.StatusService=Richte den Bastion-Dienst ein ...
english.StatusService=Setting up the Bastion service ...

[Tasks]
Name: "autostart"; Description: "{cm:TaskAutostart}"
Name: "contextmenu"; Description: "{cm:TaskContextMenu}"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "install.ps1,uninstall.ps1"

[Dirs]
; Quarantine, settings and logs: only SYSTEM and administrators (set below with icacls).
Name: "{commonappdata}\Bastion"; Flags: uninsneveruninstall

[Icons]
Name: "{autoprograms}\Bastion"; Filename: "{app}\Bastion.exe"
Name: "{autodesktop}\Bastion"; Filename: "{app}\Bastion.exe"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Bastion"; ValueData: """{app}\Bastion.exe"" --minimized"; Tasks: autostart; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\*\shell\BastionScan"; ValueType: string; ValueName: ""; ValueData: "{cm:ScanWithBastion}"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\BastionScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Bastion.exe"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\*\shell\BastionScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Bastion.exe"" --scan ""%1"""; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BastionScan"; ValueType: string; ValueName: ""; ValueData: "{cm:ScanWithBastion}"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BastionScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Bastion.exe"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\BastionScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Bastion.exe"" --scan ""%1"""; Tasks: contextmenu

[Run]
; Register (or update) the service, make it restart after a crash, lock down the data folder, start it.
Filename: "{sys}\sc.exe"; Parameters: "create {#ServiceName} binPath= ""\""{app}\Bastion.Service.exe\"""" start= auto DisplayName= ""Bastion Antivirus"""; Flags: runhidden; StatusMsg: "{cm:StatusService}"
Filename: "{sys}\sc.exe"; Parameters: "config {#ServiceName} binPath= ""\""{app}\Bastion.Service.exe\"""" start= auto"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""Echtzeitschutz von Bastion Antivirus."""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/30000"; Flags: runhidden
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Bastion"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; Flags: runhidden
Filename: "{sys}\net.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden
Filename: "{app}\Bastion.exe"; Description: "{cm:LaunchBastion}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM Bastion.exe"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{sys}\net.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden; RunOnceId: "DeleteService"
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -Command ""Get-NetFirewallRule -DisplayName 'Bastion Block*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"""; Flags: runhidden; RunOnceId: "FirewallRules"

[Code]
// Stop the running service and tray app before files are replaced, and wait until they are gone.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Bastion.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Bastion.Service.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);
  Result := '';
end;
