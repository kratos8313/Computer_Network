#define AppName "ChildSafe Parental Control"
#define AppVersion "1.0.0"

[Setup]
AppId={{7E6DA873-271A-4B85-A3AE-147833685E06}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\ChildSafe
DefaultGroupName=ChildSafe
OutputDir=..\installer-output
OutputBaseFilename=ChildSafe-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
UninstallDisplayName={#AppName}

[Dirs]
Name: "{commonappdata}\ChildSafe"; Permissions: admins-full system-full

[Files]
Source: "..\dist\ChildSafe\*"; DestDir: "{app}\Desktop"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ChildSafeService\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ChildSafe"; Filename: "{app}\Desktop\ChildSafe.exe"
Name: "{autodesktop}\ChildSafe"; Filename: "{app}\Desktop\ChildSafe.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "install --startup auto"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure ChildSafeService reset= 86400 actions= restart/5000/restart/15000/restart/30000"; Flags: runhidden waituntilterminated
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "start"; Flags: runhidden waituntilterminated
Filename: "{app}\Desktop\ChildSafe.exe"; Description: "Open ChildSafe"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"