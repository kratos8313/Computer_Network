#define AppName "NetGuard Access Control"
#define AppVersion "1.2.0"
#define ServiceName "NetGuardService"
#define LegacyServiceName "ChildSafeService"

[Setup]
AppId={{7E6DA873-271A-4B85-A3AE-147833685E06}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\NetGuard
DefaultGroupName=NetGuard
OutputDir=..\installer-output
OutputBaseFilename=NetGuard-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no
RestartApplications=no
UninstallDisplayName={#AppName}

[Dirs]
Name: "{commonappdata}\NetGuard"; Permissions: admins-full system-full

[Files]
Source: "..\dist\NetGuard\*"; DestDir: "{app}\Desktop"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\NetGuardService\*"; Excludes: "NetGuardService.exe"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\NetGuardService\NetGuardService.exe"; DestDir: "{app}\Service"; Flags: ignoreversion; AfterInstall: InstallService
Source: "..\dist\NetGuardUninstallGuard\*"; DestDir: "{app}\Guard"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetGuard"; Filename: "{app}\Desktop\NetGuard.exe"
Name: "{autodesktop}\NetGuard"; Filename: "{app}\Desktop\NetGuard.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Desktop\NetGuard.exe"; Description: "Open NetGuard"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\Service\NetGuardService.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "stop {#LegacyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopLegacyService"
Filename: "{app}\Service\NetGuardService.exe"; Parameters: "cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "CleanupPolicy"
Filename: "{app}\Service\NetGuardService.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#LegacyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveLegacyService"

[InstallDelete]
Type: files; Name: "{autodesktop}\ChildSafe.lnk"
Type: filesandordirs; Name: "{commonprograms}\ChildSafe"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeUninstall: Boolean;
var
  GuardExe: String;
  ResultCode: Integer;
begin
  GuardExe := ExpandConstant('{app}\Guard\NetGuardUninstallGuard.exe');
  ResultCode := -1;
  Result := FileExists(GuardExe) and
    Exec(GuardExe, '', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) and
    (ResultCode = 0);
  if not Result then
    MsgBox('NetGuard uninstall was blocked. An administrator must enter the network control password.',
      mbError, MB_OK);
end;
function NamedServiceExists(const Name: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query ' + Name, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function ServiceExists: Boolean;
begin
  Result := NamedServiceExists('{#ServiceName}');
end;

function LegacyServiceExists: Boolean;
begin
  Result := NamedServiceExists('{#LegacyServiceName}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if ServiceExists then
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
  if LegacyServiceExists then
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#LegacyServiceName}', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
  if ServiceExists or LegacyServiceExists then
    Sleep(3000);
end;

procedure ExecRequired(const Filename, Parameters, ErrorMessage: String);
var
  ResultCode: Integer;
begin
  ResultCode := -1;
  if (not Exec(Filename, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or
     (ResultCode <> 0) then
  begin
    RaiseException(ErrorMessage + ' (exit code ' + IntToStr(ResultCode) + ').');
  end;
end;

procedure InstallService;
var
  ServiceExe: String;
  ResultCode: Integer;
begin
  ServiceExe := ExpandConstant('{app}\Service\NetGuardService.exe');
  if ServiceExists then
    ExecRequired(ServiceExe, '--startup auto update', 'Could not update the NetGuard Windows service')
  else
    ExecRequired(ServiceExe, '--startup auto install', 'Could not install the NetGuard Windows service');

  ExecRequired(ExpandConstant('{sys}\sc.exe'),
    'failure {#ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/30000',
    'Could not configure NetGuard service recovery');
  ExecRequired(ServiceExe, 'start', 'Could not start the NetGuard Windows service');

  if not ServiceExists then
    RaiseException('NetGuard service registration could not be verified.');

  { Remove the legacy registration only after the replacement is running. }
  if LegacyServiceExists then
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#LegacyServiceName}', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
end;