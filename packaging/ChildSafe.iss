#define AppName "ChildSafe Network Control"
#define AppVersion "1.1.0"
#define ServiceName "ChildSafeService"

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
CloseApplications=no
RestartApplications=no
UninstallDisplayName={#AppName}

[Dirs]
Name: "{commonappdata}\ChildSafe"; Permissions: admins-full system-full

[Files]
Source: "..\dist\ChildSafe\*"; DestDir: "{app}\Desktop"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ChildSafeService\*"; Excludes: "ChildSafeService.exe"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ChildSafeService\ChildSafeService.exe"; DestDir: "{app}\Service"; Flags: ignoreversion; AfterInstall: InstallService
Source: "..\dist\ChildSafeUninstallGuard\*"; DestDir: "{app}\Guard"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ChildSafe"; Filename: "{app}\Desktop\ChildSafe.exe"
Name: "{autodesktop}\ChildSafe"; Filename: "{app}\Desktop\ChildSafe.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Desktop\ChildSafe.exe"; Description: "Open ChildSafe"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "CleanupPolicy"
Filename: "{app}\Service\ChildSafeService.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeUninstall: Boolean;
var
  GuardExe: String;
  ResultCode: Integer;
begin
  GuardExe := ExpandConstant('{app}\Guard\ChildSafeUninstallGuard.exe');
  ResultCode := -1;
  Result := FileExists(GuardExe) and
    Exec(GuardExe, '', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) and
    (ResultCode = 0);
  if not Result then
    MsgBox('ChildSafe uninstall was blocked. An administrator must enter the network control password.',
      mbError, MB_OK);
end;
function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#ServiceName}', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if ServiceExists then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
    Sleep(3000);
  end;
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
begin
  ServiceExe := ExpandConstant('{app}\Service\ChildSafeService.exe');
  if ServiceExists then
    ExecRequired(ServiceExe, '--startup auto update', 'Could not update the ChildSafe Windows service')
  else
    ExecRequired(ServiceExe, '--startup auto install', 'Could not install the ChildSafe Windows service');

  ExecRequired(ExpandConstant('{sys}\sc.exe'),
    'failure {#ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/30000',
    'Could not configure ChildSafe service recovery');
  ExecRequired(ServiceExe, 'start', 'Could not start the ChildSafe Windows service');

  if not ServiceExists then
    RaiseException('ChildSafe service registration could not be verified.');
end;