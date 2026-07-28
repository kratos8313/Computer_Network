# ChildSafe Parental Control

ChildSafe is a Windows parental-control application with a boot-time enforcement service and a parent desktop launcher. The service runs independently of the desktop window, applies machine-wide proxy policy, maintains hosts-file rules, and hosts the authenticated dashboard on `127.0.0.1`.

## Architecture

- **ChildSafeService** runs under the Windows Service Control Manager and starts automatically at boot.
- **ChildSafe desktop app** displays protection status and opens the parent dashboard without showing a terminal.
- **Machine-wide proxy enforcement** sets Windows to use `127.0.0.1:8080` for every account and checks the setting every two seconds.
- **Hosts-file enforcement** provides a privileged fallback and is revalidated every minute.
- **Parent dashboard** is bound to localhost, password protected, CSRF protected, and rate-limits failed logins.
- Runtime data is stored under `%ProgramData%\ChildSafe`, where the installer grants access only to Administrators and SYSTEM.

The child should use a standard Windows account. Installation and removal require a parent administrator account.

## Install for normal use

Build or obtain `ChildSafe-Setup.exe`, run it as an administrator, and complete the wizard. The installer:

1. Installs the desktop and service executables.
2. Creates and starts the automatic Windows service.
3. Configures service recovery after unexpected failures.
4. Opens the parent application for first-time password setup.

Closing the desktop application does not stop protection. Uninstalling ChildSafe stops the service and restores the proxy configuration that existed before installation.

## Run from source for development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd CNLabProject
python main.py
```

The source-development entry point uses the current user's proxy settings and is not equivalent to the installed service.

## Build the Windows application

Install build dependencies:

```powershell
pip install -r requirements-build.txt
```

Build the executables only:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -SkipInstaller
```

To produce `installer-output\ChildSafe-Setup.exe`, install Inno Setup 6 and run the build script without `-SkipInstaller`.

## Tests

```powershell
python -m unittest discover -s CNLabProject/tests -v
```

The automated tests do not install a service, change machine proxy policy, or edit the real Windows hosts file.