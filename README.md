# ChildSafe Network Control

ChildSafe is a Windows network-access-control application for homes, college labs, classrooms, libraries, and other managed computers, with a boot-time enforcement service and an administrator desktop launcher. The service runs independently of the desktop window, applies machine-wide proxy policy, maintains hosts-file rules, and hosts the authenticated dashboard on `127.0.0.1`.

## Architecture

- **ChildSafeService** runs under the Windows Service Control Manager and starts automatically at boot.
- **ChildSafe desktop app** displays protection status and opens the administrator dashboard without showing a terminal.
- **Machine-wide proxy enforcement** sets Windows to use `127.0.0.1:8080` for every account and checks the setting every two seconds.
- **Hosts-file enforcement** provides a privileged fallback and is revalidated every minute.
- **Administrator dashboard** is bound to localhost, password protected, CSRF protected, and rate-limits failed logins.
- **Administrator controls** can pause and resume enforcement only after the administrator password is re-entered.
- **Guarded uninstall** requires Windows administrator elevation and the administrator password; blocked attempts are logged and can trigger immediate remote notifications.
- **Immediate notifications** can deliver security events to an administrator-configured HTTPS endpoint for email/mobile automation, collaboration tools, or lab monitoring.
- Runtime data is stored under `%ProgramData%\ChildSafe`, where the installer grants access only to Administrators and SYSTEM.

Managed users, including children and students, should use standard Windows accounts. Installation and removal require an administrator account. A Windows administrator can always bypass controls on a local machine, so managed users must not know or control the administrator credentials.

## Install for normal use

Build or obtain `ChildSafe-Setup.exe`, run it as an administrator, and complete the wizard. The installer:

1. Installs the desktop and service executables.
2. Creates and starts the automatic Windows service.
3. Configures service recovery after unexpected failures.
4. Opens the administrator application for first-time password setup.

Closing the desktop application does not stop protection. Uninstalling ChildSafe stops the service, removes its managed hosts-file rules, and restores the proxy configuration that existed before installation.

## Configure immediate notifications

From the administrator dashboard, enter an HTTPS notification URL and an optional bearer secret, then select **Save and Send Test**. The endpoint receives JSON containing the event type, severity, message, computer name, and UTC timestamp. Blocked network activity is notified immediately and repeated attempts to the same domain are grouped for five minutes to prevent alert floods.

The same channel reports invalid administrator-password attempts, protection pauses/resumes, uninstall attempts, and service-stop requests. Without a configured endpoint, these events remain available in the local dashboard and activity logs, but remote notification is not possible.

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