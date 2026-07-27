# Computer Network — Parental Control Proxy

A Windows parental-control application that combines a localhost HTTP/HTTPS proxy, managed hosts-file rules, and an authenticated Flask dashboard.

## Requirements

- Windows 10 or 11
- Python 3.10+
- Administrator access for hosts-file updates

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd CNLabProject
python main.py
```

On first launch, choose a password of at least eight characters. Open `http://127.0.0.1:5000` to manage rules. The dashboard session secret, password database, settings, and logs are created locally and are ignored by Git.

## Safety behavior

- The original Windows proxy configuration is restored on shutdown.
- Windows is only pointed at the proxy after the listener starts successfully.
- Proxy requests are restricted to web ports and public destinations.
- Hosts-file updates use a backup and atomic replacement.
- Dashboard mutations require authenticated POST requests with CSRF tokens.

If the application is interrupted, rerun it and stop it normally to restore the proxy. A hosts-file backup is stored beside the Windows hosts file as `hosts.parental-control.bak`.

## Tests

```powershell
python -m unittest discover -s CNLabProject/tests -v
```

The tests do not modify the Windows registry, proxy settings, or system hosts file.
