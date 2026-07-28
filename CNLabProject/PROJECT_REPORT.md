# Project Report: ChildSafe Network Control

**Subject:** Computer Networks / System Programming
**Focus:** Network traffic interception, policy enforcement, administrator control, and security event notification

## 1. Project overview

ChildSafe Network Control is a Windows network-access-control application for homes, college computer labs, classrooms, libraries, and other shared or managed computers. An administrator defines website access rules while standard users work without access to the control dashboard or Windows administration tools.

The application supports two common deployments:

- Home use, where a parent or guardian manages a child's access.
- Institutional use, where a lab administrator or instructor manages student access on shared computers.

Its goals are to enforce acceptable-use policies, record denied activity, repair local enforcement settings, and immediately report important security events to a configured remote notification endpoint.

## 2. Main features

- Blacklist mode blocks administrator-selected domains.
- Whitelist mode permits only approved domains.
- The local proxy evaluates HTTP and HTTPS connection requests in real time.
- Managed IPv4 and IPv6 hosts-file entries provide a second enforcement layer.
- An automatic Windows service starts at boot and operates independently of the desktop launcher.
- The password-protected administrator dashboard manages rules, status, logs, pause/resume control, and notifications.
- The uninstall guard requires both Windows elevation and the application administrator password.
- Immediate HTTPS notifications report blocked access, invalid sensitive-action passwords, protection state changes, uninstall attempts, and service-stop requests.
- Repeated alerts for the same blocked domain are grouped for five minutes to prevent notification floods.

## 3. End-to-end flow

1. An administrator signs in to the local dashboard and defines a policy.
2. The dashboard stores normalized rules in SQLite and reapplies enforcement.
3. Windows routes web traffic through the loopback proxy.
4. The proxy extracts the destination domain and asks the rules engine for a decision.
5. Allowed connections are forwarded; blocked connections receive an HTTP 403 response and are logged.
6. A blocked event is immediately sent to the configured notification endpoint with severity, computer name, message, and UTC timestamp.
7. A watchdog periodically restores the proxy and managed hosts-file rules if they change.

## 4. Architecture

| Module | Responsibility |
| --- | --- |
| `service.py` | Runs the application as an automatic Windows service and hosts the local dashboard. |
| `desktop.py` | Shows service/protection status and opens the dashboard without a terminal. |
| `app.py` | Implements authenticated dashboard routes and sensitive administrator controls. |
| `controller.py` | Starts, stops, and monitors the proxy and hosts-file enforcement workers. |
| `rules.py` | Decides whether a destination should be allowed or blocked. |
| `proxy.py` | Intercepts HTTP and HTTPS `CONNECT` traffic and applies rule decisions. |
| `blocker.py` | Maintains the application's marked block in the Windows hosts file. |
| `machine_proxy.py` | Applies and verifies machine-wide Windows proxy settings. |
| `database.py` | Stores settings, password hashes, policies, and activity history. |
| `notifications.py` | Delivers immediate authenticated JSON security alerts over HTTPS. |
| `uninstall_guard.py` | Requires application administrator authentication before removal. |

## 5. Security model

Managed users should use standard Windows accounts. Installation, service control, system proxy changes, hosts-file changes, and removal require Windows administrator rights. The dashboard adds a separate application password and requests it again before pause, resume, notification changes, or uninstall.

The local database and logs are stored under `%ProgramData%\ChildSafe`, with access limited to Administrators and SYSTEM by the installer. Passwords use a modern salted password hash. Dashboard forms use CSRF protection, login attempts are rate-limited, and the web server listens only on `127.0.0.1`.

A Windows administrator ultimately controls the machine and can bypass any local-only product. Therefore, children and lab users must not possess administrator credentials. Enterprise or campus deployments should additionally use centralized identity, device management, and off-device alert collection.

## 6. Notification design

The administrator supplies an HTTPS endpoint and may supply a bearer secret. Events are sent as JSON with these fields: application, event, severity, message, computer, and timestamp. A test alert verifies configuration.

Synchronous delivery is used for uninstall and service-stop events because those processes may exit immediately. Normal blocking and dashboard events use a background sender so traffic handling remains responsive. Delivery success or failure is also recorded locally.

## 7. Limitations

- VPNs, alternate network stacks, direct IP access, DNS-over-HTTPS, and QUIC may require additional operating-system or browser policy controls.
- Alerts require a reachable, administrator-configured HTTPS receiver; without one, events remain local only.
- The program currently manages one Windows computer at a time and does not provide a central fleet dashboard.
- A local Windows administrator cannot be made fully subordinate to software running on the same computer.

## 8. Future improvements

- A central console for deploying policies and reviewing many lab computers.
- Native email, Teams, Slack, and mobile push integrations.
- Signed policy updates and device enrollment.
- Browser policy management for private browsing, DoH, QUIC, and extension control.
- Role-based administration and scheduled policies for classes, exams, and study hours.