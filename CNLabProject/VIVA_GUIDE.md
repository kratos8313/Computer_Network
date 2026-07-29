# Viva Guide: NetGuard Access Control

## What is the project?

NetGuard Access Control is a Windows application that enforces website-access policies on a managed computer. It can be used by parents at home or by administrators in college labs, classrooms, libraries, and similar environments.

## Why is it a computer-networks project?

The application works in the path between a browser and the internet. It configures a loopback proxy, reads the requested destination, applies a rule, and either forwards or rejects the connection. It also uses hostname resolution through the Windows hosts file as a second layer.

## What does each major file do?

### `service.py`

Runs the protection engine and dashboard as an automatic Windows service. This means closing the desktop window does not stop enforcement and protection returns after a reboot.

### `desktop.py`

Provides a normal Windows launcher. It checks the service and protection status, opens the administrator dashboard, and can request an elevated service repair when necessary.

### `app.py`

Provides the local web dashboard. It handles login, policy changes, logs, protection pause/resume, and notification settings. Sensitive operations require the administrator password again.

### `controller.py`

Coordinates the background workers. It starts and stops the proxy, applies the hosts-file policy, and periodically repairs enforcement settings.

### `rules.py`

Acts as the decision engine. In blacklist mode, listed blocked domains are denied. In whitelist mode, destinations are denied unless an allow rule matches.

### `proxy.py`

Listens locally for HTTP and HTTPS proxy requests. It extracts the hostname, consults the rules engine, forwards allowed traffic, and rejects and logs blocked traffic.

### `blocker.py`

Maintains a clearly marked section in the Windows hosts file. It adds IPv4 and IPv6 loopback entries for blocked domains while preserving unrelated system entries.

### `machine_proxy.py`

Configures the Windows machine-wide proxy and verifies that the setting has not been changed.

### `database.py`

Stores rules, settings, password hashes, and activity logs in SQLite under the protected application data directory.

### `notifications.py`

Sends security events to an administrator-configured HTTPS endpoint. Each alert identifies the event, severity, computer, message, and UTC time. Duplicate domain alerts are grouped for five minutes.

### `uninstall_guard.py`

Prompts for the application administrator password before uninstall proceeds. Successful and denied attempts are logged and notified.

## Typical request flow

1. An administrator adds a blocked domain.
2. The rule is normalized and stored in SQLite.
3. Enforcement updates the proxy decision set and hosts-file entries.
4. A standard user requests the domain.
5. The proxy asks the rules engine whether it is allowed.
6. The proxy returns 403 when blocked, records the attempt, and queues an immediate alert.
7. The configured receiver tells the parent, instructor, or lab administrator which computer generated the event.

## Important viva questions

**Why use both a proxy and the hosts file?**
The proxy provides real-time decisions and logs. The hosts file adds another local blocking layer for named destinations.

**Why must managed users be standard Windows users?**
An administrator owns the machine's security configuration and can stop services, edit protected files, or replace software. Local software cannot reliably prevent its own owner from bypassing it.

**Why is the dashboard bound to localhost?**
It prevents other network devices from directly reaching the administration interface. Remote alerts are outbound-only HTTPS requests.

**How are passwords protected?**
The database stores a salted scrypt hash, not the original password. Login is rate-limited and sensitive controls ask for the password again.

**How does immediate notification work?**
The application sends JSON to a configured HTTPS URL, optionally with a bearer secret. Block events are sent asynchronously; shutdown-related events are sent synchronously so they are not lost when a process exits.

**Can the application guarantee that an administrator cannot uninstall it?**
No local application can defeat a determined Windows administrator. The guard prevents ordinary removal and creates an alert, while organizational deployments should also use device-management policy and off-device monitoring.

**How is this useful in a college lab?**
The same policy engine can limit gaming, social media, downloads, or non-course websites; whitelist mode can restrict exam computers to approved resources; and computer-name alerts identify the workstation involved.