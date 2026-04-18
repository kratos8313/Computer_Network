# 🔒 Project Report: Child Safety Protocol (Parental Control System)

**Subject**: Computer Networks / System Programming  
**Focus**: Network Traffic Interception, DNS Manipulation, and Policy Enforcement  

---

## 1. Project Overview
### what the system does
The **Child Safety Protocol** is a Python-based security solution designed to provide parents with granular control over their children's internet usage. It acts as a local gatekeeper that monitors and filters web traffic at the system level.

### Problem it solves
In an era of unrestricted digital access, children are often exposed to inappropriate content, gaming addiction, or social media overconsumption. This system addresses these concerns by:
-   **Enforcing Discipline**: Restricting access to specific categories of websites.
-   **Preventing Interaction**: Blocking social media or gaming during study hours.
-   **Monitoring**: Providing logs of attempted access to restricted areas.

### Key Features
-   **Dual-Stack Blocking**: Coverage for both IPv4 and IPv6 protocols.
-   **Smart Normalization**: Root-domain matching to prevent subdomain bypasses.
-   **Dynamic Whitelisting**: "Lockdown" mode that blocks everything except approved educational sites.
-   **Anti-Bypass Engine**: Periodic system-file re-verification to prevent tampering.
-   **Stealth Shutdown**: Automatic restoration of network settings on system exit.

---

## 2. How the System Works (End-to-End Flow)
The system operates as a **System-Level Intermediary**. The data flow follows this path:

1.  **User (Parent) → Flask UI**: The parent uses the web dashboard to set rules (e.g., "Block Facebook").
2.  **Flask UI → Database**: The rule is normalized (e.g., `www.facebook.com` becomes `facebook.com`) and stored in SQLite.
3.  **Controller → Workers**: The Controller triggers the **Proxy** and the **Blocker**.
4.  **Browser → Rules Engine**: When the child opens a browser, the request is intercepted by our Proxy.
5.  **Rules Engine → Decision**: The engine checks the database using root-domain matching.
6.  **Enforcement**: 
    -   If allowed: The Proxy fetches the site.
    -   If blocked: The Proxy returns a `403 Forbidden` response.
7.  **Hosts File Backup**: If the child tries to bypass the proxy, the `hosts` file redirects the domain to `127.0.0.1`, resulting in a "Connection Refused" error.

---

## 3. Architecture Explanation

| Module | Responsibility |
| :--- | :--- |
| **`main.py`** | The entry point. Handles database initialization, starts the controller, and ensures a clean shutdown of network settings. |
| **`app.py`** | A Flask-based web server that provides the parent dashboard for rule management and log viewing. |
| **`controller.py`** | Coordinates the lifecycle of background threads. It keeps the Proxy and Anti-Bypass loop running. |
| **`rules.py`** | The "Decision Maker." Contains the logic for evaluating whether a domain should be blocked based on the current mode and time. |
| **`blocker.py`** | Manages the Windows `hosts` file using managed markers. Implements dual-stack (IPv4/IPv6) blocking. |
| **`database.py`** | Handles SQL operations, schema creation, and secure password hashing for the parent log-in. |
| **`proxy.py`** | A multi-threaded TCP proxy that intercepts HTTP and HTTPS `CONNECT` requests for real-time filtering. |
| **`utils/norm.py`**| A utility that standardizes URLs into root domains, ensuring that blocking `site.com` also blocks `www.site.com`. |

---

## 4. Core Concepts

### 🔴 Blacklist Mode (Restrictive)
-   **Mechanism**: Operates on the "Default Allow" principle.
-   **Blocking**: Sites are blocked only if they appear in the database with a `BLOCK` action.
-   **Transformation**: The system writes `127.0.0.1 domain.com` into the hosts file. Windows sees this and assumes the website is located on the user's own machine, where no content exists.

### 🟢 Whitelist Mode (Permissive Only)
-   **Mechanism**: Operates on the "Default Deny" principle.
-   **Blocking**: Every website is blocked by default.
-   **Allowing**: Access is granted ONLY if a domain is found in the database with an `ALLOW` action.
-   **Logic**: This is primarily enforced by the Proxy Engine, which checks every request against the approved list before establishing a connection.

---

## 5. Technical Explanation: Website Blocking
### What is the Hosts File?
The `hosts` file is a local operating system file that maps hostnames to IP addresses. It is checked **before** a DNS request is sent out to the internet.

### DNS Resolution Affect
By placing an entry for `youtube.com` pointing to `127.0.0.1` (localhost), we prevent the computer from ever asking a DNS server for the real IP. The computer is "lied to" and told that YouTube is on the local machine.

### Why 127.0.0.1 / ::1?
-   `127.0.0.1` is the IPv4 loopback address.
-   `::1` is the IPv6 loopback address.
Mapping a domain to these addresses effectively kills the connection because there is no web server running on those ports at that address.

---

## 6. Time-Based Rules & Category Blocking
-   **Implementation**: Rules are cross-referenced with a `schedules` table.
-   **Category Matching**: Websites are assigned categories (e.g., Gaming). If a schedule says "Gaming is blocked from 21:00 to 07:00," the `rules.py` engine will return a blocked status during those hours, even if the site isn't individually listed.

---

## 7. Anti-Bypass Mechanism
Children are often tech-savvy and might try to delete the entries from the `hosts` file manually.
-   **Detection**: The `controller.py` runs a background thread that wakes up every 60 seconds.
-   **Re-verification**: It reads the `hosts` file and compares it to the database rules.
-   **Auto-Healing**: If it finds the parental control rules missing or tempered with, it instantly restores them.

---

## 8. Activity Logging
Every attempt to access a blocked or allowed website is recorded in an `Activity_Log` table.
-   **Data Logged**: Timestamp, URL, Action (Blocked/Allowed), and the Reason (e.g., "Whitelist Mode").
-   **Purpose**: Allows parents to review usage patterns and identify if the child is attempting to access restricted content.

---

## 9. Challenges & 10. Solutions

| Challenge | Implementation Solution |
| :--- | :--- |
| **DNS Caching** | Implemented a `flush_dns()` function that runs `ipconfig /flushdns` after every rule update. |
| **Internet Hang on Exit** | Wrapped `main.py` in a `try...finally` block to ensure the Windows Proxy is turned OFF on exit. |
| **Subdomain Bypasses** | Developed `get_root_domain()` logic to catch `m.facebook.com` when only `facebook.com` is blocked. |
| **IPv6 Bypass** | Added dual-stack support by writing both `127.0.0.1` and `::1` entries. |

---

## 11. Limitations
-   **VPN Bypass**: A VPN creates an encrypted tunnel that bypasses local proxy and hosts file settings.
-   **Hardcoded IPs**: If a user enters a site directly via its IP address, the `hosts` file (which maps names to IPs) is bypassed.
-   **HSTS/QUIC**: Modern protocols (like QUIC/UDP 443) require registry-level browser policies for 100% reliable interception.

---

## 12. Future Improvements
-   **AI Filtering**: Using Machine Learning to analyze page content in real-time.
-   **Registry Enforcement**: Adding browser-specific policies to disable Private Browsing and DoH (DNS-over-HTTPS).
-   **Remote Mobile App**: A companion app for parents to block/unblock sites remotely.
-   **Multi-Device Sync**: Synchronizing rules across all devices in a home network using a central server.
