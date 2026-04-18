# 📖 Viva Guide: Simplified Project Breakdown

This guide explains each file in your Parental Control System in simple terms. Use this to prepare for your project demonstration and viva questions.

---

## 📁 main.py
### What it does:
This is the **starting point** (entry point) of the entire system. When you run this file, it turns everything on.

### Why we need it:
Without this, you would have to start the web dashboard, the proxy, and the blocker one by one. This file coordinates everything so the system works as a single unit.

### What happens inside:
It initializes the database, checks if you have set a parent password, and then starts the background "engine" and the web dashboard in two different threads so they can run at the same time.

### How it connects to others:
It calls functions from `controller.py` to start the engine and imports `app.py` to start the web interface.

---

## 📁 app.py
### What it does:
This file manages the **Web Dashboard** (the interface you see in your browser). It handles all the buttons, forms, and pages.

### Why we need it:
It provides a user-friendly way for a parent to manage rules without having to write code or touch the database directly.

### What happens inside:
It uses the Flask framework to define "routes" (links). For example, when you click "Add Rule," this file receives the domain name and tells the database to save it.

### How it connects to others:
It talks to `database.py` to save/load rules and calls `blocker.py` to apply those rules to the system immediately.

---

## 📁 controller.py
### What it does:
This is the **system conductor**. It manages the lifecycle of the background workers (the Proxy and the Blocker).

### Why we need it:
It ensures that the blocking logic keeps running even if you close the dashboard. It also handles the "Anti-Bypass" loop to make sure rules stay active.

### What happens inside:
It contains a loop that runs every 60 seconds to re-verify that the rules are still applied. It also makes sure the System Proxy is turned on when the app starts and off when it stops.

### How it connects to others:
It starts the threads in `proxy.py` and periodically calls the blocking functions in `blocker.py`.

---

## 📁 rules.py
### What it does:
This is the **Decision Maker**. Its only job is to look at a website and say "Yes, Allow" or "No, Block."

### Why we need it:
It contains the core logic for the **Blacklist** and **Whitelist** modes. Without this, the system wouldn't know which rule to apply when.

### What happens inside:
It takes a domain name, checks the current mode (Whitelist or Blacklist) from the database, and looks for matching rules or schedules. It returns a simple "True" (Block) or "False" (Allow).

### How it connects to others:
It is called by `proxy.py` every time a user tries to visit a website. It also pulls data from `database.py`.

---

## 📁 blocker.py
### What it does:
This is the **Security Guard**. It modifies the Windows `hosts` file to block websites at the system level.

### Why we need it:
If a user tries to bypass the proxy, the `hosts` file acts as a second wall. It redirects websites to `127.0.0.1` so they never load.

### What happens inside:
It looks at the blocked list in the database and writes them into the `hosts` file between special markers (`# BEGIN PARENTAL CONTROL`). It also handles IPv6 (`::1`) for extra security.

### How it connects to others:
It gets the list of sites from `database.py` and is triggered by `controller.py` and `app.py`.

---

## 📁 database.py
### What it does:
This is the **System Storage** (The Vault). It manages the SQLite database file where all your rules and settings live.

### Why we need it:
Without this, all your rules would disappear every time you closed the program. It makes your settings permanent.

### What happens inside:
It contains SQL commands to create tables, add new rules, delete rules, and check the parent password. It handles the "Smart Cleaning" of URLs before they are saved.

### How it connects to others:
Almost every file (`app.py`, `rules.py`, `blocker.py`) connects to this one to read or save data.

---

## 📁 proxy.py
### What it does:
This is the **Traffic Interceptor**. It acts as a middleman between your browser and the internet.

### Why we need it:
It allows the system to see exactly which website is being requested in real-time, allowing it to block specific pages even if the `hosts` file is bypassed.

### What happens inside:
It listens for data on port `8080`. When it see a request (like `facebook.com`), it asks `rules.py` for permission. If permission is denied, it sends back a "Forbidden" message to the browser.

### How it connects to others:
It asks `rules.py` for the blocking decision and is controlled by `controller.py`.

---

## 📁 auth.py
### What it does:
This file handles **Security and Access**. It manages the session and login process for the parent dashboard.

### Why we need it:
It ensures that only the parent (who knows the password) can access the settings. It prevents the child from opening the dashboard and deleting the rules.

### What happens inside:
It checks the password provided in the login form against the hashed password stored in the database.

### How it connects to others:
It is used by `app.py` to protect the dashboard routes and talks to `database.py` to verify passwords.

---

## 🔁 How Everything Works Together (The Full Flow)

1.  **Setup**: You run `main.py`, which starts the **Web Dashboard** and the **Blocking Engine**.
2.  **Configuration**: The Parent logs into the dashboard (`auth.py`) and adds a site like `facebook.com`.
3.  **Storage**: `app.py` sends that domain to `database.py`, which cleans it and saves it permanently.
4.  **Enforcement**: The system immediately calls `blocker.py` to update the Windows `hosts` file and notifies the `proxy.py` to start watching for that site.
5.  **Interception**: When someone tries to visit Facebook, the **Proxy** catches the request and asks **Rules.py**: *"Is this allowed?"*
6.  **Blocking**: `rules.py` sees the block rule in the database and tells the Proxy to stop. The browser shows a "Blocked" message.
7.  **Anti-Bypass**: Every minute, `controller.py` checks that the rules are still in place, just in case someone tried to delete them.
