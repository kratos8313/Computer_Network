import tkinter as tk
from tkinter import messagebox
import json

from core.auth import setup_password, hash_password, CONFIG_PATH
from core.blocker import load_sites, save_sites, unblock_all
from core.controller import start_system, stop_system


# ---------- SETUP ----------
setup_password()


# ---------- PASSWORD CHECK ----------
def verify_password_input(pwd):
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        return hash_password(pwd) == data.get("password")
    except:
        return False


# ---------- FUNCTIONS ----------
def add_site():
    site = entry.get().strip()

    if not site:
        messagebox.showwarning("Warning", "Enter a domain")
        return

    sites = load_sites()
    if site not in sites:
        sites.append(site)
        save_sites(sites)
        listbox.insert(tk.END, site)

    entry.delete(0, tk.END)


def start():
    start_system()
    status_label.config(text="Status: Running", fg="green")


def stop():
    pwd = password_entry.get()

    if verify_password_input(pwd):
        stop_system()
        unblock_all()
        status_label.config(text="Status: Stopped", fg="red")
        messagebox.showinfo("Success", "System stopped")
    else:
        messagebox.showerror("Error", "Wrong password")


def on_close():
    pwd = password_entry.get()

    if verify_password_input(pwd):
        stop_system()
        unblock_all()
        root.destroy()
    else:
        messagebox.showerror("Error", "Enter correct password to exit")


# ---------- UI ----------
root = tk.Tk()
root.title("Web Blocker (DPI + Proxy)")
root.geometry("420x450")

# Title
tk.Label(root, text="Web Blocker", font=("Arial", 16, "bold")).pack(pady=10)

# Input
tk.Label(root, text="Enter Domain").pack()
entry = tk.Entry(root, width=35)
entry.pack()

tk.Button(root, text="Add Site", command=add_site).pack(pady=5)

# List
listbox = tk.Listbox(root, width=45, height=8)
listbox.pack(pady=10)

# Load existing sites
for site in load_sites():
    listbox.insert(tk.END, site)

# Start Button
tk.Button(root, text="Start Blocking", bg="green", fg="white", command=start).pack(pady=5)

# Password input
tk.Label(root, text="Password to Stop / Exit").pack()
password_entry = tk.Entry(root, show="*", width=35)
password_entry.pack()

# Stop Button
tk.Button(root, text="Stop", bg="red", fg="white", command=stop).pack(pady=5)

# Status
status_label = tk.Label(root, text="Status: Stopped", fg="red")
status_label.pack(pady=10)

# Prevent closing without password
root.protocol("WM_DELETE_WINDOW", on_close)

# Run app
root.mainloop()