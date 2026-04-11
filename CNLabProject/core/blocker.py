import json

CONFIG_PATH = "config/settings.json"
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"   # Windows

REDIRECT = "127.0.0.1"

def load_sites():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)["blocked_sites"]

def save_sites(sites):
    with open(CONFIG_PATH, "r") as f:
        data = json.load(f)
    data["blocked_sites"] = sites
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f)

def block_sites():
    sites = load_sites()
    try:
        with open(HOSTS_PATH, "r+") as file:
            content = file.read()
            for site in sites:
                entry = f"{REDIRECT} {site}\n"
                if entry not in content:
                    file.write(entry)
    except PermissionError:
        print("[WARNING] Admin rights required for hosts blocking")

def unblock_all():
    with open(HOSTS_PATH, "r") as file:
        lines = file.readlines()

    with open(HOSTS_PATH, "w") as file:
        for line in lines:
            if "127.0.0.1" not in line:
                file.write(line)