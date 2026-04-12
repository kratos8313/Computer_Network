import os
import subprocess
import threading
from core.database import get_db
from utils.norm import get_domain_variants
from utils.logger import log

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
REDIRECT = "127.0.0.1"
MARKER_START = "# BEGIN PARENTAL CONTROL\n"
MARKER_END = "# END PARENTAL CONTROL\n"

hosts_lock = threading.Lock()

def flush_dns():
    """Flushes Windows DNS cache to ensure rules take effect immediately."""
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, check=True)
        log("[DNS] Flushed DNS cache successfully.")
    except Exception as e:
        log(f"[DNS ERROR] Failed to flush DNS: {e}")

def load_sites_from_db():
    conn = get_db()
    rules = conn.execute("SELECT domain FROM rules WHERE action='block'").fetchall()
    conn.close()
    
    sites = set()
    for r in rules:
        variants = get_domain_variants(r['domain'])
        for v in variants:
            sites.add(v)
            
    return sorted(list(sites))

def block_sites():
    """
    Synchronizes the hosts file with the database rules.
    Uses managed markers to avoid touching system entries.
    """
    with hosts_lock:
        target_sites = load_sites_from_db()
        try:
            if not os.path.exists(HOSTS_PATH):
                log(f"[ERROR] Hosts file not found at {HOSTS_PATH}")
                return

            with open(HOSTS_PATH, "r") as file:
                content = file.readlines()

            # 1. Identify existing managed block
            start_idx = -1
            end_idx = -1
            for i, line in enumerate(content):
                if line == MARKER_START:
                    start_idx = i
                elif line == MARKER_END:
                    end_idx = i

            # 2. Build the new managed block
            new_block = [MARKER_START]
            for site in target_sites:
                new_block.append(f"127.0.0.1 {site}\n")
                new_block.append(f"::1 {site}\n")
            new_block.append(MARKER_END)

            # 3. Construct new file content
            if start_idx != -1 and end_idx != -1:
                # Replace existing block
                final_content = content[:start_idx] + new_block + content[end_idx+1:]
            else:
                # Append new block to the end
                final_content = content + (["\n"] if content and not content[-1].endswith("\n") else []) + new_block

            # 4. Only write if changed
            if content != final_content:
                with open(HOSTS_PATH, "w") as file:
                    file.writelines(final_content)
                log(f"[BLOCKER] Updated hosts file with {len(target_sites)} active rules.")
                flush_dns()
            else:
                # log("[BLOCKER] Hosts file already in sync.") # Noisy for background loop
                pass
            
        except PermissionError:
            log("[ERROR] Permission denied: Please run the system as Administrator to apply blocks.")
        except Exception as e:
            log(f"[ERROR] Unexpected error in block_sites: {e}")

def unblock_all():
    """Removes the parental control managed block entirely."""
    with hosts_lock:
        try:
            with open(HOSTS_PATH, "r") as file:
                content = file.readlines()

            start_idx = -1
            end_idx = -1
            for i, line in enumerate(content):
                if line == MARKER_START:
                    start_idx = i
                elif line == MARKER_END:
                    end_idx = i

            if start_idx != -1 and end_idx != -1:
                final_content = content[:start_idx] + content[end_idx+1:]
                with open(HOSTS_PATH, "w") as file:
                    file.writelines(final_content)
                log("[BLOCKER] Removed all parental control rules from hosts file.")
                flush_dns()
            
        except PermissionError:
            log("[ERROR] Permission denied: Run as Administrator to unblock.")
        except Exception as e:
            log(f"[ERROR] Failed to unblock: {e}")