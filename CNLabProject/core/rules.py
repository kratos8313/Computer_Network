import datetime
from core.database import get_db

def is_within_time_range(start_str, end_str):
    if not start_str or not end_str:
        return False
    
    now = datetime.datetime.now().time()
    start = datetime.datetime.strptime(start_str, "%H:%M").time()
    end = datetime.datetime.strptime(end_str, "%H:%M").time()
    
    if start <= end:
        return start <= now <= end
    else: # Overnights (e.g. 21:00 to 07:00)
        return now >= start or now <= end

def should_block(domain):
    conn = get_db()
    
    # 1. Get Global Mode
    mode_row = conn.execute("SELECT value FROM settings WHERE key='mode'").fetchone()
    mode = mode_row['value'] if mode_row else 'blacklist'
    
    # 2. Check for explicit Domain Rule
    from utils.norm import get_root_domain
    domain_lower = get_root_domain(domain)
    
    # Root Domain / Subdomain Match
    # We check if the request domain ends with the blocked domain (e.g., m.facebook.com matches facebook.com)
    # OR if the request domain is exactly the blocked domain.
    rule = conn.execute(
        "SELECT * FROM rules WHERE ? = domain OR ? LIKE '%.' || domain", 
        (domain_lower, domain_lower)
    ).fetchone()
    
    # 3. Check for Time-based restrictions (Category or Domain)
    # Check if this domain matches a category that is restricted right now
    if rule:
        category = rule['category']
        schedule = conn.execute("SELECT * FROM schedules WHERE target=? AND type='category'", (category,)).fetchone()
        if schedule and is_within_time_range(schedule['start_time'], schedule['end_time']):
            conn.close()
            return True, f"Time-restricted Category: {category}"

    # 4. Mode-based decision
    if mode == 'whitelist':
        # In Whitelist mode, if it's not explicitly in the rules as 'allow', block it
        if rule and rule['action'] == 'allow':
            conn.close()
            return False, "Allowed by Whitelist"
        conn.close()
        return True, "Blocked by Whitelist Mode"
    
    else: # Blacklist mode
        if rule and rule['action'] == 'block':
            conn.close()
            return True, f"Blacklisted Category: {rule['category']}"
        conn.close()
        return False, "Allowed"

if __name__ == "__main__":
    # Test cases
    print(f"Should block google.com? {should_block('google.com')}")
