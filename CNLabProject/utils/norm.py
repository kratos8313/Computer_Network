import re

def normalize_domain(domain):
    """
    Cleans and normalizes a domain string.
    - Removes http://, https://, and paths.
    - Strips whitespace and converts to lowercase.
    """
    if not domain:
        return ""
    
    # Lowercase and strip
    domain = domain.lower().strip()
    
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    
    # Remove path and trailing slash
    domain = domain.split('/')[0]
    
    # Remove port if present
    domain = domain.split(':')[0]
    
    # Basic domain validation regex
    domain = re.sub(r'[^a-z0-9\.-]', '', domain)
    
    return domain

def get_root_domain(domain):
    """
    Extracts the root domain (e.g., 'www.facebook.com' -> 'facebook.com').
    Strips common subdomains like www, m, web, etc.
    """
    domain = normalize_domain(domain)
    if not domain:
        return ""
    
    # Common subdomain prefixes to strip
    prefixes = ['www.', 'm.', 'web.', 'mobile.', 'apps.']
    for p in prefixes:
        if domain.startswith(p):
            return domain[len(p):]
            
    return domain

def get_domain_variants(domain):
    """
    Returns a list of common variants for a domain to ensure blocking coverage.
    Now centered around the root domain.
    """
    root = get_root_domain(domain)
    if not root:
        return []
    
    # We return the root and the www variant to ensure standard hosts-file coverage
    return [root, f"www.{root}"]
