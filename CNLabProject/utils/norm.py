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
    # (Actually we want to keep it simple, but at least remove common invalid chars)
    domain = re.sub(r'[^a-z0-9\.-]', '', domain)
    
    return domain

def get_domain_variants(domain):
    """
    Returns a list of common variants for a domain to ensure blocking coverage.
    Example: 'facebook.com' -> ['facebook.com', 'www.facebook.com']
    """
    domain = normalize_domain(domain)
    if not domain:
        return []
    
    variants = {domain}
    
    # Add www variant
    if domain.startswith("www."):
        variants.add(domain[4:])
    else:
        variants.add("www." + domain)
        
    return list(variants)
