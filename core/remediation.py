# core/remediation.py

def generate_nginx_config(missing_headers):
    rules = []
    if "Strict-Transport-Security" in missing_headers:
        rules.append('add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;')
    if "Content-Security-Policy" in missing_headers:
        rules.append("add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\" always;")
    if "X-Frame-Options" in missing_headers:
        rules.append('add_header X-Frame-Options "SAMEORIGIN" always;')
    if "X-Content-Type-Options" in missing_headers:
        rules.append('add_header X-Content-Type-Options "nosniff" always;')
    
    if not rules:
        return "# All security headers are already correctly configured."
    
    return "\n".join(rules)

def generate_apache_config(missing_headers):
    rules = []
    if "Strict-Transport-Security" in missing_headers:
        rules.append('Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"')
    if "Content-Security-Policy" in missing_headers:
        rules.append("Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\"")
    if "X-Frame-Options" in missing_headers:
        rules.append('Header always set X-Frame-Options "SAMEORIGIN"')
    if "X-Content-Type-Options" in missing_headers:
        rules.append('Header always set X-Content-Type-Options "nosniff"')
    
    if not rules:
        return "# All security headers are already correctly configured."
    
    return "\n".join(rules)

def generate_caddy_config(missing_headers):
    rules = []
    if any(h in missing_headers for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]):
        rules.append("header {")
        if "Strict-Transport-Security" in missing_headers:
            rules.append('    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"')
        if "Content-Security-Policy" in missing_headers:
            rules.append("    Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\"")
        if "X-Frame-Options" in missing_headers:
            rules.append('    X-Frame-Options "SAMEORIGIN"')
        if "X-Content-Type-Options" in missing_headers:
            rules.append('    X-Content-Type-Options "nosniff"')
        rules.append("}")
    
    if not rules:
        return "# All security headers are already correctly configured."
    
    return "\n".join(rules)

def get_remediations_for_headers(missing_headers):
    return {
        "nginx": generate_nginx_config(missing_headers),
        "apache": generate_apache_config(missing_headers),
        "caddy": generate_caddy_config(missing_headers)
    }
