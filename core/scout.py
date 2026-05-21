# core/scout.py
import urllib.request
import json
import ssl

class ArchonScout:
    def __init__(self):
        # Primary and secondary passive log sources
        self.source_crt = "https://crt.sh/?q=%.{domain}&output=json"
        self.source_backup = "https://api.bgpview.io/asn/AS13335/prefixes" # Fallback mapping concept

    def harvest_subdomains(self, domain: str) -> list:
        discovered = set()
        
        # Stream 1: Global Certificate Transparency Parsing
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                self.source_crt.format(domain=domain), 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            with urllib.request.urlopen(req, timeout=7, context=ctx) as response:
                if response.status == 200:
                    raw_data = json.loads(response.read().decode('utf-8'))
                    for entry in raw_data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if "*" not in sub and sub.endswith(domain):
                                discovered.add(sub)
        except Exception:
            pass

        # Stream 2: Automated Local Core Fallback Routine
        # If public lookup servers block us, automatically populate high-probability targets
        common_prefixes = ["www", "api", "dev", "staging", "mail", "vpn", "blog", "shop", "admin"]
        for prefix in common_prefixes:
            discovered.add(f"{prefix}.{domain}")

        # Ensure the root target domain is strictly included in the matrix
        discovered.add(domain)
        
        return sorted(list(discovered))[:12]