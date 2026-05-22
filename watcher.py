# watcher.py
import time
import os
import re
import socket
import ssl
import hashlib
from dotenv import load_dotenv
from core.scout import ArchonScout
import database

# Load environment keys
load_dotenv()

DB_FILE = "archon_data.db"
TARGETS_FILE = "targets.txt"

def is_ip(target: str) -> bool:
    """Checks if target matches an IPv4 address pattern."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))

def read_targets(file_path=TARGETS_FILE):
    """Loads target list from file, skipping comments and empty lines."""
    if not os.path.exists(file_path):
        print(f"[Watcher] Target file '{file_path}' not found.")
        return []
    targets = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets

def get_ssl_fingerprint(hostname: str):
    """Fetches SSL certificate fingerprint (SHA-256) and expiry date."""
    try:
        # Clean hostname
        hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
        # Fetch PEM certificate
        pem_cert = ssl.get_server_certificate((hostname, 443), timeout=3)
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        fingerprint = hashlib.sha256(der_cert).hexdigest()
        
        # Try to parse expiry date via socket wrap
        expiry_str = "Unknown"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert and 'notAfter' in cert:
                        expiry_str = cert['notAfter']
        except Exception:
            pass
            
        return fingerprint, expiry_str
    except Exception:
        return None, None

def run_watcher_cycle():
    """Runs a single round of checks for SSL certificate changes and new subdomains."""
    print(f"\n[Watcher] --- Starting Watcher Cycle: {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
    targets = read_targets()
    scout = ArchonScout()
    
    for target in targets:
        print(f"[Watcher] Processing target: {target}")
        
        # SSL Change Detection
        fingerprint, expiry = get_ssl_fingerprint(target)
        if fingerprint:
            cached = database.get_ssl_cache(target)
            if not cached:
                print(f"[Watcher] Caching initial SSL fingerprint for {target}.")
                database.update_ssl_cache(target, fingerprint, expiry)
            elif cached["fingerprint"] != fingerprint:
                msg = f"SSL fingerprint changed! Old: {cached['fingerprint'][:12]}... New: {fingerprint[:12]}..."
                print(f"[Watcher] [ALERT] {msg}")
                database.add_alert("SSL_CHANGED", target, msg)
                database.update_ssl_cache(target, fingerprint, expiry)
        
        # Subdomain Change Detection
        if not is_ip(target):
            try:
                current_subs = scout.harvest_subdomains(target)
                findings = database.get_findings(target)
                scout_findings = [f for f in findings if f["connector"] == "ArchonScout"]
                
                if scout_findings:
                    old_subs = set(scout_findings[-1]["data"].get("subdomains", []))
                else:
                    old_subs = set()
                
                new_subs = [s for s in current_subs if s not in old_subs]
                for sub in new_subs:
                    msg = f"New subdomain discovered: {sub}"
                    print(f"[Watcher] [ALERT] {msg}")
                    database.add_alert("NEW_SUBDOMAIN", target, msg)
                
                # Update DB if subdomains changed or first-time load
                if len(new_subs) > 0 or not scout_findings:
                    database.save_finding(target, "ArchonScout", {"subdomains": current_subs})
                    
            except Exception as e:
                print(f"[Watcher] [!] Subdomain check failed for {target}: {e}")

def main():
    database.init_db()
    # Run once immediately
    run_watcher_cycle()
    
    print("[Watcher] Watcher running in daemon mode. Checking targets every 60 seconds...")
    try:
        while True:
            time.sleep(60)
            run_watcher_cycle()
    except KeyboardInterrupt:
        print("[Watcher] Stopped by user.")

if __name__ == "__main__":
    main()
