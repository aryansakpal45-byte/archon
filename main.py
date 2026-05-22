import os
import re
import socket
from dotenv import load_dotenv
from connector.shodan_conn import ShodanConnector
from connector.censys_conn import CensysConnector
from core.scout import ArchonScout
from core.sensor import ArchonEyes
import database

# Load keys once
load_dotenv()

def is_ip(target: str) -> bool:
    """Checks if the target is an IPv4 address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))

def read_targets(file_path="targets.txt"):
    """Reads and sanitizes targets from the target file."""
    if not os.path.exists(file_path):
        print(f"[!] Target file '{file_path}' not found.")
        return []
    targets = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets

def run_active_scan(target: str, eyes: ArchonEyes):
    """Performs active port and vulnerability scanning and saves results."""
    print(f"[*] Running active scan (ports & headers) on {target}...")
    try:
        result = eyes.scan_target(target)
        database.save_finding(target, "ArchonEyes", result)
        print(f"[+] Active scan completed and saved for {target}.")
    except Exception as e:
        print(f"[!] Active scan failed for {target}: {e}")

def run_passive_scan(ip: str, connectors: dict):
    """Performs passive Shodan and Censys intelligence lookups and saves results."""
    for name, conn in connectors.items():
        print(f"[*] Dispatching passive threat intel query ({name}) for IP {ip}...")
        try:
            result = conn.fetch(ip)
            database.save_finding(ip, name, result)
            print(f"[+] Passive intel saved for {ip} from {name}.")
        except Exception as e:
            print(f"[!] Passive scan failed for {ip} via {name}: {e}")

def resolve_domain(domain: str):
    """Attempts to resolve a domain to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"[!] DNS resolution failed for {domain}: {e}")
        return None

def main():
    print("--- Archon Orchestrator: Starting Batch Pipeline ---")
    
    # Initialize database
    database.init_db()
    
    # Ingest targets
    targets = read_targets()
    if not targets:
        print("[!] No targets to process. Exiting.")
        return
    print(f"[+] Ingested {len(targets)} base target(s) from targets.txt.")
    
    # Instantiate scanners and connectors
    scout = ArchonScout()
    eyes = ArchonEyes()
    connectors = {
        "Shodan": ShodanConnector(),
        "Censys": CensysConnector()
    }
    
    for base_target in targets:
        print(f"\n========================================\n[+] Processing Base Target: {base_target}\n========================================")
        
        if is_ip(base_target):
            print(f"[*] Target identified as IP.")
            # Active scan
            run_active_scan(base_target, eyes)
            # Passive scan
            run_passive_scan(base_target, connectors)
        else:
            print(f"[*] Target identified as Domain. Harvesting subdomains...")
            try:
                subdomains = scout.harvest_subdomains(base_target)
                print(f"[+] Discovered {len(subdomains)} subdomain(s) for {base_target}: {subdomains}")
                # Save subdomain list
                database.save_finding(base_target, "ArchonScout", {"subdomains": subdomains})
            except Exception as e:
                print(f"[!] Subdomain discovery failed for {base_target}: {e}")
                subdomains = [base_target] # Fallback to original domain target if scout failed
            
            for sub in subdomains:
                print(f"\n  [-] Auditing subdomain: {sub}")
                # Active scan on subdomain
                run_active_scan(sub, eyes)
                
                # Resolve DNS to run threat intel on the IP
                ip = resolve_domain(sub)
                if ip:
                    print(f"  [-] Resolved {sub} to {ip}")
                    # Run passive intel queries on the IP
                    run_passive_scan(ip, connectors)
                else:
                    print(f"  [!] Skipping passive scan for {sub} (DNS resolution failed).")
    
    print("\n--- Archon Orchestrator: Batch Pipeline Completed ---")

if __name__ == "__main__":
    main()