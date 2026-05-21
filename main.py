# main.py
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.sensor import ArchonEyes
from core.scout import ArchonScout
from core.report import generate_master_report
from connectors.shodan_conn import ShodanConnector
from connectors.censys_conn import CensysConnector

print_lock = threading.Lock()

def process_single_target(sensor, connectors, target, idx, total):
    # Core internal scan
    raw_intel = sensor.scan_target(target)
    vulns = raw_intel["vulnerabilities_detected"]
    high_count = sum(1 for v in vulns if v["severity"] == "High")
    ssl_info = raw_intel.get("ssl_metadata", {"status": "Unknown", "issuer": "Unknown"})
    
    # API Connectors scan
    api_results = []
    for conn in connectors:
        api_results.append(conn.fetch(target))

    raw_intel["api_intel"] = api_results

    with print_lock:
        print(f"[{idx}/{total}] RUNNING ENHANCED SCAN AGAINST: {target}")
        print(f"    ├── Status: {raw_intel['status']} | Platform: {raw_intel['server_banner']}")
        print(f"    └── SSL: {ssl_info['status']} | Authority: {ssl_info['issuer']}")
        for res in api_results:
            print(f"    └── Connector {res['source']}: OK")
        print("-" * 65)

    # Format the file path to maintain uniform telemetry tracking
    sanitized = target.replace("https://", "").replace("http://", "").replace("/", "_")
    output_path = f"results/https__{sanitized}.json"
    with open(output_path, "w") as out_file:
        json.dump(raw_intel, out_file, indent=4)

def run_engine():
    print("=" * 65)
    print("  ▲ ARCHON v4.0 // PASSIVE ASSET HARVEST & THREAT MATRIX ▲")
    print("=" * 65)
    
    # Clean old records before fresh intelligence gathering
    if os.path.exists("results"):
        for f in os.listdir("results"):
            if f.endswith(".json"):
                os.remove(os.path.join("results", f))
    else:
        os.makedirs("results", exist_ok=True)

    if not os.path.exists("targets.txt"):
        print("[✗] Error: targets.txt not found.")
        return

    with open("targets.txt", "r") as f:
        root_targets = [line.strip() for line in f if line.strip()]

    if not root_targets:
        print("[✗] Error: targets.txt is empty.")
        return

    print(f"\n[*] Activating Passive Discovery Array against global logs...")
    scout = ArchonScout()

    targets = []
    for root_target in root_targets:
        subdomains = scout.harvest_subdomains(root_target)
        if subdomains:
            targets.extend(subdomains)
        else:
            targets.append(root_target)

    # De-duplicate and sort
    targets = sorted(list(set(targets)))

    if not targets:
        print(f"[!] No targets found.")
        return
    else:
        print(f"[✓] Successfully harvested {len(targets)} active subdomains passively!")
        print("-" * 65)
        for t in targets:
            print(f"  └─► Discovered: {t}")
        print("-" * 65)

    print("\n[*] Initializing High-Speed Concurrent Auditing Thread Pool...")
    print("=" * 65)
    
    sensor = ArchonEyes()
    connectors = [ShodanConnector(), CensysConnector()]

    max_threads = min(5, len(targets))
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for idx, target in enumerate(targets, start=1):
            futures.append(executor.submit(process_single_target, sensor, connectors, target, idx, len(targets)))
        
        for future in as_completed(futures):
            pass

    print("\n" + "=" * 65)
    print("  ▲ SCAN MATRIX COMPLETE // INITIATING MASTER POSTURE SUMMARY ▲")
    print("=" * 65)
    print("\n")
    
    generate_master_report()

if __name__ == "__main__":
    run_engine()