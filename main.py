# main.py
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.sensor import ArchonEyes
from core.scout import ArchonScout
from core.report import generate_master_report

print_lock = threading.Lock()

def process_single_target(sensor, target, idx, total):
    raw_intel = sensor.scan_target(target)
    vulns = raw_intel["vulnerabilities_detected"]
    high_count = sum(1 for v in vulns if v["severity"] == "High")
    ssl_info = raw_intel["ssl_metadata"]
    
    with print_lock:
        print(f"[{idx}/{total}] RUNNING ENHANCED SCAN AGAINST: {target}")
        print(f"    ├── Status: {raw_intel['status']} | Platform: {raw_intel['server_banner']}")
        print(f"    └── SSL: {ssl_info['status']} | Authority: {ssl_info['issuer']}")
        print("-" * 65)

    # Format the file path to maintain uniform telemetry tracking
    sanitized = target.replace("https://", "").replace("http://", "").replace("/", "_")
    output_path = f"output/https__{sanitized}_telemetry.json"
    with open(output_path, "w") as out_file:
        json.dump(raw_intel, out_file, indent=4)

def run_engine():
    print("=" * 65)
    print("  ▲ ARCHON v4.0 // PASSIVE ASSET HARVEST & THREAT MATRIX ▲")
    print("=" * 65)
    
    # Clean old records before fresh intelligence gathering
    if os.path.exists("output"):
        for f in os.listdir("output"):
            if f.endswith(".json"):
                os.remove(os.path.join("output", f))

    root_target = input("[+] Enter Root Corporate Domain (e.g., github.com): ").strip()
    if not root_target:
        print("[✗] Error: Target cannot be null.")
        return

    print(f"\n[*] Activating Passive Discovery Array against global logs...")
    scout = ArchonScout()
    targets = scout.harvest_subdomains(root_target)

    if not targets:
        print(f"[!] No secondary perimeters found in public logs. Defaulting to root.")
        targets = [root_target]
    else:
        print(f"[✓] Successfully harvested {len(targets)} active subdomains passively!")
        print("-" * 65)
        for t in targets:
            print(f"  └─► Discovered: {t}")
        print("-" * 65)

    print("\n[*] Initializing High-Speed Concurrent Auditing Thread Pool...")
    print("=" * 65)
    
    sensor = ArchonEyes()
    os.makedirs("output", exist_ok=True)

    max_threads = min(5, len(targets))
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for idx, target in enumerate(targets, start=1):
            futures.append(executor.submit(process_single_target, sensor, target, idx, len(targets)))
        
        for future in as_completed(futures):
            pass

    print("\n" + "=" * 65)
    print("  ▲ SCAN MATRIX COMPLETE // INITIATING MASTER POSTURE SUMMARY ▲")
    print("=" * 65)
    print("\n")
    
    generate_master_report()

if __name__ == "__main__":
    run_engine()