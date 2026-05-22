# core/report.py
import sqlite3
import json
import os

DB_FILE = "archon_data.db"

def generate_master_report(db_path=DB_FILE):
    if not os.path.exists(db_path):
        print(f"[ERROR] Database file '{db_path}' not found. Please run the scanner first.")
        return
    
    print("=" * 80)
    print("   === ARCHON INTEL AGGREGATOR // UNIFIED PERIMETER AUDITING REPORT ===")
    print("=" * 80)

    # Fetch all data from database
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT target, connector, data, timestamp FROM scan_findings")
        rows = cursor.fetchall()
    
    if not rows:
        print("[!] Database is empty. No findings to report.")
        return

    # Group findings by target
    # Structure: target -> { "scout": [...], "eyes": {}, "shodan": {}, "censys": {} }
    findings_by_target = {}
    for target, connector, data_str, timestamp in rows:
        try:
            data = json.loads(data_str)
        except Exception:
            data = data_str

        if target not in findings_by_target:
            findings_by_target[target] = {
                "scout": None,
                "eyes": None,
                "shodan": None,
                "censys": None
            }

        if connector == "ArchonScout":
            findings_by_target[target]["scout"] = data
        elif connector == "ArchonEyes":
            findings_by_target[target]["eyes"] = data
        elif connector == "Shodan":
            findings_by_target[target]["shodan"] = data
        elif connector == "Censys":
            findings_by_target[target]["censys"] = data

    print(f"{'TARGET ASSET':<35} | {'EXPOSED PORTS':<25} | {'GAP COUNT':<10}")
    print("-" * 80)

    total_gaps = 0
    critical_alerts = 0
    total_exposed_ports = 0
    scanned_ips_domains = len(findings_by_target)

    # Detail view of each target in database
    for target, modules in findings_by_target.items():
        exposed_ports_list = []
        gaps_list = []

        # Parse ArchonEyes active scan data
        if modules["eyes"]:
            eyes_data = modules["eyes"]
            exposed_ports = eyes_data.get("exposed_ports", {})
            for port, service in exposed_ports.items():
                exposed_ports_list.append(port)
                total_exposed_ports += 1
            
            vulnerabilities = eyes_data.get("vulnerabilities_detected", [])
            for vuln in vulnerabilities:
                gaps_list.append(vuln)
                total_gaps += 1
                if vuln.get("severity") == "High":
                    critical_alerts += 1
        
        ports_str = ", ".join(exposed_ports_list) if exposed_ports_list else "None Detected"
        gap_count = len(gaps_list)
        
        # Display summary row
        print(f"{target:<35} | {ports_str:<25} | {gap_count:<10}")

    print("=" * 80)
    print("   === DETAIL VULNERABILITY LOG ===")
    print("=" * 80)
    
    # Print vulnerabilities if any
    has_vulns = False
    for target, modules in findings_by_target.items():
        if modules["eyes"] and modules["eyes"].get("vulnerabilities_detected"):
            for vuln in modules["eyes"]["vulnerabilities_detected"]:
                has_vulns = True
                sev = vuln.get("severity", "Medium")
                threat = vuln.get("vulnerability", "Unknown")
                desc = vuln.get("threat_impact", "")
                sev_marker = "[HIGH]" if sev == "High" else "[MED ]"
                print(f"{sev_marker} {target} -> {threat}: {desc}")
                
    if not has_vulns:
        print("No active vulnerabilities or missing security headers identified.")

    print("=" * 80)
    print("   === PASSIVE THREAT INTEL SUMMARY ===")
    print("=" * 80)
    
    # Print threat intel summaries
    intel_found = False
    for target, modules in findings_by_target.items():
        shodan_data = modules["shodan"]
        censys_data = modules["censys"]

        shodan_summary = "No Data"
        if shodan_data:
            intel_found = True
            if "error" in shodan_data:
                shodan_summary = f"API Error: {shodan_data['error']}"
            else:
                shodan_os = shodan_data.get("os") or "Unknown OS"
                shodan_ports = shodan_data.get("ports") or []
                shodan_ports_str = ", ".join(map(str, shodan_ports)) if shodan_ports else "None"
                shodan_summary = f"OS: {shodan_os} | Exposed Ports: {shodan_ports_str}"

        censys_summary = "No Data"
        if censys_data:
            intel_found = True
            if "error" in censys_data:
                err = censys_data['error']
                if "Unauthorized" in err:
                    censys_summary = "API Error: 401 Unauthorized"
                else:
                    censys_summary = f"API Error: {err[:30]}..."
            else:
                censys_services = censys_data.get("services") or []
                censys_ports = [str(s.get("port", "")) for s in censys_services if s.get("port")]
                censys_ports_str = ", ".join(censys_ports) if censys_ports else "None"
                censys_summary = f"Exposed Ports: {censys_ports_str}"
        
        if shodan_data or censys_data:
            print(f"IP {target:<15} | Shodan: {shodan_summary}")
            print(f"{'':<18} | Censys: {censys_summary}")
            print("-" * 80)

    if not intel_found:
        print("No passive intelligence details populated in database.")

    print("=" * 80)
    print(f"PERIMETER METRICS: Tracked Assets: {scanned_ips_domains} | Open Services: {total_exposed_ports} | Total Gaps: {total_gaps} | Critical Remediations: {critical_alerts}")
    print("=" * 80)

if __name__ == "__main__":
    generate_master_report()