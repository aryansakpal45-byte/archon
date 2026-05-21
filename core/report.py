# core/report.py
import os
import json

def generate_master_report():
    output_dir = "output"
    print("=" * 70)
    print("   ▲ ARCHON INTEL AGGREGATOR // UNIFIED PERIMETER AUDITING REPORT ▲")
    print("=" * 70)
    
    if not os.path.exists(output_dir):
        print("[✗] Database output layer empty.")
        return

    json_files = [f for f in os.listdir(output_dir) if f.endswith(".json")]
    if not json_files:
        return

    print(f"{'TARGET ASSET':<28} | {'EXPOSED PORTS':<22} | {'GAP COUNT':<10}")
    print("-" * 70)

    total_gaps = 0
    critical_alerts = 0

    for file_name in json_files:
        with open(os.path.join(output_dir, file_name), "r") as f:
            data = json.load(f)
            
        target = data.get("target", "Unknown").replace("https://", "").replace("http://", "")
        exposed_ports = list(data.get("exposed_ports", {}).keys())
        vulns = data.get("vulnerabilities_detected", [])
        
        ports_str = ", ".join(exposed_ports) if exposed_ports else "None Detected"
        gap_count = len(vulns)
        total_gaps += gap_count
        
        print(f"{target:<28} | {ports_str:<22} | {gap_count:<10}")
        
        for v in vulns:
            if v["severity"] == "High":
                critical_alerts += 1

    print("=" * 70)
    print(f"[⚡] ANALYSIS METRICS: Total Tracked Gaps: {total_gaps} | Critical Remediations: {critical_alerts}")
    print("=" * 70)