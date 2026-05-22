import json
import os
import threading
import asyncio
import sqlite3
import time
import socket
import shodan
from censys.search import CensysHosts
from dotenv import load_dotenv

# --- CONFIG & SETUP ---
load_dotenv()
# Initialize APIs
shodan_api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
censys_api = CensysHosts(api_token=os.getenv("CENSYS_API_TOKEN"))
DB_FILE = "intel_cache.db"
print_lock = threading.Lock()

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS cache (ip TEXT PRIMARY KEY, data TEXT, timestamp REAL)")

def get_ip(target):
    """Resolves a domain name to an IP address."""
    try: 
        return socket.gethostbyname(target)
    except socket.gaierror: 
        return target # Return as-is if it's already an IP or resolution fails

async def fetch_intel(ip):
    """Fetches and caches Shodan/Censys data."""
    init_db()
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT data, timestamp FROM cache WHERE ip=?", (ip,)).fetchone()
        if row and (time.time() - row[1] < 86400): 
            return json.loads(row[0])
    
    try:
        loop = asyncio.get_event_loop()
        # Fetch from APIs concurrently
        task1 = loop.run_in_executor(None, shodan_api.host, ip)
        task2 = loop.run_in_executor(None, censys_api.view, ip)
        results = await asyncio.gather(task1, task2, return_exceptions=True)
        
        report = {
            "shodan": results[0] if not isinstance(results[0], Exception) else None,
            "censys": results[1] if not isinstance(results[1], Exception) else None
        }
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?)", (ip, json.dumps(report), time.time()))
        return report
    except Exception as e:
        return {"error": str(e)}

# --- CORE SCANNING LOGIC ---
def process_single_target(target, idx, total):
    ip = get_ip(target)
    print(f"[{idx}/{total}] SCANNING: {target} (Resolved: {ip})")
    
    intel = asyncio.run(fetch_intel(ip))
    shodan_data = intel.get("shodan", {})
    
    if shodan_data and "ports" in shodan_data:
        ports = shodan_data["ports"]
        with print_lock:
            print(f"    - Open Ports: {ports}")
            if 22 in ports: print("    [!] ALERT: SSH (22) exposed!")
            if 3389 in ports: print("    [!] ALERT: RDP (3389) exposed!")
    else:
        print("    - Intelligence: No public data found.")
    print("-" * 40)

def run_engine():
    if not os.path.exists("targets.txt"): 
        print("ERROR: targets.txt missing.")
        return
    with open("targets.txt", "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print("--- ARCHON v4.1 ACTIVE ---")
    for idx, target in enumerate(targets, 1):
        process_single_target(target, idx, len(targets))

if __name__ == "__main__":
    run_engine()