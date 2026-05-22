import os
from dotenv import load_dotenv
from connector.shodan_conn import ShodanConnector
from connector.censys_conn import CensysConnector

# Load keys once
load_dotenv()

def main():
    target = "8.8.8.8"
    print(f"--- Archon Engine: Analyzing {target} ---")
    
    # Initialize your connectors
    # This design is pluggable; you can add more sources here later
    connectors = {
        "Shodan": ShodanConnector(),
        "Censys": CensysConnector()
    }
    
    for name, conn in connectors.items():
        print(f"[*] Dispatching to {name}...")
        try:
            # We assume your connectors are already fixed to take the token
            result = conn.fetch(target)
            print(f"[+] {name} Data retrieved successfully.")
            # Here, you would eventually pass 'result' to a file or DB writer
        except Exception as e:
            print(f"[!] {name} failed: {e}")

if __name__ == "__main__":
    main()