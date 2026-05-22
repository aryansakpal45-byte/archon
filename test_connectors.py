import os
import sys
from dotenv import load_dotenv

# 1. Add current directory to path to ensure modules are found
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from connector.shodan_conn import ShodanConnector
from connector.censys_conn import CensysConnector

# 2. Load environment variables
load_dotenv()

def test_all():
    target = "8.8.8.8"
    print(f"--- Starting Connector Test for {target} ---")
    
    # 3. Instantiate connectors
    try:
        shodan = ShodanConnector()
        censys = CensysConnector()
    except Exception as e:
        print(f"[!] Initialization Error: {e}")
        return

    connectors = {"Shodan": shodan, "Censys": censys}
    
    # 4. Execute and report
    for name, conn in connectors.items():
        print(f"\n[+] Testing {name}...")
        try:
            result = conn.fetch(target)
            if isinstance(result, dict) and "error" in result:
                print(f"[!] {name} reported an error: {result['error']}")
            else:
                print(f"[✓] {name} success! Data structure retrieved.")
                # Optional: print(result) if you need to see the full JSON
        except Exception as e:
            print(f"[!] Critical Failure in {name}: {e}")

if __name__ == "__main__":
    test_all()