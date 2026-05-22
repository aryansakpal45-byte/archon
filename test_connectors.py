import os
import sys
from dotenv import load_dotenv

# Ensure the current directory is in the path to find your 'connector' folder
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Now we can safely import these
from connector.shodan_conn import ShodanConnector
from connector.censys_conn import CensysConnector

# Load environment variables from the .env file in the root
load_dotenv()

def test_all():
    target = "8.8.8.8"
    print(f"--- Starting Connector Test for {target} ---")
    
    # 1. Initialize Shodan
    try:
        shodan = ShodanConnector()
        print("[+] Shodan initialized.")
    except Exception as e:
        print(f"[!] Shodan Init Error: {e}")
        return

    # 2. Initialize Censys (with explicit token check)
    try:
        censys = CensysConnector()
        print("[+] Censys initialized.")
    except Exception as e:
        print(f"[!] Censys Init Error: {e}")
        return

    # 3. Fetch Data
    for name, conn in [("Shodan", shodan), ("Censys", censys)]:
        print(f"\n[+] Testing {name}...")
        try:
            result = conn.fetch(target)
            if isinstance(result, dict) and "error" in result:
                print(f"[!] {name} reported an error: {result['error']}")
            else:
                print(f"[✓] {name} success! Data retrieved.")
        except Exception as e:
            print(f"[!] Critical Failure in {name}: {e}")

if __name__ == "__main__":
    test_all()