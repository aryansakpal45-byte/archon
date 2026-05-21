# core/sensor.py
import urllib.request
import urllib.error
import ssl
import socket
from datetime import datetime

class ArchonEyes:
    def __init__(self):
        self.header_rules = {
            "Strict-Transport-Security": {"severity": "High", "desc": "Lack of forced HTTPS encryption policies exposes users to MITM attacks."},
            "Content-Security-Policy": {"severity": "High", "desc": "Absence allows unauthorized script execution and Cross-Site Scripting (XSS)."},
            "X-Frame-Options": {"severity": "Medium", "desc": "Missing clickjacking defense; site can be embedded inside frames."},
            "X-Content-Type-Options": {"severity": "Medium", "desc": "MIME-sniffing protection disabled; allows script cross-execution."}
        }
        # Enterprise Infrastructure Open Ports Matrix
        self.audit_ports = [80, 443, 22, 8080]

    def audit_network_ports(self, hostname: str) -> dict:
        """Lightweight asynchronous socket connector loop"""
        open_services = {}
        for port in self.audit_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.5)
                    result = sock.connect_ex((hostname, port))
                    if result == 0:
                        open_services[str(port)] = "Open"
            except Exception:
                pass
        return open_services

    def scan_target(self, target_url: str) -> dict:
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        hostname = target_url.replace("https://", "").replace("http://", "").split('/')[0]

        telemetry = {
            "target": target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "Offline / Filtered",
            "server_banner": "Hidden/Protected",
            "exposed_ports": {},
            "vulnerabilities_detected": []
        }

        # 1. Execute Multi-Port Active Grid Scan
        telemetry["exposed_ports"] = self.audit_network_ports(hostname)

        # 2. Check web configurations if port 443 or 80 responds
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                target_url, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                telemetry["status"] = f"{response.status} OK"
                headers = response.info()
                
                if "Server" in headers:
                    telemetry["server_banner"] = headers["Server"]

                for header, rules in self.header_rules.items():
                    matched_key = next((k for k in headers.keys() if k.lower() == header.lower()), None)
                    if not matched_key:
                        telemetry["vulnerabilities_detected"].append({
                            "vulnerability": f"Missing {header}",
                            "severity": rules["severity"],
                            "threat_impact": rules["desc"]
                        })
        except Exception:
            pass

        return telemetry