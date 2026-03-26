import socket
import ssl
import subprocess
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# 🔹 Ports to scan
PORTS = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]

# 🔹 Resolve domain to IP
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

# 🔹 Check ICMP (Ping)
def check_ping(domain):
    try:
        output = subprocess.run(
            ["ping", "-n", "1", domain],
            capture_output=True,
            text=True
        )
        return "Reachable" if "TTL=" in output.stdout else "Unreachable"
    except:
        return "Error"

# 🔹 Check Port
def check_port(domain, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        sock.close()
        return "Open" if result == 0 else "Closed"
    except:
        return "Error"

# 🔹 Fast Port Scanning (Multithreading)
def scan_ports(domain):
    results = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_port, domain, port): port
            for port in PORTS
        }

        for future in futures:
            port = futures[future]
            results[port] = future.result()

    return results

# 🔹 SSL Certificate Check
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(
            cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
        )

        days_left = (expiry_date - datetime.now()).days

        return {
            "status": "Valid",
            "expires_in_days": days_left
        }

    except Exception as e:
        return {
            "status": "Error",
            "message": str(e)
        }

# 🔹 Risk Detection
def analyze_risks(port_results, ssl_info):
    risks = []

    if port_results.get(21) == "Open":
        risks.append("FTP (21) is open - insecure protocol")

    if port_results.get(23) == "Open":
        risks.append("Telnet (23) is open - highly insecure")

    if port_results.get(3389) == "Open":
        risks.append("RDP (3389) is open - brute-force risk")

    if ssl_info.get("status") == "Valid":
        if ssl_info.get("expires_in_days", 999) < 30:
            risks.append("SSL certificate expiring soon")

    return risks

# 🔹 Generate Report
def generate_report(domain):
    print(f"\n🔍 Scanning: {domain}\n")

    ip = resolve_domain(domain)
    if not ip:
        print("❌ Unable to resolve domain")
        return

    print(f"🌐 Resolved IP: {ip}")

    ping_status = check_ping(domain)
    print(f"📡 Ping: {ping_status}")

    print("\n🔎 Scanning Ports...")
    port_results = scan_ports(domain)

    for port, status in port_results.items():
        print(f"Port {port}: {status}")

    ssl_info = check_ssl(domain)

    print("\n🔐 SSL Info:")
    if ssl_info["status"] == "Valid":
        print(f"Valid (expires in {ssl_info['expires_in_days']} days)")
    else:
        print(f"SSL Error: {ssl_info.get('message')}")

    risks = analyze_risks(port_results, ssl_info)

    print("\n🚨 Risk Analysis:")
    if risks:
        for r in risks:
            print(f"[WARNING] {r}")
    else:
        print("No major risks detected")

    # 🔹 Save Report
    report_data = {
        "domain": domain,
        "ip": ip,
        "ping": ping_status,
        "ports": port_results,
        "ssl": ssl_info,
        "risks": risks
    }

    with open("../reports/report.json", "w") as f:
        json.dump(report_data, f, indent=4)

    with open("../reports/report.txt", "w") as f:
        f.write(json.dumps(report_data, indent=4))

    print("\n📁 Report saved in /reports folder")

# 🔹 Main
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter domain: ")

    generate_report(target)