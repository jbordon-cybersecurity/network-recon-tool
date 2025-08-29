import os
import subprocess
import json
import pandas as pd
from datetime import datetime
import nmap

# Paths
CAPTURE_DIR = "captures"
REPORT_DIR = "reports"

# Paths to external tools

NMAP_PATH = r"C:\Path\To\nmap\nmap.exe"
DUMPCAP_PATH = r"C:\Path\To\Wireshark\dumpcap.exe"


os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def run_nmap_scan(target="127.0.0.1"):
    print(f"[INFO] Running Nmap scan on {target}...")
    nm = nmap.PortScanner(nmap_search_path=[NMAP_PATH])
    nm.scan(hosts=target, arguments='-sV -T4')

    # Save JSON report
    json_path = os.path.join(REPORT_DIR, "scan_results.json")
    with open(json_path, "w") as f:
        json.dump(nm._scan_result, f, indent=4)
    print(f"[INFO] JSON report saved: {json_path}")

    # Convert results to CSV
    csv_data = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, service in nm[host][proto].items():
                csv_data.append({
                    "host": host,
                    "protocol": proto,
                    "port": port,
                    "state": service["state"],
                    "service": service.get("name", "unknown"),
                    "version": service.get("version", "unknown"),
                })

    df = pd.DataFrame(csv_data)
    csv_path = os.path.join(REPORT_DIR, "scan_results.csv")
    df.to_csv(csv_path, index=False)
    print(f"[INFO] CSV report saved: {csv_path}")

def list_interfaces():
    print("[INFO] Listing available interfaces...")
    try:
        result = subprocess.run(
            [DUMPCAP_PATH, "-D"], capture_output=True, text=True, check=True
        )
        print(result.stdout)
    except FileNotFoundError:
        print("[ERROR] dumpcap not found. Check the path to Wireshark.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to list interfaces: {e}")

def capture_traffic(interface_number, duration=30):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
    print(f"[INFO] Capturing traffic for {duration}s on interface #{interface_number}...")

    cmd = [
        DUMPCAP_PATH, "-i", str(interface_number),
        "-a", f"duration:{duration}",
        "-w", pcap_file
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"[INFO] Traffic captured: {pcap_file}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] dumpcap failed: {e}")

if __name__ == "__main__":
    target = input("Enter target (default: 127.0.0.1): ") or "127.0.0.1"
    run_nmap_scan(target)

    # List interfaces and select one
    list_interfaces()
    iface = input("Enter interface number for capture (e.g., 5 for WiFi): ")
    duration = input("Capture duration in seconds (default: 30): ") or "30"
    capture_traffic(iface, int(duration))
