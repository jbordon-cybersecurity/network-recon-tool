## Network Recon Tool ##

A Python-based tool to:
- Perform **Nmap scans** and save results in JSON and CSV formats.
- Capture live network traffic using Wireshark's `dumpcap`.
- Generate `.pcap` files for analysis in Wireshark or other tools.

---

## Features
- Run Nmap scans with version detection (`-sV`) and faster timing (`-T4`).
- Save Nmap results as:
  - `scan_results.json` – detailed output
  - `scan_results.csv` – easy-to-read report
- Capture traffic for a specified duration and store `.pcap` files for offline analysis.

---

## Requirements
- **Python 3.8+**
- **Installed Tools**:
  - [Nmap](https://nmap.org/download.html)
  - [Wireshark](https://www.wireshark.org/download.html) (for `dumpcap`)

---

## Python Libraries
Install dependencies:
```bash
pip install python-nmap pandas
# Setup
Clone the repository:

git clone https://github.com/jbordon-cybersecurity/network-recon-tool.git
cd network-recon-tool
Update recon.py paths to point to your installations:

NMAP_PATH = r"C:\Path\To\nmap\nmap.exe"
DUMPCAP_PATH = r"C:\Path\To\Wireshark\dumpcap.exe"

# Usage
Run the tool:

python recon.py

Follow prompts:

Enter a target (default: 127.0.0.1)

Enter the network interface (use dumpcap -D to list)

Enter capture duration in seconds (default: 30)

## Project Structure

network-recon-tool/
├── recon.py                # Main script
├── captures/               # Generated PCAP files
├── reports/                # JSON and CSV scan reports
└── README.md               # Documentation

## Next Steps
Use generated .pcap files for advanced analysis in Wireshark or your own PCAP analyzer project.
