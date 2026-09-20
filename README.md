# PortPulse Studio

> **All-in-One Network Scanner, Sniffer & Diagnostics Suite**

PortPulse Studio is a comprehensive web-based network operations and security diagnostics dashboard powered by real system backends.

## Key Features

- **Live Wireshark-Style Packet Sniffer**:
  - Powered by Python Scapy and Windows Npcap kernel driver.
  - Multi-Network Adapter Support (Wi-Fi, Ethernet, VMware, Loopback).
  - Real-time packet inspection (Hex preview, IP headers, protocol distribution).
  - Smart non-destructive capture limits (Safe 10k, Normal 50k, Deep 100k, Custom).
  - Traffic spike detection & automated malicious payload quarantine (cleartext password leaks, C2 beacons, port sweeps).

- **Zenmap-Style Port & Vulnerability Scanner**:
  - Direct integration with official Nmap binary (`nmap.exe`).
  - SYN Stealth Scans (`-sS`), version detection (`-sV`), and OS fingerprinting (`-O`).
  - Real-time interactive CLI terminal trace output.
  - Automated CVE and CVSS vulnerability correlation for detected services.

- **Network Tools & Diagnostics**:
  - WHOIS & IP Threat Intelligence radar.
  - Packet Forge crafter & raw frame compiler.
  - TCP Stream dialogue reconstructor ("Follow TCP Stream").
  - Protocol Hierarchy statistical breakdown.
  - Continuous ICMP Ping sparklines & subnet sweep utility.
  - Interactive Canvas Network Topology Flow Radar.
  - Multi-format audit reporting (JSON, TXT, PDF).

## Getting Started

### Prerequisites
- Python 3.10+
- [Npcap](https://npcap.com/) (installed with WinPcap API-compatible mode)
- [Nmap](https://nmap.org/) (optional for port scanner module)

### Installation
```bash
pip install flask scapy
```

### Running the Application
```bash
python server.py
```

Open your browser to:
```
http://localhost:3000/
```
Click **"1-Click Demo Admin Login"** to enter the dashboard.
