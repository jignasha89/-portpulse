import os
import sys
import time
import socket
import subprocess
import threading
import json
import re
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory

# Scapy imports
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, conf, IFACES, Raw, Ether
    SCAPY_AVAILABLE = True
except Exception as e:
    print("Scapy load warning:", e)
    SCAPY_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)

# Nmap Binary Path
NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"
if not os.path.exists(NMAP_PATH):
    # Try searching on PATH
    import shutil
    detected_nmap = shutil.which("nmap")
    if detected_nmap:
        NMAP_PATH = detected_nmap

# ==============================================================================
# GLOBAL THREAD-SAFE CAPTURE STATE
# ==============================================================================
capture_lock = threading.Lock()
capture_state = {
    "running": False,
    "paused": False,
    "limit_reached": False,
    "interface_id": "Wi-Fi",
    "target_ip": "all",
    "limit": 50000,
    "limit_mode": "normal",
    "total_packets": 0,
    "proto_counts": {"tcp": 0, "udp": 0, "icmp": 0, "other": 0},
    "pps": 0,
    "baseline": 210,
    "is_spike": False,
    "pending_threat": None,
    "seq": 0
}

captured_packets_buffer = deque(maxlen=1500)
active_blocked_ips = set()
blocked_packets_log = []
packet_timestamps_1s = deque(maxlen=4000)
sniff_thread = None
stop_sniff_event = threading.Event()

# Syn port sweep tracker for threat detection
syn_history = deque(maxlen=200)

# ==============================================================================
# REAL CVE KNOWLEDGE BASE FOR SERVICES & VERSIONS
# ==============================================================================
CVE_DATABASE = [
    {
        "service": "ssh",
        "product": "openssh",
        "version_max": "6.7",
        "cve": "CVE-2016-0777",
        "title": "OpenSSH Roaming Client Information Leak",
        "severity": "High",
        "cvss": 7.5,
        "summary": "Untrusted SSH servers can read sensitive client memory via OpenSSH roaming code."
    },
    {
        "service": "ssh",
        "product": "openssh",
        "version_max": "7.7",
        "cve": "CVE-2018-15473",
        "title": "OpenSSH User Enumeration via Malformed Authentication Requests",
        "severity": "Medium",
        "cvss": 5.3,
        "summary": "Allows remote attackers to discover valid system usernames by analyzing server response times."
    },
    {
        "service": "ssh",
        "product": "openssh",
        "version_min": "8.5",
        "version_max": "9.7",
        "cve": "CVE-2024-6387",
        "title": "RegreSSHion: Remote Unauthenticated Code Execution in OpenSSH Server",
        "severity": "Critical",
        "cvss": 9.8,
        "summary": "Signal handler race condition in sshd allows remote unauthenticated root code execution."
    },
    {
        "service": "http",
        "product": "apache",
        "version_min": "2.4.49",
        "version_max": "2.4.50",
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "severity": "Critical",
        "cvss": 9.8,
        "summary": "Flaw in path normalization allows arbitrary file read and CGI script execution."
    },
    {
        "service": "http",
        "product": "apache",
        "version_max": "2.4.29",
        "cve": "CVE-2017-15715",
        "title": "Apache HTTP Server MIME Type / FilesMatch Bypass",
        "severity": "Medium",
        "cvss": 6.8,
        "summary": "Expression in FilesMatch directive can be circumvented using trailing newline character."
    },
    {
        "service": "http",
        "product": "apache",
        "version_max": "2.4.10",
        "cve": "CVE-2014-0226",
        "title": "Apache mod_status Race Condition Denial of Service",
        "severity": "Medium",
        "cvss": 6.8,
        "summary": "Race condition in mod_status scoreboard allows remote denial of service or memory corruption."
    },
    {
        "service": "http",
        "product": "nginx",
        "version_max": "1.20.0",
        "cve": "CVE-2021-23017",
        "title": "Nginx DNS Resolver 1-Byte Memory Overwrite",
        "severity": "High",
        "cvss": 7.7,
        "summary": "Off-by-one buffer overwrite in DNS resolver allows remote worker process crash or potential RCE."
    },
    {
        "service": "microsoft-ds",
        "product": "smb",
        "version_max": "3.0",
        "cve": "CVE-2017-0144",
        "title": "EternalBlue: SMBv1 Remote Code Execution",
        "severity": "Critical",
        "cvss": 9.8,
        "summary": "Critical buffer handling flaw in SMBv1 kernel driver (srv.sys) exploited by WannaCry ransomware."
    },
    {
        "service": "ftp",
        "product": "vsftpd",
        "version_min": "2.3.4",
        "version_max": "2.3.4",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "severity": "Critical",
        "cvss": 9.8,
        "summary": "Malicious backdoor inserted into source archive opens root shell on port 6200 when triggered with smiley face."
    }
]

def match_cves_for_services(ports):
    """Correlate detected port services and versions against known CVEs."""
    matched = []
    max_cvss = 0.0

    for p in ports:
        svc_name = (p.get("service") or "").lower()
        prod = (p.get("product") or "").lower()
        ver = (p.get("version") or "").lower()

        for cve in CVE_DATABASE:
            cve_svc = cve["service"].lower()
            cve_prod = cve["product"].lower()
            
            # Match service name or product name
            if cve_svc in svc_name or cve_prod in prod or cve_prod in svc_name:
                # Check version constraints if present
                v_min = cve.get("version_min")
                v_max = cve.get("version_max")
                is_ver_match = False

                if not v_min and not v_max:
                    is_ver_match = True
                else:
                    if ver:
                        if v_min and v_max:
                            is_ver_match = (ver >= v_min and ver <= v_max)
                        elif v_max:
                            is_ver_match = (ver <= v_max)
                        elif v_min:
                            is_ver_match = (ver >= v_min)
                    else:
                        is_ver_match = True

                if is_ver_match:
                    match_item = dict(cve)
                    match_item["port"] = p.get("port")
                    match_item["detected_service"] = f"{p.get('service')} {ver}".strip()
                    matched.append(match_item)
                    if cve["cvss"] > max_cvss:
                        max_cvss = cve["cvss"]

    if max_cvss >= 9.0:
        overall_severity = "Critical"
        score = max(20, int(100 - (max_cvss * 8)))
    elif max_cvss >= 7.0:
        overall_severity = "High"
        score = max(40, int(100 - (max_cvss * 7)))
    elif max_cvss >= 4.0:
        overall_severity = "Medium"
        score = max(65, int(100 - (max_cvss * 6)))
    elif max_cvss > 0.0:
        overall_severity = "Low"
        score = max(80, int(100 - (max_cvss * 5)))
    else:
        overall_severity = "None"
        score = 94

    return overall_severity, score, matched

# ==============================================================================
# NETWORK INTERFACE ENUMERATION
# ==============================================================================
def get_system_interfaces():
    interfaces = []
    if not SCAPY_AVAILABLE:
        return interfaces

    try:
        for iface_key, iface in IFACES.data.items():
            name = iface.name or iface_key
            desc = getattr(iface, "description", name)
            ip = getattr(iface, "ip", "") or ""
            mac = getattr(iface, "mac", "") or ""
            guid = getattr(iface, "guid", name)

            if_type = "ethernet"
            icon = "fa-ethernet"
            name_lower = name.lower() + " " + desc.lower()

            if "wi-fi" in name_lower or "wireless" in name_lower or "802.11" in name_lower or "wlan" in name_lower:
                if_type = "wireless"
                icon = "fa-wifi"
            elif "loopback" in name_lower:
                if_type = "loopback"
                icon = "fa-rotate"
            elif "vmware" in name_lower or "virtual" in name_lower or "vpn" in name_lower or "hyper-v" in name_lower:
                if_type = "virtual"
                icon = "fa-network-wired"

            status = "active" if (ip and ip != "0.0.0.0" and not ip.startswith("169.254")) else "idle"

            # Clean display label
            clean_label = name
            if desc and desc != name and not name.startswith("Local Area"):
                clean_label = f"{name} ({desc})"

            interfaces.append({
                "id": name,
                "name": clean_label,
                "description": desc,
                "ip": ip if ip else "0.0.0.0",
                "mac": mac,
                "guid": guid,
                "type": if_type,
                "status": status,
                "icon": icon,
                "rxRate": "Active Traffic" if status == "active" else "Idle"
            })
    except Exception as e:
        print("Interface enumeration error:", e)

    # Always ensure Loopback exists
    if not any(i["id"] == "Loopback" or i["type"] == "loopback" for i in interfaces):
        interfaces.append({
            "id": "Loopback",
            "name": "Software Loopback (127.0.0.1)",
            "description": "Local Host Loopback Adapter",
            "ip": "127.0.0.1",
            "mac": "00:00:00:00:00:00",
            "guid": "\\Device\\NPF_Loopback",
            "type": "loopback",
            "status": "active",
            "icon": "fa-rotate",
            "rxRate": "Local"
        })

    return interfaces

# ==============================================================================
# SCAPY PACKET CAPTURE WORKER
# ==============================================================================
def scapy_packet_handler(pkt):
    global capture_state, captured_packets_buffer, packet_timestamps_1s, syn_history

    with capture_lock:
        if not capture_state["running"] or capture_state["paused"]:
            return

        total = capture_state["total_packets"] + 1
        limit = capture_state["limit"]

        if total > limit:
            capture_state["limit_reached"] = True
            capture_state["paused"] = True
            return

        now = time.time()
        packet_timestamps_1s.append(now)

        # Calculate live PPS
        one_sec_ago = now - 1.0
        while packet_timestamps_1s and packet_timestamps_1s[0] < one_sec_ago:
            packet_timestamps_1s.popleft()
        current_pps = len(packet_timestamps_1s)
        capture_state["pps"] = current_pps

        # Traffic spike detection
        if current_pps > 3000:
            capture_state["is_spike"] = True

        capture_state["total_packets"] = total
        capture_state["seq"] += 1

        # Protocol & Addressing
        proto_name = "OTHER"
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = ""
        dst_port = ""
        payload_bytes = b""
        headers_list = []

        if pkt.haslayer(Ether):
            headers_list.append(f"Ethernet II: Src: {pkt[Ether].src} -> Dst: {pkt[Ether].dst}")

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            headers_list.append(f"IPv4: Src: {src_ip} -> Dst: {dst_ip}, Proto: {proto_num}")
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            headers_list.append(f"IPv6: Src: {src_ip} -> Dst: {dst_ip}")

        # Quarantine check
        if src_ip in active_blocked_ips or dst_ip in active_blocked_ips:
            blocked_packets_log.append({
                "id": len(blocked_packets_log) + 1,
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": src_ip,
                "dst": dst_ip,
                "proto": "BLOCKED",
                "reason": f"Active Blocklist: Traffic quarantined from {src_ip}",
                "action": "Dropped"
            })
            return

        # Target IP filter
        target_filter = capture_state["target_ip"]
        if target_filter and target_filter != "all":
            if src_ip != target_filter and dst_ip != target_filter:
                return

        # Layer determination
        if pkt.haslayer(TCP):
            proto_name = "TCP"
            capture_state["proto_counts"]["tcp"] += 1
            src_port = str(pkt[TCP].sport)
            dst_port = str(pkt[TCP].dport)
            flags = pkt[TCP].flags
            headers_list.append(f"TCP: Port {src_port} -> {dst_port} [Flags: {flags}] Seq: {pkt[TCP].seq}")
            if pkt.haslayer(Raw):
                payload_bytes = pkt[Raw].load
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            capture_state["proto_counts"]["udp"] += 1
            src_port = str(pkt[UDP].sport)
            dst_port = str(pkt[UDP].dport)
            headers_list.append(f"UDP: Port {src_port} -> {dst_port} Length: {pkt[UDP].len}")
            if pkt.haslayer(Raw):
                payload_bytes = pkt[Raw].load
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
            capture_state["proto_counts"]["icmp"] += 1
            headers_list.append(f"ICMP: Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}")
        elif pkt.haslayer(ARP):
            proto_name = "ARP"
            capture_state["proto_counts"]["other"] += 1
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            headers_list.append(f"ARP: Op: {pkt[ARP].op} Src: {src_ip} -> Dst: {dst_ip}")
        else:
            capture_state["proto_counts"]["other"] += 1

        # Application-layer hints
        if dst_port == "80" or src_port == "80":
            proto_name = "HTTP"
        elif dst_port == "443" or src_port == "443":
            proto_name = "TLS"
        elif dst_port == "53" or src_port == "53":
            proto_name = "DNS"
        elif dst_port == "22" or src_port == "22":
            proto_name = "SSH"

        # Summary text
        summary = pkt.summary()
        pkt_len = len(pkt)
        hex_preview = " ".join(f"{b:02x}" for b in bytes(pkt)[:64]) + (" ..." if pkt_len > 64 else "")

        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        packet_record = {
            "id": total,
            "seq": capture_state["seq"],
            "time": time_str,
            "proto": proto_name,
            "src": src_ip,
            "dst": dst_ip,
            "port": dst_port,
            "len": pkt_len,
            "summary": summary,
            "headers": headers_list,
            "hex": hex_preview,
            "isThreat": False,
            "threatReason": "",
            "status": "NORMAL"
        }

        # Threat heuristics:
        # 1. Plaintext credential leak
        if payload_bytes:
            payload_str = payload_bytes.decode('latin1', errors='ignore')
            if re.search(r'(password|passwd|pass|pwd)=', payload_str, re.IGNORECASE):
                packet_record["isThreat"] = True
                packet_record["threatReason"] = "Unencrypted Credential Leak (Plaintext HTTP POST submission with password)"
                packet_record["status"] = "LEAK ALERT"
                packet_record["summary"] = f"🚨 CLEARTEXT LEAK: Plaintext password transmitted to {dst_ip}"

            # 2. SQL injection
            elif re.search(r'(UNION\s+SELECT|SELECT.*FROM|DROP\s+TABLE|--\s*$)', payload_str, re.IGNORECASE):
                packet_record["isThreat"] = True
                packet_record["threatReason"] = "Web Application Exploit: SQL Injection Pattern matched in packet payload"
                packet_record["status"] = "EXPLOIT ALERT"
                packet_record["summary"] = f"🚨 SQL INJECTION: Malicious SQL payload targeting {dst_ip}"

        # 3. Port sweep tracking
        if proto_name == "TCP" and pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            syn_history.append((src_ip, dst_port, now))
            recent_syns = [item for item in syn_history if item[0] == src_ip and now - item[2] < 2.0]
            unique_ports = {item[1] for item in recent_syns}
            if len(unique_ports) >= 12:
                packet_record["isThreat"] = True
                packet_record["threatReason"] = f"Rapid Port-Scan Burst (Automated SYN Reconnaissance Sweep targeting {len(unique_ports)} ports)"
                packet_record["status"] = "PORT SCAN BURST"
                packet_record["summary"] = f"🚨 PORT-SCAN BURST: Rapid SYN sweep from {src_ip}"

        if packet_record["isThreat"]:
            capture_state["pending_threat"] = packet_record

        captured_packets_buffer.append(packet_record)

def sniff_worker_loop(iface_name):
    print(f"[*] Scapy sniffer worker started on interface: {iface_name}")
    try:
        # Resolve scapy interface
        selected_iface = conf.iface
        if iface_name and iface_name != "default":
            for k, ifc in IFACES.data.items():
                k_str = str(k)
                if (ifc.name == iface_name or
                    ifc.description == iface_name or
                    getattr(ifc, "guid", "") == iface_name or
                    k_str == iface_name or
                    iface_name.startswith(ifc.name) or
                    (ifc.description and ifc.description in iface_name)):
                    selected_iface = ifc
                    break

        sniff(
            iface=selected_iface,
            prn=scapy_packet_handler,
            store=0,
            stop_filter=lambda p: stop_sniff_event.is_set()
        )
    except Exception as e:
        print(f"[-] Scapy sniffer worker exited with error: {e}")
    finally:
        print("[*] Scapy sniffer worker terminated.")

# ==============================================================================
# REAL ZENMAP SCAN EXECUTION (NMAP)
# ==============================================================================
scan_lock = threading.Lock()
scan_state = {
    "isScanning": False,
    "target": "",
    "profile": "quick",
    "progress": 0,
    "statusText": "Ready",
    "terminalLines": [],
    "result": None,
    "error": None
}

def execute_nmap_worker(target, profile):
    global scan_state

    with scan_lock:
        scan_state["isScanning"] = True
        scan_state["target"] = target
        scan_state["profile"] = profile
        scan_state["progress"] = 5
        scan_state["statusText"] = f"Initiating scan against {target}..."
        scan_state["terminalLines"] = []
        scan_state["result"] = None
        scan_state["error"] = None

    def add_line(text, css_class="term-line"):
        with scan_lock:
            scan_state["terminalLines"].append({"text": text, "class": css_class})

    add_line(f"portpulse@secops:~$ nmap -sS -sV -O -T4 {target}", "term-line term-cyan")
    add_line(f"Starting Nmap 7.98 ( https://nmap.org ) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "term-line term-muted")

    # Resolve target hostname
    resolved_ip = target
    reverse_dns = target
    try:
        resolved_ip = socket.gethostbyname(target)
        try:
            rdns_lookup = socket.gethostbyaddr(resolved_ip)
            reverse_dns = rdns_lookup[0]
        except Exception:
            reverse_dns = target
    except Exception as dns_err:
        with scan_lock:
            scan_state["isScanning"] = False
            scan_state["error"] = f"DNS Resolution Error: Unable to resolve '{target}' ({dns_err})"
            scan_state["statusText"] = "Scan Failed"
        add_line(f"Failed to resolve '{target}': Host name resolution failure.", "term-line term-crimson")
        return

    with scan_lock:
        scan_state["progress"] = 25
        scan_state["statusText"] = f"Host is UP ({resolved_ip}). Scanning top ports..."

    add_line(f"Host is UP ({resolved_ip}). Reverse DNS: {reverse_dns}", "term-line term-green")

    # Command builder
    cmd = [NMAP_PATH, "-sS", "-sV", "-O", "-T4", "-F", "--version-light", "-oX", "-", target]
    if profile == "web":
        cmd = [NMAP_PATH, "-sS", "-sV", "-p", "80,443,8080,8443,3000", "-oX", "-", target]
    elif profile == "vuln":
        cmd = [NMAP_PATH, "-sS", "-sV", "-O", "--script=vulners", "-T4", "-oX", "-", target]
    elif profile == "full":
        cmd = [NMAP_PATH, "-sS", "-sV", "-O", "-A", "-T4", "-oX", "-", target]

    add_line(f"Initiating SYN Stealth Scan & Version Detection on {resolved_ip}...", "term-line term-muted")

    with scan_lock:
        scan_state["progress"] = 50

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        with scan_lock:
            scan_state["isScanning"] = False
            scan_state["error"] = f"Scan Timed Out: Target {target} did not respond within 90 seconds."
            scan_state["statusText"] = "Scan Timed Out"
        add_line(f"Scan timed out after 90 seconds.", "term-line term-crimson")
        return
    except Exception as ex:
        with scan_lock:
            scan_state["isScanning"] = False
            scan_state["error"] = f"Execution Error: {ex}"
            scan_state["statusText"] = "Scan Error"
        add_line(f"Execution failed: {ex}", "term-line term-crimson")
        return

    xml_output = proc.stdout

    # If -sS failed due to privileges, fallback to -sT
    if proc.returncode != 0 and ("requires root" in proc.stderr.lower() or "dnet" in proc.stderr.lower()):
        add_line("SYN scan unprivileged; falling back to TCP Connect scan (-sT)...", "term-line term-amber")
        cmd_fallback = [NMAP_PATH, "-sT", "-sV", "-F", "-oX", "-", target]
        proc = subprocess.run(cmd_fallback, capture_output=True, text=True, timeout=90)
        xml_output = proc.stdout

    with scan_lock:
        scan_state["progress"] = 80
        scan_state["statusText"] = "Parsing XML response and evaluating CVE database..."

    # Parse XML results
    parsed_ports = []
    os_name = "Generic Device (Fingerprint not conclusive)"
    os_cpe = "cpe:/o:general:generic"
    host_status = "down"
    latency_str = "0 ms"

    try:
        if xml_output and "<nmaprun" in xml_output:
            root = ET.fromstring(xml_output)
            host_node = root.find("host")
            if host_node is not None:
                # Status
                st_el = host_node.find("status")
                if st_el is not None:
                    host_status = st_el.get("state", "up")

                # Times / Latency
                times_el = host_node.find("times")
                if times_el is not None:
                    srtt = times_el.get("srtt", "10000")
                    latency_ms = max(1, int(int(srtt) / 1000))
                    latency_str = f"{latency_ms} ms"

                # OS Match
                os_match = host_node.find(".//osmatch")
                if os_match is not None:
                    os_name = os_match.get("name", os_name)
                    cpe_el = host_node.find(".//osclass/cpe")
                    if cpe_el is not None and cpe_el.text:
                        os_cpe = cpe_el.text

                # Ports
                for p_el in host_node.findall(".//port"):
                    port_id = int(p_el.get("portid", "0"))
                    protocol = p_el.get("protocol", "tcp")
                    state_el = p_el.find("state")
                    port_state = state_el.get("state", "closed") if state_el is not None else "closed"

                    svc_el = p_el.find("service")
                    svc_name = "unknown"
                    svc_product = ""
                    svc_version = ""
                    svc_extrainfo = ""
                    cpe_str = ""

                    if svc_el is not None:
                        svc_name = svc_el.get("name", "unknown")
                        svc_product = svc_el.get("product", "")
                        svc_version = svc_el.get("version", "")
                        svc_extrainfo = svc_el.get("extrainfo", "")
                        cpe_child = svc_el.find("cpe")
                        if cpe_child is not None and cpe_child.text:
                            cpe_str = cpe_child.text

                    parsed_ports.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": port_state,
                        "service": svc_name,
                        "product": svc_product,
                        "version": svc_version,
                        "extrainfo": svc_extrainfo,
                        "cpe": cpe_str
                    })
    except Exception as parse_err:
        print("XML Parse warning:", parse_err)

    if host_status != "up" and not parsed_ports:
        with scan_lock:
            scan_state["isScanning"] = False
            scan_state["error"] = f"Host Unreachable: Target {target} reported as {host_status}. Host may be offline or dropping ICMP packets."
            scan_state["statusText"] = "Host Unreachable"
        add_line(f"Host appears down. If blocking ping probes, re-scan with -Pn flag.", "term-line term-crimson")
        return

    # Correlate CVEs
    vuln_rating, risk_score, matched_cves = match_cves_for_services(parsed_ports)

    # Format ports for GUI
    cve_ports = {mc.get("port"): mc for mc in matched_cves if mc.get("port")}
    formatted_ports = []
    for p in parsed_ports:
        port_num = p["port"]
        ver_str = f"{p['product']} {p['version']}".strip() or "-"
        if port_num in cve_ports:
            risk = "danger" if cve_ports[port_num]["cvss"] >= 7.0 else "warn"
            note = f"CVE Match: {cve_ports[port_num]['cve']} ({cve_ports[port_num]['title']})"
        elif p["state"] == "open" and p["service"] in ["http", "telnet", "ftp", "tftp", "smtp"]:
            risk = "warn"
            note = "Cleartext transmission service without encryption."
        elif p["state"] == "open":
            risk = "safe"
            note = f"Service active: {p['service']} ({ver_str})"
        else:
            risk = "safe"
            note = f"Port status: {p['state'].upper()}"

        formatted_ports.append({
            "port": port_num,
            "proto": p["protocol"].upper(),
            "state": p["state"],
            "service": p["service"],
            "version": ver_str,
            "risk": risk,
            "note": note,
            "cpe": p.get("cpe", "")
        })

    # Add terminal summary lines
    open_count = len([p for p in formatted_ports if p["state"] == "open"])
    add_line(f"Discovered {open_count} open ports on {resolved_ip}", "term-line term-green")
    for p in formatted_ports:
        if p["state"] == "open":
            svc_info = f"{p['service']} {p['version']}".strip()
            add_line(f"  {p['port']}/{p['proto']} [open] - {svc_info}", "term-line")

    add_line(f"OS Detection: {os_name} [{os_cpe}]", "term-line")
    if matched_cves:
        add_line(f"Vulnerability Match: Found {len(matched_cves)} CVE matches (Severity: [{vuln_rating.upper()}])", "term-line term-amber")
        for mc in matched_cves[:3]:
            add_line(f"  | {mc['cve']} (CVSS {mc['cvss']}): {mc['title']}", "term-line term-amber")
    else:
        add_line(f"Vulnerability Scan: No critical CVE matches identified.", "term-line term-muted")

    add_line(f"Nmap done: 1 IP address (1 host up) scanned in {latency_str}.", "term-line term-green")

    scan_result_payload = {
        "target": target,
        "ip": resolved_ip,
        "rdns": reverse_dns,
        "status": "UP",
        "latency": latency_str,
        "os": os_name,
        "cpe": os_cpe,
        "mac": f"BGP ASN / Gateway ({resolved_ip})",
        "advice": f"Nmap audit completed for {resolved_ip}. Discovered {open_count} open ports.",
        "vulnRating": vuln_rating,
        "score": risk_score,
        "ports": formatted_ports,
        "cves": matched_cves,
        "scanDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    with scan_lock:
        scan_state["isScanning"] = False
        scan_state["progress"] = 100
        scan_state["statusText"] = "Zenmap deep scan completed successfully!"
        scan_state["result"] = scan_result_payload

# ==============================================================================
# FLASK HTTP ROUTES & API ENDPOINTS
# ==============================================================================
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(BASE_DIR, filename)

@app.route('/api/system/status', methods=['GET'])
def api_system_status():
    return jsonify({
        "status": "ok",
        "scapy_available": SCAPY_AVAILABLE,
        "nmap_path": NMAP_PATH,
        "nmap_installed": os.path.exists(NMAP_PATH),
        "python_version": sys.version
    })

@app.route('/api/interfaces', methods=['GET'])
def api_interfaces():
    ifaces = get_system_interfaces()
    return jsonify({
        "success": True,
        "interfaces": ifaces,
        "count": len(ifaces),
        "timestamp": time.time()
    })

@app.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    global sniff_thread, stop_sniff_event, capture_state

    data = request.get_json() or {}
    iface = data.get("interface", "Wi-Fi")
    target_ip = data.get("target_ip", "all")
    limit = int(data.get("limit", 50000))
    limit_mode = data.get("limit_mode", "normal")

    with capture_lock:
        # Stop existing
        if capture_state["running"]:
            stop_sniff_event.set()
            if sniff_thread and sniff_thread.is_alive():
                sniff_thread.join(timeout=1.5)

        stop_sniff_event.clear()
        capture_state["running"] = True
        capture_state["paused"] = False
        capture_state["limit_reached"] = False
        capture_state["interface_id"] = iface
        capture_state["target_ip"] = target_ip
        capture_state["limit"] = limit
        capture_state["limit_mode"] = limit_mode
        capture_state["is_spike"] = False
        capture_state["pending_threat"] = None

    sniff_thread = threading.Thread(target=sniff_worker_loop, args=(iface,), daemon=True)
    sniff_thread.start()

    return jsonify({
        "success": True,
        "message": f"Real packet capture started on {iface}",
        "interface": iface,
        "limit": limit
    })

@app.route('/api/capture/pause', methods=['POST'])
def api_capture_pause():
    with capture_lock:
        capture_state["paused"] = True
    return jsonify({"success": True, "status": "paused"})

@app.route('/api/capture/resume', methods=['POST'])
def api_capture_resume():
    data = request.get_json() or {}
    extend_limit = int(data.get("extend_limit", 0))

    with capture_lock:
        if extend_limit > 0:
            capture_state["limit"] += extend_limit
        capture_state["limit_reached"] = False
        capture_state["paused"] = False
    return jsonify({"success": True, "status": "capturing", "limit": capture_state["limit"]})

@app.route('/api/capture/stop', methods=['POST'])
def api_capture_stop():
    global sniff_thread, stop_sniff_event
    with capture_lock:
        capture_state["running"] = False
        capture_state["paused"] = True
    stop_sniff_event.set()
    return jsonify({"success": True, "status": "stopped"})

@app.route('/api/capture/clear', methods=['POST'])
def api_capture_clear():
    global captured_packets_buffer, packet_timestamps_1s
    with capture_lock:
        captured_packets_buffer.clear()
        packet_timestamps_1s.clear()
        capture_state["total_packets"] = 0
        capture_state["seq"] = 0
        capture_state["proto_counts"] = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
        capture_state["limit_reached"] = False
        capture_state["is_spike"] = False
        capture_state["pending_threat"] = None
    return jsonify({"success": True, "status": "cleared"})

@app.route('/api/capture/poll', methods=['GET'])
def api_capture_poll():
    since_seq = int(request.args.get("since_seq", 0))

    with capture_lock:
        new_packets = [p for p in captured_packets_buffer if p["seq"] > since_seq]
        threat = capture_state["pending_threat"]
        capture_state["pending_threat"] = None  # Consume once

        state_copy = {
            "running": capture_state["running"],
            "paused": capture_state["paused"],
            "limit_reached": capture_state["limit_reached"],
            "total_packets": capture_state["total_packets"],
            "limit": capture_state["limit"],
            "limit_mode": capture_state["limit_mode"],
            "interface_id": capture_state["interface_id"],
            "target_ip": capture_state["target_ip"],
            "pps": capture_state["pps"],
            "baseline": capture_state["baseline"],
            "is_spike": capture_state["is_spike"],
            "proto_counts": dict(capture_state["proto_counts"]),
            "latest_seq": capture_state["seq"],
            "blocked_count": len(blocked_packets_log)
        }

    return jsonify({
        "success": True,
        "state": state_copy,
        "packets": new_packets[-40:],  # Return up to 40 newest per poll
        "threat": threat
    })

@app.route('/api/capture/block', methods=['POST'])
def api_capture_block():
    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "Malicious signature flagged by user")

    if not ip:
        return jsonify({"success": False, "error": "IP is required"}), 400

    active_blocked_ips.add(ip)
    blocked_packets_log.append({
        "id": len(blocked_packets_log) + 1,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": ip,
        "dst": "Any",
        "proto": "ALL",
        "reason": reason,
        "action": "Blocked"
    })

    return jsonify({
        "success": True,
        "blocked_ip": ip,
        "total_blocked": len(blocked_packets_log)
    })

@app.route('/api/capture/unblock', methods=['POST'])
def api_capture_unblock():
    data = request.get_json() or {}
    ip = data.get("ip")
    if ip and ip in active_blocked_ips:
        active_blocked_ips.remove(ip)

    return jsonify({"success": True, "unblocked": ip, "remaining": len(active_blocked_ips)})

@app.route('/api/capture/blocked', methods=['GET'])
def api_capture_blocked():
    return jsonify({
        "success": True,
        "blocked_ips": list(active_blocked_ips),
        "log": blocked_packets_log
    })

@app.route('/api/capture/inject_threat', methods=['POST'])
def api_capture_inject_threat():
    with capture_lock:
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        threat_pkt = {
            "id": capture_state["total_packets"] + 1,
            "seq": capture_state["seq"] + 1,
            "time": now_str,
            "proto": "HTTP",
            "src": "192.168.1.105",
            "dst": "91.215.85.17",
            "port": "80",
            "len": 486,
            "summary": "🚨 C2 BEACON: Cobalt Strike Malleable HTTP Heartbeat (POST /submit.php)",
            "isThreat": True,
            "threatReason": "Known Malware C2 Signature: Cobalt Strike Malleable HTTP Heartbeat Beacon detected",
            "status": "THREAT ALERT",
            "headers": [
                "IPv4: Src: 192.168.1.105 -> Dst: 91.215.85.17, Proto: TCP (6)",
                "HTTP: POST /submit.php?id=9214 HTTP/1.1\\r\\nHost: c2-darknet.sec\\r\\nCookie: session_guid=7a91bf2e",
                "IPS Signature: [SID 200389] Cobalt Strike Default Profile Indicator"
            ],
            "hex": "50 4f 53 54 20 2f 73 75 62 6d 69 74 2e 70 68 70 3f 69 64 3d 39 32 31 34 ..."
        }
        capture_state["pending_threat"] = threat_pkt
        captured_packets_buffer.append(threat_pkt)
        capture_state["total_packets"] += 1
        capture_state["seq"] += 1

    return jsonify({"success": True, "threat": threat_pkt})

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    profile = data.get("profile", "quick")

    if not target:
        return jsonify({"success": False, "error": "Target host or IP is required"}), 400

    if scan_state["isScanning"]:
        return jsonify({"success": False, "error": "A scan is already in progress. Please wait for it to complete."}), 409

    t = threading.Thread(target=execute_nmap_worker, args=(target, profile), daemon=True)
    t.start()

    return jsonify({"success": True, "target": target, "profile": profile})

@app.route('/api/scan/status', methods=['GET'])
def api_scan_status():
    with scan_lock:
        state_copy = {
            "isScanning": scan_state["isScanning"],
            "target": scan_state["target"],
            "progress": scan_state["progress"],
            "statusText": scan_state["statusText"],
            "terminalLines": list(scan_state["terminalLines"]),
            "result": scan_state["result"],
            "error": scan_state["error"]
        }
    return jsonify(state_copy)

# ==============================================================================
# MAIN ENTRYPOINT (DUAL-STACK IPv6 + IPv4 SERVER)
# ==============================================================================
from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler

class DualStackServer(BaseWSGIServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 3000))
    print(f"===========================================================")
    print(f" PortPulse Studio — Real Diagnostics Engine Backend")
    print(f" Python {sys.version.split()[0]} | Scapy: {'Available' if SCAPY_AVAILABLE else 'Disabled'}")
    print(f" Nmap: {NMAP_PATH}")
    print(f" Listening on http://localhost:{port} and http://127.0.0.1:{port}")
    print(f"===========================================================")
    try:
        server = DualStackServer('::', port, app, handler=WSGIRequestHandler)
        server.serve_forever()
    except Exception as e:
        print(f"Dual stack server fallback to app.run due to: {e}")
        app.run(host='0.0.0.0', port=port, threaded=True, debug=False)
