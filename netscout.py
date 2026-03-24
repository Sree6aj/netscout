#!/usr/bin/env python3
"""
NetScout - Network Enumeration & Security Assessment Tool
=========================================================
Author  : Security Intern
Purpose : Network reconnaissance, port scanning, service enumeration,
          banner grabbing, and basic vulnerability detection.
Usage   : python3 netscout.py --help
WARNING : For authorized penetration testing / lab environments ONLY.
"""

import argparse
import socket
import sys
import os
import json
import csv
import threading
import time
import struct
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# ─── ANSI Colour Helpers ───────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def info(msg):  print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def banner(msg):
    width = 60
    print(f"\n{C.BOLD}{C.BLUE}{'═'*width}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  {msg}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'═'*width}{C.RESET}")

# ─── Port / Service Database ──────────────────────────────────────────────────
WELL_KNOWN_PORTS = {
    21:   "FTP",      22:  "SSH",     23:  "Telnet",    25:  "SMTP",
    53:   "DNS",      67:  "DHCP",    80:  "HTTP",      110: "POP3",
    111:  "RPCBind",  119: "NNTP",    123: "NTP",       135: "MS-RPC",
    137:  "NetBIOS",  138: "NetBIOS", 139: "NetBIOS",   143: "IMAP",
    161:  "SNMP",     194: "IRC",     389: "LDAP",      443: "HTTPS",
    445:  "SMB",      465: "SMTPS",   500: "IKE",       514: "Syslog",
    515:  "LPD",      587: "SMTP",    631: "IPP",       636: "LDAPS",
    873:  "rsync",    993: "IMAPS",   995: "POP3S",    1080: "SOCKS",
   1433: "MSSQL",   1521: "Oracle", 2049: "NFS",      2121: "FTP-Alt",
   3306: "MySQL",   3389: "RDP",    4444: "Metasploit",5432: "PostgreSQL",
   5900: "VNC",     6379: "Redis",  6667: "IRC",       8080: "HTTP-Alt",
   8443: "HTTPS-Alt",8888:"Jupyter",27017:"MongoDB",
}

TOP_1000_PORTS = list(WELL_KNOWN_PORTS.keys()) + [
    # Common web / app ports
    81, 82, 83, 280, 300, 591, 593, 832, 981, 1010, 1311, 1723,
    2000, 2001, 2082, 2083, 2086, 2087, 2095, 2096, 2100, 2222,
    3000, 3001, 3128, 3333, 4000, 4001, 4002, 4003, 4004, 4005,
    4045, 4100, 4125, 4444, 4567, 4848, 4993, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061,
    5101, 5120, 5190, 5357, 5432, 5500, 5566, 5631, 5666, 5800,
    5814, 5985, 5986, 6000, 6001, 6005, 6646, 7000, 7001, 7002,
    7004, 7070, 7100, 7200, 7201, 7402, 7777, 7778, 7779, 8000,
    8001, 8002, 8008, 8009, 8010, 8011, 8021, 8031, 8042, 8045,
    8069, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8093, 8099, 8100, 8180, 8181, 8182, 8243, 8280, 8281,
    8333, 8384, 8444, 8445, 8446, 8531, 8583, 8686, 8765, 8812,
    8834, 8880, 8888, 8899, 8983, 9000, 9043, 9060, 9080, 9090,
    9091, 9200, 9300, 9418, 9443, 9444, 9999, 10000, 10001, 10443,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159
]

# ─── Vulnerability Signatures ─────────────────────────────────────────────────
VULN_SIGNATURES = {
    "FTP_ANONYMOUS": {
        "desc": "Anonymous FTP Login Allowed",
        "severity": "HIGH",
        "cve": "N/A",
        "remediation": "Disable anonymous FTP access on the server."
    },
    "SSH_WEAK_ALGO": {
        "desc": "SSH Server Exposes Weak Algorithms",
        "severity": "MEDIUM",
        "cve": "CVE-2023-38408",
        "remediation": "Configure SSH to use only strong ciphers (AES-256-GCM, chacha20-poly1305)."
    },
    "HTTP_SERVER_HEADER": {
        "desc": "HTTP Server Version Disclosed in Header",
        "severity": "LOW",
        "cve": "N/A",
        "remediation": "Suppress server version information via ServerTokens Prod (Apache) or server_tokens off (Nginx)."
    },
    "SMB_V1_ENABLED": {
        "desc": "SMBv1 Protocol May Be Enabled (EternalBlue Risk)",
        "severity": "CRITICAL",
        "cve": "CVE-2017-0143",
        "remediation": "Disable SMBv1 immediately. Apply MS17-010 patch."
    },
    "TELNET_OPEN": {
        "desc": "Telnet Service Detected (Cleartext Protocol)",
        "severity": "HIGH",
        "cve": "N/A",
        "remediation": "Replace Telnet with SSH for remote administration."
    },
    "FTP_CLEARTEXT": {
        "desc": "FTP Transmits Credentials in Cleartext",
        "severity": "HIGH",
        "cve": "N/A",
        "remediation": "Replace FTP with SFTP or FTPS."
    },
    "OPEN_REDIS": {
        "desc": "Redis Accessible Without Authentication",
        "severity": "CRITICAL",
        "cve": "CVE-2022-0543",
        "remediation": "Configure Redis requirepass and bind to loopback only."
    },
    "OPEN_MONGODB": {
        "desc": "MongoDB Listening Without Authentication",
        "severity": "CRITICAL",
        "cve": "N/A",
        "remediation": "Enable MongoDB authentication and restrict network access."
    },
}

# ─── Port Scanner ─────────────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, threads: int = 100):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports: Dict[int, Dict] = {}
        self._lock = threading.Lock()

    def _scan_port(self, port: int) -> Optional[int]:
        """Attempt TCP connect to a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    return port
        except (socket.error, OSError):
            pass
        return None

    def scan(self, ports: List[int]) -> Dict[int, Dict]:
        """Scan a list of ports using a thread pool."""
        info(f"Scanning {len(ports)} ports on {self.target} ({self.threads} threads) ...")
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(futures):
                port = future.result()
                if port is not None:
                    service = WELL_KNOWN_PORTS.get(port, "unknown")
                    with self._lock:
                        self.open_ports[port] = {
                            "port": port,
                            "state": "open",
                            "service": service,
                            "banner": "",
                            "version": "",
                            "vulnerabilities": [],
                        }

        elapsed = time.time() - start
        info(f"Scan complete in {elapsed:.2f}s — {len(self.open_ports)} open port(s) found.")
        return self.open_ports

# ─── Banner Grabber ───────────────────────────────────────────────────────────
class BannerGrabber:
    PROBES = {
        21:   b"",
        22:   b"",
        23:   b"",
        25:   b"EHLO netscout\r\n",
        80:   b"HEAD / HTTP/1.0\r\n\r\n",
        110:  b"",
        143:  b"",
        3306: b"",
        5432: b"",
        6379: b"PING\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\n\r\n",
    }

    def __init__(self, target: str, timeout: float = 3.0):
        self.target = target
        self.timeout = timeout

    def grab(self, port: int) -> str:
        """Connect and retrieve service banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                probe = self.PROBES.get(port, b"")
                if probe:
                    s.sendall(probe)
                raw = s.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()
                return banner[:200]   # cap at 200 chars
        except Exception:
            return ""

# ─── Service Enumerators ──────────────────────────────────────────────────────
class FTPEnumerator:
    def __init__(self, target: str, port: int = 21, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout

    def enumerate(self) -> Dict:
        result = {"anonymous_login": False, "banner": "", "details": []}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, self.port))
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                result["banner"] = banner

                # Test anonymous login
                s.sendall(b"USER anonymous\r\n")
                resp = s.recv(1024).decode("utf-8", errors="replace")
                if resp.startswith("331"):
                    s.sendall(b"PASS anonymous@example.com\r\n")
                    resp2 = s.recv(1024).decode("utf-8", errors="replace")
                    if resp2.startswith("230"):
                        result["anonymous_login"] = True
                        result["details"].append("Anonymous FTP login SUCCESSFUL")
                        # Try listing
                        s.sendall(b"SYST\r\n")
                        syst = s.recv(1024).decode("utf-8", errors="replace").strip()
                        result["details"].append(f"SYST: {syst}")
                    else:
                        result["details"].append("Anonymous login REJECTED")
                else:
                    result["details"].append("Server does not accept anonymous USER")
        except Exception as e:
            result["details"].append(f"Enumeration error: {e}")
        return result


class SSHEnumerator:
    def __init__(self, target: str, port: int = 22, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout

    def enumerate(self) -> Dict:
        result = {"banner": "", "version": "", "details": []}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, self.port))
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                result["banner"] = banner
                # SSH banner format: SSH-2.0-OpenSSH_8.2p1
                if "SSH" in banner:
                    parts = banner.split("-", 2)
                    if len(parts) >= 3:
                        result["version"] = parts[2].strip()
                        result["details"].append(f"SSH version string: {result['version']}")
                # Check for old/weak versions
                version_str = result["version"].lower()
                if "openssh" in version_str:
                    try:
                        ver_num = version_str.split("_")[1].split("p")[0]
                        major, minor = map(int, ver_num.split(".")[:2])
                        if major < 8:
                            result["details"].append(
                                f"WARNING: OpenSSH {ver_num} may be outdated — consider upgrading to 9.x+")
                    except Exception:
                        pass
        except Exception as e:
            result["details"].append(f"SSH enumeration error: {e}")
        return result


class HTTPEnumerator:
    def __init__(self, target: str, port: int = 80, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout

    def _request(self, method: str, path: str = "/") -> Tuple[str, Dict]:
        """Send a raw HTTP request and parse response."""
        headers = {}
        body = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, self.port))
                req = (f"{method} {path} HTTP/1.0\r\n"
                       f"Host: {self.target}\r\n"
                       f"User-Agent: NetScout/1.0\r\n"
                       f"Connection: close\r\n\r\n")
                s.sendall(req.encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 65536:
                        break
                decoded = raw.decode("utf-8", errors="replace")
                if "\r\n\r\n" in decoded:
                    header_part, body = decoded.split("\r\n\r\n", 1)
                    for line in header_part.splitlines()[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    status_line = header_part.splitlines()[0]
                    return status_line, headers
        except Exception:
            pass
        return "", headers

    def enumerate(self) -> Dict:
        result = {"headers": {}, "server": "", "details": [], "interesting_paths": []}
        status, headers = self._request("HEAD")
        result["headers"] = headers
        result["server"] = headers.get("server", "Not disclosed")
        result["details"].append(f"Status: {status}")
        result["details"].append(f"Server header: {result['server']}")
        if "x-powered-by" in headers:
            result["details"].append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-frame-options" not in headers:
            result["details"].append("Missing security header: X-Frame-Options")
        if "content-security-policy" not in headers:
            result["details"].append("Missing security header: Content-Security-Policy")
        if "strict-transport-security" not in headers:
            result["details"].append("Missing header: Strict-Transport-Security (HSTS)")

        # Quick path probing
        interesting_paths = [
            "/robots.txt", "/admin", "/login", "/.git/HEAD",
            "/wp-admin", "/phpmyadmin", "/server-status", "/backup",
        ]
        for path in interesting_paths:
            sts, _ = self._request("HEAD", path)
            if sts.startswith("HTTP/") and not sts.split()[1].startswith(("404", "400")):
                result["interesting_paths"].append(f"{path} → {sts.split()[1]}")

        return result


class SMBEnumerator:
    """Basic SMB/NetBIOS detection via TCP handshake inspection."""
    SMB_NEG_PROTO = (
        b"\x00\x00\x00\x85"           # NetBIOS session
        b"\xff\x53\x4d\x42"           # SMB Magic
        b"\x72\x00\x00\x00\x00\x18"
        b"\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
        b"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
        b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
        b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f"
        b"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70"
        b"\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
        b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
        b"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    )

    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout

    def enumerate(self) -> Dict:
        result = {"smb_detected": False, "smb_version": "", "details": [], "shares": []}
        # Port 445 (SMB direct) check
        for port in (445, 139):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.target, port)) == 0:
                        result["smb_detected"] = True
                        result["details"].append(f"SMB/NetBIOS port {port} is open")
                        try:
                            if port == 445:
                                s.sendall(self.SMB_NEG_PROTO)
                                resp = s.recv(1024)
                                if len(resp) > 4 and resp[4:8] == b'\xff\x53\x4d\x42':
                                    result["details"].append("SMBv1 negotiate response received — POTENTIAL EternalBlue risk")
                                    result["smb_version"] = "SMBv1 (detected)"
                        except Exception:
                            result["details"].append(f"Port {port} open but could not negotiate")
            except Exception:
                pass
        if not result["smb_detected"]:
            result["details"].append("No SMB service detected on ports 139/445")
        return result


# ─── Vulnerability Analyser ───────────────────────────────────────────────────
class VulnerabilityAnalyser:
    def analyse(self, open_ports: Dict, enum_data: Dict) -> List[Dict]:
        findings = []

        # FTP checks
        if 21 in open_ports:
            ftp = enum_data.get("ftp", {})
            findings.append({**VULN_SIGNATURES["FTP_CLEARTEXT"],
                              "port": 21, "evidence": "FTP service detected on port 21"})
            if ftp.get("anonymous_login"):
                findings.append({**VULN_SIGNATURES["FTP_ANONYMOUS"],
                                  "port": 21, "evidence": "Anonymous FTP login succeeded"})

        # Telnet
        if 23 in open_ports:
            findings.append({**VULN_SIGNATURES["TELNET_OPEN"],
                              "port": 23, "evidence": "Telnet port 23 is open"})

        # HTTP
        for port in (80, 8080, 8000, 8888):
            if port in open_ports:
                http = enum_data.get(f"http_{port}", {})
                server = http.get("server", "")
                if server and server != "Not disclosed":
                    findings.append({**VULN_SIGNATURES["HTTP_SERVER_HEADER"],
                                      "port": port, "evidence": f"Server: {server}"})

        # SMB
        smb = enum_data.get("smb", {})
        if smb.get("smb_detected"):
            if 445 in open_ports:
                findings.append({**VULN_SIGNATURES["SMB_V1_ENABLED"],
                                  "port": 445, "evidence": "SMB port 445 open; SMBv1 negotiation possible"})

        # Redis
        if 6379 in open_ports:
            findings.append({**VULN_SIGNATURES["OPEN_REDIS"],
                              "port": 6379, "evidence": "Redis port 6379 open without confirmed auth"})

        # MongoDB
        if 27017 in open_ports:
            findings.append({**VULN_SIGNATURES["OPEN_MONGODB"],
                              "port": 27017, "evidence": "MongoDB port 27017 accessible"})

        return findings


# ─── Reporter ─────────────────────────────────────────────────────────────────
class Reporter:
    def __init__(self, target: str, scan_time: str):
        self.target = target
        self.scan_time = scan_time

    def print_summary(self, open_ports, enum_data, vulns):
        banner("SCAN RESULTS SUMMARY")
        print(f"\n  {C.BOLD}Target:{C.RESET} {self.target}   {C.BOLD}Scan time:{C.RESET} {self.scan_time}")

        banner("OPEN PORTS")
        if not open_ports:
            warn("No open ports found.")
        else:
            print(f"\n  {'PORT':<8} {'STATE':<8} {'SERVICE':<16} {'BANNER'}")
            print(f"  {'─'*8} {'─'*8} {'─'*16} {'─'*30}")
            for port in sorted(open_ports.keys()):
                p = open_ports[port]
                banner_snip = (p["banner"][:45] + "…") if len(p["banner"]) > 45 else p["banner"]
                state_col = f"{C.GREEN}{p['state']}{C.RESET}"
                print(f"  {port:<8} {state_col:<17} {p['service']:<16} {banner_snip}")

        banner("SERVICE ENUMERATION DETAILS")
        for svc, data in enum_data.items():
            print(f"\n  {C.BOLD}{C.CYAN}[ {svc.upper()} ]{C.RESET}")
            for detail in data.get("details", []):
                if "WARN" in detail or "anon" in detail.lower() or "risk" in detail.lower():
                    warn(detail)
                else:
                    info(detail)
            if data.get("interesting_paths"):
                for path in data["interesting_paths"]:
                    ok(f"Interesting path: {path}")

        banner("VULNERABILITY FINDINGS")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        vulns_sorted = sorted(vulns, key=lambda x: sev_order.get(x["severity"], 4))
        sev_colours = {
            "CRITICAL": C.RED + C.BOLD,
            "HIGH":     C.RED,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.CYAN,
        }
        for v in vulns_sorted:
            col = sev_colours.get(v["severity"], "")
            print(f"\n  {col}[{v['severity']}]{C.RESET}  Port {v['port']}  —  {v['desc']}")
            print(f"           CVE: {v.get('cve','N/A')}")
            print(f"           Evidence: {v['evidence']}")
            print(f"           Fix: {v['remediation']}")

        if not vulns:
            ok("No vulnerabilities detected.")

        print()

    def save_json(self, open_ports, enum_data, vulns, filename: str):
        report = {
            "metadata": {
                "target": self.target,
                "scan_time": self.scan_time,
                "tool": "NetScout v1.0",
            },
            "open_ports": open_ports,
            "service_enumeration": enum_data,
            "vulnerabilities": vulns,
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        ok(f"JSON report saved → {filename}")

    def save_csv(self, open_ports, vulns, filename: str):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "State", "Service", "Banner"])
            for port, data in sorted(open_ports.items()):
                writer.writerow([port, data["state"], data["service"],
                                  data.get("banner", "")[:100]])
            writer.writerow([])
            writer.writerow(["Severity", "Port", "Description", "CVE", "Remediation"])
            for v in vulns:
                writer.writerow([v["severity"], v["port"], v["desc"],
                                  v.get("cve",""), v["remediation"]])
        ok(f"CSV report saved → {filename}")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────
def parse_ports(port_arg: str) -> List[int]:
    """Parse port specification: '80', '80,443', '1-1000', 'top'."""
    if port_arg == "top":
        return sorted(set(TOP_1000_PORTS))
    if port_arg == "all":
        return list(range(1, 65536))
    if port_arg == "common":
        return sorted(WELL_KNOWN_PORTS.keys())

    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def resolve_target(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            ok(f"Resolved {host} → {ip}")
        return ip
    except socket.gaierror:
        err(f"Cannot resolve host: {host}")
        sys.exit(1)


def main():
    print(f"""
{C.BOLD}{C.BLUE}
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
  Network Enumeration & Security Assessment Tool  v1.0{C.RESET}
  {C.YELLOW}⚠  For authorized use in controlled lab environments ONLY{C.RESET}
""")

    parser = argparse.ArgumentParser(
        description="NetScout — Network Enumeration & Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 netscout.py -t 192.168.1.1
  python3 netscout.py -t 192.168.1.1 -p 1-1024
  python3 netscout.py -t 192.168.1.1 -p top --threads 200 --timeout 0.5
  python3 netscout.py -t 192.168.1.0/24 --sweep   (ping sweep)
  python3 netscout.py -t 192.168.1.1 -p common --no-enum --json out.json
        """
    )
    parser.add_argument("-t", "--target",   required=True, help="Target IP, hostname, or CIDR (for --sweep)")
    parser.add_argument("-p", "--ports",    default="common", help="Ports: common | top | all | 80,443 | 1-1024")
    parser.add_argument("--threads",        type=int, default=100, help="Number of scan threads (default: 100)")
    parser.add_argument("--timeout",        type=float, default=1.0, help="TCP connect timeout in seconds (default: 1.0)")
    parser.add_argument("--no-enum",        action="store_true", help="Skip service enumeration")
    parser.add_argument("--no-vuln",        action="store_true", help="Skip vulnerability analysis")
    parser.add_argument("--sweep",          action="store_true", help="Ping sweep mode for CIDR range")
    parser.add_argument("--json",           metavar="FILE", help="Save JSON report")
    parser.add_argument("--csv",            metavar="FILE", help="Save CSV report")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Verbose output")

    args = parser.parse_args()

    # ── Host Discovery (Ping Sweep) ──
    if args.sweep:
        banner("HOST DISCOVERY — PING SWEEP")
        try:
            network = ipaddress.ip_network(args.target, strict=False)
        except ValueError:
            err(f"Invalid CIDR: {args.target}")
            sys.exit(1)
        info(f"Sweeping {network} ({network.num_addresses} addresses) ...")
        alive = []
        def ping(ip):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((str(ip), 80)) == 0:
                        return str(ip)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=200) as ex:
            results = list(ex.map(ping, network.hosts()))
        alive = [r for r in results if r]
        for h in alive:
            ok(f"Host up: {h}")
        info(f"Found {len(alive)} live host(s)")
        return

    # ── Single Target Scan ──
    target_ip = resolve_target(args.target)
    ports = parse_ports(args.ports)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Port Scan
    scanner = PortScanner(target_ip, timeout=args.timeout, threads=args.threads)
    open_ports = scanner.scan(ports)

    # 2. Banner Grabbing
    if open_ports:
        banner("BANNER GRABBING")
        grabber = BannerGrabber(target_ip, timeout=3.0)
        for port in open_ports:
            b = grabber.grab(port)
            if b:
                open_ports[port]["banner"] = b
                if args.verbose:
                    ok(f"Port {port} banner: {b[:80]}")

    # 3. Service Enumeration
    enum_data = {}
    if not args.no_enum and open_ports:
        banner("SERVICE ENUMERATION")
        if 21 in open_ports:
            info("Enumerating FTP ...")
            enum_data["ftp"] = FTPEnumerator(target_ip).enumerate()
        if 22 in open_ports:
            info("Enumerating SSH ...")
            enum_data["ssh"] = SSHEnumerator(target_ip).enumerate()
        for http_port in (80, 8080, 8000, 8888, 8443):
            if http_port in open_ports:
                info(f"Enumerating HTTP on port {http_port} ...")
                enum_data[f"http_{http_port}"] = HTTPEnumerator(target_ip, port=http_port).enumerate()
        if 445 in open_ports or 139 in open_ports:
            info("Enumerating SMB ...")
            enum_data["smb"] = SMBEnumerator(target_ip).enumerate()

    # 4. Vulnerability Analysis
    vulns = []
    if not args.no_vuln:
        analyser = VulnerabilityAnalyser()
        vulns = analyser.analyse(open_ports, enum_data)

    # 5. Reporting
    reporter = Reporter(target_ip, scan_time)
    reporter.print_summary(open_ports, enum_data, vulns)

    if args.json:
        reporter.save_json(open_ports, enum_data, vulns, args.json)
    if args.csv:
        reporter.save_csv(open_ports, vulns, args.csv)

    print(f"\n{C.BOLD}Scan complete.{C.RESET}  Found {len(open_ports)} open ports, {len(vulns)} vulnerability finding(s).\n")


if __name__ == "__main__":
    main()
