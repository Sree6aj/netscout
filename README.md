# NetScout 🔍

**Network Enumeration & Security Assessment Tool**

> ⚠️ **For authorized use in controlled lab environments ONLY.** Unauthorized scanning is illegal.

---

## Features

| Module | Capability |
|--------|-----------|
| **Port Scanner** | Multi-threaded TCP connect scan with configurable threads/timeout |
| **Banner Grabber** | Service banner retrieval for version fingerprinting |
| **FTP Enumerator** | Anonymous login detection, SYST info, banner capture |
| **SSH Enumerator** | Version string extraction, outdated version detection |
| **HTTP Enumerator** | Header analysis, missing security headers, path probing |
| **SMB Enumerator** | NetBIOS/SMB port detection, SMBv1 handshake probing |
| **Vuln Analyser** | Maps findings to known vulnerability signatures + CVEs |
| **Reporter** | Coloured terminal output + JSON + CSV export |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/netscout.git
cd netscout
python3 -m pip install -r requirements.txt   # no third-party deps — stdlib only
```

> **Requires:** Python 3.8+  |  No external dependencies (pure stdlib)

---

## Usage

```bash
# Scan common ports (FTP, SSH, HTTP, SMB, etc.)
python3 netscout.py -t 192.168.1.100

# Scan top 1000 ports with more threads
python3 netscout.py -t 192.168.1.100 -p top --threads 200

# Scan specific port range
python3 netscout.py -t 192.168.1.100 -p 1-1024

# Scan specific ports
python3 netscout.py -t 192.168.1.100 -p 22,80,443,445

# Export JSON + CSV reports
python3 netscout.py -t 192.168.1.100 --json report.json --csv report.csv

# Host discovery sweep over a subnet
python3 netscout.py -t 192.168.1.0/24 --sweep

# Skip enumeration (port scan only)
python3 netscout.py -t 192.168.1.100 --no-enum

# Verbose mode
python3 netscout.py -t 192.168.1.100 -v
```

---

## Port Specification

| Value | Description |
|-------|-------------|
| `common` | ~50 well-known ports (default) |
| `top` | Top ~1000 ports |
| `all` | All 65535 ports |
| `80,443,8080` | Comma-separated list |
| `1-1024` | Port range |

---

## Sample Output

```
  [*] Resolved metasploitable.local → 192.168.56.101
  [*] Scanning 52 ports on 192.168.56.101 (100 threads) ...
  [*] Scan complete in 1.23s — 8 open port(s) found.

══════════════════════════════════════════════════════════════
  OPEN PORTS
══════════════════════════════════════════════════════════════

  PORT     STATE    SERVICE          BANNER
  ─────── ─────── ──────────────── ──────────────────────────
  21       open     FTP              220 (vsFTPd 2.3.4)
  22       open     SSH              SSH-2.0-OpenSSH_4.7p1
  80       open     HTTP             HTTP/1.1 200 OK
  139      open     NetBIOS
  445      open     SMB

══════════════════════════════════════════════════════════════
  VULNERABILITY FINDINGS
══════════════════════════════════════════════════════════════

  [CRITICAL]  Port 445  —  SMBv1 Protocol May Be Enabled (EternalBlue Risk)
              CVE: CVE-2017-0143
              Evidence: SMB port 445 open; SMBv1 negotiation possible
              Fix: Disable SMBv1 immediately. Apply MS17-010 patch.

  [HIGH]  Port 21  —  Anonymous FTP Login Allowed
          CVE: N/A
          Evidence: Anonymous FTP login succeeded
          Fix: Disable anonymous FTP access on the server.
```

---

## Architecture

```
netscout/
├── netscout.py          # Main tool (all-in-one)
├── README.md
├── requirements.txt     # (empty — pure stdlib)
├── sample_output/
│   ├── sample_report.json
│   └── sample_report.csv
└── tests/
    └── test_netscout.py
```

---

## Enumerated Services

### FTP (Port 21)
- Banner capture
- Anonymous login test (`USER anonymous` / `PASS anonymous@example.com`)
- SYST command for OS fingerprinting

### SSH (Port 22)
- Protocol version string capture
- OpenSSH version comparison against known-old versions

### HTTP (Ports 80, 8080, 8000, 8888, 8443)
- Server header disclosure detection
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Technology fingerprinting (X-Powered-By)
- Interesting path probing (/admin, /.git/HEAD, /robots.txt, etc.)

### SMB (Ports 139, 445)
- Port reachability
- SMBv1 negotiate probe
- EternalBlue risk assessment

---

## Detected Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| FTP_ANONYMOUS | HIGH | Anonymous FTP Login Allowed |
| FTP_CLEARTEXT | HIGH | FTP Transmits Credentials in Cleartext |
| SSH_WEAK_ALGO | MEDIUM | SSH Server Exposes Weak Algorithms |
| HTTP_SERVER_HEADER | LOW | HTTP Server Version Disclosed |
| SMB_V1_ENABLED | CRITICAL | SMBv1 Enabled (EternalBlue Risk) |
| TELNET_OPEN | HIGH | Telnet Service Detected |
| OPEN_REDIS | CRITICAL | Redis Accessible Without Auth |
| OPEN_MONGODB | CRITICAL | MongoDB Without Authentication |

---

## Legal Disclaimer

This tool is provided for **educational purposes and authorized security testing only**.
Running this tool against systems you do not own or have explicit written permission
to test is **illegal** under the Computer Fraud and Abuse Act (CFAA) and equivalent
laws in other jurisdictions.

The author assumes no liability for misuse of this tool.

---

## License

MIT License — see `LICENSE` file.

---

## Suggested Lab Targets

- **Metasploitable 2/3** — intentionally vulnerable Linux VM
- **DVWA** (Damn Vulnerable Web Application)
- **VulnHub** machines
- **HackTheBox** (Starting Point)
- **TryHackMe** labs
