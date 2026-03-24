#!/usr/bin/env python3
"""
Unit tests for NetScout — safe tests against loopback/mock data only.
Run: python3 -m pytest tests/test_netscout.py -v
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscout import (
    parse_ports, resolve_target, WELL_KNOWN_PORTS,
    VulnerabilityAnalyser, Reporter, C
)


class TestParsePortsFunction(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(parse_ports("80,443,22"), [22, 80, 443])

    def test_range(self):
        ports = parse_ports("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

    def test_common(self):
        ports = parse_ports("common")
        self.assertIn(80, ports)
        self.assertIn(22, ports)
        self.assertIn(445, ports)

    def test_top(self):
        ports = parse_ports("top")
        self.assertGreater(len(ports), 100)

    def test_deduplication(self):
        ports = parse_ports("80,80,443")
        self.assertEqual(len(ports), 2)


class TestWellKnownPorts(unittest.TestCase):
    def test_ftp(self):
        self.assertEqual(WELL_KNOWN_PORTS[21], "FTP")

    def test_ssh(self):
        self.assertEqual(WELL_KNOWN_PORTS[22], "SSH")

    def test_http(self):
        self.assertEqual(WELL_KNOWN_PORTS[80], "HTTP")

    def test_smb(self):
        self.assertEqual(WELL_KNOWN_PORTS[445], "SMB")

    def test_https(self):
        self.assertEqual(WELL_KNOWN_PORTS[443], "HTTPS")


class TestVulnerabilityAnalyser(unittest.TestCase):
    def setUp(self):
        self.analyser = VulnerabilityAnalyser()

    def test_ftp_cleartext_detected(self):
        open_ports = {21: {"port": 21, "state": "open", "service": "FTP",
                           "banner": "", "version": "", "vulnerabilities": []}}
        vulns = self.analyser.analyse(open_ports, {})
        sigs = [v["desc"] for v in vulns]
        self.assertIn("FTP Transmits Credentials in Cleartext", sigs)

    def test_anonymous_ftp_detected(self):
        open_ports = {21: {"port": 21, "state": "open", "service": "FTP",
                           "banner": "", "version": "", "vulnerabilities": []}}
        enum_data = {"ftp": {"anonymous_login": True, "details": []}}
        vulns = self.analyser.analyse(open_ports, enum_data)
        sigs = [v["desc"] for v in vulns]
        self.assertIn("Anonymous FTP Login Allowed", sigs)

    def test_telnet_detected(self):
        open_ports = {23: {"port": 23, "state": "open", "service": "Telnet",
                           "banner": "", "version": "", "vulnerabilities": []}}
        vulns = self.analyser.analyse(open_ports, {})
        sigs = [v["desc"] for v in vulns]
        self.assertIn("Telnet Service Detected (Cleartext Protocol)", sigs)

    def test_no_vulns_on_clean_target(self):
        open_ports = {443: {"port": 443, "state": "open", "service": "HTTPS",
                            "banner": "", "version": "", "vulnerabilities": []}}
        vulns = self.analyser.analyse(open_ports, {})
        self.assertEqual(len(vulns), 0)

    def test_smb_vuln_detected(self):
        open_ports = {445: {"port": 445, "state": "open", "service": "SMB",
                            "banner": "", "version": "", "vulnerabilities": []}}
        enum_data = {"smb": {"smb_detected": True, "details": []}}
        vulns = self.analyser.analyse(open_ports, enum_data)
        sigs = [v["desc"] for v in vulns]
        self.assertIn("SMBv1 Protocol May Be Enabled (EternalBlue Risk)", sigs)

    def test_severity_ordering(self):
        """CRITICAL findings must appear before LOW ones."""
        open_ports = {
            21: {"port": 21, "state": "open", "service": "FTP",
                 "banner": "", "version": "", "vulnerabilities": []},
            445: {"port": 445, "state": "open", "service": "SMB",
                  "banner": "", "version": "", "vulnerabilities": []},
        }
        enum_data = {"smb": {"smb_detected": True, "details": []}}
        vulns = self.analyser.analyse(open_ports, enum_data)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_v = sorted(vulns, key=lambda x: sev_order.get(x["severity"], 4))
        self.assertEqual(sorted_v[0]["severity"], "CRITICAL")


class TestReporterInit(unittest.TestCase):
    def test_reporter_creation(self):
        r = Reporter("192.168.1.1", "2025-01-01 12:00:00")
        self.assertEqual(r.target, "192.168.1.1")
        self.assertEqual(r.scan_time, "2025-01-01 12:00:00")


class TestResolveTarget(unittest.TestCase):
    def test_loopback(self):
        ip = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    def test_localhost(self):
        ip = resolve_target("localhost")
        self.assertIn(ip, ["127.0.0.1", "::1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
