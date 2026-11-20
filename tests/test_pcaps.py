"""Automated forensic validation tests for all 4 Wireshark .pcap captures."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from analyze_pcap import analyze_pcap  # noqa: E402


class TestNetworkIncidentPcaps(unittest.TestCase):
    def test_01_dns_resolution_failure_pcap(self) -> None:
        report = analyze_pcap(ROOT / "pcaps" / "01_dns_resolution_failure.pcap")
        self.assertEqual(report["packet_count"], 8)
        joined = "\n".join(report["findings"])
        self.assertIn("NXDOMAIN", joined)
        self.assertIn("SERVFAIL", joined)
        self.assertIn("DNS ISOLATION", joined)

    def test_02_tcp_syn_timeout_firewall_drop_pcap(self) -> None:
        report = analyze_pcap(ROOT / "pcaps" / "02_tcp_syn_timeout_firewall_drop.pcap")
        self.assertEqual(report["packet_count"], 11)
        joined = "\n".join(report["findings"])
        self.assertIn("TCP HEALTHY", joined)
        self.assertIn("TCP FIREWALL DROP / TIMEOUT", joined)
        self.assertIn("sent 6 SYNs with 0 replies", joined)
        self.assertIn("TCP REJECTED (RST)", joined)

    def test_03_http_vs_https_tls_handshake_pcap(self) -> None:
        report = analyze_pcap(ROOT / "pcaps" / "03_http_vs_https_tls_handshake.pcap")
        self.assertEqual(report["packet_count"], 20)
        joined = "\n".join(report["findings"])
        self.assertIn("CLEARTEXT EXPOSURE (HTTP/80)", joined)
        self.assertIn("SNI='secure-portal.corp.example'", joined)
        self.assertIn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", joined)
        self.assertIn("TLS X.509 Certificate observed", joined)
        self.assertIn("TLS Encrypted Application Data", joined)

    def test_04_arp_spoofing_duplicate_ip_pcap(self) -> None:
        report = analyze_pcap(ROOT / "pcaps" / "04_arp_spoofing_duplicate_ip.pcap")
        self.assertEqual(report["packet_count"], 9)
        joined = "\n".join(report["findings"])
        self.assertIn("IP 10.20.10.1 claimed by multiple MACs", joined)
        self.assertIn("de:ad:be:ef:66:09", joined)
        self.assertIn("IP 10.20.10.88 claimed by multiple MACs", joined)


if __name__ == "__main__":
    unittest.main()
