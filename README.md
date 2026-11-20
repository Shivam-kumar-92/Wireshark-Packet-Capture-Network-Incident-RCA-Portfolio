# Wireshark Packet Capture & Network Incident RCA Portfolio

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Wireshark Validated](https://img.shields.io/badge/Wireshark%20%2F%20tshark-PCAP%20Validated-1679A7)
![OSI Layers](https://img.shields.io/badge/OSI%20Layers-L2%20%7C%20L3%20%7C%20L4%20%7C%20L7-brightgreen)

A packet-level **Network Troubleshooting & Root Cause Analysis (RCA) Portfolio** demonstrating enterprise L2/L3 NOC diagnostic methodology across **4 real-world network failure scenarios**. Each incident includes a genuine **Wireshark `.pcap` capture**, a structured **postmortem RCA report**, **Wireshark display filters**, and a **step-by-step remediation runbook**, plus a zero-dependency **Python PCAP Forensic Analyzer** (`tools/analyze_pcap.py`).

---

## Incident Catalog & Captures

| # | Incident Scenario | OSI Layer | Capture File | RCA & Runbook | Key Wire Signature Diagnosed |
| :---: | --- | :---: | --- | --- | --- |
| **01** | **DNS Resolution Failure** | L7 (UDP/53) | [`01_dns_resolution_failure.pcap`](pcaps/01_dns_resolution_failure.pcap) | [Read RCA](incidents/01-dns-resolution-failure/RCA.md) | `NXDOMAIN (RCODE=3)` + `SERVFAIL (RCODE=2)` on internal DNS vs. `NOERROR` on `1.1.1.1` (isolates local forwarder failure) |
| **02** | **TCP 3-Way Handshake Timeout / Firewall Drop** | L4 (TCP) | [`02_tcp_syn_timeout_firewall_drop.pcap`](pcaps/02_tcp_syn_timeout_firewall_drop.pcap) | [Read RCA](incidents/02-tcp-handshake-timeout-firewall-drop/RCA.md) | 6 `SYN` retries (`1s->2s->4s->8s->16s` backoff, silent `DROP`) vs. `RST,ACK` on port 22 proving host is L3-reachable |
| **03** | **HTTP vs. HTTPS TLS Handshake Inspection** | L6/L7 (HTTP/TLS) | [`03_http_vs_https_tls_handshake.pcap`](pcaps/03_http_vs_https_tls_handshake.pcap) | [Read RCA](incidents/03-http-vs-https-tls-inspection/RCA.md) | Cleartext HTTP `Basic Auth` & `Set-Cookie` on `:80` vs. TLS 1.2 SNI, ECDHE-GCM cipher, X.509v3 cert & encrypted payload on `:443` |
| **04** | **ARP Spoofing & Duplicate IP Conflict** | L2 (ARP) | [`04_arp_spoofing_duplicate_ip.pcap`](pcaps/04_arp_spoofing_duplicate_ip.pcap) | [Read RCA](incidents/04-arp-spoofing-duplicate-ip/RCA.md) | Unsolicited ARP replies flipping gateway `10.20.10.1` MAC + Duplicate IP conflict on `10.20.10.88`, mitigated via DAI + Port Security |

---

## Repository Structure

```text
wireshark-network-rca-portfolio/
├── pcaps/                                       # Standard libpcap files (open directly in Wireshark)
│   ├── 01_dns_resolution_failure.pcap
│   ├── 02_tcp_syn_timeout_firewall_drop.pcap
│   ├── 03_http_vs_https_tls_handshake.pcap
│   └── 04_arp_spoofing_duplicate_ip.pcap
├── incidents/                                   # Enterprise-grade RCA reports & runbooks
│   ├── 01-dns-resolution-failure/RCA.md
│   ├── 02-tcp-handshake-timeout-firewall-drop/RCA.md
│   ├── 03-http-vs-https-tls-inspection/RCA.md
│   └── 04-arp-spoofing-duplicate-ip/RCA.md
├── tools/
│   ├── analyze_pcap.py                          # Zero-dependency Python PCAP forensic triage CLI
│   └── generate_lab_pcaps.py                    # Reproducible RFC-compliant PCAP generator
├── cheatsheets/
│   └── wireshark-noc-filters.md                 # Wireshark & tshark NOC troubleshooting filter guide
├── labs/
│   └── reproduce_in_wireshark.md                # Live capture reproduction guide (Windows & Linux)
├── tests/
│   └── test_pcaps.py                            # Automated forensic test suite
└── .github/workflows/ci.yml                     # CI verifying all PCAPs with Python + real Wireshark tshark
```

---

## Quick Start

### 1. Open in Wireshark GUI
Open any file in `pcaps/` directly in **Wireshark** and apply the filters listed in each incident's `RCA.md` or in [`cheatsheets/wireshark-noc-filters.md`](cheatsheets/wireshark-noc-filters.md).

### 2. Run the Automated Python PCAP Forensic Analyzer
Requires **Python 3.10+** (zero external dependencies):

```bash
# Analyze all 4 incident captures and print timelines + automated NOC findings
python tools/analyze_pcap.py

# Or analyze a single capture
python tools/analyze_pcap.py pcaps/02_tcp_syn_timeout_firewall_drop.pcap

# Run automated unit tests
python -m unittest discover -s tests -v
```

### 3. Validate with Wireshark `tshark` (Linux / macOS / Windows with Wireshark)
```bash
tshark -r pcaps/01_dns_resolution_failure.pcap -Y "dns.flags.rcode != 0"
tshark -r pcaps/02_tcp_syn_timeout_firewall_drop.pcap -Y "tcp.analysis.retransmission || tcp.flags.reset == 1"
tshark -r pcaps/03_http_vs_https_tls_handshake.pcap -Y "http.authorization || tls.handshake"
tshark -r pcaps/04_arp_spoofing_duplicate_ip.pcap -Y "arp.duplicate-address-detected || arp.opcode == 2"
```

---

## Supporting Guides
- **NOC Display Filter Cheat Sheet:** [`cheatsheets/wireshark-noc-filters.md`](cheatsheets/wireshark-noc-filters.md)
- **Reproduce Captures Live in Your Own Lab:** [`labs/reproduce_in_wireshark.md`](labs/reproduce_in_wireshark.md)
