# Wireshark & tshark NOC Troubleshooting Cheat Sheet

Quick-reference display filters and CLI one-liners used during live L2/L3 incident triage.

## 1. DNS Troubleshooting
| Goal | Wireshark Display Filter |
| --- | --- |
| All DNS traffic | `dns` |
| Only failed DNS responses (`NXDOMAIN`, `SERVFAIL`, `REFUSED`) | `dns.flags.response == 1 && dns.flags.rcode != 0` |
| Specific `NXDOMAIN` responses | `dns.flags.rcode == 3` |
| Specific `SERVFAIL` responses | `dns.flags.rcode == 2` |
| Slow DNS lookups (> 250ms) | `dns.time > 0.25` |
| Queries for a specific domain | `dns.qry.name contains "corp.example"` |

## 2. TCP Latency, Drops & Resets
| Goal | Wireshark Display Filter |
| --- | --- |
| SYN packets (new connections / unanswered SYNs) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP retransmissions & fast retransmissions | `tcp.analysis.retransmission || tcp.analysis.fast_retransmission` |
| TCP resets (`RST` — closed ports / firewall reject) | `tcp.flags.reset == 1` |
| Zero-window stalls (receiver overwhelmed) | `tcp.analysis.zero_window` |
| High TCP handshake latency (> 100ms) | `tcp.analysis.initial_rtt > 0.1` |
| Follow a single TCP stream | `tcp.stream == 0` |

## 3. HTTP vs. HTTPS / TLS Inspection
| Goal | Wireshark Display Filter |
| --- | --- |
| Cleartext HTTP requests & errors | `http.request || http.response.code >= 400` |
| Cleartext credentials / cookies | `http.authorization || http.set_cookie` |
| TLS handshake frames only | `tls.handshake` |
| TLS `ClientHello` SNI hostnames | `tls.handshake.extensions_server_name` |
| TLS `ServerHello` negotiated cipher | `tls.handshake.type == 2` |
| TLS X.509 certificates | `tls.handshake.certificate` |
| TLS fatal alerts (cert expired, cipher mismatch) | `tls.alert_message.level == 2` |
| Encrypted application data | `tls.record.content_type == 23` |

## 4. Layer 2 / ARP Anomalies
| Goal | Wireshark Display Filter |
| --- | --- |
| All ARP traffic | `arp` |
| Duplicate IP / ARP spoofing alerts | `arp.duplicate-address-detected || arp.duplicate-address-frame` |
| Unsolicited / Gratuitous ARP | `arp.isgratuitous == 1` |
| All ARP replies (`opcode == 2`) | `arp.opcode == 2` |

## 5. Useful `tshark` CLI One-Liners (Linux / EC2)
```bash
# 1. Inspect failed DNS responses in a PCAP
tshark -r pcaps/01_dns_resolution_failure.pcap -Y "dns.flags.rcode != 0"

# 2. List TCP SYN retransmissions and RSTs
tshark -r pcaps/02_tcp_syn_timeout_firewall_drop.pcap -Y "tcp.flags.syn == 1 || tcp.flags.reset == 1"

# 3. Extract TLS SNI hostnames and selected ciphers
tshark -r pcaps/03_http_vs_https_tls_handshake.pcap -Y "tls.handshake" -T fields -e frame.number -e tls.handshake.extensions_server_name -e tls.handshake.ciphersuite

# 4. Detect duplicate IP / ARP conflicts automatically
tshark -r pcaps/04_arp_spoofing_duplicate_ip.pcap -Y "arp.duplicate-address-detected || arp.opcode == 2"

# 5. Verify zero malformed packets across all captures
tshark -r pcaps/03_http_vs_https_tls_handshake.pcap -Y "_ws.malformed"
```
