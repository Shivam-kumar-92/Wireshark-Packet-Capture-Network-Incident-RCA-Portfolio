# Incident RCA #02: TCP 3-Way Handshake Timeout & Silent Firewall Drop

| Field | Detail |
| --- | --- |
| **Incident ID** | `INC-2026-0102` |
| **Severity** | SEV-1 (Application Tier Unable to Connect to Database Tier) |
| **OSI Layer** | Layer 4 (TCP) / Firewall Policy Enforcement |
| **Capture File** | [`pcaps/02_tcp_syn_timeout_firewall_drop.pcap`](../../pcaps/02_tcp_syn_timeout_firewall_drop.pcap) (11 packets) |
| **Affected Hosts** | Client `10.20.10.45`, Healthy App `10.20.50.25:443`, DB Server `10.20.60.15` (`:5432` & `:22`) |
| **Key Wireshark Filters** | `tcp.analysis.retransmission`, `tcp.flags.syn == 1 && tcp.flags.ack == 0`, `tcp.flags.reset == 1` |

---

## 1. User Symptom & Triage Question
> *"The application server hangs for ~30+ seconds and throws `Connection timed out` when trying to connect to PostgreSQL on `10.20.60.15:5432`. The DBA insists PostgreSQL is up and listening."*

**Goal:** Distinguish at the packet level between:
- **Host down / routing blackhole**,
- **Port closed / service stopped (`TCP RST,ACK`)**, and
- **Stateful Firewall / Security Group Silent `DROP` (SYN retransmissions with exponential backoff)**.

---

## 2. Packet-Level Evidence (`02_tcp_syn_timeout_firewall_drop.pcap`)

| Frame | Time (s) | Delta (s) | Flow | Flags | Diagnostic Meaning |
| ---: | ---: | ---: | --- | --- | --- |
| **#1–#3** | `0.000`–`0.012` | `0.011s` RTT | `10.20.10.45:54100` <-> `10.20.50.25:443` | `SYN` -> `SYN,ACK` -> `ACK` | **Control Baseline:** Client TCP stack & default gateway routing are healthy. |
| **#4** | `2.000` | `—` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` `Seq=200000` | Initial PostgreSQL connection attempt. |
| **#5** | `3.005` | `+1.005s` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` (Retransmission #1) | No `SYN,ACK`, no `RST`, no ICMP Unreachable -> 1s RTO retry. |
| **#6** | `5.012` | `+2.007s` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` (Retransmission #2) | RFC 6298 exponential backoff (~2s). |
| **#7** | `9.020` | `+4.008s` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` (Retransmission #3) | Exponential backoff (~4s). |
| **#8** | `17.035` | `+8.015s` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` (Retransmission #4) | Exponential backoff (~8s). |
| **#9** | `33.050` | `+16.015s` | `10.20.10.45:54101` -> `10.20.60.15:5432` | `[SYN]` (Retransmission #5) | Exponential backoff (~16s) -> client times out after ~31s! |
| **#10–#11** | `35.000`–`35.006` | `0.006s` RTT | `10.20.10.45:54102` <-> `10.20.60.15:22` | `SYN` -> **`RST,ACK`** | **Isolation Proof:** Same destination IP `10.20.60.15` responds in **6 ms** on port 22 with `RST,ACK` -> proves L3 routing is valid and host is UP! Port `5432` is explicitly being **silently dropped** by an intermediate firewall/ACL or host firewall (`iptables`/`nftables`/AWS SG). |

---

## 3. Silent DROP vs. Explicit REJECT / Closed Port (Interview Key Concept)

| Wire Signature | Meaning | Typical Cause |
| --- | --- | --- |
| `SYN` -> 1s, 2s, 4s, 8s, 16s retries, **0 replies** | **Silent DROP** (Timeout) | Stateful Firewall (Palo Alto/Fortinet), AWS Security Group missing inbound rule, `iptables -j DROP`, or asymmetric routing |
| `SYN` -> immediate **`RST,ACK`** (<20ms) | **Connection Refused** | Host is reachable, firewall allowed SYN, but no process listening on port (or `iptables -j REJECT --reject-with tcp-reset`) |
| `SYN` -> **ICMP Type 3 Code 13** | **Administratively Prohibited** | Router ACL explicitly rejecting traffic with ICMP feedback |

---

## 4. Wireshark Investigation Filters
```text
# Isolate all unanswered SYN packets & retransmissions
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Highlight Wireshark-flagged TCP retransmissions
tcp.analysis.retransmission

# Inspect all traffic to the affected DB server
ip.addr == 10.20.60.15 && (tcp.port == 5432 || tcp.port == 22)

# Find TCP resets (closed ports / active rejections)
tcp.flags.reset == 1
```

CLI forensic reproduction:
```bash
python tools/analyze_pcap.py pcaps/02_tcp_syn_timeout_firewall_drop.pcap
```

---

## 5. Remediation Runbook

### Step-by-Step Verification & Fix
1. **Confirm DB listener locally on `10.20.60.15`:**
   ```bash
   ss -tlnp | grep 5432
   ```
2. **Capture simultaneously on `10.20.60.15` to split host-firewall vs. network-firewall:**
   ```bash
   sudo tcpdump -nn -i any host 10.20.10.45 and port 5432
   ```
   - If `SYN` **never arrives** at `10.20.60.15` -> blocked by upstream network firewall, NACL, or AWS Security Group.
   - If `SYN` **arrives** at `10.20.60.15` with no `SYN,ACK` -> blocked by local host firewall (`ufw`/`firewalld`/`nftables`) or asymmetric return route (`rp_filter`).
3. **Apply Least-Privilege Firewall Rule:**
   ```bash
   # Example: allow app subnet 10.20.10.0/24 -> PostgreSQL TCP/5432
   sudo ufw allow from 10.20.10.0/24 to any port 5432 proto tcp
   ```
4. **Verify Resolution:**
   ```bash
   nc -zv -w 3 10.20.60.15 5432
   ```
   Confirm `SYN -> SYN,ACK -> ACK` completes in `<20 ms`.
