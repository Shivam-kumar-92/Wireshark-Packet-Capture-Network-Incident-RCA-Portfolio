# Incident RCA #04: ARP Spoofing (Gateway Poisoning) & Duplicate IP Conflict Detection

| Field | Detail |
| --- | --- |
| **Incident ID** | `INC-2026-0104` |
| **Severity** | SEV-1 (Subnet Outage & Active L2 Man-in-the-Middle Threat on VLAN 20) |
| **OSI Layer** | Layer 2 (ARP — EtherType `0x0806`) |
| **Capture File** | [`pcaps/04_arp_spoofing_duplicate_ip.pcap`](../../pcaps/04_arp_spoofing_duplicate_ip.pcap) (9 packets) |
| **Affected Subnet** | `10.20.10.0/24` (Gateway `10.20.10.1`, Victim `10.20.10.45`, Conflicting IP `10.20.10.88`) |
| **Key Wireshark Filters** | `arp`, `arp.duplicate-address-detected`, `arp.opcode == 2`, `arp.isgratuitous == 1` |

---

## 1. User Symptom & Triage Question
> *"Users on VLAN 20 (`10.20.10.0/24`) report intermittent internet dropouts, TLS certificate warnings, and workstation `10.20.10.88` displays 'Windows has detected an IP address conflict'."*

**Goal:** Prove L2 ARP anomalies from the wire, differentiate **malicious ARP Cache Poisoning (Gateway MAC spoofing)** from **accidental Duplicate IP assignment**, and validate L2 switch remediation.

---

## 2. Packet-Level Evidence (`04_arp_spoofing_duplicate_ip.pcap`)

| Frame | Time (s) | ARP Opcode | Sender MAC -> Claimed IP | Target IP | Diagnostic Meaning |
| ---: | ---: | --- | --- | --- | --- |
| **#1** | `0.000` | Request (`1`) | `00:50:56:a1:10:45` (`10.20.10.45`) | `10.20.10.1` | Normal broadcast: *"Who has gateway `10.20.10.1`?"* |
| **#2** | `0.001` | Reply (`2`) | **`00:1b:21:aa:00:01`** -> `10.20.10.1` | `10.20.10.45` | **Legitimate Core Gateway MAC** recorded (`00:1b:21:aa:00:01`). |
| **#3** | `2.500` | **Unsolicited Reply (`2`)** | **`de:ad:be:ef:66:09`** -> `10.20.10.1` | `10.20.10.45` | **ARP SPOOFING DETECTED:** Unsolicited ARP reply with **no prior request** overwrites victim's ARP cache for gateway `10.20.10.1`! |
| **#4–#5** | `3.500`–`4.500` | **Unsolicited Reply (`2`)** | **`de:ad:be:ef:66:09`** -> `10.20.10.1` | Broadcast & `10.20.10.45` | Periodic 1-second re-poisoning frames keeping the MITM attack alive across the broadcast domain. |
| **#6** | `6.000` | Gratuitous Request (`1`) | **`00:50:56:b2:20:88`** -> `10.20.10.88` | `10.20.10.88` | Host A brings up interface with static IP `10.20.10.88` (Duplicate Address Detection). |
| **#7** | `6.002` | Reply (`2`) | **`00:50:56:c3:99:88`** -> `10.20.10.88` | `10.20.10.88` | **DUPLICATE IP CONFLICT:** Host B immediately defends `10.20.10.88` with a different MAC (`00:50:56:c3:99:88`). |
| **#8–#9** | `10.000`–`10.001` | Request + Reply | **`00:1b:21:aa:00:01`** -> `10.20.10.1` | `10.20.10.45` | **Post-Remediation Verification:** After isolating rogue switch port and enabling DAI, ARP table cleanly resolves gateway to `00:1b:21:aa:00:01`. |

---

## 3. Root Cause Determination
1. **Gateway ARP Spoofing (`10.20.10.1`):** An unauthorized device (`de:ad:be:ef:66:09`) plugged into an access port without **Dynamic ARP Inspection (DAI)** or **Port Security** sent unsolicited ARP replies every 1 second claiming the gateway IP `10.20.10.1`.
2. **Duplicate IP Conflict (`10.20.10.88`):** A workstation (`00:50:56:b2:20:88`) was manually configured with a static IP inside the active DHCP pool already leased to `00:50:56:c3:99:88`.

---

## 4. Wireshark Investigation Filters
```text
# View all ARP frames
arp

# Built-in Wireshark expert detector for duplicate IP / MAC flips
arp.duplicate-address-detected || arp.duplicate-address-frame

# Filter unsolicited ARP replies claiming the default gateway
arp.opcode == 2 && arp.src.proto_ipv4 == 10.20.10.1

# Find Gratuitous ARP announcements
arp.isgratuitous == 1
```

CLI forensic reproduction:
```bash
python tools/analyze_pcap.py pcaps/04_arp_spoofing_duplicate_ip.pcap
```

---

## 5. Remediation Runbook (Cisco IOS / Enterprise Switch)

### Immediate Containment
1. **Locate the rogue MAC on the access switch and shut down the port:**
   ```text
   show mac address-table address dead.beef.6609
   configure terminal
     interface GigabitEthernet1/0/24
       shutdown
       description QUARANTINED-ARP-SPOOF-INC-2026-0104
   ```
2. **Clear poisoned ARP caches on affected hosts / gateway:**
   ```bash
   # Linux
   sudo ip -s -s neigh flush all

   # Windows (Admin)
   arp -d *
   ```
3. **Resolve Duplicate IP (`10.20.10.88`):** Convert Host A to DHCP or move its static IP outside the DHCP pool exclusion range (`10.20.10.1–10.20.10.50`).

### Permanent L2 Hardening (Prevent Recurrence)
Enable **DHCP Snooping + Dynamic ARP Inspection (DAI) + Port Security**:
```text
ip dhcp snooping
ip dhcp snooping vlan 20
ip arp inspection vlan 20

! Trust ONLY switch uplinks and legitimate DHCP servers
interface GigabitEthernet1/0/48
  ip dhcp snooping trust
  ip arp inspection trust

! Enforce port-security & ARP rate limiting on user access ports
interface range GigabitEthernet1/0/1 - 47
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation restrict
  ip arp inspection limit rate 15
```
