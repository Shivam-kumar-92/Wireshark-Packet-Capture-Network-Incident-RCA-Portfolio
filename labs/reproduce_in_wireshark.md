# Lab Guide: Reproducing All 4 Captures Live in Wireshark / tcpdump

Use this guide if you want to capture fresh live traffic on your own Windows workstation, Linux VM, or AWS EC2 lab and compare it against the reference captures in `pcaps/`.

---

## Scenario 1: DNS Resolution Failure (`NXDOMAIN` vs. Upstream Isolation)
1. Start Wireshark on your active NIC with capture filter `port 53` (or `sudo tcpdump -i any -w dns.pcap port 53`).
2. Run these 3 commands to generate healthy, `NXDOMAIN`, and upstream comparison packets:
   ```bash
   nslookup google.com
   nslookup nonexistent-test-host-999.invalid
   nslookup github.com 1.1.1.1
   ```
3. Stop capture and apply display filter `dns.flags.rcode != 0` to isolate failures.

## Scenario 2: TCP 3-Way Handshake Timeout (Firewall Drop) vs. `RST`
1. Start Wireshark with capture filter `tcp`.
2. Trigger a silent timeout (RFC 5737 blackhole/unroutable test IP or closed AWS Security Group port):
   ```bash
   # Silent drop (watch SYN retransmissions at 1s, 2s, 4s, 8s...)
   curl -m 15 http://192.0.2.1:5432

   # Explicit RST/ACK (connect to a closed local port)
   curl -m 3 http://127.0.0.1:65432
   ```
3. Apply display filter `tcp.flags.syn == 1 || tcp.flags.reset == 1`.

## Scenario 3: HTTP vs. HTTPS TLS Handshake Inspection
1. Start Wireshark with capture filter `port 80 or port 443`.
2. Send one unencrypted HTTP request and one encrypted HTTPS request:
   ```bash
   curl -i http://example.com
   curl -i https://example.com
   ```
3. Compare right-click -> **Follow -> TCP Stream** on Port 80 (readable HTML/headers) vs. Port 443 (encrypted `Application Data` preceded by `ClientHello`, `ServerHello`, and `Certificate`).

## Scenario 4: ARP Conflict / Gratuitous ARP Inspection (Isolated Lab Only)
> **Warning:** Only perform ARP lab tests on an isolated local VM network or home lab you own.

1. Start Wireshark with capture filter `arp`.
2. Clear local ARP entry for your gateway and ping it to capture normal ARP Request/Reply:
   ```bash
   # Linux
   sudo ip neigh flush all && ping -c 1 <gateway-ip>

   # Windows (Admin)
   arp -d * && ping -n 1 <gateway-ip>
   ```
3. Send a Gratuitous ARP announcement in a Linux VM lab (`arping -U -c 2 -I eth0 <your-ip>`) and inspect with `arp.isgratuitous == 1` and `arp.duplicate-address-detected`.
