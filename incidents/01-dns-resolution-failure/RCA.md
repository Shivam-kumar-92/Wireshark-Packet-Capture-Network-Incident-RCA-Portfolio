# Incident RCA #01: DNS Resolution Failure (NXDOMAIN vs. Upstream SERVFAIL Isolation)

| Field | Detail |
| --- | --- |
| **Incident ID** | `INC-2026-0101` |
| **Severity** | SEV-2 (Partial Service Degradation — External SaaS & Payment API Unreachable) |
| **OSI Layer** | Layer 7 (DNS over UDP/53) |
| **Capture File** | [`pcaps/01_dns_resolution_failure.pcap`](../../pcaps/01_dns_resolution_failure.pcap) (8 packets) |
| **Affected Host / Resolver** | Client `10.20.10.45`, Internal DNS `10.20.1.10`, Upstream Public DNS `1.1.1.1` |
| **Key Wireshark Filters** | `dns`, `dns.flags.rcode != 0`, `dns.qry.name == "erp.vendor-cloud.example"` |

---

## 1. User Symptom & Triage Question
> *"Users on the corporate LAN can access the internal intranet (`portal.corp.internal`), but the Partner Payments integration and Vendor Cloud ERP fail immediately with `ERR_NAME_NOT_RESOLVED` / `Could not resolve host`."*

**Goal:** Prove at the packet level whether the failure is:
1. A client-side DNS/firewall issue (UDP/53 blocked),
2. A nonexistent/misconfigured DNS record (`NXDOMAIN`), or
3. An internal DNS resolver forwarder / DNSSEC failure (`SERVFAIL`) vs. upstream outage.

---

## 2. Packet-Level Evidence (`01_dns_resolution_failure.pcap`)

| Frame | Time (s) | Source -> Destination | Transaction ID | Query / Response | RCODE / Result | Diagnostic Meaning |
| ---: | ---: | --- | --- | --- | --- | --- |
| **#1–#2** | `0.000` -> `0.004` | `10.20.10.45` <-> `10.20.1.10` | `0xa101` | `A portal.corp.internal` | `NOERROR` -> `10.20.50.100` (4 ms) | Proves UDP/53 path and internal DNS daemon are **UP** and authoritative internal zones work. |
| **#3–#4** | `1.200` -> `1.218` | `10.20.10.45` <-> `10.20.1.10` | `0xa102` | `A api-payments.partner-bank.invalid` | **`NXDOMAIN` (`RCODE=3`)** + Authority SOA (18 ms) | Fast authoritative negative reply: domain does not exist (stale config / typo / deleted DNS record). |
| **#5–#6** | `3.500` -> `5.512` | `10.20.10.45` <-> `10.20.1.10` | `0xa103` | `A erp.vendor-cloud.example` | **`SERVFAIL` (`RCODE=2`)** after **2.012 s** | Resolver failed to obtain a valid answer (upstream forwarder timeout, broken recursive path, or DNSSEC validation failure). |
| **#7–#8** | `6.000` -> `6.019` | `10.20.10.45` <-> `1.1.1.1` | `0xa104` | `A erp.vendor-cloud.example` | **`NOERROR`** -> `203.0.113.42` (19 ms) | **Smoking Gun:** Direct lookup to external resolver `1.1.1.1` succeeds in 19 ms -> isolates fault to internal DNS server `10.20.1.10` forwarding/recursion, NOT ISP or vendor outage! |

---

## 3. Root Cause Determination
Two distinct DNS fault signatures were isolated in a single capture:
1. **`api-payments.partner-bank.invalid` (`NXDOMAIN`):** Application configuration referenced a retired/typo'd hostname. The authoritative SOA record returned in Frame #4 confirms the domain does not exist in DNS.
2. **`erp.vendor-cloud.example` (`SERVFAIL` on `10.20.1.10`, `NOERROR` on `1.1.1.1`):** Internal DNS server `10.20.1.10` experienced a 2-second timeout / failure reaching its configured upstream forwarder (or stale DNSSEC trust anchor), while direct internet DNS resolution worked cleanly.

---

## 4. Wireshark Investigation Commands & Filters
```text
# Show all DNS traffic
dns

# Highlight only failed DNS responses (NXDOMAIN=3, SERVFAIL=2, REFUSED=5)
dns.flags.response == 1 && dns.flags.rcode != 0

# Compare responses from internal resolver vs. public resolver
dns && (ip.addr == 10.20.1.10 || ip.addr == 1.1.1.1)

# Find slow DNS responses (> 500ms)
dns.time > 0.5
```

CLI forensic reproduction using the included analyzer:
```bash
python tools/analyze_pcap.py pcaps/01_dns_resolution_failure.pcap
```

---

## 5. Remediation Runbook

### Immediate Mitigation
1. **For `SERVFAIL` on `10.20.1.10`:**
   - Verify upstream forwarder reachability from the DNS server (`dig @1.1.1.1 erp.vendor-cloud.example +trace` and `dig @<forwarder> +dnssec`).
   - Check firewall egress rules on `10.20.1.10` for **both UDP/53 and TCP/53** (large DNSSEC responses fall back to TCP/53).
   - Flush negative cache and reload forwarders:
     ```bash
     # BIND9
     sudo rndc flush
     sudo rndc status

     # systemd-resolved / Unbound
     sudo unbound-control flush_zone vendor-cloud.example
     ```
2. **For `NXDOMAIN` on `api-payments.partner-bank.invalid`:**
   - Confirm exact partner FQDN in change ticket / application config, correct the endpoint hostname, and clear client DNS cache (`ipconfig /flushdns` on Windows or `resolvectl flush-caches` on Linux).

### Long-Term Prevention
- Configure redundant upstream forwarders (e.g., primary ISP/cloud resolver + secondary `1.1.1.1`/`9.9.9.9`) with automated health checks.
- Monitor DNS query latency and `SERVFAIL`/`NXDOMAIN` spike rates via automated NOC synthetic checks (see Project 1: NOC Health Monitor checking TCP/53 & DNS resolution).
