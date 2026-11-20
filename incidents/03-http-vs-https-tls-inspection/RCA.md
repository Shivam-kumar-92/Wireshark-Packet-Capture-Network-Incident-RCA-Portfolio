# Incident RCA #03: HTTP Cleartext Credential Exposure vs. HTTPS TLS 1.2 Handshake Inspection

| Field | Detail |
| --- | --- |
| **Incident ID** | `INC-2026-0103` |
| **Severity** | SEV-2 (Security & Compliance Audit Finding — Unencrypted Admin Auth on Port 80) |
| **OSI Layer** | Layer 6/7 (HTTP vs. TLS 1.2 over TCP/443) |
| **Capture File** | [`pcaps/03_http_vs_https_tls_handshake.pcap`](../../pcaps/03_http_vs_https_tls_handshake.pcap) (20 packets) |
| **Affected Hosts** | Client `10.20.10.45` <-> Web Gateway `198.51.100.80` (`:80` HTTP & `:443` HTTPS) |
| **Key Wireshark Filters** | `http`, `tls.handshake`, `tls.handshake.extensions_server_name`, `tls.record.content_type == 23` |

---

## 1. Incident Summary & Audit Objective
> *"During a routine NOC/SecOps packet capture on a legacy portal migration, engineers needed to prove that port 80 exposed admin credentials in cleartext and verify that the migrated HTTPS endpoint (`secure-portal.corp.example:443`) negotiated modern ECDHE-GCM encryption with a valid X.509 certificate."*

---

## 2. Side-by-Side Packet Evidence (`03_http_vs_https_tls_handshake.pcap`)

### Flow A: Unencrypted HTTP (`10.20.10.45:55200` <-> `198.51.100.80:80`)
| Frame | Time (s) | Protocol | Wire Observation | Security Impact |
| ---: | ---: | --- | --- | --- |
| **#1–#3** | `0.000`–`0.015` | `TCP` | `SYN -> SYN,ACK -> ACK` (14 ms RTT) | Standard TCP connection established. |
| **#4** | `0.020` | **`HTTP`** | `POST /api/v1/login HTTP/1.1` containing **`Authorization: Basic bm9jX2FkbWluOkRlbW9DbGVhcnRleHRQYXNzMjAyNiE=`** + JSON body `{"user":"noc_admin","action":"sync_config"}` | **CRITICAL:** Base64 decodes trivially to `noc_admin:DemoCleartextPass2026!` — any L2/L3 passive sniffer captures credentials instantly! |
| **#5** | `0.038` | **`HTTP`** | `HTTP/1.1 200 OK` with **`Set-Cookie: session_id=PLAINTEXT_SESSION_998877; Path=/`** | Session hijacking possible (missing `Secure` & `HttpOnly` flags over HTTP). |
| **#6–#8** | `0.042`–`0.057` | `TCP` | `FIN,ACK -> FIN,ACK -> ACK` | Clean TCP teardown. |

### Flow B: Encrypted HTTPS / TLS 1.2 (`10.20.10.45:55201` <-> `198.51.100.80:443`)
| Frame | Time (s) | Protocol | TLS Handshake Stage | Wire Details Verified |
| ---: | ---: | --- | --- | --- |
| **#9–#11** | `1.000`–`1.016` | `TCP` | 3-Way Handshake | 15 ms RTT to `198.51.100.80:443`. |
| **#12** | `1.020` | **`TLS`** | **`ClientHello`** | Offers TLS 1.2 + AEAD ECDHE cipher suites (`0xc02f`, `0xc030`); **SNI Extension = `secure-portal.corp.example`** (still visible in plaintext for virtual-host routing). |
| **#13** | `1.042` | **`TLS`** | **`ServerHello` + `Certificate` + `ServerHelloDone`** | Negotiates **`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xc02f`)** (Forward Secrecy + AEAD) and presents X.509v3 certificate (`CN=secure-portal.corp.example`, Issuer: `Corp TLS Issuing CA G2`, Valid `2026-01-01` to `2027-12-31`). |
| **#14–#15** | `1.050`–`1.066` | **`TLS`** | **`ChangeCipherSpec` + `Encrypted Handshake`** | Both peers switch to negotiated symmetric session keys and verify handshake integrity (`Finished`). |
| **#16–#17** | `1.072`–`1.090` | **`TLS`** | **`Application Data` (`0x17`)** | **Opaque ciphertext (96 bytes each):** HTTP method, URL path, `Authorization` header, cookies, and JSON payload are completely unreadable on the wire! |
| **#18–#20** | `1.095`–`1.111` | `TCP` | `FIN,ACK -> FIN,ACK -> ACK` | Clean TCP teardown. |

---

## 3. Wireshark Investigation Filters
```text
# Expose cleartext HTTP requests & authentication headers
http.request || http.authorization || http.set_cookie

# Inspect TLS handshake negotiation only (ClientHello, ServerHello, Certificate)
tls.handshake

# Extract SNI hostname from TLS ClientHello
tls.handshake.extensions_server_name

# Inspect X.509 certificates sent on the wire
tls.handshake.certificate

# Show encrypted TLS application data frames
tls.record.content_type == 23
```

CLI forensic reproduction:
```bash
python tools/analyze_pcap.py pcaps/03_http_vs_https_tls_handshake.pcap
```

---

## 4. Remediation Runbook

1. **Enforce HTTP -> HTTPS Permanent Redirect (301) & HSTS** on NGINX / Load Balancer:
   ```nginx
   server {
       listen 80;
       server_name secure-portal.corp.example;
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl http2;
       ssl_protocols TLSv1.2 TLSv1.3;
       add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   }
   ```
2. **Harden Session Cookies:** Add `Secure; HttpOnly; SameSite=Lax` flags to all session cookies.
3. **Rotate Exposed Credentials:** Immediately rotate `noc_admin` credentials and revoke any session tokens transmitted over cleartext HTTP.
4. **Verify TLS Certificate & Cipher Suite via CLI:**
   ```bash
   openssl s_client -connect secure-portal.corp.example:443 -servername secure-portal.corp.example </dev/null
   ```
