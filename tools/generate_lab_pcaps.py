#!/usr/bin/env python3
"""Generate RFC-compliant Wireshark .pcap files for 4 enterprise network incidents.

Produces genuine libpcap Ethernet/IPv4 captures with valid checksums, realistic
timestamps, and Wireshark-decodable DNS, TCP, HTTP, TLS 1.2 (with X.509 cert),
and ARP frames:
  1. pcaps/01_dns_resolution_failure.pcap
  2. pcaps/02_tcp_syn_timeout_firewall_drop.pcap
  3. pcaps/03_http_vs_https_tls_handshake.pcap
  4. pcaps/04_arp_spoofing_duplicate_ip.pcap
"""

from __future__ import annotations

import base64
import hashlib
import socket
import struct
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
PCAP_MAJOR = 2
PCAP_MINOR = 4
LINKTYPE_ETHERNET = 1

BASE_EPOCH = 1795152000  # 2026-11-20T05:20:00Z


# ---------------------------------------------------------------------------
# Low-level PCAP & L2/L3/L4 packet builders
# ---------------------------------------------------------------------------

class PcapWriter:
    """Minimal standard libpcap (.pcap) writer."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._packets: list[tuple[float, bytes]] = []

    def add_packet(self, rel_seconds: float, frame: bytes) -> None:
        self._packets.append((BASE_EPOCH + rel_seconds, frame))

    def save(self) -> int:
        with self.path.open("wb") as fh:
            # Global header (24 bytes, little-endian)
            fh.write(
                struct.pack(
                    "<IHHiIII",
                    PCAP_MAGIC,
                    PCAP_MAJOR,
                    PCAP_MINOR,
                    0,
                    0,
                    65535,
                    LINKTYPE_ETHERNET,
                )
            )
            for ts, frame in self._packets:
                ts_sec = int(ts)
                ts_usec = int(round((ts - ts_sec) * 1_000_000))
                fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
                fh.write(frame)
        return len(self._packets)


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ethernet(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ethertype) + payload


def build_ipv4(
    src_ip: str,
    dst_ip: str,
    proto: int,
    payload: bytes,
    ident: int = 0x1000,
    ttl: int = 64,
    df: bool = True,
) -> bytes:
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000 if df else 0x0000
    header_no_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        ident & 0xFFFF,
        flags_frag,
        ttl,
        proto,
        0,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    cksum = internet_checksum(header_no_cksum)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        ident & 0xFFFF,
        flags_frag,
        ttl,
        proto,
        cksum,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    return header + payload


def build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    udp_no_cksum = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    pseudo = struct.pack("!4s4sBBH", ip_bytes(src_ip), ip_bytes(dst_ip), 0, 17, length)
    cksum = internet_checksum(pseudo + udp_no_cksum) or 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, cksum) + payload


def build_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 65535,
) -> bytes:
    data_offset = (5 << 4)  # 20 bytes
    tcp_no_cksum = (
        struct.pack("!HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, data_offset, flags, window, 0, 0)
        + payload
    )
    pseudo = struct.pack("!4s4sBBH", ip_bytes(src_ip), ip_bytes(dst_ip), 0, 6, len(tcp_no_cksum))
    cksum = internet_checksum(pseudo + tcp_no_cksum)
    return (
        struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            data_offset,
            flags,
            window,
            cksum,
            0,
        )
        + payload
    )


def build_arp(
    src_mac: str,
    dst_mac: str,
    opcode: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:
    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,       # Ethernet
        0x0800,  # IPv4
        6,       # MAC length
        4,       # IPv4 length
        opcode,  # 1=Request, 2=Reply
        mac_bytes(sender_mac),
        ip_bytes(sender_ip),
        mac_bytes(target_mac),
        ip_bytes(target_ip),
    )
    return build_ethernet(src_mac, dst_mac, 0x0806, arp_payload)


# TCP flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


# ---------------------------------------------------------------------------
# DNS builder (RFC 1035)
# ---------------------------------------------------------------------------

def encode_dns_name(domain: str) -> bytes:
    out = b""
    for label in domain.strip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_dns_query(txid: int, domain: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def build_dns_response(
    txid: int,
    domain: str,
    rcode: int = 0,
    answer_ip: str | None = None,
    ttl: int = 300,
    include_soa: bool = False,
) -> bytes:
    flags = 0x8180 | (rcode & 0x0F)  # QR=1, RD=1, RA=1
    qname = encode_dns_name(domain)
    question = qname + struct.pack("!HH", 1, 1)

    ancount = 1 if answer_ip else 0
    nscount = 1 if include_soa else 0
    header = struct.pack("!HHHHHH", txid, flags, 1, ancount, nscount, 0)

    answer = b""
    if answer_ip:
        # Name pointer to offset 12 (0xC00C)
        answer = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + ip_bytes(answer_ip)

    authority = b""
    if include_soa:
        zone = ".".join(domain.split(".")[-2:])
        mname = encode_dns_name(f"ns1.{zone}")
        rname = encode_dns_name(f"hostmaster.{zone}")
        soa_rdata = mname + rname + struct.pack("!IIIII", 2026112001, 3600, 900, 604800, 300)
        authority = encode_dns_name(zone) + struct.pack("!HHIH", 6, 1, 300, len(soa_rdata)) + soa_rdata

    return header + question + answer + authority


# ---------------------------------------------------------------------------
# Minimal RFC-valid DER X.509 v3 Certificate & TLS 1.2 Handshake builders
# ---------------------------------------------------------------------------

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(items))


def _der_int(val: int) -> bytes:
    if val == 0:
        raw = b"\x00"
    else:
        raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
        else:
            chunks = []
            while p:
                chunks.append(p & 0x7F)
                p >>= 7
            chunks.reverse()
            for idx, c in enumerate(chunks):
                out.append(c | 0x80 if idx < len(chunks) - 1 else c)
    return _der_tlv(0x06, bytes(out))


def _der_utf8(text: str) -> bytes:
    return _der_tlv(0x0C, text.encode("utf-8"))


def _der_utctime(yymmddhhmmss: str) -> bytes:
    return _der_tlv(0x17, (yymmddhhmmss + "Z").encode("ascii"))


def _der_bitstring(data: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + data)


def build_demo_x509_cert(common_name: str = "secure-portal.corp.example") -> bytes:
    """Build a syntactically valid DER X.509v3 certificate for Wireshark TLS inspection."""
    sha256_rsa_alg = _der_seq(_der_oid("1.2.840.113549.1.1.11"), b"\x05\x00")
    rsa_enc_alg = _der_seq(_der_oid("1.2.840.113549.1.1.1"), b"\x05\x00")

    def rdn(oid: str, val: str) -> bytes:
        return _der_set(_der_seq(_der_oid(oid), _der_utf8(val)))

    issuer = _der_seq(
        rdn("2.5.4.10", "Enterprise Internal CA"),
        rdn("2.5.4.3", "Corp TLS Issuing CA G2"),
    )
    subject = _der_seq(
        rdn("2.5.4.10", "Enterprise NOC Demo Corp"),
        rdn("2.5.4.3", common_name),
    )
    validity = _der_seq(_der_utctime("260101000000"), _der_utctime("271231235959"))

    # Synthetic 1024-bit RSA public key structure (valid ASN.1 RSAPublicKey)
    modulus_seed = hashlib.sha256(b"noc-demo-rsa-modulus").digest() * 4
    modulus_int = int.from_bytes(b"\x81" + modulus_seed[1:], "big")
    rsa_pubkey_der = _der_seq(_der_int(modulus_int), _der_int(65537))
    spki = _der_seq(rsa_enc_alg, _der_bitstring(rsa_pubkey_der))

    version = _der_tlv(0xA0, _der_int(2))  # v3
    tbs = _der_seq(version, _der_int(0x202611200001), sha256_rsa_alg, issuer, validity, subject, spki)

    sig_bytes = hashlib.sha256(tbs).digest() * 4
    return _der_seq(tbs, sha256_rsa_alg, _der_bitstring(sig_bytes))


def tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def tls_handshake_msg(hs_type: int, body: bytes) -> bytes:
    length_3 = len(body).to_bytes(3, "big")
    return bytes([hs_type]) + length_3 + body


def build_tls_client_hello(server_name: str) -> bytes:
    client_random = struct.pack("!I", BASE_EPOCH) + hashlib.sha256(b"client-random-noc").digest()[:28]
    ciphers = struct.pack("!HHHH", 0xC02F, 0xC030, 0x009C, 0x009D)  # ECDHE-RSA-AES128/256-GCM
    # SNI extension (0x0000)
    sni_host = server_name.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_host)) + sni_host
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    # supported_groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
    groups = struct.pack("!HHH", 4, 0x001D, 0x0017)
    ext_groups = struct.pack("!HH", 0x000A, len(groups)) + groups
    # ec_point_formats (0x000b): uncompressed (0)
    ext_ecpf = struct.pack("!HHBB", 0x000B, 2, 1, 0)
    # signature_algorithms (0x000d): rsa_pss_rsae_sha256 (0x0804), rsa_pkcs1_sha256 (0x0401)
    sig_algs = struct.pack("!HHH", 4, 0x0804, 0x0401)
    ext_sig = struct.pack("!HH", 0x000D, len(sig_algs)) + sig_algs

    extensions = ext_sni + ext_groups + ext_ecpf + ext_sig
    body = (
        struct.pack("!H", 0x0303)        # TLS 1.2
        + client_random
        + b"\x00"                        # Session ID length 0
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"                    # Compression: null
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return tls_record(0x16, 0x0301, tls_handshake_msg(0x01, body))


def build_tls_server_flight(server_name: str) -> bytes:
    server_random = struct.pack("!I", BASE_EPOCH) + hashlib.sha256(b"server-random-noc").digest()[:28]
    session_id = hashlib.sha256(b"tls-session-id").digest()[:16]
    sh_body = (
        struct.pack("!H", 0x0303)        # TLS 1.2
        + server_random
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", 0xC02F)      # Selected: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        + b"\x00"                        # Compression: null (no empty extensions block per RFC 5246)
    )
    rec_sh = tls_record(0x16, 0x0303, tls_handshake_msg(0x02, sh_body))

    cert_der = build_demo_x509_cert(server_name)
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    cert_list = len(cert_entry).to_bytes(3, "big") + cert_entry
    rec_cert = tls_record(0x16, 0x0303, tls_handshake_msg(0x0B, cert_list))

    # RFC 8422 ServerKeyExchange (named_curve = x25519 0x001d + 32B pubkey + rsa_pkcs1_sha256 sig)
    server_ecdh_pub = hashlib.sha256(b"server-x25519-pubkey").digest()
    ecdh_params = struct.pack("!BHB", 3, 0x001D, len(server_ecdh_pub)) + server_ecdh_pub
    ske_sig = hashlib.sha256(ecdh_params).digest() * 4  # 128-byte RSA-1024 signature
    ske_body = ecdh_params + struct.pack("!HH", 0x0401, len(ske_sig)) + ske_sig
    rec_ske = tls_record(0x16, 0x0303, tls_handshake_msg(0x0C, ske_body))

    rec_done = tls_record(0x16, 0x0303, tls_handshake_msg(0x0E, b""))
    return rec_sh + rec_cert + rec_ske + rec_done


def build_tls_client_key_exchange() -> bytes:
    client_ecdh_pub = hashlib.sha256(b"client-x25519-pubkey").digest()
    cke_body = bytes([len(client_ecdh_pub)]) + client_ecdh_pub
    return tls_record(0x16, 0x0303, tls_handshake_msg(0x10, cke_body))


# ---------------------------------------------------------------------------
# Scenario Generators
# ---------------------------------------------------------------------------

CLIENT_MAC = "00:50:56:a1:10:45"
GW_MAC = "00:1b:21:aa:00:01"
DNS_MAC = "00:50:56:d0:01:10"
ROGUE_MAC = "de:ad:be:ef:66:09"
HOST_A_MAC = "00:50:56:b2:20:88"
HOST_B_MAC = "00:50:56:c3:99:88"

CLIENT_IP = "10.20.10.45"
GW_IP = "10.20.10.1"
CORP_DNS_IP = "10.20.1.10"
PUBLIC_DNS_IP = "1.1.1.1"
APP_SERVER_IP = "10.20.50.25"
DB_SERVER_IP = "10.20.60.15"
WEB_SERVER_IP = "198.51.100.80"


def generate_incident_01_dns(out_path: Path) -> int:
    writer = PcapWriter(out_path)
    ip_id = 0x1100

    def add_udp(ts: float, smac: str, dmac: str, sip: str, dip: str, sp: int, dp: int, data: bytes) -> None:
        nonlocal ip_id
        ip_id += 1
        udp = build_udp(sip, dip, sp, dp, data)
        ip = build_ipv4(sip, dip, 17, udp, ident=ip_id)
        writer.add_packet(ts, build_ethernet(smac, dmac, 0x0800, ip))

    # 1. Control check: internal DNS healthy (portal.corp.internal -> NOERROR 10.20.50.100)
    add_udp(0.000, CLIENT_MAC, DNS_MAC, CLIENT_IP, CORP_DNS_IP, 51001, 53, build_dns_query(0xA101, "portal.corp.internal"))
    add_udp(0.004, DNS_MAC, CLIENT_MAC, CORP_DNS_IP, CLIENT_IP, 53, 51001, build_dns_response(0xA101, "portal.corp.internal", rcode=0, answer_ip="10.20.50.100"))

    # 2. Failed lookup: nonexistent/misconfigured FQDN -> NXDOMAIN (RCODE=3) with SOA
    add_udp(1.200, CLIENT_MAC, DNS_MAC, CLIENT_IP, CORP_DNS_IP, 51002, 53, build_dns_query(0xA102, "api-payments.partner-bank.invalid"))
    add_udp(1.218, DNS_MAC, CLIENT_MAC, CORP_DNS_IP, CLIENT_IP, 53, 51002, build_dns_response(0xA102, "api-payments.partner-bank.invalid", rcode=3, include_soa=True))

    # 3. Upstream forwarder failure on Corp DNS: erp.vendor-cloud.example -> SERVFAIL (RCODE=2) after 2.012s
    add_udp(3.500, CLIENT_MAC, DNS_MAC, CLIENT_IP, CORP_DNS_IP, 51003, 53, build_dns_query(0xA103, "erp.vendor-cloud.example"))
    add_udp(5.512, DNS_MAC, CLIENT_MAC, CORP_DNS_IP, CLIENT_IP, 53, 51003, build_dns_response(0xA103, "erp.vendor-cloud.example", rcode=2))

    # 4. Isolation test: direct nslookup against 1.1.1.1 -> NOERROR (203.0.113.42) in 19ms
    add_udp(6.000, CLIENT_MAC, GW_MAC, CLIENT_IP, PUBLIC_DNS_IP, 51004, 53, build_dns_query(0xA104, "erp.vendor-cloud.example"))
    add_udp(6.019, GW_MAC, CLIENT_MAC, PUBLIC_DNS_IP, CLIENT_IP, 53, 51004, build_dns_response(0xA104, "erp.vendor-cloud.example", rcode=0, answer_ip="203.0.113.42"))

    return writer.save()


def generate_incident_02_tcp_syn_drop(out_path: Path) -> int:
    writer = PcapWriter(out_path)
    ip_id = 0x2100

    def add_tcp(ts: float, smac: str, dmac: str, sip: str, dip: str, sp: int, dp: int, seq: int, ack: int, flags: int, data: bytes = b"") -> None:
        nonlocal ip_id
        ip_id += 1
        tcp = build_tcp(sip, dip, sp, dp, seq, ack, flags, data)
        ip = build_ipv4(sip, dip, 6, tcp, ident=ip_id)
        writer.add_packet(ts, build_ethernet(smac, dmac, 0x0800, ip))

    # 1. Baseline healthy 3-way handshake to App Server :443 (11ms RTT)
    add_tcp(0.000, CLIENT_MAC, GW_MAC, CLIENT_IP, APP_SERVER_IP, 54100, 443, 100000, 0, TCP_SYN)
    add_tcp(0.011, GW_MAC, CLIENT_MAC, APP_SERVER_IP, CLIENT_IP, 443, 54100, 500000, 100001, TCP_SYN | TCP_ACK)
    add_tcp(0.012, CLIENT_MAC, GW_MAC, CLIENT_IP, APP_SERVER_IP, 54100, 443, 100001, 500001, TCP_ACK)

    # 2. Firewall silent DROP on DB Server :5432 -> SYN + 5 retransmissions (1s, 2s, 4s, 8s, 16s)
    for ts in (2.000, 3.005, 5.012, 9.020, 17.035, 33.050):
        add_tcp(ts, CLIENT_MAC, GW_MAC, CLIENT_IP, DB_SERVER_IP, 54101, 5432, 200000, 0, TCP_SYN)

    # 3. Contrast probe to same DB host :22 -> instant RST,ACK (proves host is UP, port 5432 is firewalled)
    add_tcp(35.000, CLIENT_MAC, GW_MAC, CLIENT_IP, DB_SERVER_IP, 54102, 22, 300000, 0, TCP_SYN)
    add_tcp(35.006, GW_MAC, CLIENT_MAC, DB_SERVER_IP, CLIENT_IP, 22, 54102, 0, 300001, TCP_RST | TCP_ACK)

    return writer.save()


def generate_incident_03_http_vs_https(out_path: Path) -> int:
    writer = PcapWriter(out_path)
    ip_id = 0x3100

    def add_tcp(ts: float, smac: str, dmac: str, sip: str, dip: str, sp: int, dp: int, seq: int, ack: int, flags: int, data: bytes = b"") -> None:
        nonlocal ip_id
        ip_id += 1
        tcp = build_tcp(sip, dip, sp, dp, seq, ack, flags, data)
        ip = build_ipv4(sip, dip, 6, tcp, ident=ip_id)
        writer.add_packet(ts, build_ethernet(smac, dmac, 0x0800, ip))

    # --- Flow A: Cleartext HTTP (Port 80) ---
    c_seq, s_seq = 10000, 90000
    add_tcp(0.000, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55200, 80, c_seq, 0, TCP_SYN)
    add_tcp(0.014, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 80, 55200, s_seq, c_seq + 1, TCP_SYN | TCP_ACK)
    c_seq += 1
    s_seq += 1
    add_tcp(0.015, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55200, 80, c_seq, s_seq, TCP_ACK)

    auth_b64 = base64.b64encode(b"noc_admin:DemoCleartextPass2026!").decode("ascii")
    http_body = b'{"user":"noc_admin","action":"sync_config"}'
    http_req = (
        f"POST /api/v1/login HTTP/1.1\r\n"
        f"Host: legacy-portal.corp.example\r\n"
        f"Authorization: Basic {auth_b64}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(http_body)}\r\n"
        f"\r\n"
    ).encode("ascii") + http_body
    add_tcp(0.020, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55200, 80, c_seq, s_seq, TCP_PSH | TCP_ACK, http_req)
    c_seq += len(http_req)

    http_resp_body = b'{"status":"ok","role":"network_admin"}'
    http_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Set-Cookie: session_id=PLAINTEXT_SESSION_998877; Path=/\r\n"
        f"Content-Length: {len(http_resp_body)}\r\n"
        f"\r\n"
    ).encode("ascii") + http_resp_body
    add_tcp(0.038, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 80, 55200, s_seq, c_seq, TCP_PSH | TCP_ACK, http_resp)
    s_seq += len(http_resp)

    add_tcp(0.042, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55200, 80, c_seq, s_seq, TCP_FIN | TCP_ACK)
    add_tcp(0.056, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 80, 55200, s_seq, c_seq + 1, TCP_FIN | TCP_ACK)
    add_tcp(0.057, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55200, 80, c_seq + 1, s_seq + 1, TCP_ACK)

    # --- Flow B: Encrypted HTTPS / TLS 1.2 (Port 443) ---
    c_seq, s_seq = 40000, 80000
    add_tcp(1.000, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, 0, TCP_SYN)
    add_tcp(1.015, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 443, 55201, s_seq, c_seq + 1, TCP_SYN | TCP_ACK)
    c_seq += 1
    s_seq += 1
    add_tcp(1.016, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, s_seq, TCP_ACK)

    # TLS ClientHello with SNI
    ch = build_tls_client_hello("secure-portal.corp.example")
    add_tcp(1.020, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, s_seq, TCP_PSH | TCP_ACK, ch)
    c_seq += len(ch)

    # TLS ServerHello + Certificate (X.509) + ServerHelloDone
    sf = build_tls_server_flight("secure-portal.corp.example")
    add_tcp(1.042, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 443, 55201, s_seq, c_seq, TCP_PSH | TCP_ACK, sf)
    s_seq += len(sf)

    # Client ClientKeyExchange + ChangeCipherSpec + Encrypted Handshake Message (Finished)
    c_ccs = (
        build_tls_client_key_exchange()
        + tls_record(0x14, 0x0303, b"\x01")
        + tls_record(0x16, 0x0303, hashlib.sha256(b"client-finished-enc").digest() + b"\x00" * 8)
    )
    add_tcp(1.050, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, s_seq, TCP_PSH | TCP_ACK, c_ccs)
    c_seq += len(c_ccs)

    # Server ChangeCipherSpec + Encrypted Handshake Message (Finished)
    s_ccs = tls_record(0x14, 0x0303, b"\x01") + tls_record(0x16, 0x0303, hashlib.sha256(b"server-finished-enc").digest() + b"\x00" * 8)
    add_tcp(1.066, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 443, 55201, s_seq, c_seq, TCP_PSH | TCP_ACK, s_ccs)
    s_seq += len(s_ccs)

    # Encrypted TLS Application Data (request & response — completely opaque on wire)
    app_req = tls_record(0x17, 0x0303, hashlib.sha512(b"encrypted-https-request-1").digest() + hashlib.sha256(b"tag1").digest())
    add_tcp(1.072, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, s_seq, TCP_PSH | TCP_ACK, app_req)
    c_seq += len(app_req)

    app_resp = tls_record(0x17, 0x0303, hashlib.sha512(b"encrypted-https-response-1").digest() + hashlib.sha256(b"tag2").digest())
    add_tcp(1.090, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 443, 55201, s_seq, c_seq, TCP_PSH | TCP_ACK, app_resp)
    s_seq += len(app_resp)

    add_tcp(1.095, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq, s_seq, TCP_FIN | TCP_ACK)
    add_tcp(1.110, GW_MAC, CLIENT_MAC, WEB_SERVER_IP, CLIENT_IP, 443, 55201, s_seq, c_seq + 1, TCP_FIN | TCP_ACK)
    add_tcp(1.111, CLIENT_MAC, GW_MAC, CLIENT_IP, WEB_SERVER_IP, 55201, 443, c_seq + 1, s_seq + 1, TCP_ACK)

    return writer.save()


def generate_incident_04_arp_spoofing(out_path: Path) -> int:
    writer = PcapWriter(out_path)
    bcast = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"

    # 1. Healthy baseline ARP resolution for Default Gateway 10.20.10.1
    writer.add_packet(0.000, build_arp(CLIENT_MAC, bcast, 1, CLIENT_MAC, CLIENT_IP, zero_mac, GW_IP))
    writer.add_packet(0.001, build_arp(GW_MAC, CLIENT_MAC, 2, GW_MAC, GW_IP, CLIENT_MAC, CLIENT_IP))

    # 2. Rogue host sends unsolicited ARP Replies (ARP Cache Poisoning / MITM claiming Gateway IP)
    writer.add_packet(2.500, build_arp(ROGUE_MAC, CLIENT_MAC, 2, ROGUE_MAC, GW_IP, CLIENT_MAC, CLIENT_IP))
    writer.add_packet(3.500, build_arp(ROGUE_MAC, bcast, 2, ROGUE_MAC, GW_IP, bcast, GW_IP))
    writer.add_packet(4.500, build_arp(ROGUE_MAC, CLIENT_MAC, 2, ROGUE_MAC, GW_IP, CLIENT_MAC, CLIENT_IP))

    # 3. Duplicate IP conflict on 10.20.10.88 (Host A Gratuitous ARP vs Host B defense reply)
    writer.add_packet(6.000, build_arp(HOST_A_MAC, bcast, 1, HOST_A_MAC, "10.20.10.88", zero_mac, "10.20.10.88"))
    writer.add_packet(6.002, build_arp(HOST_B_MAC, bcast, 2, HOST_B_MAC, "10.20.10.88", HOST_A_MAC, "10.20.10.88"))

    # 4. Post-remediation verification (after DAI + Port Security shutdown of rogue port)
    writer.add_packet(10.000, build_arp(CLIENT_MAC, bcast, 1, CLIENT_MAC, CLIENT_IP, zero_mac, GW_IP))
    writer.add_packet(10.001, build_arp(GW_MAC, CLIENT_MAC, 2, GW_MAC, GW_IP, CLIENT_MAC, CLIENT_IP))

    return writer.save()


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    pcap_dir = root / "pcaps"
    targets = [
        ("01_dns_resolution_failure.pcap", generate_incident_01_dns),
        ("02_tcp_syn_timeout_firewall_drop.pcap", generate_incident_02_tcp_syn_drop),
        ("03_http_vs_https_tls_handshake.pcap", generate_incident_03_http_vs_https),
        ("04_arp_spoofing_duplicate_ip.pcap", generate_incident_04_arp_spoofing),
    ]
    for filename, builder in targets:
        count = builder(pcap_dir / filename)
        print(f"Generated pcaps/{filename} ({count} packets)")


if __name__ == "__main__":
    main()
