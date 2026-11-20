#!/usr/bin/env python3
"""Zero-dependency PCAP Forensic Analyzer for NOC Root Cause Analysis (RCA).

Parses standard libpcap (.pcap) captures and automatically detects:
  - DNS resolution errors (NXDOMAIN, SERVFAIL) & local vs. upstream discrepancies
  - TCP 3-way handshake timeouts (SYN retransmissions / silent firewall drops) vs RSTs
  - Cleartext HTTP credential/cookie exposure vs. TLS 1.2 handshake (SNI, cipher, cert)
  - ARP spoofing (gateway MAC flip) & Duplicate IP conflicts on L2 subnets
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import socket
import struct
import sys

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

TLS_CIPHERS = {
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
}

TLS_CONTENT_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}

TLS_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0E: "ServerHelloDone",
    0x10: "ClientKeyExchange",
}


@dataclass(frozen=True)
class PacketRecord:
    index: int
    rel_time: float
    frame: bytes


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def format_ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def read_pcap(path: Path) -> list[PacketRecord]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"File too small to be a valid PCAP: {path}")

    magic = struct.unpack("<I", raw[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise ValueError(f"Unsupported PCAP magic header: 0x{magic:08x}")

    offset = 24
    packets: list[PacketRecord] = []
    first_ts: float | None = None
    idx = 0

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", raw[offset : offset + 16])
        offset += 16
        frame = raw[offset : offset + incl_len]
        offset += incl_len
        ts = ts_sec + ts_usec / 1_000_000.0
        if first_ts is None:
            first_ts = ts
        idx += 1
        packets.append(PacketRecord(index=idx, rel_time=round(ts - first_ts, 4), frame=frame))

    return packets


def parse_dns_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    orig_offset = offset
    visited = 0

    while offset < len(buf) and visited < 64:
        visited += 1
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        labels.append(buf[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), (orig_offset if jumped else offset)


def parse_dns(payload: bytes) -> dict:
    if len(payload) < 12:
        return {}
    txid, flags, qdcount, ancount, nscount, _arcount = struct.unpack("!HHHHHH", payload[:12])
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    qname = ""
    pos = 12
    if qdcount >= 1:
        qname, pos = parse_dns_name(payload, pos)
        pos += 4  # QTYPE + QCLASS

    answers: list[str] = []
    for _ in range(ancount):
        if pos >= len(payload):
            break
        _aname, pos = parse_dns_name(payload, pos)
        if pos + 10 > len(payload):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[pos : pos + 10])
        pos += 10
        rdata = payload[pos : pos + rdlen]
        pos += rdlen
        if rtype == 1 and len(rdata) == 4:
            answers.append(format_ip(rdata))

    return {
        "txid": txid,
        "is_response": is_response,
        "rcode": rcode,
        "rcode_name": DNS_RCODES.get(rcode, f"RCODE-{rcode}"),
        "qname": qname,
        "answers": answers,
        "nscount": nscount,
    }


def parse_tls_records(payload: bytes) -> list[dict]:
    records: list[dict] = []
    pos = 0
    while pos + 5 <= len(payload):
        ctype, ver, length = struct.unpack("!BHH", payload[pos : pos + 5])
        if ctype not in TLS_CONTENT_TYPES or pos + 5 + length > len(payload):
            break
        body = payload[pos + 5 : pos + 5 + length]
        pos += 5 + length
        rec: dict = {"content_type": TLS_CONTENT_TYPES[ctype], "version": f"0x{ver:04x}", "length": length}

        if ctype == 0x16 and len(body) >= 4:
            hs_type = body[0]
            hs_len = int.from_bytes(body[1:4], "big")
            hs_name = TLS_HANDSHAKE_TYPES.get(hs_type)
            if hs_name and hs_len <= len(body) - 4:
                rec["handshake_type"] = hs_name
                hs_body = body[4 : 4 + hs_len]
                if hs_type == 0x01 and len(hs_body) > 38:
                    # Extract SNI from ClientHello
                    idx = 34
                    sid_len = hs_body[idx]
                    idx += 1 + sid_len
                    cs_len = struct.unpack("!H", hs_body[idx : idx + 2])[0]
                    idx += 2 + cs_len
                    comp_len = hs_body[idx]
                    idx += 1 + comp_len
                    if idx + 2 <= len(hs_body):
                        ext_end = idx + 2 + struct.unpack("!H", hs_body[idx : idx + 2])[0]
                        idx += 2
                        while idx + 4 <= min(ext_end, len(hs_body)):
                            etype, elen = struct.unpack("!HH", hs_body[idx : idx + 4])
                            edata = hs_body[idx + 4 : idx + 4 + elen]
                            idx += 4 + elen
                            if etype == 0x0000 and len(edata) >= 5:
                                host_len = struct.unpack("!H", edata[3:5])[0]
                                rec["sni"] = edata[5 : 5 + host_len].decode("ascii", errors="replace")
                elif hs_type == 0x02 and len(hs_body) >= 38:
                    idx = 34
                    sid_len = hs_body[idx]
                    idx += 1 + sid_len
                    if idx + 2 <= len(hs_body):
                        cipher_id = struct.unpack("!H", hs_body[idx : idx + 2])[0]
                        rec["selected_cipher"] = TLS_CIPHERS.get(cipher_id, f"0x{cipher_id:04x}")
            else:
                rec["handshake_type"] = "EncryptedHandshake"
        records.append(rec)
    return records


def tcp_flags_str(flags: int) -> str:
    names = []
    for bit, label in ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST")):
        if flags & bit:
            names.append(label)
    return ",".join(names) or "NONE"


def analyze_pcap(path: Path) -> dict:
    packets = read_pcap(path)
    timeline: list[str] = []
    findings: list[str] = []

    dns_outcomes: dict[tuple[str, str], list[str]] = defaultdict(list)  # (qname, resolver) -> rcodes
    tcp_syns: dict[tuple[str, int, str, int], list[float]] = defaultdict(list)
    tcp_syn_acks: set[tuple[str, int, str, int]] = set()
    tcp_rsts: set[tuple[str, int, str, int]] = set()
    arp_ip_to_macs: dict[str, list[str]] = defaultdict(list)
    http_cleartext_hits: list[str] = []
    tls_summaries: list[str] = []

    for pkt in packets:
        frame = pkt.frame
        if len(frame) < 14:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]

        if ethertype == 0x0806 and len(payload) >= 28:
            _ht, _pt, _hl, _pl, opcode, smac_b, sip_b, _tmac_b, tip_b = struct.unpack("!HHBBH6s4s6s4s", payload[:28])
            smac = format_mac(smac_b)
            sip = format_ip(sip_b)
            tip = format_ip(tip_b)
            if smac not in arp_ip_to_macs[sip]:
                arp_ip_to_macs[sip].append(smac)
            if opcode == 1:
                info = f"Who has {tip}? Tell {sip} ({smac})"
                if sip == tip:
                    info = f"Gratuitous ARP Request for {sip} from {smac}"
            else:
                info = f"{sip} is at {smac} (to {tip})"
            timeline.append(f"{pkt.index:>3} {pkt.rel_time:>8.4f}s  {'ARP':<6} {smac:<18} -> {tip:<15} {info}")
            continue

        if ethertype != 0x0800 or len(payload) < 20:
            continue

        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        sip = format_ip(payload[12:16])
        dip = format_ip(payload[16:20])
        l4 = payload[ihl:]

        if proto == 17 and len(l4) >= 8:
            sp, dp, _ulen, _ck = struct.unpack("!HHHH", l4[:8])
            app = l4[8:]
            if sp == 53 or dp == 53:
                dns = parse_dns(app)
                if dns.get("is_response"):
                    ans = f" -> {','.join(dns['answers'])}" if dns["answers"] else ""
                    info = f"DNS Response 0x{dns['txid']:04x} {dns['qname']} [{dns['rcode_name']}]{ans}"
                    dns_outcomes[(dns["qname"], sip)].append(dns["rcode_name"])
                    if dns["rcode"] in (2, 3):
                        findings.append(
                            f"DNS {dns['rcode_name']} from resolver {sip} for '{dns['qname']}' (frame #{pkt.index})"
                        )
                else:
                    info = f"DNS Query    0x{dns['txid']:04x} A {dns['qname']}"
                timeline.append(f"{pkt.index:>3} {pkt.rel_time:>8.4f}s  {'DNS':<6} {sip:<18} -> {dip:<15} {info}")

        elif proto == 6 and len(l4) >= 20:
            sp, dp, seq, ack, off_res, flags, _win, _ck, _urg = struct.unpack("!HHIIBBHHH", l4[:20])
            tcp_hdr_len = (off_res >> 4) * 4
            app = l4[tcp_hdr_len:]
            fstr = tcp_flags_str(flags)

            if (flags & 0x02) and not (flags & 0x10):
                tcp_syns[(sip, sp, dip, dp)].append(pkt.rel_time)
            elif (flags & 0x12) == 0x12:
                tcp_syn_acks.add((dip, dp, sip, sp))
            elif flags & 0x04:
                tcp_rsts.add((dip, dp, sip, sp))

            proto_lbl = "TCP"
            detail = f"{sp}->{dp} [{fstr}] Seq={seq} Ack={ack} Len={len(app)}"

            if app and (dp == 80 or sp == 80) and (app.startswith(b"GET ") or app.startswith(b"POST ") or app.startswith(b"HTTP/")):
                proto_lbl = "HTTP"
                first_line = app.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                detail = f"{sp}->{dp} {first_line}"
                text = app.decode("utf-8", errors="replace")
                if "Authorization:" in text or "Set-Cookie:" in text:
                    http_cleartext_hits.append(f"Frame #{pkt.index} ({sip}:{sp}->{dip}:{dp}): {first_line}")

            elif app and (dp == 443 or sp == 443):
                tls_recs = parse_tls_records(app)
                if tls_recs:
                    proto_lbl = "TLS"
                    parts = []
                    for r in tls_recs:
                        lbl = r.get("handshake_type") or r["content_type"]
                        if "sni" in r:
                            lbl += f"(SNI={r['sni']})"
                            tls_summaries.append(f"TLS ClientHello SNI='{r['sni']}' (frame #{pkt.index})")
                        if "selected_cipher" in r:
                            lbl += f"(Cipher={r['selected_cipher']})"
                            tls_summaries.append(f"TLS ServerHello cipher={r['selected_cipher']} (frame #{pkt.index})")
                        if r.get("handshake_type") == "Certificate":
                            tls_summaries.append(f"TLS X.509 Certificate observed ({r['length']} bytes, frame #{pkt.index})")
                        if r["content_type"] == "ApplicationData":
                            tls_summaries.append(f"TLS Encrypted Application Data ({r['length']} bytes, frame #{pkt.index})")
                        parts.append(lbl)
                    detail = f"{sp}->{dp} " + " + ".join(parts)

            timeline.append(f"{pkt.index:>3} {pkt.rel_time:>8.4f}s  {proto_lbl:<6} {sip:<18} -> {dip:<15} {detail}")

    # Post-processing findings
    by_qname: dict[str, dict[str, list[str]]] = defaultdict(dict)
    for (qname, resolver), rcodes in dns_outcomes.items():
        by_qname[qname][resolver] = rcodes
    for qname, res_map in by_qname.items():
        if len(res_map) >= 2:
            failed = [r for r, codes in res_map.items() if any(c != "NOERROR" for c in codes)]
            passed = [r for r, codes in res_map.items() if "NOERROR" in codes]
            if failed and passed:
                findings.append(
                    f"DNS ISOLATION: '{qname}' failed on {failed} but resolved cleanly via {passed} -> local resolver/forwarder issue!"
                )

    for flow, times in tcp_syns.items():
        sip, sp, dip, dp = flow
        if flow in tcp_syn_acks:
            findings.append(f"TCP HEALTHY: {sip}:{sp} -> {dip}:{dp} completed 3-way handshake.")
        elif flow in tcp_rsts:
            findings.append(f"TCP REJECTED (RST): {sip}:{sp} -> {dip}:{dp} host reachable but port closed/rejected.")
        elif len(times) >= 2:
            deltas = [round(times[i] - times[i - 1], 2) for i in range(1, len(times))]
            findings.append(
                f"TCP FIREWALL DROP / TIMEOUT: {sip}:{sp} -> {dip}:{dp} sent {len(times)} SYNs with 0 replies (backoff intervals: {deltas}s)."
            )

    for hit in http_cleartext_hits:
        findings.append(f"CLEARTEXT EXPOSURE (HTTP/80): Sensitive headers visible in plaintext - {hit}")

    findings.extend(tls_summaries)

    for ip, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            findings.append(
                f"ARP ANOMALY / IP-MAC CONFLICT: IP {ip} claimed by multiple MACs -> {', '.join(macs)}"
            )

    return {
        "file": str(path),
        "packet_count": len(packets),
        "timeline": timeline,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze .pcap captures for NOC RCA triage.")
    parser.add_argument("pcaps", nargs="*", help="One or more .pcap file paths (defaults to all files in pcaps/)")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    paths = [Path(p) for p in args.pcaps] if args.pcaps else sorted((root / "pcaps").glob("*.pcap"))

    if not paths:
        print("No .pcap files found. Run `python tools/generate_lab_pcaps.py` first.")
        return 1

    for p in paths:
        report = analyze_pcap(p)
        print("=" * 94)
        print(f"PCAP REPORT: {p.name} ({report['packet_count']} packets)")
        print("=" * 94)
        for line in report["timeline"]:
            print(line)
        print("\n--- Automated NOC Forensic Findings ---")
        if report["findings"]:
            for item in report["findings"]:
                print(f"  * {item}")
        else:
            print("  * No anomalies detected.")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
