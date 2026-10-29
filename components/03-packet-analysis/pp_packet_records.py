"""Offline, capture-scoped packet observations; no detection or live networking.

Scapy supplies protocol decoding. TShark mode independently checks the selected
normalised header fields against Wireshark, using the same immutable input bytes.
Unsupported/malformed frames remain addressable rather than disappearing.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import shutil
import struct
import subprocess
import tempfile
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_PACKETS = 10_000
LAB = ipaddress.ip_network("10.77.0.0/24")
FLAG_NAMES = ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"),
              (32, "URG"), (64, "ECE"), (128, "CWR"), (256, "NS"))


def read_container(path):
    """Validate classic-PCAP framing, not protocol decoding; bound input memory."""
    path = Path(path)
    if not path.is_file():
        raise ValueError("Capture file does not exist.")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if not 24 <= len(data) <= MAX_BYTES:
        raise ValueError("Capture must be a non-empty classic PCAP of at most 8 MiB.")
    magics = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
              b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    if data[:4] not in magics:
        raise ValueError("This version accepts classic Ethernet PCAP, not PCAPNG or other files.")
    endian, precision = magics[data[:4]]
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    if (major, minor) != (2, 4) or linktype != 1 or not 1 <= snaplen <= MAX_BYTES:
        raise ValueError("Unsupported PCAP version, link type or snapshot length.")
    offset, frames = 24, []
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Incomplete packet-record header.")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if fraction >= precision or not 1 <= captured <= snaplen or captured > original or offset + captured > len(data):
            raise ValueError("Truncated or invalid packet record; analysis stopped.")
        frames.append({"number": len(frames) + 1, "seconds": seconds, "fraction": fraction,
                       "precision": precision, "captured_bytes": captured, "wire_bytes": original,
                       "file_offset": offset, "raw": data[offset:offset + captured]})
        offset += captured
        if len(frames) > MAX_PACKETS:
            raise ValueError("Capture exceeds this prototype's 10,000-packet limit.")
    if not frames:
        raise ValueError("Capture contains no packets.")
    capture = {"sha256": hashlib.sha256(data).hexdigest(), "packet_count": len(frames), "size_bytes": len(data),
               "format": "classic-pcap", "link_type": 1, "snapshot_bytes": snaplen,
               "timestamp_resolution": "nanoseconds" if precision == 1_000_000_000 else "microseconds"}
    return data, capture, frames


def _scope(src, dst):
    if any(ipaddress.ip_address(value) not in LAB for value in (src, dst)):
        raise ValueError("This version only accepts the configured 10.77.0.0/24 lab addresses.")


def _decode_frame(frame, capture_hash):
    from scapy.all import Ether, IP, TCP, UDP
    raw = frame["raw"]
    row = {"id": f'{capture_hash}:p{frame["number"]}', "packet": frame["number"],
           "timestamp": f'{frame["seconds"]}.{frame["fraction"]:0{9 if frame["precision"] == 1_000_000_000 else 6}d}',
           "time": frame["seconds"] + frame["fraction"] / frame["precision"],
           "file_offset": frame["file_offset"], "captured_bytes": len(raw), "wire_bytes": frame["wire_bytes"],
           "frame_sha256": hashlib.sha256(raw).hexdigest(), "status": "unsupported", "issues": [],
           "protocol": "Ethernet", "ethernet": None, "ipv4": None, "tcp": None, "udp": None, "flow_id": None}
    truncated = len(raw) < frame["wire_bytes"]
    if truncated:
        row["issues"].append("capture_snapshot_truncated")
    if len(raw) < 14:
        row["status"] = "truncated" if truncated else "malformed"
        row["issues"].append("incomplete_ethernet_header")
        return row
    try:
        packet = Ether(raw)
    except (ValueError, struct.error, IndexError):
        row["status"] = "malformed"
        row["issues"].append("ethernet_decode_failed")
        return row
    row["ethernet"] = {"src": packet.src, "dst": packet.dst, "type": int(packet.type)}
    # Deliberately inspect only the outer, directly carried IPv4 layer. Nested
    # tunnel transports must not be attributed to their outer IP addresses.
    if int(packet.type) != 0x0800 or not isinstance(packet.payload, IP):
        row["protocol"] = {0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}.get(int(packet.type), "Ethernet")
        row["issues"].append("unsupported_link_payload" if int(packet.type) != 0x0800 else "incomplete_ipv4_header")
        row["status"] = "truncated" if truncated else ("malformed" if int(packet.type) == 0x0800 else "unsupported")
        return row
    ip = packet.payload
    _scope(ip.src, ip.dst)
    row["protocol"] = {6: "TCP", 17: "UDP"}.get(int(ip.proto), "IPv4")
    header = int(ip.ihl or 0) * 4
    total = int(ip.len or 0)
    row["ipv4"] = {"src": ip.src, "dst": ip.dst, "protocol_number": int(ip.proto),
                   "ttl": int(ip.ttl), "id": int(ip.id), "header_bytes": header, "total_bytes": total,
                   "fragment_offset": int(ip.frag), "more_fragments": bool(int(ip.flags) & 1),
                   "checksum": int(ip.chksum), "options_hex": raw[34:14 + header].hex() if header >= 20 else ""}
    if ip.version != 4 or header < 20 or total < header or len(raw) < 14 + header:
        row["status"] = "truncated" if truncated else "malformed"
        row["issues"].append("invalid_ipv4_header")
        return row
    if total > len(raw) - 14:
        row['decode_bounds'] = {'version':'packetpilot-decode-bounds-1.0',
            'link_header_bytes':14,'saved_frame_bytes':len(raw),
            'saved_ipv4_bytes':len(raw)-14,'declared_ipv4_bytes':total,
            'ipv4_shortfall_bytes':total-(len(raw)-14),
            'saved_transport_prefix_bytes':max(0,len(raw)-14-header),
            'snapshot_shortfall_bytes':max(0,frame['wire_bytes']-len(raw)),
            'tcp_tuple_identified':False,'tcp_flags_identified':False,
            'scope':'Length inconsistency, not proof of snaplen cause or a service reply; this parser exposes no validated transport.'}
        row["status"] = "truncated" if truncated else "malformed"
        row["issues"].append("ipv4_length_exceeds_captured_bytes")
        return row
    if ip.frag or int(ip.flags) & 1:
        row["issues"].append("ipv4_fragment_not_reassembled")
        row["status"] = "truncated" if truncated else "unsupported"
        return row
    available = total - header
    if ip.proto == 6 and isinstance(ip.payload, TCP):
        tcp = ip.payload
        tcp_header = int(tcp.dataofs or 0) * 4
        if tcp_header < 20 or tcp_header > available:
            row["status"] = "malformed"
            row["issues"].append("invalid_tcp_header_length")
            return row
        start = 14 + header
        row["tcp"] = {"src_port": int(tcp.sport), "dst_port": int(tcp.dport),
                      "flags": int(tcp.flags), "flag_names": [name for bit, name in FLAG_NAMES if int(tcp.flags) & bit],
                      "sequence": int(tcp.seq), "acknowledgement": int(tcp.ack), "window": int(tcp.window),
                      "header_bytes": tcp_header, "checksum": int(tcp.chksum),
                      "urgent_pointer": int(tcp.urgptr), "options_hex": raw[start + 20:start + tcp_header].hex(),
                      "payload_bytes": available - tcp_header}
        payload_start, payload_length = start + tcp_header, available - tcp_header
    elif ip.proto == 17 and isinstance(ip.payload, UDP):
        udp = ip.payload
        if not 8 <= int(udp.len or 0) <= available:
            row["status"] = "malformed"
            row["issues"].append("invalid_udp_length")
            return row
        row["udp"] = {"src_port": int(udp.sport), "dst_port": int(udp.dport),
                      "length": int(udp.len), "checksum": int(udp.chksum), "payload_bytes": int(udp.len) - 8}
        payload_start, payload_length = 14 + header + 8, int(udp.len) - 8
        if int(udp.len) != available:
            row["issues"].append("ipv4_bytes_after_udp_datagram")
    else:
        row["issues"].append("unsupported_ipv4_protocol" if ip.proto not in (6, 17) else "incomplete_transport_header")
        row["status"] = "unsupported" if ip.proto not in (6, 17) else "malformed"
        return row
    row["payload"] = {"length": payload_length, "preview_hex": raw[payload_start:payload_start + min(64, payload_length)].hex(),
                      "preview_limit_bytes": 64, "preview_truncated": payload_length > 64}
    from pp_service_evidence import application_fields
    row['application'] = application_fields(raw[payload_start:payload_start+payload_length],row['protocol'],
        (row['tcp'] or row['udp'])['src_port'],(row['tcp'] or row['udp'])['dst_port'])
    row["status"] = "truncated" if truncated else "decoded"
    return row


TSHARK_FIELDS = ("frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "ip.src", "ip.dst",
                "ip.ttl", "ip.id", "ip.hdr_len", "ip.len", "ip.proto", "tcp.srcport", "tcp.dstport",
                "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.window_size_value", "tcp.hdr_len",
                "udp.srcport", "udp.dstport", "udp.length")


def verify_tshark(data, records):
    """Independent field extraction on a private immutable copy; no shell/filter injection."""
    executable = shutil.which("tshark")
    if not executable:
        raise ValueError("TShark is not installed/on PATH; use --decoder scapy until VM setup.")
    with tempfile.TemporaryDirectory(prefix="packetpilot-decode-") as directory:
        source = Path(directory) / "capture.pcap"
        source.write_bytes(data)
        command = [executable, "-n", "-r", str(source), "-o", "ip.defragment:FALSE", "-T", "fields",
                   "-E", "separator=/t", "-E", "occurrence=f"]
        for field in TSHARK_FIELDS:
            command.extend(["-e", field])
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=20)
            version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=5, check=True).stdout.splitlines()[0]
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            raise ValueError("TShark execution failed or timed out.") from exc
        if result.returncode:
            raise ValueError("TShark could not decode the complete capture.")
    lines = result.stdout.splitlines()
    if len(lines) != len(records):
        raise ValueError("TShark did not account for every packet.")
    checks = 0
    for row, line in zip(records, lines):
        values = line.split("\t")
        if len(values) != len(TSHARK_FIELDS):
            raise ValueError("Unexpected TShark output format.")
        fields = dict(zip(TSHARK_FIELDS, values))
        expected = {"frame.number": row["packet"], "frame.len": row["wire_bytes"], "frame.cap_len": row["captured_bytes"]}
        if row["status"] == "decoded":
            ip = row["ipv4"]
            if fields["ip.src"] != ip["src"] or fields["ip.dst"] != ip["dst"]:
                raise ValueError(f'TShark address disagreement at packet {row["packet"]}.')
            checks += 2
            expected.update({"ip.ttl": ip["ttl"], "ip.id": ip["id"], "ip.hdr_len": ip["header_bytes"],
                             "ip.len": ip["total_bytes"], "ip.proto": ip["protocol_number"]})
            if row["tcp"]:
                tcp = row["tcp"]
                expected.update({"tcp.srcport": tcp["src_port"], "tcp.dstport": tcp["dst_port"], "tcp.flags": tcp["flags"],
                                 "tcp.seq_raw": tcp["sequence"], "tcp.ack_raw": tcp["acknowledgement"],
                                 "tcp.window_size_value": tcp["window"], "tcp.hdr_len": tcp["header_bytes"]})
            if row["udp"]:
                udp = row["udp"]
                expected.update({"udp.srcport": udp["src_port"], "udp.dstport": udp["dst_port"], "udp.length": udp["length"]})
        for field, value in expected.items():
            try:
                actual = int(fields[field], 16 if fields[field].lower().startswith("0x") else 10)
            except ValueError as exc:
                raise ValueError(f'TShark missing/invalid field {field} at packet {row["packet"]}.') from exc
            if actual != value:
                raise ValueError(f'TShark field disagreement for {field} at packet {row["packet"]}.')
            checks += 1
        # Decimal comparison avoids losing nanosecond fidelity to binary float.
        from decimal import Decimal
        if Decimal(fields["frame.time_epoch"]) != Decimal(row["timestamp"]):
            raise ValueError("TShark timestamp disagreement.")
        checks += 1
    return {"version": version, "verified_field_count": checks, "fields": list(TSHARK_FIELDS),
            "method": "Independent offline TShark fields compared to Scapy/container records; malformed/unsupported frames checked at container level only."}


def build_observations(records, capture):
    grouped = defaultdict(list)
    for row in records:
        if row["status"] != "decoded":
            continue
        ip, transport = row["ipv4"], row["tcp"] or row["udp"]
        endpoints = sorted(((ip["src"], transport["src_port"]), (ip["dst"], transport["dst_port"])))
        grouped[(row["protocol"], *endpoints)].append(row)
    flows = []
    for key, members in sorted(grouped.items()):
        protocol, a, b = key
        identity = hashlib.sha256(repr(key).encode()).hexdigest()[:16]
        flow_id = f'{capture["sha256"]}:f{identity}'
        directions = {"a_to_b": 0, "b_to_a": 0}
        flags = Counter()
        for row in members:
            row["flow_id"] = flow_id
            transport = row["tcp"] or row["udp"]
            directions["a_to_b" if (row["ipv4"]["src"], transport["src_port"]) == a else "b_to_a"] += 1
            flags.update(row["tcp"]["flag_names"] if row["tcp"] else [])
        times = [row["time"] for row in members]
        flows.append({"id": flow_id, "protocol": protocol, "endpoint_a": {"address": a[0], "port": a[1]},
                      "endpoint_b": {"address": b[0], "port": b[1]}, "packet_refs": [row["packet"] for row in members],
                      "packet_count": len(members), "captured_bytes": sum(row["captured_bytes"] for row in members),
                      "first_time": min(times), "last_time": max(times), "duration_seconds": float(max(Decimal(r['timestamp']) for r in members) - min(Decimal(r['timestamp']) for r in members)),
                      "directions": directions, "tcp_flag_counts": dict(sorted(flags.items()))})
    statuses = Counter(row["status"] for row in records)
    issues = defaultdict(list)
    for row in records:
        for issue in row["issues"]:
            issues[issue].append(row["packet"])
    coverage = {"total_packets": len(records), "decoded_packets": statuses["decoded"],
                "unsupported_packets": statuses["unsupported"], "malformed_packets": statuses["malformed"],
                "truncated_packets": statuses["truncated"], "complete_for_supported_headers": statuses["decoded"] == len(records),
                "issues": [{"code": code, "packet_refs": refs} for code, refs in sorted(issues.items())],
                "scope": "Outer unfragmented Ethernet/IPv4/TCP and UDP headers; no decryption, reassembly or application-protocol interpretation."}
    times = [row["time"] for row in records]
    overview = {"protocol_counts": dict(sorted(Counter(row["protocol"] for row in records).items())),
                "decoded_protocol_counts": dict(sorted(Counter(row["protocol"] for row in records if row["status"] == "decoded").items())),
                "flow_count": len(flows), "captured_bytes": sum(row["captured_bytes"] for row in records),
                "wire_bytes": sum(row["wire_bytes"] for row in records), "first_time": min(times), "last_time": max(times),
                "duration_seconds": float(max(Decimal(r['timestamp']) for r in records) - min(Decimal(r['timestamp']) for r in records)),
                "out_of_order_timestamps": any(b["time"] < a["time"] for a, b in zip(records, records[1:]))}
    return flows, coverage, overview


def decode_capture(path, selected):
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    import scapy
    data, capture, frames = read_container(path)
    records = [_decode_frame(frame, capture["sha256"]) for frame in frames]
    decoder = {"name": selected, "version": f"Scapy {scapy.__version__}", "normalizer": f"Scapy {scapy.__version__}",
               "tshark_verification": None}
    if selected == "tshark":
        decoder["tshark_verification"] = verify_tshark(data, records)
        decoder["version"] = decoder["tshark_verification"]["version"]
    flows, coverage, overview = build_observations(records, capture)
    return capture, records, flows, coverage, overview, decoder
