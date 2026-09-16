"""Small saved-PCAP decoder and an explicitly bounded TCP port-check rule."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import shutil
import struct
import subprocess
from collections import defaultdict, deque
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_PACKETS = 10_000
WINDOW_SECONDS = 10.0
PORT_THRESHOLD = 6
LAB = ipaddress.ip_network("10.77.0.0/24")
SERVER = "10.77.0.10"


def preflight(path: Path):
    """Reject incomplete/unsupported captures before a decoder can skip errors."""
    if not path.is_file():
        raise ValueError("Capture file does not exist.")
    if not 24 <= path.stat().st_size <= MAX_BYTES:
        raise ValueError("Capture must be a non-empty classic PCAP of at most 8 MiB.")
    data = path.read_bytes()
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in magics:
        raise ValueError("This version accepts classic Ethernet PCAP, not PCAPNG or other files.")
    endian, precision = magics[data[:4]]
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    if (major, minor) != (2, 4) or linktype != 1 or not 1 <= snaplen <= MAX_BYTES:
        raise ValueError("Unsupported PCAP version, link type or snapshot length.")
    offset, count = 24, 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Incomplete packet-record header.")
        _, fraction, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if (fraction >= precision or not 14 <= captured <= snaplen
                or captured != original or offset + captured > len(data)):
            raise ValueError("Truncated or invalid packet record; analysis stopped.")
        offset += captured
        count += 1
        if count > MAX_PACKETS:
            raise ValueError("Capture exceeds this prototype's 10,000-packet limit.")
    if not count:
        raise ValueError("Capture contains no packets.")
    return {"sha256": hashlib.sha256(data).hexdigest(), "packet_count": count,
            "size_bytes": len(data)}


def _record(number, timestamp, length, src, dst, sport, dport, flags):
    values = (number, length, sport, dport, flags)
    if any(type(value) is not int for value in values):
        raise ValueError("Non-integer packet field.")
    if number < 1 or length < 14 or not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("Invalid packet number, length or timestamp.")
    if not 0 <= sport <= 65535 or not 0 <= dport <= 65535 or not 0 <= flags <= 511:
        raise ValueError("Invalid TCP port or flags.")
    return {"packet": number, "time": timestamp, "length": length,
            "src": str(ipaddress.IPv4Address(src)), "dst": str(ipaddress.IPv4Address(dst)),
            "sport": sport, "dport": dport, "flags": flags}


def _scapy(path):
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    import scapy
    from scapy.all import Ether, IP, TCP, PcapReader
    records, skipped, total = [], 0, 0
    with PcapReader(str(path)) as reader:
        for number, packet in enumerate(reader, 1):
            total += 1
            if Ether not in packet or IP not in packet or TCP not in packet:
                skipped += 1
                continue
            ip, tcp = packet[IP], packet[TCP]
            if int(ip.proto) != 6 or int(ip.frag) or int(ip.flags) & 1:
                skipped += 1
                continue
            if (ip.ihl is None or ip.ihl < 5 or tcp.dataofs is None or tcp.dataofs < 5
                    or ip.len is None or ip.len < ip.ihl * 4 + tcp.dataofs * 4
                    or len(bytes(ip)) < ip.len):
                raise ValueError("Incomplete IPv4/TCP headers.")
            records.append(_record(number, float(packet.time), len(packet),
                                   ip.src, ip.dst, int(tcp.sport), int(tcp.dport), int(tcp.flags)))
    return records, skipped, total, f"Scapy {scapy.__version__}"


TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "ip.frag_offset", "ip.flags.mf", "ip.proto",
)


def _tshark_flag(value):
    """Wireshark versions render Boolean fields as True/False or 1/0."""
    normalised = value.strip().lower()
    if normalised in {"true", "false"}:
        return normalised == "true"
    number = int(normalised or "0", 0)
    if number not in {0, 1}:
        raise ValueError("Unexpected TShark Boolean field.")
    return bool(number)


def _tshark(path):
    executable = shutil.which("tshark")
    if not executable:
        raise ValueError("TShark is not installed/on PATH; use --decoder scapy until VM setup.")
    command = [executable, "-n", "-r", str(path), "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f"]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="strict", timeout=20, check=False)
        if completed.returncode:
            raise ValueError("TShark could not decode the complete capture.")
        version = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                 timeout=5, check=True).stdout.splitlines()[0]
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        raise ValueError("TShark execution failed or timed out.") from exc
    records, skipped, total = [], 0, 0
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != len(TSHARK_FIELDS):
            raise ValueError("Unexpected TShark output format.")
        total += 1
        if any(not fields[index] for index in range(3, 8)):
            skipped += 1
            continue
        if (int(fields[8] or "0", 0) or _tshark_flag(fields[9])
                or int(fields[10] or "0", 0) != 6):
            skipped += 1
            continue
        records.append(_record(int(fields[0]), float(fields[1]), int(fields[2]),
                               fields[3], fields[4], int(fields[5]), int(fields[6]),
                               int(fields[7], 0)))
    return records, skipped, total, version


def summarise(records, capture, decoder, skipped=0):
    if any(ipaddress.ip_address(row[key]) not in LAB for row in records for key in ("src", "dst")):
        raise ValueError("This version only accepts the configured 10.77.0.0/24 lab addresses.")
    records = sorted(records, key=lambda row: (row["time"], row["packet"]))
    windows = defaultdict(deque)
    best = []
    for row in records:
        # SYN without ACK: an initial TCP connection attempt, not proof of an attack.
        if row["dst"] != SERVER or not row["flags"] & 2 or row["flags"] & 16:
            continue
        window = windows[(row["src"], row["dst"])]
        window.append(row)
        while window and row["time"] - window[0]["time"] > WINDOW_SECONDS:
            window.popleft()
        if len({item["dport"] for item in window}) > len({item["dport"] for item in best}):
            best = list(window)
    ports = sorted({row["dport"] for row in best})
    if not records or skipped:
        finding = "insufficient_evidence"
    elif len(ports) >= PORT_THRESHOLD:
        finding = "scan_like"
    else:
        finding = "no_scan_pattern"
    prefix = capture["sha256"][:16]
    facts = [{
        "id": f"{prefix}:capture",
        "text": f'{capture["packet_count"]} frames; {len(records)} supported IPv4/TCP frames; {skipped} unsupported frames.',
        "packet_refs": [row["packet"] for row in records[:24]],
    }]
    if best:
        facts.append({
            "id": f"{prefix}:ports",
            "text": (f'{best[0]["src"]} tried {len(ports)} different ports on {SERVER} '
                     f'within {best[-1]["time"] - best[0]["time"]:.3f} seconds. '
                     f'Ports: {ports[:24]}{" (first 24 shown)" if len(ports) > 24 else ""}.'),
            "packet_refs": [row["packet"] for row in best[:24]],
        })
    if len(best) > 24:
        facts[-1]["text"] += " Displayed packet references are a sample of this window."
    return {
        "schema_version": "1", "capture": capture, "decoder": decoder,
        "lab_server": SERVER, "finding": finding,
        "candidate_source": best[0]["src"] if best else None,
        "distinct_ports": ports, "facts": facts,
        "rule": {"id": "tcp-port-check-v1", "ports": PORT_THRESHOLD, "seconds": WINDOW_SECONDS},
        "limitations": [
            "This simple demonstration rule is not a general attack detector.",
            "A port-check pattern can also be authorised maintenance; intent is not established.",
            "No matching pattern does not prove that a network is safe.",
            "Only complete classic Ethernet PCAP and unfragmented lab IPv4/TCP are supported.",
        ],
    }


def analyse_capture(path: Path, decoder="auto"):
    path = path.resolve()
    capture = preflight(path)
    if decoder not in {"auto", "scapy", "tshark"}:
        raise ValueError("Unknown decoder.")
    selected = ("tshark" if shutil.which("tshark") else "scapy") if decoder == "auto" else decoder
    try:
        records, skipped, total, version = (_tshark if selected == "tshark" else _scapy)(path)
    except ImportError as exc:
        raise ValueError("Install the pinned Python requirements in a virtual environment.") from exc
    if total != capture["packet_count"]:
        raise ValueError("Decoder did not account for every packet.")
    if [row["packet"] for row in records] != sorted({row["packet"] for row in records}):
        raise ValueError("Decoder packet references are inconsistent.")
    return summarise(records, capture, {"name": selected, "version": version}, skipped)


def evidence_digest(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()
