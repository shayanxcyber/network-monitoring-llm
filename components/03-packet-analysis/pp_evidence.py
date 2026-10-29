"""Versioned packet evidence with a narrow legacy application compatibility view."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import shutil
from collections import defaultdict, deque
from pathlib import Path

from pp_packet_records import MAX_BYTES, MAX_PACKETS, LAB, decode_capture, read_container

WINDOW_SECONDS = 10.0
PORT_THRESHOLD = 6
SERVER = "10.77.0.10"


def preflight(path: Path):
    return read_container(path)[1]


def _tshark_flag(value):
    """Kept for callers using Wireshark's Boolean field normalisation."""
    normalised = value.strip().lower()
    if normalised in {"true", "false"}:
        return normalised == "true"
    number = int(normalised or "0", 0)
    if number not in {0, 1}:
        raise ValueError("Unexpected TShark Boolean field.")
    return bool(number)


def summarise(records, capture, decoder, skipped=0):
    """Legacy TCP-only view, NOT the new observation schema or an LLM verdict."""
    if any(ipaddress.ip_address(row[key]) not in LAB for row in records for key in ("src", "dst")):
        raise ValueError("This version only accepts the configured 10.77.0.0/24 lab addresses.")
    records = sorted(records, key=lambda row: (row["time"], row["packet"]))
    windows = defaultdict(deque)
    best = []
    for row in records:
        if row["dst"] != SERVER or not row["flags"] & 2 or row["flags"] & 16:
            continue
        window = windows[(row["src"], row["dst"])]
        window.append(row)
        while window and row["time"] - window[0]["time"] > WINDOW_SECONDS:
            window.popleft()
        if len({item["dport"] for item in window}) > len({item["dport"] for item in best}):
            best = list(window)
    ports = sorted({row["dport"] for row in best})
    # A frame outside this legacy rule's scope must not erase supported evidence.
    finding = "insufficient_evidence" if not records else ("scan_like" if len(ports) >= PORT_THRESHOLD else "no_scan_pattern")
    prefix = capture["sha256"][:16]
    facts = [{
        "id": f"{prefix}:capture",
        "text": f'{capture["packet_count"]} frames; {len(records)} usable IPv4/TCP frames; {skipped} frames outside the legacy TCP rule.',
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
        "lab_server": SERVER, "finding": finding, "candidate_source": best[0]["src"] if best else None,
        "distinct_ports": ports, "facts": facts,
        "rule": {"id": "tcp-port-check-v1", "ports": PORT_THRESHOLD, "seconds": WINDOW_SECONDS},
        "limitations": [
            "The legacy TCP rule is retained only for application compatibility, not a general attack detector.",
            "A port-check pattern can also be authorised maintenance; intent is not established.",
            "No matching pattern does not prove that a network is safe.",
            "Classic Ethernet PCAP, at most 8 MiB / 10,000 frames; supported transport observations are unfragmented lab IPv4/TCP and UDP.",
            "No stream or fragment reassembly, checksum validation, decryption, application-protocol interpretation or general log parser.",
            "Payload previews contain at most 64 bytes; full original bytes remain in the retained capture.",
            "Flows group a bidirectional five-tuple within this capture; they do not prove a completed session or separate reused connections.",
            "Independent model context uses packet/flow observations; the TCP rule remains a separately labelled baseline.",
        ],
    }


def analyse_capture(path: Path, decoder="auto"):
    if decoder not in {"auto", "scapy", "tshark"}:
        raise ValueError("Unknown decoder.")
    selected = ("tshark" if shutil.which("tshark") else "scapy") if decoder == "auto" else decoder
    try:
        capture, packets, flows, coverage, overview, provenance = decode_capture(Path(path).resolve(), selected)
    except ImportError as exc:
        raise ValueError("Install the pinned Python requirements in a virtual environment.") from exc
    tcp_records = [
        {"packet": p["packet"], "time": p["time"], "length": p["captured_bytes"],
         "src": p["ipv4"]["src"], "dst": p["ipv4"]["dst"], "sport": p["tcp"]["src_port"],
         "dport": p["tcp"]["dst_port"], "flags": p["tcp"]["flags"]}
        for p in packets if p["status"] == "decoded" and p["tcp"] is not None
    ]
    result = summarise(tcp_records, capture, provenance, len(packets) - len(tcp_records))
    result.update({"schema_version": "2", "packets": packets, "flows": flows,
                   "coverage": coverage, "overview": overview,
                   "legacy_assessment": {"purpose": "Compatibility only; independent from observations and not an AI assessment.",
                                         "scope": "Usable IPv4/TCP frames only; UDP-only captures can have useful observations with no TCP-rule result.",
                                         "finding": result["finding"], "packet_refs": [p["packet"] for p in tcp_records]}})
    return result


def evidence_digest(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()
