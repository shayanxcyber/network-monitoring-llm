"""Construct two saved examples. This module never sends or sniffs traffic."""
from __future__ import annotations

import hashlib
import json
import logging
import struct
from pathlib import Path

SERVER = "10.77.0.10"
CUSTOMER = "10.77.0.20"
PROBE = "10.77.0.30"
FIXTURE_EPOCH = 1788134400  # Fixed synthetic clock, not an activity timestamp.


def sample_packets():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import Ether, IP, TCP

    def packet(src, dst, sport, dport, flags, seq, ack=0):
        # Explicit MACs prevent Scapy from consulting the host network.
        return (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src=src, dst=dst, id=1)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )

    normal = []
    for index, port in enumerate((80, 443, 80)):
        sport, seq, server_seq = 40000 + index, 1000 + index * 100, 5000 + index * 100
        start = index * 1.0
        normal.extend([
            (start, packet(CUSTOMER, SERVER, sport, port, "S", seq)),
            (start + .02, packet(SERVER, CUSTOMER, port, sport, "SA", server_seq, seq + 1)),
            (start + .04, packet(CUSTOMER, SERVER, sport, port, "A", seq + 1, server_seq + 1)),
        ])
    scan = [
        (index * .1, packet(PROBE, SERVER, 45000 + index, port, "S", 9000 + index))
        for index, port in enumerate((21, 22, 25, 53, 80, 110, 443, 8080))
    ]
    return {"normal": normal, "port-check": scan}


def pcap_bytes(packets):
    """Classic Ethernet PCAP with Scapy-built frames/checksums."""
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for offset, packet in packets:
        raw = bytes(packet)
        micros = round(offset * 1_000_000)
        result.extend(struct.pack("<IIII", FIXTURE_EPOCH + micros // 1_000_000,
                                  micros % 1_000_000, len(raw), len(raw)))
        result.extend(raw)
    return bytes(result)


def make_samples(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format_version": "1",
        "source": "Synthetic packet construction; no live capture or transmitted traffic.",
        "timestamp_note": "Packet timestamps use a fixed synthetic clock.",
        "network": "10.77.0.0/24",
        "server": SERVER,
        "cases": [],
    }
    for name, packets in sample_packets().items():
        content = pcap_bytes(packets)
        target = directory / f"{name}.pcap"
        if target.exists():
            if target.read_bytes() != content:
                raise ValueError(f"Existing {target.name} differs; choose a new output directory.")
        else:
            target.write_bytes(content)
        manifest["cases"].append({
            "id": name, "file": target.name, "packets": len(packets),
            "sha256": hashlib.sha256(content).hexdigest(),
            "expected_finding": "scan_like" if name == "port-check" else "no_scan_pattern",
            "purpose": (
                "Eight TCP connection attempts to different server ports in 0.7 seconds."
                if name == "port-check"
                else "Three normal-looking TCP handshakes to two server ports."
            ),
        })
    manifest_path = directory / "manifest.json"
    text = json.dumps(manifest, indent=2) + "\n"
    if manifest_path.exists() and manifest_path.read_text(encoding="utf-8") != text:
        raise ValueError("Existing manifest differs; choose a new output directory.")
    if not manifest_path.exists():
        manifest_path.write_text(text, encoding="utf-8")
    return manifest
