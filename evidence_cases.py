"""Labelled offline fixtures. Labels are evaluation metadata, not model input."""
from pp_samples import pcap_bytes, sample_packets


def evidence_cases():
    from scapy.all import ARP, Ether, IP, TCP, UDP, Raw
    ethernet = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    udp = Ether(**ethernet) / IP(src="10.77.0.20", dst="10.77.0.10", id=9, ttl=50) / UDP(sport=53000, dport=9000) / Raw(b"fixture payload")
    arp = Ether(**ethernet) / ARP(hwsrc=ethernet["src"], hwdst="00:00:00:00:00:00", psrc="10.77.0.20", pdst="10.77.0.10")
    fragments = Ether(**ethernet) / IP(src="10.77.0.20", dst="10.77.0.10", flags="MF") / TCP(sport=50000, dport=443)
    malformed = Ether(**ethernet) / IP(src="10.77.0.20", dst="10.77.0.10", len=200) / TCP(sport=50000, dport=443)
    original = sample_packets()
    return {
        "normal": (original["normal"], "Three TCP handshakes, nine frames, three bidirectional flows."),
        "port-check": (original["port-check"], "Eight SYN attempts to eight ports in 0.7 seconds; intent unknown."),
        "mixed-udp": (original["port-check"] + [(1.0, udp)], "Eight SYN attempts remain present alongside one UDP datagram."),
        "udp-only": ([(0.0, udp)], "One supported UDP datagram; not evidence for a TCP rule."),
        "mixed-arp": (original["port-check"] + [(1.0, arp)], "Eight SYN attempts plus unsupported ARP; retain useful TCP evidence."),
        "mixed-fragment": (original["port-check"] + [(1.0, fragments)], "Eight SYN attempts plus one unsupported IPv4 fragment."),
        "mixed-malformed": (original["port-check"] + [(1.0, malformed)], "Eight SYN attempts plus one malformed IPv4 length; retain valid frames."),
    }


def case_bytes():
    return {name: (pcap_bytes(packets), label) for name, (packets, label) in evidence_cases().items()}
