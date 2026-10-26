"""Extraction/reference/coverage regressions, not LLM accuracy measurements."""
import copy
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_evidence import analyse_capture
from pp_packet_records import verify_tshark
from pp_samples import pcap_bytes, sample_packets
from evidence_cases import case_bytes


class EvidenceV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="packetpilot-v2-")
        self.folder = Path(self.temp.name)
        self.sources = {}
        for name, (content, _) in case_bytes().items():
            path = self.folder / (name + ".pcap")
            path.write_bytes(content)
            self.sources[name] = path
        self.schema = json.loads((ROOT / "components/03-packet-analysis/evidence-v2.schema.json").read_text())
        self.validator = Draft202012Validator(self.schema, format_checker=FormatChecker())

    def tearDown(self):
        self.temp.cleanup()

    def analyse(self, name="mixed-udp", decoder="scapy"):
        return analyse_capture(self.sources[name], decoder)

    def custom(self, content):
        path = self.folder / "custom.pcap"
        path.write_bytes(content)
        return analyse_capture(path, "scapy")

    def test_regression_udp_does_not_erase_tcp(self):
        plain, mixed = self.analyse("port-check"), self.analyse()
        self.assertEqual(mixed["finding"], "scan_like")
        self.assertEqual(plain["distinct_ports"], mixed["distinct_ports"])
        self.assertEqual(mixed["coverage"]["decoded_packets"], 9)
        self.assertEqual(mixed["overview"]["decoded_protocol_counts"], {"TCP": 8, "UDP": 1})
        self.assertEqual(mixed["packets"][-1]["udp"]["dst_port"], 9000)

    def test_udp_only_has_useful_evidence_despite_legacy_tcp_status(self):
        value = self.analyse("udp-only")
        self.assertEqual(value["finding"], "insufficient_evidence")
        self.assertEqual(value["coverage"]["decoded_packets"], 1)
        self.assertTrue(value["coverage"]["complete_for_supported_headers"])
        self.assertEqual(len(value["flows"]), 1)
        row = value["packets"][0]
        self.assertEqual(row["ipv4"]["ttl"], 50)
        self.assertEqual(row["ipv4"]["id"], 9)
        self.assertEqual(row["udp"]["src_port"], 53000)
        self.assertEqual(row["payload"]["preview_hex"], b"fixture payload".hex())
        self.assertFalse(row["payload"]["preview_truncated"])

    def test_unsupported_malformed_fragment_keep_valid_packets(self):
        for name, status, issue in (("mixed-arp", "unsupported", "unsupported_link_payload"),
                                     ("mixed-fragment", "unsupported", "ipv4_fragment_not_reassembled"),
                                     ("mixed-malformed", "malformed", "ipv4_length_exceeds_captured_bytes")):
            with self.subTest(name=name):
                value = self.analyse(name)
                self.assertEqual(value["finding"], "scan_like")
                self.assertEqual(value["coverage"]["decoded_packets"], 8)
                self.assertFalse(value["coverage"]["complete_for_supported_headers"])
                self.assertEqual(value["packets"][-1]["status"], status)
                self.assertIn(issue, value["packets"][-1]["issues"])
                self.assertIsNone(value["packets"][-1]["flow_id"])

    def test_all_cases_match_schema(self):
        Draft202012Validator.check_schema(self.schema)
        for name in self.sources:
            with self.subTest(name=name):
                self.validator.validate(self.analyse(name))

    def test_schema_rejects_invalid_port_status_and_missing_refs(self):
        value = self.analyse()
        for mutate in (lambda v: v["packets"][0]["tcp"].update(src_port=99999),
                       lambda v: v["packets"][0].update(status="safe"),
                       lambda v: v["flows"][0].pop("packet_refs")):
            changed = copy.deepcopy(value)
            mutate(changed)
            self.assertFalse(self.validator.is_valid(changed))

    def test_decode_bounds_are_optional_strict_and_nonnegative(self):
        value = self.analyse('mixed-malformed')
        self.validator.validate(value)
        self.assertNotIn('decode_bounds', self.analyse('normal')['packets'][0])
        for mutate in (lambda b: b.update(ipv4_shortfall_bytes=-1),
                       lambda b: b.update(tcp_tuple_identified=True),
                       lambda b: b.update(unexpected_field=1),
                       lambda b: b.pop('saved_ipv4_bytes')):
            changed = copy.deepcopy(value)
            mutate(changed['packets'][-1]['decode_bounds'])
            self.assertFalse(self.validator.is_valid(changed))

    def test_packet_offsets_hashes_and_full_reference_membership(self):
        for name, source in self.sources.items():
            value = self.analyse(name)
            original = source.read_bytes()
            self.assertEqual(value["capture"]["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual([p["packet"] for p in value["packets"]], list(range(1, len(value["packets"]) + 1)))
            for row in value["packets"]:
                self.assertEqual(row["id"], f'{value["capture"]["sha256"]}:p{row["packet"]}')
                raw = original[row["file_offset"]:row["file_offset"] + row["captured_bytes"]]
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row["frame_sha256"])
            flow_refs = [n for flow in value["flows"] for n in flow["packet_refs"]]
            self.assertEqual(sorted(flow_refs), [p["packet"] for p in value["packets"] if p["status"] == "decoded"])
            for flow in value["flows"]:
                self.assertEqual(flow["packet_count"], len(flow["packet_refs"]))
                self.assertEqual(sum(flow["directions"].values()), flow["packet_count"])
                for number in flow["packet_refs"]:
                    self.assertEqual(value["packets"][number - 1]["flow_id"], flow["id"])
            c = value["coverage"]
            self.assertEqual(c["total_packets"], sum(c[k] for k in ("decoded_packets", "unsupported_packets", "malformed_packets", "truncated_packets")))

    def test_normal_bidirectional_flows_and_tcp_fields(self):
        value = self.analyse("normal")
        self.assertEqual(len(value["flows"]), 3)
        for flow in value["flows"]:
            self.assertEqual(flow["packet_count"], 3)
            self.assertEqual(sorted(flow["directions"].values()), [1, 2])
            self.assertAlmostEqual(flow["duration_seconds"], .04, places=6)
            self.assertEqual(flow["tcp_flag_counts"], {"ACK": 2, "SYN": 2})
        syn, synack, ack = value["packets"][:3]
        self.assertEqual(syn["tcp"]["sequence"], 1000)
        self.assertEqual(synack["tcp"]["acknowledgement"], 1001)
        self.assertEqual(synack["tcp"]["flags"], 18)
        self.assertEqual(ack["tcp"]["flag_names"], ["ACK"])
        self.assertEqual(syn["tcp"]["header_bytes"], 20)

    def test_snapshot_truncation_is_not_file_corruption(self):
        content = bytearray(self.sources["port-check"].read_bytes())
        wire = struct.unpack("<I", content[36:40])[0]
        content[36:40] = struct.pack("<I", wire + 100)
        value = self.custom(content)
        self.assertEqual(value["coverage"]["truncated_packets"], 1)
        self.assertEqual(value["coverage"]["decoded_packets"], 7)
        self.assertEqual(value["finding"], "scan_like")
        self.assertIn("capture_snapshot_truncated", value["packets"][0]["issues"])
        self.validator.validate(value)

    def test_physically_incomplete_file_and_missing_capture_rejected(self):
        with self.assertRaises(ValueError):
            self.custom(self.sources["normal"].read_bytes()[:-1])
        with self.assertRaises(ValueError):
            analyse_capture(self.folder / "missing.pcap", "scapy")
        with self.assertRaises(ValueError):
            self.custom(pcap_bytes([]))

    def test_short_frame_is_accounted_for(self):
        content = pcap_bytes([(0, b"short")])
        value = self.custom(content)
        self.assertEqual(value["coverage"]["malformed_packets"], 1)
        self.assertEqual(value["packets"][0]["issues"], ["incomplete_ethernet_header"])
        self.validator.validate(value)

    def test_outside_lab_udp_is_rejected(self):
        from scapy.all import Ether, IP, UDP
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="203.0.113.4", dst="10.77.0.10") / UDP()
        with self.assertRaises(ValueError):
            self.custom(pcap_bytes([(0, packet)]))

    def test_tunnel_is_not_misattributed_as_outer_tcp(self):
        from scapy.all import Ether, IP, TCP
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.77.0.20", dst="10.77.0.10") / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=22)
        value = self.custom(pcap_bytes([(0, packet)]))
        self.assertEqual(value["packets"][0]["status"], "unsupported")
        self.assertIsNone(value["packets"][0]["tcp"])

    def test_payload_preview_is_bounded_and_explicit(self):
        from scapy.all import Raw
        packet = sample_packets()["normal"][0][1] / Raw(b"z" * 300)
        value = self.custom(pcap_bytes([(0, packet)]))
        payload = value["packets"][0]["payload"]
        self.assertEqual(payload["length"], 300)
        self.assertTrue(payload["preview_truncated"])
        self.assertEqual(len(bytes.fromhex(payload["preview_hex"])), 64)

    def test_references_are_not_limited_to_legacy_24(self):
        packet = sample_packets()["normal"][0][1]
        value = self.custom(pcap_bytes([(i * .1, packet) for i in range(30)]))
        self.assertEqual(value["flows"][0]["packet_refs"], list(range(1, 31)))
        self.assertEqual(len(value["packets"]), 30)

    def test_timestamp_resolution_endianness_and_out_of_order(self):
        raw = bytes(sample_packets()["normal"][0][1])
        for endian in ("<", ">"):
            header = struct.pack(endian + "IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
            content = header + struct.pack(endian + "IIII", 100, 123456789, len(raw), len(raw)) + raw
            value = self.custom(content)
            self.assertEqual(value["packets"][0]["timestamp"], "100.123456789")
            self.assertEqual(value["capture"]["timestamp_resolution"], "nanoseconds")
        reversed_packets = list(reversed(sample_packets()["normal"]))
        self.assertTrue(self.custom(pcap_bytes(reversed_packets))["overview"]["out_of_order_timestamps"])

    def test_tshark_failure_and_disagreement_are_explicit(self):
        data = self.sources["normal"].read_bytes()
        records = self.analyse("normal")["packets"]
        with patch("pp_packet_records.shutil.which", return_value="fake-tshark"):
            with patch("pp_packet_records.subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 20)):
                with self.assertRaisesRegex(ValueError, "timed out"):
                    verify_tshark(data, records)
            with patch("pp_packet_records.subprocess.run", side_effect=[Mock(returncode=0, stdout="wrong\n"), Mock(stdout="test version\n")]):
                with self.assertRaisesRegex(ValueError, "every packet"):
                    verify_tshark(data, records)

    @unittest.skipUnless(shutil.which("tshark"), "Independent TShark checks run on Ubuntu.")
    def test_tshark_agrees_on_all_supported_and_partial_cases(self):
        for name in self.sources:
            with self.subTest(name=name):
                first, second = self.analyse(name), self.analyse(name, "tshark")
                self.assertGreater(second["decoder"]["tshark_verification"]["verified_field_count"], 0)
                first.pop("decoder")
                second.pop("decoder")
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
