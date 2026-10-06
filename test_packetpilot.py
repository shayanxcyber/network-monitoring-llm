"""Controlled functional/negative checks, not a general detection benchmark."""
from __future__ import annotations

import copy
import io
import json
import shutil
import struct
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot  # Installs the six existing role-module paths.
from pp_evidence import analyse_capture, preflight, summarise, _tshark_flag
from pp_llm import (
    APIConfig, ChatClient, LLMError, MAX_RESPONSE_BYTES, NoRedirect,
    baseline_explanation, build_request, strict_json, validate_explanation,
)
from pp_operator import render_report
from pp_policy import preview_response
from pp_samples import make_samples, pcap_bytes, sample_packets
from pp_workflow import run_analysis
from pp_context import build_context
from assessment_fixtures import stub_answer


class Body(io.BytesIO):
    pass


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="packetpilot-tests-")
        cls.folder = Path(cls.temporary.name)
        cls.manifest = make_samples(cls.folder / "samples")
        cls.normal_path = cls.folder / "samples" / "normal.pcap"
        cls.scan_path = cls.folder / "samples" / "port-check.pcap"
        cls.normal = analyse_capture(cls.normal_path, "scapy")
        cls.scan = analyse_capture(cls.scan_path, "scapy")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def answer(self, evidence=None):
        evidence = evidence or self.scan
        return stub_answer(build_context(evidence, 'Why?'))

    def response(self, answer=None, **changes):
        result = {
            "model": "protocol-test-stub",
            "choices": [{"finish_reason": "stop", "message": {
                "role": "assistant", "content": json.dumps(answer or self.answer()),
            }}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }
        result.update(changes)
        return json.dumps(result).encode()

    def client(self, body=None, config=None):
        opener = Mock()
        opener.open.return_value = Body(body or self.response())
        return ChatClient(config or APIConfig("https://api.example.test", "test-model", "test-secret"),
                          opener=opener, sleep=Mock())

    def write_bad(self, data, name="bad.pcap"):
        path = self.folder / name
        path.write_bytes(data)
        return path

    def test_fixtures_are_deterministic_and_idempotent(self):
        self.assertEqual(make_samples(self.folder / "samples"), self.manifest)
        self.assertEqual([case["packets"] for case in self.manifest["cases"]], [9, 8])

    def test_existing_different_sample_is_not_overwritten(self):
        directory = self.folder / "different"
        directory.mkdir(exist_ok=True)
        (directory / "normal.pcap").write_bytes(b"preserve this")
        with self.assertRaises(ValueError):
            make_samples(directory)
        self.assertEqual((directory / "normal.pcap").read_bytes(), b"preserve this")

    def test_normal_example_does_not_trigger_rule(self):
        self.assertEqual(self.normal["finding"], "no_scan_pattern")
        self.assertEqual(self.normal["distinct_ports"], [80, 443])

    def test_tshark_boolean_versions(self):
        for value in ("False", "false", "0", "0x00", ""):
            self.assertFalse(_tshark_flag(value))
        for value in ("True", "true", "1", "0x01"):
            self.assertTrue(_tshark_flag(value))
        for value in ("2", "unknown", "-1"):
            with self.assertRaises(ValueError):
                _tshark_flag(value)

    def test_port_check_triggers_rule(self):
        self.assertEqual(self.scan["finding"], "scan_like")
        self.assertEqual(len(self.scan["distinct_ports"]), 8)
        self.assertEqual(self.scan["candidate_source"], "10.77.0.30")

    def test_filename_is_not_a_detection_label(self):
        renamed = self.folder / "looks-normal.pcap"
        renamed.write_bytes(self.scan_path.read_bytes())
        self.assertEqual(analyse_capture(renamed, "scapy"), self.scan)

    def test_empty_file_rejected(self):
        with self.assertRaises(ValueError):
            preflight(self.write_bad(b""))

    def test_non_pcap_rejected(self):
        with self.assertRaises(ValueError):
            preflight(self.write_bad(b"not-a-capture" * 3))

    def test_partial_record_header_rejected(self):
        with self.assertRaises(ValueError):
            preflight(self.write_bad(self.scan_path.read_bytes()[:25]))

    def test_truncated_packet_rejected(self):
        with self.assertRaises(ValueError):
            analyse_capture(self.write_bad(self.scan_path.read_bytes()[:-1]), "scapy")

    def test_non_ethernet_rejected(self):
        data = bytearray(self.scan_path.read_bytes())
        data[20:24] = struct.pack("<I", 101)
        with self.assertRaises(ValueError):
            preflight(self.write_bad(data))

    def test_outside_lab_rejected(self):
        packets = sample_packets()["port-check"]
        for _, packet in packets:
            packet["IP"].src = "203.0.113.10"
        with self.assertRaises(ValueError):
            analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")

    def test_fragmented_traffic_returns_insufficient(self):
        packets = sample_packets()["port-check"]
        for _, packet in packets:
            packet["IP"].flags = "MF"
        evidence = analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")
        self.assertEqual(evidence["finding"], "insufficient_evidence")

    def test_unsupported_traffic_returns_insufficient(self):
        from scapy.all import Ether, IP, UDP
        packets = [(0, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                    / IP(src="10.77.0.20", dst="10.77.0.10") / UDP(sport=3000, dport=53))]
        evidence = analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")
        self.assertEqual(evidence["finding"], "insufficient_evidence")

    def test_slow_port_attempts_do_not_cross_window(self):
        packets = [(index * 20., packet) for index, (_, packet) in enumerate(sample_packets()["port-check"])]
        self.assertEqual(analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")["finding"], "no_scan_pattern")

    def test_repeated_single_port_is_not_many_ports(self):
        packets = sample_packets()["port-check"]
        for _, packet in packets:
            packet["TCP"].dport = 80
        self.assertEqual(analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")["finding"], "no_scan_pattern")

    def test_threshold_boundary(self):
        for count, expected in ((5, "no_scan_pattern"), (6, "scan_like")):
            with self.subTest(count=count):
                packets = sample_packets()["port-check"][:count]
                self.assertEqual(analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")["finding"], expected)

    def test_different_sources_are_not_combined(self):
        packets = sample_packets()["port-check"]
        for index, (_, packet) in enumerate(packets):
            packet["IP"].src = "10.77.0.30" if index < 4 else "10.77.0.31"
        self.assertEqual(analyse_capture(self.write_bad(pcap_bytes(packets)), "scapy")["finding"], "no_scan_pattern")

    @unittest.skipUnless(shutil.which("tshark"), "TShark is not installed on this host; validate it in Ubuntu.")
    def test_tshark_agrees_on_both_examples(self):
        for path in (self.normal_path, self.scan_path):
            scapy_result = analyse_capture(path, "scapy")
            tshark_result = analyse_capture(path, "tshark")
            for key in ("finding", "capture", "distinct_ports", "facts"):
                self.assertEqual(scapy_result[key], tshark_result[key])

    def test_valid_model_reply_checked(self):
        response = self.client().explain(self.scan, "Why was this flagged?")
        self.assertEqual(response["source"], "api")
        self.assertEqual(response['answer']['assessment'], 'inconclusive')
        self.assertEqual(response["usage"]["total_tokens"], 30)

    def test_rich_evidence_and_question_without_verdict_are_sent(self):
        config = APIConfig("https://api.example.test/v1", "test-model", "test-secret", thinking="disabled")
        payload, metadata = build_request(self.scan, "Why?", config)
        body = json.loads(payload["messages"][1]["content"])
        self.assertEqual(len(body['packets']), 8)
        self.assertEqual(len(body['flows']), 8)
        self.assertNotIn('finding', body)
        self.assertNotIn('scan_like', json.dumps(body))
        self.assertNotIn("test-secret", json.dumps(payload))
        self.assertEqual(payload["thinking"], {"type": "disabled"})
        self.assertEqual(len(metadata["prompt_sha256"]), 64)
        self.assertEqual(config.endpoint(), "https://api.example.test/v1/chat/completions")

    def test_key_is_not_in_config_representation(self):
        self.assertNotIn("test-secret", repr(APIConfig("https://example.test", "test", "test-secret")))

    def test_direct_request_supports_max_reasoning_without_sampling_temperature(self):
        config = APIConfig('https://example.test', 'test', 'test-secret', thinking='enabled',
                           reasoning_effort='max', timeout=180, max_output_tokens=32768)
        config.endpoint()
        request, _ = build_request(self.scan, 'Inspect the evidence.', config)
        self.assertEqual(request['thinking'], {'type': 'enabled'})
        self.assertEqual(request['reasoning_effort'], 'max')
        self.assertEqual(request['max_tokens'], 32768)
        self.assertNotIn('temperature', request)

    def test_invalid_configuration_rejected(self):
        configs = [
            APIConfig("http://api.example.test", "test", "secret"),
            APIConfig("https://user:pass@example.test", "test", "secret"),
            APIConfig("https://example.test?key=bad", "test", "secret"),
            APIConfig("https://example.test", "", "secret"),
            APIConfig("https://example.test", "test", ""),
            APIConfig("https://example.test", "test", "bad\nkey"),
            APIConfig("https://example.test", "test", "secret", timeout=float("nan")),
            APIConfig("https://example.test", "test", "secret", timeout=True),
            APIConfig("https://example.test", "test", "secret", timeout=301),
            APIConfig("https://example.test", "test", "secret", thinking="enabled", reasoning_effort="invalid"),
            APIConfig("https://example.test", "test", "secret", thinking="disabled", reasoning_effort="max"),
            APIConfig("https://example.test", "test", "secret", max_output_tokens=True),
            APIConfig("https://example.test", "test", "secret", max_output_tokens=0),
        ]
        for config in configs:
            with self.subTest(config=config):
                with self.assertRaises(LLMError):
                    config.endpoint()

    def test_http_is_allowed_only_in_explicit_loopback_tests(self):
        self.assertEqual(APIConfig("http://127.0.0.1:1234", "test", "secret",
                                   allow_loopback_http=True).endpoint(),
                         "http://127.0.0.1:1234/chat/completions")
        with self.assertRaises(LLMError):
            APIConfig("http://203.0.113.20", "test", "secret", allow_loopback_http=True).endpoint()

    def test_redirect_handler_never_forwards_request(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_unknown_and_cross_capture_references_rejected(self):
        for refs in (["invented"], [self.normal["facts"][0]["id"]], [], ["same", "same"]):
            answer = self.answer()
            answer['observations'][0]['references'] = refs
            with self.assertRaises(ValueError):
                validate_explanation(json.dumps(answer), self.scan)

    def test_model_can_assess_independently_of_rule(self):
        answer = self.answer()
        answer['assessment'] = 'normal_observations'
        self.assertEqual(validate_explanation(json.dumps(answer), self.scan)['assessment'], 'normal_observations')

    def test_command_field_rejected(self):
        answer = self.answer()
        answer["command"] = "do not execute this"
        with self.assertRaises(ValueError):
            validate_explanation(json.dumps(answer), self.scan)

    def test_missing_and_empty_text_rejected(self):
        for modification in ("missing", "empty", "long", "control"):
            answer = self.answer()
            if modification == "missing":
                del answer["summary"]
            else:
                answer["summary"] = {"empty": "", "long": "x" * 1401, "control": "\x1b[31m"}[modification]
            with self.assertRaises(ValueError):
                validate_explanation(json.dumps(answer), self.scan)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(text)

    def test_incomplete_or_tool_output_rejected(self):
        for reason in ("length", "tool_calls", "content_filter"):
            response = json.loads(self.response())
            response["choices"][0]["finish_reason"] = reason
            with self.assertRaises(LLMError):
                self.client(json.dumps(response).encode()).explain(self.scan, "Why?")

    def test_large_or_invalid_response_rejected(self):
        for body in (b"x" * (MAX_RESPONSE_BYTES + 1), b"not json", b"\xff"):
            with self.assertRaises(LLMError):
                self.client(body).explain(self.scan, "Why?")

    def test_authentication_error_does_not_retry_or_echo_body(self):
        client = self.client()
        client.opener.open.side_effect = HTTPError("https://example.test", 401, "bad", {}, Body(b"test-secret"))
        with self.assertRaises(LLMError) as raised:
            client.explain(self.scan, "Why?")
        self.assertEqual(raised.exception.code, "authentication")
        self.assertNotIn("test-secret", str(raised.exception))
        self.assertEqual(client.opener.open.call_count, 1)

    def test_retry_only_for_explicit_temporary_response(self):
        client = self.client()
        client.opener.open.side_effect = [
            HTTPError("https://example.test", 429, "busy", {}, Body(b"")),
            Body(self.response()),
        ]
        result = client.explain(self.scan, "Why?")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(client.sleep.call_count, 1)
        self.assertEqual(result['http_attempts'], [
            {'attempt': 1, 'outcome': 'http_error', 'status': 429},
            {'attempt': 2, 'outcome': 'response_received'},
        ])

    def test_invalid_adapter_reply_retains_redacted_attempt_evidence(self):
        answer = self.answer()
        answer['summary'] = 'test-secret'
        answer['observations'][0]['references'] = ['fabricated-reference']
        with self.assertRaises(LLMError) as raised:
            self.client(self.response(answer)).explain(self.scan, 'Why?')
        record = raised.exception.record
        self.assertEqual(raised.exception.code, 'invalid_response')
        self.assertEqual(record['attempts'], 1)
        self.assertEqual(record['finish_reason'], 'stop')
        self.assertEqual(record['model'], 'protocol-test-stub')
        self.assertEqual(record['usage']['total_tokens'], 30)
        self.assertIn('fabricated-reference', record['raw_content'])
        self.assertIn('[redacted]', record['raw_content'])
        self.assertNotIn('test-secret', json.dumps(record))
        self.assertEqual(len(record['request']['messages']), 2)
        self.assertNotIn('Authorization', json.dumps(record))

    def test_adapter_failure_records_http_status_without_provider_body(self):
        client = self.client()
        client.opener.open.side_effect = HTTPError('https://example.test', 401, 'bad', {}, Body(b'test-secret'))
        with self.assertRaises(LLMError) as raised:
            client.explain(self.scan, 'Why?')
        record = raised.exception.record
        self.assertEqual(record['http_attempts'], [{'attempt': 1, 'outcome': 'http_error', 'status': 401}])
        self.assertEqual(record['attempts'], 1)
        self.assertEqual(record['raw_content'], '')
        self.assertNotIn('test-secret', json.dumps(record))

    def test_timeout_does_not_retry_an_ambiguous_request(self):
        client = self.client()
        client.opener.open.side_effect = URLError("timed out")
        with self.assertRaises(LLMError) as raised:
            client.explain(self.scan, "Why?")
        self.assertEqual(raised.exception.code, "connection")
        self.assertEqual(client.opener.open.call_count, 1)

    def test_rule_mode_does_not_claim_model_output(self):
        result = baseline_explanation(self.normal, "Why?")
        self.assertEqual(result["status"], "no_model_called")
        self.assertEqual(result["source"], "rules")
        self.assertIsNone(result["model"])

    def test_query_size_and_control_characters_checked(self):
        for query in ("", "x" * 601, "hello\x00", "\u202eevil"):
            with self.assertRaises(ValueError):
                baseline_explanation(self.normal, query)

    def test_block_preview_is_bounded_and_never_executed(self):
        result = preview_response(self.scan, "block_source", "10.77.0.30", 60)
        self.assertTrue(result["allowed_preview"])
        self.assertFalse(result["executed"])
        self.assertEqual(result["state"], "preview_only")

    def test_no_block_for_normal_or_unknown_evidence(self):
        result = preview_response(self.normal, "block_source", "10.77.0.20", 60)
        self.assertFalse(result["allowed_preview"])

    def test_protected_outside_and_unseen_targets_rejected(self):
        for address in ("10.77.0.10", "10.77.0.1", "203.0.113.1", "10.77.0.31", "invalid", None):
            with self.subTest(address=address):
                self.assertFalse(preview_response(self.scan, "block_source", address)["allowed_preview"])

    def test_bad_duration_rejected(self):
        for duration in (0, 121, -1, True, "60"):
            self.assertFalse(preview_response(self.scan, "block_source", "10.77.0.30", duration)["allowed_preview"])

    def test_execution_request_is_rejected(self):
        result = preview_response(self.scan, "block_source", "10.77.0.30", apply=True)
        self.assertFalse(result["allowed_preview"])
        self.assertFalse(result["executed"])

    def test_unknown_action_and_inappropriate_target_rejected(self):
        self.assertFalse(preview_response(self.scan, "run_shell")["allowed_preview"])
        self.assertFalse(preview_response(self.scan, "investigate", "10.77.0.30")["allowed_preview"])
        self.assertFalse(preview_response(self.scan, "no_action")["allowed_preview"])

    def test_real_local_http_protocol_round_trip_not_inference(self):
        body = self.response()
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                content = self.rfile.read(int(self.headers["Content-Length"]))
                requests.append((self.path, json.loads(content)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        try:
            config = APIConfig(f"http://127.0.0.1:{server.server_port}/v1", "protocol-test-stub",
                               "test-secret", allow_loopback_http=True)
            result = ChatClient(config).explain(self.scan, "Why was it flagged?")
            self.assertEqual(result["model"], "protocol-test-stub")
            self.assertEqual(requests[0][0], "/v1/chat/completions")
            self.assertEqual(requests[0][1]["messages"][0]["role"], "system")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_run_preserves_evidence_result_and_audit(self):
        result, evidence, folder = run_analysis(self.scan_path, self.folder / "runs",
                                              "Why?", decoder="scapy")
        self.assertTrue((folder / "evidence.json").exists())
        self.assertTrue((folder / "result.json").exists())
        events = [json.loads(line) for line in (folder / "audit.jsonl").read_text().splitlines()]
        self.assertEqual(events[-1]["stage"], "finished")
        self.assertTrue(all(event["run_id"] == result["run_id"] for event in events))
        self.assertEqual(result["capture_sha256"], evidence["capture"]["sha256"])
        self.assertFalse(result["response"]["executed"])
        report = render_report(result, evidence, folder)
        self.assertIn("RULE-BASED RESULT", report)
        self.assertIn("Packet references:", report)

    def test_failed_api_falls_back_and_records_failure(self):
        client = Mock()
        client.explain.side_effect = LLMError("authentication", "API authentication failed.")
        result, evidence, folder = run_analysis(self.scan_path, self.folder / "runs", "Why?",
                                              provider="api", decoder="scapy", client=client)
        self.assertEqual(result["explanation"]["status"], "fallback_after_api_failure")
        self.assertEqual(result["explanation"]["source"], "rules")
        self.assertIn("api_failed", (folder / "audit.jsonl").read_text())
        self.assertIn("API UNAVAILABLE", render_report(result, evidence, folder))

    def test_failed_capture_has_audit_but_no_success_result(self):
        output = self.folder / "failed-runs"
        with self.assertRaises(ValueError):
            run_analysis(self.write_bad(b"invalid"), output, "Why?", decoder="scapy")
        run = next(output.iterdir())
        self.assertFalse((run / "result.json").exists())
        events = [json.loads(line) for line in (run / "audit.jsonl").read_text().splitlines()]
        self.assertEqual(events[-1]["stage"], "failed")

    def test_new_runs_never_overwrite_previous_results(self):
        first = run_analysis(self.normal_path, self.folder / "runs", "Why?", decoder="scapy")
        second = run_analysis(self.normal_path, self.folder / "runs", "Why?", decoder="scapy")
        self.assertNotEqual(first[2], second[2])
        self.assertEqual(first[0]["capture_sha256"], second[0]["capture_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
