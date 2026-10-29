"""Exercise the real Agno/OpenAI SDK against a local protocol stub, not inference."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_agent import LegacyAgnoClient as AgnoClient
from pp_evidence import analyse_capture
from pp_llm import APIConfig, LLMError
from pp_samples import make_samples
from assessment_fixtures import stub_answer

TEST_KEY = "test-key-never-persist-this"


class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.received = []
        cls.response_mode = "valid"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                cls.received.append(payload)
                current = json.loads(payload["messages"][-1]["content"])
                answer = stub_answer(current)
                if cls.response_mode == "bad_reference":
                    answer['observations'][0]['references'] = ['invented-reference']
                if cls.response_mode == 'wrong_capture':
                    answer['capture_sha256'] = '0' * 64
                body = {
                    "id": "stub-response", "object": "chat.completion", "created": 1,
                    "model": "protocol-test-stub", "choices": [{"index": 0,
                        "finish_reason": "length" if cls.response_mode == "truncated" else "stop",
                        "message": {"role": "assistant", "content": json.dumps(answer)},
                    }], "usage": {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50},
                }
                status = 200
                if payload.get('thinking') == {'type': 'enabled'}:
                    body['choices'][0]['message']['reasoning_content'] = 'private-stub-reasoning-not-for-history'
                    body['usage']['completion_tokens_details'] = {'reasoning_tokens': 12}
                if cls.response_mode == "authentication":
                    status, body = 401, {"error": {"message": TEST_KEY, "type": "auth_error"}}
                if cls.response_mode == "rate_limit":
                    status, body = 429, {"error": {"message": "test limit"}}
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="packetpilot-agent-")
        self.folder = Path(self.temporary.name)
        make_samples(self.folder / "samples")
        self.evidence = analyse_capture(self.folder / "samples" / "port-check.pcap", "scapy")
        self.database = self.folder / "history.sqlite3"
        self.session = str(uuid.uuid4())
        self.config = APIConfig(f"http://127.0.0.1:{self.server.server_port}",
                                "deepseek-v4-flash", TEST_KEY, thinking="disabled",
                                retries=0, allow_loopback_http=True)
        type(self).received.clear()
        type(self).response_mode = "valid"

    def tearDown(self):
        self.temporary.cleanup()

    def client(self, session=None):
        return AgnoClient(self.config, self.database, session or self.session)

    def assert_key_not_persisted(self):
        for path in self.folder.glob("*.sqlite3*"):
            self.assertNotIn(TEST_KEY.encode(), path.read_bytes())

    def test_sdk_round_trip_uses_one_flash_call_without_tools(self):
        result = self.client().explain(self.evidence, "Why should I check this?")
        self.assertEqual(result["runtime"], "Agno")
        self.assertEqual(result["source"], "api")
        self.assertEqual(result["usage"]["total_tokens"], 50)
        self.assertEqual(len(self.received), 1)
        self.assertNotIn("tools", self.received[0])
        self.assertEqual(self.received[0]["thinking"], {"type": "disabled"})
        self.assert_key_not_persisted()

    def test_history_survives_a_new_agent_instance(self):
        self.client().explain(self.evidence, "My first question is about service ports.")
        result = self.client().explain(self.evidence, "Explain that term more simply.")
        messages = self.received[-1]["messages"]
        self.assertGreaterEqual(result["request_message_count"], 4)
        self.assertIn("My first question", json.dumps(messages))
        self.assertTrue(any(message["role"] == "assistant" for message in messages))
        self.assert_key_not_persisted()

    def test_max_reasoning_reaches_sdk_and_private_reasoning_is_not_stored(self):
        self.config = replace(self.config, thinking='enabled', reasoning_effort='max',
                              timeout=180, max_output_tokens=32768)
        result = self.client().explain(self.evidence, 'Inspect the evidence.')
        request = self.received[-1]
        self.assertEqual(request['thinking'], {'type': 'enabled'})
        self.assertEqual(request['reasoning_effort'], 'max')
        self.assertEqual(request['max_tokens'], 32768)
        self.assertNotIn('temperature', request)
        self.assertTrue(result['reasoning_present'])
        self.assertEqual(result['usage']['reasoning_tokens'], 12)
        self.assertEqual(result['settings']['reasoning_effort'], 'max')
        self.client().explain(self.evidence, 'Explain the last answer.')
        self.assertNotIn('private-stub-reasoning', json.dumps(self.received[-1]))
        for path in self.folder.glob('*.sqlite3*'):
            self.assertNotIn(b'private-stub-reasoning', path.read_bytes())
        self.assert_key_not_persisted()

    def test_reasoning_switch_does_not_import_nonreasoning_answers(self):
        self.client().explain(self.evidence, 'Old nonreasoning history marker.')
        self.config = replace(self.config, thinking='enabled', reasoning_effort='max')
        self.client().explain(self.evidence, 'Fresh reasoning assessment.')
        self.assertNotIn('Old nonreasoning history marker', json.dumps(self.received[-1]))

    def test_sessions_do_not_share_messages(self):
        self.client().explain(self.evidence, "Unique first-session question.")
        self.client(str(uuid.uuid4())).explain(self.evidence, "Independent review.")
        self.assertNotIn("Unique first-session", json.dumps(self.received[-1]))

    def test_invalid_responses_fail_and_are_not_reused_as_history(self):
        for mode in ("bad_reference", "wrong_capture", "truncated"):
            with self.subTest(mode=mode):
                type(self).response_mode = mode
                with self.assertRaises(LLMError) as caught:
                    self.client().explain(self.evidence, "This failed question must not become successful history.")
                self.assertEqual(caught.exception.code, "invalid_response")
        type(self).response_mode = "valid"
        self.client().explain(self.evidence, "Try this new question.")
        self.assertNotIn("failed question", json.dumps(self.received[-1]))

    def test_authentication_error_is_sanitised_without_retry(self):
        type(self).response_mode = "authentication"
        with self.assertRaises(LLMError) as caught:
            self.client().explain(self.evidence, "Why?")
        self.assertEqual(caught.exception.code, "authentication")
        self.assertEqual(len(self.received), 1)
        self.assertNotIn(TEST_KEY, str(caught.exception))
        self.assert_key_not_persisted()

    def test_rate_limit_is_not_automatically_retried(self):
        type(self).response_mode = "rate_limit"
        with self.assertRaises(LLMError):
            self.client().explain(self.evidence, "Why?")
        self.assertEqual(len(self.received), 1)

    def test_same_review_id_with_another_capture_cannot_read_history(self):
        self.client().explain(self.evidence, 'Capture-specific secret phrase.')
        other = analyse_capture(self.folder / 'samples/normal.pcap', 'scapy')
        self.client().explain(other, 'Independent capture.')
        self.assertNotIn('Capture-specific secret phrase', json.dumps(self.received[-1]))

    def test_history_window_is_bounded_but_saved(self):
        for i in range(5):
            self.client().explain(self.evidence, f'History marker {i}.')
        sent = json.dumps(self.received[-1])
        self.assertNotIn('History marker 0.', sent)
        self.assertIn('History marker 3.', sent)
        import sqlite3
        with sqlite3.connect(self.database) as db:
            stored = json.dumps(list(db.iterdump()))
        db.close()
        self.assertIn('History marker 0.', stored)

    def test_invalid_attempt_retains_actual_input_output_and_usage(self):
        type(self).response_mode = 'bad_reference'
        with self.assertRaises(LLMError) as caught:
            self.client().explain(self.evidence, 'Retain failed evidence.')
        record = caught.exception.record
        self.assertIn('invented-reference', record['raw_content'])
        self.assertEqual(record['usage']['total_tokens'], 50)
        self.assertEqual(record['request']['model'], self.config.model)
        self.assertNotIn(TEST_KEY, json.dumps(record))


if __name__ == "__main__":
    unittest.main()
