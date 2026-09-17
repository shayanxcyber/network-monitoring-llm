"""Local web/storage checks with synthetic captures and no external model calls."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_llm import APIConfig, LLMError, baseline_explanation
from pp_web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="packetpilot-web-")
        self.root = Path(self.temporary.name)
        (self.root / "web").mkdir()
        shutil.copy2(ROOT / "web" / "index.html", self.root / "web" / "index.html")
        self.config = APIConfig("https://api.example.test", "test-model", "")
        self.factory = Mock()
        self.application = self.make_app()
        self.client = TestClient(self.application)
        self.token = self.client.get("/api/config").json()["csrf"]

    def make_app(self):
        return create_app(self.root, config_loader=lambda: self.config,
                          client_factory=self.factory, test_mode=True)

    def tearDown(self):
        self.client.close()
        self.temporary.cleanup()

    def post(self, path, **kwargs):
        headers = {"X-PacketPilot-Token": self.token, **kwargs.pop("headers", {})}
        return self.client.post(path, headers=headers, **kwargs)

    def new(self, sample="port-check", provider="rules"):
        response = self.post("/api/reviews", json={"sample": sample, "provider": provider})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def ask(self, review, question="What does this show?", request_id=None):
        return self.post(f'/api/reviews/{review["id"]}/questions', json={
            "question": question, "request_id": request_id or str(uuid.uuid4()),
        })

    def test_page_and_configuration_do_not_expose_a_key(self):
        self.config = APIConfig("https://api.example.test", "test-model", "private-test-value")
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertNotIn("private-test-value", self.client.get("/api/config").text)
        self.assertEqual(self.client.get("/api/config").json()["application"], "PacketPilot")
        self.assertEqual(self.client.get("/docs").status_code, 404)

    def test_operator_copy_is_provider_neutral_without_changing_configuration(self):
        self.assertNotIn("deepseek", self.client.get("/").text.lower())
        self.assertNotIn("deepseek", (ROOT / "web" / "app.js").read_text(encoding="utf-8").lower())
        self.config = APIConfig("https://api.example.test", "actual-configured-model", "test-value")
        self.assertEqual(self.client.get("/api/config").json()["model"], "actual-configured-model")

    def test_missing_csrf_token_is_rejected(self):
        response = self.client.post("/api/reviews", json={"sample": "normal"})
        self.assertEqual(response.status_code, 403)

    def test_cross_origin_post_is_rejected(self):
        response = self.post("/api/reviews", headers={"Origin": "https://other.example"}, json={"sample": "normal"})
        self.assertEqual(response.status_code, 403)

    def test_untrusted_host_is_rejected(self):
        self.assertEqual(self.client.get("/api/reviews", headers={"Host": "other.example"}).status_code, 400)

    def test_oversized_request_is_rejected_before_parsing(self):
        response = self.post("/api/reviews", headers={"Content-Length": "99999999"}, content=b"{}")
        self.assertEqual(response.status_code, 413)

    def test_both_sample_findings_are_available_without_a_model(self):
        self.assertEqual(self.new()["evidence"]["finding"], "scan_like")
        self.assertEqual(self.new("normal")["evidence"]["finding"], "no_scan_pattern")
        self.factory.assert_not_called()

    def test_rules_reply_is_saved_once_for_repeated_request_id(self):
        review, request_id = self.new(), str(uuid.uuid4())
        first = self.ask(review, request_id=request_id)
        second = self.ask(review, request_id=request_id)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["run_id"], second.json()["run_id"])
        self.assertEqual(first.json()["explanation"]["source"], "rules")
        saved = self.client.get(f'/api/reviews/{review["id"]}').json()
        self.assertEqual(len(saved["turns"]), 1)
        self.assertFalse(saved["turns"][0]["response"]["executed"])
        self.factory.assert_not_called()

    def test_review_and_questions_survive_application_recreation(self):
        review = self.new()
        self.ask(review, "A question to keep.")
        with TestClient(self.make_app()) as restarted:
            saved = restarted.get(f'/api/reviews/{review["id"]}').json()
            self.assertEqual(saved["turns"][0]["question"], "A question to keep.")
            self.assertEqual(saved["evidence"], review["evidence"])

    def test_api_review_requires_a_key_and_does_not_auto_call(self):
        response = self.post("/api/reviews", json={"sample": "normal", "provider": "api"})
        self.assertEqual(response.status_code, 400)
        self.config = APIConfig("https://api.example.test", "test-model", "test-value")
        self.new(provider="api")
        self.factory.assert_not_called()

    def test_api_failure_is_explicit_and_preserved(self):
        self.config = APIConfig("https://api.example.test", "test-model", "test-value")
        self.factory.return_value.explain.side_effect = LLMError("connection", "Controlled connection failure.")
        response = self.ask(self.new(provider="api"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["explanation"]["status"], "fallback_after_api_failure")
        self.assertFalse(response.json()["response"]["executed"])

    def test_api_adapter_is_used_for_each_followup_in_same_session(self):
        self.config = APIConfig("https://api.example.test", "test-model", "test-value")
        def explain(evidence, question):
            value = baseline_explanation(evidence, question)
            return value | {"source": "api", "model": "protocol-stub", "prompt_sha256": "test-prompt"}
        self.factory.return_value.explain.side_effect = explain
        review = self.new(provider="api")
        self.assertEqual(self.ask(review).status_code, 200)
        self.assertEqual(self.ask(review, "Explain the previous answer.").status_code, 200)
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(self.factory.call_args.args[1], review["id"])

    def test_uploaded_capture_uses_generated_storage_path(self):
        source = (self.root / "sample-data" / "port-check.pcap").read_bytes()
        response = self.post("/api/reviews/upload", files={"file": ("../../custom.pcap", source)}, data={"provider": "rules"})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["title"], "custom.pcap")
        stored = self.application.state.store.get(response.json()["id"])
        self.assertEqual(Path(stored["capture"]).parent, self.root / "runtime" / "captures")

    def test_invalid_upload_is_not_accepted(self):
        response = self.post("/api/reviews/upload", files={"file": ("bad.pcap", b"not a capture")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/reviews").json(), [])

    def test_preview_is_bounded_and_never_executes(self):
        review = self.new()
        response = self.post(f'/api/reviews/{review["id"]}/preview', json={"action": "block_source"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed_preview"])
        self.assertFalse(response.json()["executed"])
        self.assertEqual(response.json()["duration_seconds"], 60)
        self.assertEqual(len(self.client.get(f'/api/reviews/{review["id"]}').json()["previews"]), 1)
        rejected = self.post(f'/api/reviews/{review["id"]}/preview', json={"action": "block_source", "apply": True})
        self.assertEqual(rejected.status_code, 422)

    def test_changed_capture_requires_new_review(self):
        review = self.new()
        shutil.copy2(self.root / "sample-data" / "normal.pcap", self.root / "sample-data" / "port-check.pcap")
        self.assertEqual(self.ask(review).status_code, 400)

    def test_export_keeps_evidence_questions_and_results_together(self):
        review = self.new()
        self.ask(review)
        response = self.client.get(f'/api/reviews/{review["id"]}/export')
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["content-disposition"])
        self.assertEqual(len(response.json()["turns"]), 1)
        self.assertEqual(response.json()["evidence"]["capture"]["sha256"], review["evidence"]["capture"]["sha256"])


if __name__ == "__main__":
    unittest.main()
