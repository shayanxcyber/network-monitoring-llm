"""Connect ingestion, explanation, safe previews and per-run traceable records."""
from __future__ import annotations

import json
import platform
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pp_evidence import analyse_capture, evidence_digest
from pp_logs import analyse_input
from pp_llm import APIConfig, ChatClient, LLMError, baseline_explanation, clean_text, MAX_QUESTION
from pp_policy import preview_response


def now():
    return datetime.now(timezone.utc).isoformat()


class RunStore:
    def __init__(self, output: Path):
        self.run_id = str(uuid.uuid4())
        self.directory = output.resolve() / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)

    def write(self, name, value):
        with (self.directory / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")

    def event(self, stage, **fields):
        value = {"run_id": self.run_id, "recorded_at": now(), "stage": stage, **fields}
        with (self.directory / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")


def run_analysis(capture: Path, output: Path, question, provider="rules", decoder="auto",
                 preview="investigate", target=None, duration=60, apply=False,
                 client=None, cached_evidence=None, selected_reference=None):
    question = clean_text(question, MAX_QUESTION)
    if provider not in {"rules", "api"}:
        raise ValueError("Unknown explanation provider.")
    store = RunStore(output)
    started = time.perf_counter()
    store.event("started", provider=provider, decoder=decoder, question=question)
    try:
        evidence = cached_evidence if cached_evidence is not None else analyse_input(capture, decoder)
        digest = evidence_digest(evidence)
        store.write("evidence.json", evidence)
        store.event("evidence_ready", evidence_sha256=digest,
                    capture_sha256=evidence["capture"]["sha256"], finding=evidence["finding"])
        if provider == "api":
            try:
                connection = client or ChatClient(APIConfig.from_environment())
                explanation = connection.explain(evidence, question)
                store.event("api_response_validated", model=explanation["model"],
                            prompt_sha256=explanation["prompt_sha256"])
            except LLMError as exc:
                explanation = baseline_explanation(evidence, question)
                explanation["status"] = "fallback_after_api_failure"
                explanation["api_error"] = {"code": exc.code, "message": str(exc)}
                explanation['failed_attempt'] = exc.record
                store.event("api_failed", error_code=exc.code)
        else:
            explanation = baseline_explanation(evidence, question)
            store.event("rules_explanation_ready", model_called=False)
        response = preview_response(evidence, preview, target, duration, apply)
        store.event("response_preview", **response)
        result = {
            "format_version": "2" if evidence.get('schema_version') == '2' else '1', "run_id": store.run_id, "recorded_at": now(),
            "execution_environment": {"os": platform.system(), "python": platform.python_version()},
            "question": question, "capture_sha256": evidence["capture"]["sha256"],
            "evidence_sha256": digest, "finding": evidence["finding"],
            'finding_scope': ('Compatibility placeholder; no rule verdict applied to log input.' if evidence.get('input_kind') == 'network_log'
                              else 'Legacy TCP comparator only; not the model assessment.'),
            "explanation": explanation, "response": response,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
            "limitations": evidence["limitations"],
        }
        if selected_reference:
            result['selected_reference'] = selected_reference
        store.write("result.json", result)
        store.event("finished", result_file="result.json", executed=False)
        return result, evidence, store.directory
    except Exception:
        # Do not serialize arbitrary decoder/HTTP exceptions: they may contain sensitive data.
        store.event("failed", error_code="analysis_stopped", executed=False)
        raise
