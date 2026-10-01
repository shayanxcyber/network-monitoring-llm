"""One configurable chat-completions connection; never a shell/tool executor."""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROMPT_VERSION = "packetpilot-explain-v1"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_QUESTION = 600
SYSTEM_PROMPT = Path(__file__).with_name("prompts") / "system.txt"


class LLMError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def clean_text(value, maximum):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum:
        raise ValueError("Text is empty, not a string or exceeds the allowed length.")
    if any(unicodedata.category(char).startswith("C") and char not in "\n\t" for char in value):
        raise ValueError("Control or invisible formatting characters are not accepted.")
    return value.strip()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field.")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("Non-finite JSON number.")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


@dataclass(frozen=True)
class APIConfig:
    base_url: str
    model: str
    api_key: str = field(repr=False)
    timeout: float = 25
    thinking: str = ""
    retries: int = 1
    allow_loopback_http: bool = False

    def endpoint(self):
        try:
            parts = urlsplit(self.base_url)
            port = parts.port
        except ValueError as exc:
            raise LLMError("configuration", "The API URL is invalid.") from exc
        local_http = (
            self.allow_loopback_http and parts.scheme == "http"
            and parts.hostname in {"127.0.0.1", "::1", "localhost"}
        )
        if (not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
                or (parts.scheme != "https" and not local_http)
                or any(char.isspace() for char in self.base_url)):
            raise LLMError("configuration", "Use an HTTPS API base URL without credentials or query parameters.")
        if port is not None and not 1 <= port <= 65535:
            raise LLMError("configuration", "The API port is invalid.")
        try:
            clean_text(self.model, 120)
            clean_text(self.api_key, 4096)
        except ValueError as exc:
            raise LLMError("configuration", "Set a model ID and API key before choosing API mode.") from exc
        if (type(self.timeout) not in {int, float}
                or not math.isfinite(self.timeout) or not 1 <= self.timeout <= 60
                or type(self.retries) is not int or not 0 <= self.retries <= 2
                or self.thinking not in {"", "disabled", "enabled"}):
            raise LLMError("configuration", "Invalid timeout, retry or thinking setting.")
        if not self.api_key.isascii() or any(char.isspace() for char in self.api_key):
            raise LLMError("configuration", "API key contains invalid characters.")
        path = parts.path.rstrip("/")
        if not path.endswith("/chat/completions"):
            path += "/chat/completions"
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))

    @classmethod
    def from_environment(cls, key_override=None):
        try:
            timeout = float(os.environ.get("PACKETPILOT_API_TIMEOUT", "25"))
        except ValueError as exc:
            raise LLMError("configuration", "API timeout must be a number.") from exc
        return cls(
            base_url=os.environ.get("PACKETPILOT_API_BASE_URL", "https://api.deepseek.com"),
            model=os.environ.get("PACKETPILOT_MODEL", ""),
            api_key=key_override if key_override is not None else os.environ.get("PACKETPILOT_API_KEY", ""),
            timeout=timeout, thinking=os.environ.get("PACKETPILOT_THINKING", ""),
        )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        # Never forward the Authorization header to a redirect destination.
        return None


def build_request(evidence, question, config):
    question = clean_text(question, MAX_QUESTION)
    system = SYSTEM_PROMPT.read_text(encoding="utf-8")
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps({
                "question": question, "finding": evidence["finding"],
                "facts": evidence["facts"], "limitations": evidence["limitations"],
            }, ensure_ascii=False, allow_nan=False)},
        ],
        "response_format": {"type": "json_object"},
        "stream": False, "max_tokens": 900,
    }
    if config.thinking:
        payload["thinking"] = {"type": config.thinking}
    return payload, {
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
        "request_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
    }


def validate_explanation(content, evidence):
    if not isinstance(content, str) or len(content.encode("utf-8")) > 12_000:
        raise ValueError("Explanation content is absent or too large.")
    value = strict_json(content)
    required = {"finding", "summary", "why", "next_step", "fact_ids"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Explanation has missing or extra fields.")
    if value["finding"] != evidence["finding"]:
        raise ValueError("Model finding conflicts with the packet evidence rule.")
    for key, maximum in (("summary", 900), ("why", 900), ("next_step", 400)):
        value[key] = clean_text(value[key], maximum)
    refs = value["fact_ids"]
    known = {fact["id"] for fact in evidence["facts"]}
    if (not isinstance(refs, list) or not 1 <= len(refs) <= len(known)
            or any(not isinstance(ref, str) for ref in refs)
            or len(set(refs)) != len(refs) or not set(refs) <= known):
        raise ValueError("Explanation contains absent, repeated or unknown evidence references.")
    # These checks cannot establish the semantic truth of every natural-language sentence.
    return value


class ChatClient:
    def __init__(self, config, opener=None, sleep=time.sleep):
        self.config = config
        self.endpoint = config.endpoint()
        self.opener = opener or build_opener(NoRedirect())
        self.sleep = sleep

    def explain(self, evidence, question):
        payload, metadata = build_request(evidence, question, self.config)
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        started = time.perf_counter()
        for attempt in range(self.config.retries + 1):
            request = Request(self.endpoint, data=raw, method="POST", headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.config.api_key,
            })
            try:
                with self.opener.open(request, timeout=self.config.timeout) as response:
                    body = response.read(MAX_RESPONSE_BYTES + 1)
                break
            except HTTPError as exc:
                status = exc.code
                exc.close()
                if status in {429, 503} and attempt < self.config.retries:
                    self.sleep(.3 * (attempt + 1))
                    continue
                code = "authentication" if status in {401, 403} else "http_error"
                raise LLMError(code, f"API request failed with HTTP {status}; no response body was logged.") from None
            except (URLError, TimeoutError, OSError):
                # Do not retry ambiguous timeouts: the provider might already have processed the call.
                raise LLMError("connection", "API connection failed or timed out; check the guest connection.") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise LLMError("invalid_response", "API response exceeded the size limit.")
        try:
            outer = strict_json(body.decode("utf-8"))
            if not isinstance(outer, dict) or not isinstance(outer.get("choices"), list) or len(outer["choices"]) != 1:
                raise ValueError("Expected one completion choice.")
            choice = outer["choices"][0]
            if choice["finish_reason"] != "stop" or choice["message"].get("tool_calls"):
                raise ValueError("Incomplete, filtered or tool-call response.")
            if choice["message"].get("role") != "assistant":
                raise ValueError("Unexpected message role.")
            explanation = validate_explanation(choice["message"]["content"], evidence)
            returned_model = clean_text(outer.get("model", self.config.model), 120)
            usage = {}
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                value = (outer.get("usage") or {}).get(key)
                if type(value) is int and value >= 0:
                    usage[key] = value
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
            raise LLMError("invalid_response", "The model response failed the output/evidence checks.") from None
        return {
            "source": "api", "status": "validated_structure_and_references",
            "model": returned_model, "provider": urlsplit(self.endpoint).hostname,
            "attempts": attempt + 1, "usage": usage,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
            **metadata, "answer": explanation,
            "review_note": "Structure and references were checked; the operator must still review the explanation.",
        }


def baseline_explanation(evidence, question):
    clean_text(question, MAX_QUESTION)
    finding = evidence["finding"]
    if finding == "scan_like":
        summary = "This traffic needs checking: one computer tried several ports on the server."
        next_step = "Check whether this was an authorised test. Review the source before considering a temporary block."
    elif finding == "no_scan_pattern":
        summary = "This capture did not trigger the port-check rule. That is not proof that all traffic is safe."
        next_step = "Keep the result for comparison; investigate other concerns using more evidence."
    else:
        summary = "There is not enough supported traffic to give a complete answer."
        next_step = "Use a complete lab IPv4/TCP capture and check the skipped or missing traffic."
    return {
        "source": "rules", "status": "no_model_called", "model": None,
        "answer": {
            "finding": finding, "summary": summary,
            "why": evidence["facts"][-1]["text"], "next_step": next_step,
            "fact_ids": [fact["id"] for fact in evidence["facts"]],
        },
        "review_note": "Fixed rule-based explanation; arbitrary questions are not interpreted by an LLM in this mode.",
    }
