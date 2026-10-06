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

PROMPT_VERSION = "packetpilot-assessment-2.1"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REASONING_RESPONSE_BYTES = 1024 * 1024
MAX_QUESTION = 600
SYSTEM_PROMPT = Path(__file__).with_name("prompts") / "system.txt"


class LLMError(Exception):
    def __init__(self, code, message, record=None):
        super().__init__(message)
        self.code = code
        self.record = record or {}


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
    reasoning_effort: str = ""
    max_output_tokens: int | None = None

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
                or not math.isfinite(self.timeout) or not 1 <= self.timeout <= 300
                or type(self.retries) is not int or not 0 <= self.retries <= 2
                or self.thinking not in {"", "disabled", "enabled"}):
            raise LLMError("configuration", "Invalid timeout, retry or thinking setting.")
        if (self.reasoning_effort not in {"", "low", "high", "max"}
                or (self.reasoning_effort and self.thinking != "enabled")
                or (self.max_output_tokens is not None and
                    (type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= 131072))):
            raise LLMError("configuration", "Invalid reasoning effort or output token budget.")
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
            token_value = os.environ.get("PACKETPILOT_MAX_OUTPUT_TOKENS", "")
            max_tokens = int(token_value) if token_value else None
        except ValueError as exc:
            raise LLMError("configuration", "API timeout and token budget must be numeric.") from exc
        return cls(
            base_url=os.environ.get("PACKETPILOT_API_BASE_URL", "https://api.deepseek.com"),
            model=os.environ.get("PACKETPILOT_MODEL", ""),
            api_key=key_override if key_override is not None else os.environ.get("PACKETPILOT_API_KEY", ""),
            timeout=timeout, thinking=os.environ.get("PACKETPILOT_THINKING", ""),
            reasoning_effort=os.environ.get("PACKETPILOT_REASONING_EFFORT", ""),
            max_output_tokens=max_tokens,
        )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        # Never forward the Authorization header to a redirect destination.
        return None


def build_request(evidence, question, config):
    question = clean_text(question, MAX_QUESTION)
    from pp_context import build_context, context_metadata, MAX_OUTPUT_TOKENS
    from pp_assessment import SCHEMA_VERSION, SCHEMA_SHA256
    modern = evidence.get('schema_version') == '2'
    context = build_context(evidence, question) if modern else {
        'question': question, 'finding': evidence['finding'], 'facts': evidence['facts'], 'limitations': evidence['limitations']}
    system = (SYSTEM_PROMPT if modern else SYSTEM_PROMPT.with_name('system-v1.txt')).read_text(encoding='utf-8')
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False, allow_nan=False)},
        ],
        "response_format": {"type": "json_object"},
        "stream": False,
        "max_tokens": config.max_output_tokens or (32768 if config.thinking == "enabled" else MAX_OUTPUT_TOKENS if modern else 900),
    }
    if config.thinking != "enabled":
        payload["temperature"] = 0
    if config.reasoning_effort:
        payload["reasoning_effort"] = config.reasoning_effort
    if config.thinking:
        payload["thinking"] = {"type": config.thinking}
    return payload, {
        "prompt_version": PROMPT_VERSION if modern else 'packetpilot-explain-v1',
        **(context_metadata(context) if modern else {'context_version': 'legacy-v1'}),
        **({'schema_revision': SCHEMA_VERSION, 'schema_sha256': SCHEMA_SHA256} if modern else {}),
        "prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
        "request_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
    }


def validate_explanation(content, evidence, context=None):
    if not isinstance(content, str) or len(content.encode("utf-8")) > 32_000:
        raise ValueError("Explanation content is absent or too large.")
    value = strict_json(content)
    if evidence.get('schema_version') == '2':
        from pp_assessment import validate_assessment
        return validate_assessment(value, evidence, context)
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
        response_limit = MAX_REASONING_RESPONSE_BYTES if self.config.thinking == "enabled" else MAX_RESPONSE_BYTES
        record = {**metadata, 'request': payload, 'raw_content': '', 'usage': {},
                  'requested_model': self.config.model, 'model': None, 'finish_reason': '',
                  'http_attempts': []}
        def fail(code, message):
            record['elapsed_seconds'] = round(time.perf_counter() - started, 4)
            record['attempts'] = len(record['http_attempts'])
            raise LLMError(code, message, record)
        for attempt in range(self.config.retries + 1):
            trace = {'attempt': attempt + 1, 'outcome': 'started'}
            record['http_attempts'].append(trace)
            request = Request(self.endpoint, data=raw, method="POST", headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.config.api_key,
            })
            try:
                with self.opener.open(request, timeout=self.config.timeout) as response:
                    body = response.read(response_limit + 1)
                trace['outcome'] = 'response_received'
                break
            except HTTPError as exc:
                status = exc.code
                exc.close()
                trace.update(outcome='http_error', status=status)
                if status in {429, 503} and attempt < self.config.retries:
                    self.sleep(.3 * (attempt + 1))
                    continue
                code = "authentication" if status in {401, 403} else "http_error"
                fail(code, f"API request failed with HTTP {status}; no response body was logged.")
            except (URLError, TimeoutError, OSError):
                # Do not retry ambiguous timeouts: the provider might already have processed the call.
                trace['outcome'] = 'connection_failed'
                fail("connection", "API connection failed or timed out; check the guest connection.")
        if len(body) > response_limit:
            fail("invalid_response", "API response exceeded the size limit.")
        try:
            outer = strict_json(body.decode("utf-8"))
            if not isinstance(outer, dict) or not isinstance(outer.get("choices"), list) or len(outer["choices"]) != 1:
                raise ValueError("Expected one completion choice.")
            choice = outer["choices"][0]
            content = choice['message'].get('content')
            record['raw_content'] = (content[:32_000] if isinstance(content, str) else '').replace(self.config.api_key, '[redacted]')
            record['raw_content_truncated'] = isinstance(content, str) and len(content) > 32_000
            record['finish_reason'] = choice.get('finish_reason')
            record['reasoning_present'] = bool(choice['message'].get('reasoning_content'))
            returned_model = clean_text(outer.get('model', self.config.model), 120)
            record['model'] = returned_model
            usage = {}
            for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                value = (outer.get('usage') or {}).get(key)
                if type(value) is int and value >= 0:
                    usage[key] = value
            record['usage'] = usage
            detail = (outer.get('usage') or {}).get('completion_tokens_details') or {}
            value = detail.get('reasoning_tokens')
            if type(value) is int and value >= 0:
                usage['reasoning_tokens'] = value
            if choice["finish_reason"] != "stop" or choice["message"].get("tool_calls") or choice['message'].get('refusal'):
                raise ValueError("Incomplete, filtered or tool-call response.")
            if choice["message"].get("role") != "assistant":
                raise ValueError("Unexpected message role.")
            explanation = validate_explanation(choice["message"]["content"], evidence, json.loads(payload['messages'][-1]['content']))
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
            fail("invalid_response", "The model response failed the output/evidence checks.")
        return {
            "source": "api", "status": "validated_structure_and_references",
            "model": returned_model, "provider": urlsplit(self.endpoint).hostname,
            "attempts": attempt + 1, "usage": usage,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
            **record, "answer": explanation,
            "review_note": "Structure and references were checked; the operator must still review the explanation.",
        }


def baseline_explanation(evidence, question):
    clean_text(question, MAX_QUESTION)
    finding = evidence["finding"]
    if evidence.get('input_kind') == 'network_log':
        summary = 'The saved field log has usable observations, but no model was called and no detection rule was applied.'
        next_step = 'Inspect log rows and coverage, or choose AI investigation. Raw packet bytes and unexported fields are not available in this log.'
    elif finding == "scan_like":
        summary = "This traffic needs checking: one computer tried several ports on the server."
        next_step = "Check whether this was an authorised test. Review the source before considering a temporary block."
    elif finding == "no_scan_pattern":
        summary = "This capture did not trigger the port-check rule. That is not proof that all traffic is safe."
        next_step = "Keep the result for comparison; investigate other concerns using more evidence."
    else:
        summary = "The legacy TCP-only rule cannot give a complete finding for this input; other usable evidence may still be present."
        next_step = "Review the rich packet records and coverage, or use AI investigation. This legacy rule does not analyse UDP."
    return {
        "source": "rules", "status": "no_model_called", "model": None,
        "answer": {
            "finding": finding, "summary": summary,
            "why": evidence["facts"][-1]["text"], "next_step": next_step,
            "fact_ids": [fact["id"] for fact in evidence["facts"]],
        },
        "review_note": "Fixed rule-based explanation; arbitrary questions are not interpreted by an LLM in this mode.",
    }
