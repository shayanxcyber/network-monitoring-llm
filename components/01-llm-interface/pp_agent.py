"""Agno owns the instructions/history; this adapter checks the provider boundary.

Only structured lab evidence leaves the VM. No shell or network-action tools are
registered. A failed reply is excluded from Agno's normal conversation history.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

os.environ.setdefault("AGNO_TELEMETRY", "false")

import httpx
from agno.agent import Agent
from agno.db.sqlite import SqliteDb
from agno.exceptions import ModelProviderError
from agno.models.deepseek import DeepSeek
from openai import APIConnectionError, APIStatusError, OpenAI

from pp_llm import LLMError, MAX_QUESTION, clean_text, validate_explanation, build_request
from pp_context import MAX_REQUEST_BYTES, HISTORY_RUNS, encoded

PROMPT_VERSION = "packetpilot-conversation-2.1"
CONVERSATION_INSTRUCTIONS = """
This is a saved conversation about one capture. Use previous questions and
answers to understand follow-up questions, but do not treat previous claims as
new packet evidence. The current evidence JSON is authoritative. Explain
unfamiliar terms when asked, distinguish observation from interpretation, and
state when the capture cannot answer a question. Keep the required JSON format.
"""


@dataclass
class CheckedDeepSeek(DeepSeek):
    """Use Agno's native provider, sanitising errors before storage/logging."""

    evidence: dict = field(default_factory=dict, repr=False)
    context: dict = field(default_factory=dict, repr=False)
    answer: dict | None = field(default=None, init=False, repr=False)
    request_sha256: str = field(default="", init=False)
    request_messages: int = field(default=0, init=False)
    returned_model: str = field(default="", init=False)
    usage: dict = field(default_factory=dict, init=False)
    error_code: str = field(default="", init=False)
    request_payload: dict = field(default_factory=dict, init=False, repr=False)
    raw_content: str = field(default='', init=False, repr=False)
    finish_reason: str = field(default='', init=False)
    reasoning_present: bool = field(default=False, init=False)

    def _reject(self, code, message, status=None):
        self.error_code = code
        raise ModelProviderError(message=message, status_code=status,
                                 model_name=self.name, model_id=self.id) from None

    def invoke(self, messages, assistant_message, response_format=None, tools=None,
               tool_choice=None, run_response=None, compress_tool_results=False):
        if tools:
            self._reject("tools_disabled", "Model tools are not enabled in this prototype.")
        formatted = self._format_all_messages(messages, compress_tool_results)
        params = self.get_request_params(response_format={"type": "json_object"})
        payload = {"model": self.id, "messages": formatted, **params}
        if len(encoded(payload)) > MAX_REQUEST_BYTES:
            self._reject('context_limit', 'Request exceeds the bounded context limit; start a new review or use a smaller capture.')
        self.request_payload = payload
        self.request_sha256 = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        self.request_messages = len(formatted)
        assistant_message.metrics.start_timer()
        try:
            response = self.get_client().chat.completions.create(**payload)
        except APIStatusError as exc:
            # Never persist or print the provider's error body or request headers.
            status = exc.status_code
            code = "authentication" if status in {401, 403} else "http_error"
            self._reject(code, f"Provider returned HTTP {status}; no error body was recorded.", status)
        except APIConnectionError:
            self._reject("connection", "Provider connection failed or timed out. No automatic retry was made.")
        except Exception:
            self._reject("provider_error", "The provider request could not be completed.")
        finally:
            assistant_message.metrics.stop_timer()
        try:
            if getattr(response, "error", None) or len(response.choices) != 1:
                raise ValueError("Expected one completed response.")
            choice = response.choices[0]
            self.reasoning_present = bool(getattr(choice.message, 'reasoning_content', None))
            # This no-tool application needs final answers as history, not private reasoning.
            if self.reasoning_present:
                choice.message.reasoning_content = None
            self.raw_content = (choice.message.content or '')[:32_000].replace(self.api_key, '[redacted]')
            self.finish_reason = choice.finish_reason or ''
            self.returned_model = clean_text(response.model or self.id, 120)
            if response.usage:
                for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                    value = getattr(response.usage, key, None)
                    if type(value) is int and value >= 0:
                        self.usage[key] = value
                detail = getattr(response.usage, 'completion_tokens_details', None)
                value = getattr(detail, 'reasoning_tokens', None)
                if type(value) is int and value >= 0:
                    self.usage['reasoning_tokens'] = value
            if (choice.finish_reason != "stop" or choice.message.role != "assistant"
                    or choice.message.tool_calls or choice.message.refusal):
                raise ValueError("Incomplete or unsupported response.")
            self.answer = validate_explanation(choice.message.content, self.evidence, self.context)
        except (ValueError, TypeError, AttributeError, KeyError):
            self._reject("invalid_response", "The reply failed the completion, JSON or evidence-reference checks.")
        # Only a checked response enters Agno's successful session history.
        return self._parse_provider_response(response)


class LegacyAgnoClient:
    def __init__(self, config, database: Path, session_id: str):
        self.config = config
        self.endpoint = config.endpoint()
        self.database = Path(database)
        self.session_id = session_id

    def explain(self, evidence, question):
        question = clean_text(question, MAX_QUESTION)
        prepared, context_meta = build_request(evidence, question, self.config)
        system = prepared['messages'][0]['content'] + CONVERSATION_INSTRUCTIONS
        prompt_hash = hashlib.sha256(system.encode()).hexdigest()
        input_text = prepared['messages'][1]['content']
        modern = evidence.get('schema_version') == '2'
        scoped_session = (f'{self.session_id}:assessment-2.1:{evidence["capture"]["sha256"]}'
                          if modern else self.session_id)
        if self.config.thinking == 'enabled':
            scoped_session += f':thinking:{self.config.reasoning_effort or "provider-default"}'
        self.database.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        # Do not silently follow redirects with a credential or use ambient proxies.
        with httpx.Client(follow_redirects=False, trust_env=False,
                          timeout=self.config.timeout) as transport:
            with OpenAI(api_key=self.config.api_key,
                        base_url=self.endpoint.removesuffix("/chat/completions"),
                        timeout=self.config.timeout, max_retries=0,
                        http_client=transport) as provider:
                model = CheckedDeepSeek(
                    id=self.config.model, api_key=self.config.api_key,
                    base_url=self.config.base_url, client=provider,
                    max_tokens=prepared.get('max_tokens'), temperature=prepared.get('temperature'), max_retries=0, retries=0,
                    reasoning_effort=self.config.reasoning_effort or None,
                    use_thinking=self.config.thinking == "enabled", evidence=evidence, context=json.loads(input_text),
                )
                database = SqliteDb(db_file=str(self.database))
                agent = Agent(
                    id="packetpilot-traffic-review", name="PacketPilot",
                    model=model, db=database,
                    session_id=scoped_session, user_id="local-operator",
                    system_message=system, add_history_to_context=True,
                    num_history_runs=HISTORY_RUNS, num_history_messages=None,
                    store_history_messages=False, tools=[],
                    retries=0, telemetry=False, debug_mode=False,
                )
                try:
                    output = agent.run(input_text, metadata={
                        "capture_sha256": evidence["capture"]["sha256"],
                        "prompt_version": PROMPT_VERSION, "prompt_sha256": prompt_hash,
                    })
                except Exception:
                    output = None
                finally:
                    database.db_engine.dispose()
        record = {
            **context_meta, 'request': model.request_payload, 'raw_content': model.raw_content,
            'finish_reason': model.finish_reason, 'requested_model': self.config.model,
            'model': model.returned_model, 'usage': model.usage,
            'reasoning_present': model.reasoning_present,
            'prompt_version': PROMPT_VERSION if modern else 'packetpilot-conversation-v1',
            'prompt_sha256': prompt_hash, 'request_sha256': model.request_sha256,
            'elapsed_seconds': round(time.perf_counter() - started, 4), 'attempts': 1,
            'settings': {'thinking': self.config.thinking, 'reasoning_effort': self.config.reasoning_effort,
                         'max_tokens': prepared.get('max_tokens'), 'temperature': prepared.get('temperature'),
                         'timeout_seconds': self.config.timeout, 'automatic_retries': 0},
        }
        if model.error_code or model.answer is None or output is None or str(output.status.value) != "COMPLETED":
            raise LLMError(model.error_code or "agent_error",
                           'The AI service did not return a usable answer. Any fallback is explicitly labelled.', record)
        return {
            "source": "api", "status": "validated_structure_and_references",
            "model": model.returned_model, "provider": urlsplit(self.endpoint).hostname,
            "runtime": "Agno", "agent_run_id": output.run_id,
            "session_id": self.session_id, 'agent_session_id': scoped_session,
            **record,
            "request_message_count": model.request_messages,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
            'answer': model.answer,
            'review_note': 'Structure, capture-scoped references, copied measurements and preview scope were checked. Interpretations still need semantic review; a valid response is not proof of detection accuracy.',
        }


class AgnoClient:
    """New v2-evidence investigations use tools; v1 saved evidence stays legacy."""
    def __init__(self, config, database, session_id, workspace_upgrade=True):
        self.config, self.database, self.session_id = config, database, session_id
        self.workspace_upgrade, self.response_scope = workspace_upgrade, None
        self.event_callback = None
        config.endpoint()

    def configure_workspace(self, scope):
        self.response_scope = scope

    def configure_events(self, callback):
        self.event_callback = callback

    def explain(self, evidence, question):
        if evidence.get('schema_version') == '2':
            from pp_investigator import InvestigatorClient
            return InvestigatorClient(self.config, self.database, self.session_id, self.workspace_upgrade, self.response_scope, self.event_callback).explain(evidence, question)
        return LegacyAgnoClient(self.config, self.database, self.session_id).explain(evidence, question)
