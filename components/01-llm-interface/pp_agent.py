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

from pp_llm import LLMError, MAX_QUESTION, SYSTEM_PROMPT, clean_text, validate_explanation

PROMPT_VERSION = "packetpilot-conversation-v1"
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
    answer: dict | None = field(default=None, init=False, repr=False)
    request_sha256: str = field(default="", init=False)
    request_messages: int = field(default=0, init=False)
    returned_model: str = field(default="", init=False)
    usage: dict = field(default_factory=dict, init=False)
    error_code: str = field(default="", init=False)

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
            if (choice.finish_reason != "stop" or choice.message.role != "assistant"
                    or choice.message.tool_calls or choice.message.refusal):
                raise ValueError("Incomplete or unsupported response.")
            self.answer = validate_explanation(choice.message.content, self.evidence)
            self.returned_model = clean_text(response.model or self.id, 120)
            if response.usage:
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    value = getattr(response.usage, key, None)
                    if type(value) is int and value >= 0:
                        self.usage[key] = value
        except (ValueError, TypeError, AttributeError, KeyError):
            self._reject("invalid_response", "The reply failed the completion, JSON or evidence-reference checks.")
        # Only a checked response enters Agno's successful session history.
        return self._parse_provider_response(response)


class AgnoClient:
    def __init__(self, config, database: Path, session_id: str):
        self.config = config
        self.endpoint = config.endpoint()
        self.database = Path(database)
        self.session_id = session_id

    def explain(self, evidence, question):
        question = clean_text(question, MAX_QUESTION)
        system = SYSTEM_PROMPT.read_text(encoding="utf-8") + CONVERSATION_INSTRUCTIONS
        prompt_hash = hashlib.sha256(system.encode()).hexdigest()
        input_text = json.dumps({
            "question": question, "finding": evidence["finding"],
            "facts": evidence["facts"], "limitations": evidence["limitations"],
        }, ensure_ascii=False, allow_nan=False)
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
                    max_tokens=900, max_retries=0, retries=0,
                    use_thinking=self.config.thinking == "enabled", evidence=evidence,
                )
                database = SqliteDb(db_file=str(self.database))
                agent = Agent(
                    id="packetpilot-traffic-review", name="PacketPilot",
                    model=model, db=database,
                    session_id=self.session_id, user_id="local-operator",
                    system_message=system, add_history_to_context=True,
                    num_history_runs=None, num_history_messages=None,
                    store_history_messages=False, tools=[],
                    retries=0, telemetry=False, debug_mode=False,
                )
                try:
                    output = agent.run(input_text, metadata={
                        "capture_sha256": evidence["capture"]["sha256"],
                        "prompt_version": PROMPT_VERSION, "prompt_sha256": prompt_hash,
                    })
                except Exception:
                    raise LLMError("agent_error", "The saved agent run could not be completed.") from None
                finally:
                    database.db_engine.dispose()
        if model.error_code or model.answer is None or str(output.status.value) != "COMPLETED":
            raise LLMError(model.error_code or "agent_error",
                           "The AI service did not return a usable answer. The fixed-rule result is shown instead.")
        return {
            "source": "api", "status": "validated_structure_and_references",
            "model": model.returned_model, "provider": urlsplit(self.endpoint).hostname,
            "runtime": "Agno", "agent_run_id": output.run_id,
            "session_id": self.session_id, "attempts": 1, "usage": model.usage,
            "request_message_count": model.request_messages,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
            "prompt_version": PROMPT_VERSION, "prompt_sha256": prompt_hash,
            "request_sha256": model.request_sha256, "answer": model.answer,
            "review_note": "JSON structure, finding and fact IDs were checked. Review the explanation; this is not semantic proof.",
        }
