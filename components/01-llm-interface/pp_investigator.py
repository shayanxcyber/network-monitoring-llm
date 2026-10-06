"""Agno investigator: bounded native tool loop, private continuity, final repair."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import queue
import threading
import time
import re
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

os.environ.setdefault('AGNO_TELEMETRY', 'false')
import httpx
from agno.agent import Agent
from agno.db.sqlite import SqliteDb
from agno.exceptions import ModelProviderError
from agno.models.deepseek import DeepSeek
from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI
from openai.types.chat import ChatCompletion

from pp_context import encoded, MAX_REQUEST_BYTES, HISTORY_RUNS
from pp_investigation_contract import InvestigationAnswer, WorkspaceAnswer, SCHEMA_SHA256, WORKSPACE_SCHEMA_SHA256, validate_final
from pp_investigation_tools import EvidenceWorkspace, MAX_TOOL_CALLS, timestamp, validate_tool_arguments
from pp_llm import LLMError, MAX_QUESTION, clean_text

VERSION = 'packetpilot-investigator-3.4'
MAX_MODEL_CALLS = 6
MAX_RUN_SECONDS = 600
MAX_RUN_COMPLETION_TOKENS = 65_536
MAX_RUN_TOTAL_TOKENS = 240_000
PROMPTS = Path(__file__).with_name('prompts')


def bounded_request(client, payload, seconds):
    """Bound caller wait, including slow streamed HTTP bodies. Never retry.

    A timed-out provider may still bill/finish; cancellation is best effort.
    The daemon holds no workspace/state references and cannot publish a result.
    """
    result = queue.Queue(maxsize=1)
    def request():
        try:
            result.put((True, client.chat.completions.create(**payload, timeout=seconds)))
        except Exception as exc:
            result.put((False, exc))
    thread = threading.Thread(target=request, daemon=True, name='packetpilot-provider-request')
    thread.start()
    try:
        success, value = result.get(timeout=seconds)
    except queue.Empty:
        raise TimeoutError('Provider wall-clock limit reached.') from None
    if not success:
        raise value
    return value


def safe_record(value, secret):
    """Private provider reasoning is replayed in memory/SQLite, never exported."""
    if isinstance(value, dict):
        return {k: safe_record(v, secret) for k, v in value.items()
                if k not in ('reasoning_content', 'reasoning', 'api_key', 'authorization')}
    if isinstance(value, list):
        return [safe_record(v, secret) for v in value]
    return value.replace(secret, '[redacted]') if isinstance(value, str) and secret else value


def provisional_summary(content):
    """Only a bounded summary string, never raw JSON or private reasoning."""
    match = re.search(r'"summary"\s*:\s*"', content)
    if not match: return ''
    fragment, escaped = '', False
    for character in content[match.end():]:
        if character == '"' and not escaped: break
        fragment += character
        escaped = character == '\\' and not escaped
    # A chunk can end halfway through an escape or Unicode sequence.
    fragment = re.sub(r'\\u[0-9a-fA-F]{0,3}$', '', fragment)
    if len(fragment) - len(fragment.rstrip('\\')) & 1: fragment = fragment[:-1]
    try: return json.loads('"'+fragment+'"')[:1400]
    except (ValueError, TypeError): return ''


def streamed_request(client, payload, seconds, emit, secret):
    """Consume genuine SDK chunks, preserving reasoning for private tool replay.

    Agno still owns its native validated tool loop. This adapter streams only
    provisional public summary snapshots and factual lifecycle events.
    """
    result, closed = queue.Queue(maxsize=1), threading.Event()
    from pp_runs import InvestigationCancelled
    callback = getattr(getattr(emit, '__self__', None), 'event_callback', emit)
    cancelled = getattr(callback, 'cancelled', None)
    def consume():
        stream = None
        try:
            stream = client.chat.completions.create(**payload, timeout=seconds, stream=True,
                                                    stream_options={'include_usage': True})
            content, reasoning, tools, refusal = '', '', {}, None
            finish, usage, model, identity, created = None, None, payload['model'], 'stream', 0
            last_summary, last_emit = '', 0.0
            for chunk in stream:
                if closed.is_set(): break
                if cancelled is not None and cancelled.is_set():
                    raise InvestigationCancelled()
                model, identity, created = chunk.model or model, chunk.id or identity, chunk.created or created
                if chunk.usage is not None: usage = chunk.usage.model_dump()
                if not chunk.choices: continue
                if len(chunk.choices) != 1 or chunk.choices[0].index != 0:
                    raise ValueError('Expected exactly one streamed choice.')
                choice, delta = chunk.choices[0], chunk.choices[0].delta
                content += delta.content or ''
                reasoning += getattr(delta, 'reasoning_content', None) or ''
                refusal = delta.refusal or refusal
                for call in delta.tool_calls or []:
                    row = tools.setdefault(call.index, {'id': '', 'type': 'function', 'function': {'name': '', 'arguments': ''}})
                    row['id'] += call.id or ''
                    if call.function:
                        row['function']['name'] += call.function.name or ''
                        row['function']['arguments'] += call.function.arguments or ''
                if choice.finish_reason: finish = choice.finish_reason
                summary = provisional_summary(content)
                if summary != last_summary and time.monotonic()-last_emit > .12:
                    emit('summary', {'text': safe_record(summary, secret), 'provisional': True})
                    last_summary, last_emit = summary, time.monotonic()
            if closed.is_set(): return
            summary = provisional_summary(content)
            if summary and summary != last_summary:
                emit('summary', {'text': safe_record(summary, secret), 'provisional': True})
            message = {'role': 'assistant', 'content': content or None, 'reasoning_content': reasoning or None,
                       'refusal': refusal, 'tool_calls': [tools[key] for key in sorted(tools)] or None}
            response = ChatCompletion.model_validate({'id': identity, 'object': 'chat.completion', 'created': created,
                'model': model, 'usage': usage, 'choices': [{'index': 0, 'finish_reason': finish, 'message': message}]})
            result.put((True, response))
        except InvestigationCancelled as exc:
            if not closed.is_set(): result.put((False, exc))
        except Exception as exc:
            if not closed.is_set(): result.put((False, exc))
        finally:
            if stream is not None: stream.close()
    threading.Thread(target=consume, daemon=True, name='packetpilot-provider-stream').start()
    try:
        success, value = result.get(timeout=seconds)
        if not success: raise value
        return value
    except queue.Empty:
        raise TimeoutError('Provider wall-clock limit reached.') from None
    finally:
        closed.set()


@dataclass
class InvestigatorModel(DeepSeek):
    workspace: object = field(default=None, repr=False)
    deadline: float = 0
    per_request_timeout: float = 180
    calls: list = field(default_factory=list, init=False, repr=False)
    answer: dict | None = field(default=None, init=False, repr=False)
    wire_answer: dict | None = field(default=None, init=False, repr=False)
    usage_total: dict = field(default_factory=dict, init=False)
    corrections: int = field(default=0, init=False)
    error_code: str = field(default='', init=False)
    returned_model: str = field(default='', init=False)
    event_callback: object = field(default=None, repr=False)

    def event(self, kind, data):
        if self.event_callback: self.event_callback(kind, data)

    def reject(self, code, message, status=None):
        self.error_code = code
        raise ModelProviderError(message=message, status_code=status, model_name=self.name, model_id=self.id) from None

    def _call(self, payload):
        remaining = self.deadline - time.monotonic()
        used = self.usage_total.get('completion_tokens', 0)
        if len(self.calls) >= MAX_MODEL_CALLS or remaining < 1 or used >= MAX_RUN_COMPLETION_TOKENS or self.usage_total.get('total_tokens', 0) >= MAX_RUN_TOTAL_TOKENS:
            self.reject('investigation_limit', 'Investigation call, time or token budget reached; no further request was made.')
        payload['max_tokens'] = min(payload.get('max_tokens') or 32768, MAX_RUN_COMPLETION_TOKENS-used)
        if len(encoded(payload)) > MAX_REQUEST_BYTES:
            self.reject('context_limit', 'Investigation request exceeds its byte limit. Use a smaller capture or a new review.')
        entry = {'index': len(self.calls)+1, 'started_at': timestamp(),
                 'request': safe_record(payload, self.api_key),
                 'request_sha256': hashlib.sha256(encoded(payload)).hexdigest(),
                 'reasoning_messages_replayed': sum(bool(m.get('reasoning_content')) for m in payload['messages'])}
        self.calls.append(entry)
        self.event('provider_started', {'call': entry['index'], 'message': 'Assessing the selected evidence.'})
        started = time.monotonic()
        try:
            response = (streamed_request(self.get_client(), payload, min(self.per_request_timeout, remaining), self.event, self.api_key)
                        if self.event_callback else bounded_request(self.get_client(), payload, min(self.per_request_timeout, remaining)))
        except (APITimeoutError, TimeoutError):
            entry['error'] = 'timeout'
            self.reject('timeout', 'The API request timed out. It was not automatically repeated.')
        except APIStatusError as exc:
            entry.update(error='http_error', http_status=exc.status_code)
            self.reject('authentication' if exc.status_code in (401, 403) else 'http_error',
                        f'Provider returned HTTP {exc.status_code}; no error body was recorded.', exc.status_code)
        except APIConnectionError:
            entry['error'] = 'connection'
            self.reject('connection', 'Provider connection failed. No automatic retry was made.')
        except Exception:
            entry['error'] = 'provider_error'
            self.reject('provider_error', 'The provider request could not be completed.')
        finally:
            entry.update(finished_at=timestamp(), elapsed_seconds=round(time.monotonic()-started, 4))
        if getattr(response, 'error', None) or len(response.choices) != 1:
            self.reject('invalid_response', 'Expected exactly one completed provider response.')
        choice = response.choices[0]
        self.returned_model = clean_text(response.model or self.id, 120)
        usage = {}
        if response.usage:
            for name in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                value = getattr(response.usage, name, None)
                if type(value) is int and value >= 0:
                    usage[name] = value
            detail = getattr(response.usage, 'completion_tokens_details', None)
            value = getattr(detail, 'reasoning_tokens', None)
            if type(value) is int and value >= 0:
                usage['reasoning_tokens'] = value
        for name, value in usage.items():
            self.usage_total[name] = self.usage_total.get(name, 0)+value
        entry.update(usage=usage, model=self.returned_model, finish_reason=choice.finish_reason,
                     reasoning_present=bool(getattr(choice.message, 'reasoning_content', None)),
                     raw_content=safe_record((choice.message.content or '')[:32_000], self.api_key),
                     tool_calls=safe_record([c.model_dump(exclude_none=True) for c in choice.message.tool_calls or []], self.api_key))
        self.event('provider_finished', {'call': entry['index'], 'finish_reason': choice.finish_reason,
                                        'elapsed_seconds': entry['elapsed_seconds']})
        if choice.message.role != 'assistant' or choice.message.refusal:
            self.reject('invalid_response', 'Unsupported/refused provider response; no answer was accepted.')
        return response

    def invoke(self, messages, assistant_message, response_format=None, tools=None,
               tool_choice=None, run_response=None, compress_tool_results=False):
        # Use native formatter/dispatch; genuine thinking fields survive the
        # intermediate tool messages and subsequent successful history turns.
        formatted = self._format_all_messages(messages, compress_tool_results)
        params = self.get_request_params(response_format={'type': 'json_object'}, tools=tools,
                                         tool_choice='auto' if tools else None, run_response=run_response)
        payload = {'model': self.id, 'messages': formatted, **params}
        assistant_message.metrics.start_timer()
        try:
            response = self._call(payload)
            choice = response.choices[0]
            if choice.finish_reason == 'tool_calls' and choice.message.tool_calls:
                allowed = self.workspace.tool_names
                calls = choice.message.tool_calls
                ids = [call.id for call in calls]
                if (len(calls)+len(self.workspace.trace) > MAX_TOOL_CALLS or len(set(ids)) != len(ids)
                        or any(c.type != 'function' or c.function.name not in allowed for c in calls)):
                    self.reject('invalid_tool_request', 'Unknown, duplicate or over-budget tool request rejected.')
                try:
                    for call in calls:
                        validate_tool_arguments(call.function.name, call.function.arguments)
                except (ValueError, TypeError):
                    self.reject('invalid_tool_request', 'Tool arguments failed the strict type/size check; no tool was executed.')
                return self._parse_provider_response(response)
            if choice.finish_reason != 'stop' or choice.message.tool_calls:
                self.reject('invalid_response', 'Provider response did not finish; no incomplete answer was accepted.')
            try:
                self.event('validation', {'message': 'Checking answer structure and original references.'})
                self.answer, self.wire_answer = validate_final(choice.message.content, self.workspace)
            except (ValueError, TypeError, KeyError) as exc:
                self.calls[-1]['validation_error'] = str(exc)[:1000]
                if self.corrections:
                    self.reject('invalid_response', 'Final response still failed validation after one correction.')
                self.corrections += 1
                self.event('correction', {'message': 'One bounded correction is checking the answer format.', 'clear_provisional': True})
                repair = ('Correct the previous final JSON once. Do not request tools. Preserve supported observations; '
                          'do not invent evidence. Validation error: ' + str(exc)[:1000])
                assistant = choice.message.model_dump(exclude_none=True)
                assistant = {k: v for k, v in assistant.items() if k in ('role', 'content', 'reasoning_content')}
                # The failed output remains in the trace; it is not committed as
                # a successful history turn. No network/tool side effect to retry.
                repaired_payload = {k: v for k, v in payload.items() if k not in ('tools', 'tool_choice')}
                repaired_payload['messages'] = [*formatted, assistant, {'role': 'user', 'content': repair}]
                response = self._call(repaired_payload)
                choice = response.choices[0]
                if choice.finish_reason != 'stop' or choice.message.tool_calls:
                    self.reject('invalid_response', 'Correction did not finish with final JSON.')
                try:
                    self.answer, self.wire_answer = validate_final(choice.message.content, self.workspace)
                except (ValueError, TypeError, KeyError) as error:
                    self.calls[-1]['validation_error'] = str(error)[:1000]
                    self.reject('invalid_response', 'Final response still failed validation after one correction.')
            return self._parse_provider_response(response)
        finally:
            assistant_message.metrics.stop_timer()


def state_read(database, scope):
    with closing(sqlite3.connect(database, timeout=10)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS pp_investigation_state (scope TEXT PRIMARY KEY, state TEXT NOT NULL)')
        db.commit()
        row = db.execute('SELECT state FROM pp_investigation_state WHERE scope=?', (scope,)).fetchone()
        return json.loads(row[0]) if row else {}


def state_write(database, scope, state):
    with closing(sqlite3.connect(database, timeout=10)) as db:
        db.execute('INSERT OR REPLACE INTO pp_investigation_state VALUES (?,?)', (scope, json.dumps(state)))
        db.commit()


class InvestigatorClient:
    def __init__(self, config, database, session_id, workspace_upgrade=True, response_scope=None, event_callback=None):
        self.config, self.database, self.session_id = config, Path(database), session_id
        self.endpoint = config.endpoint()
        self.workspace_upgrade, self.response_scope = workspace_upgrade, response_scope
        self.event_callback = event_callback

    def explain(self, evidence, question):
        question = clean_text(question, MAX_QUESTION)
        started = time.monotonic()
        is_log = evidence.get('input_kind') == 'network_log'
        if is_log:
            from pp_log_tools import LogWorkspace
            workspace = LogWorkspace(evidence, question, started+MAX_RUN_SECONDS)
        else:
            workspace = EvidenceWorkspace(evidence, question, started+MAX_RUN_SECONDS)
        workspace.event_callback = self.event_callback
        version = 'packetpilot-workspace-4.1' if self.workspace_upgrade else VERSION
        answer_type = WorkspaceAnswer if self.workspace_upgrade else InvestigationAnswer
        if self.workspace_upgrade:
            from pp_workspace_tools import ResponseWorkspace
            workspace = ResponseWorkspace(workspace, self.response_scope)
        instructions = [(PROMPTS / name).read_text(encoding='utf-8') for name in
                        ('workspace-v4.txt' if self.workspace_upgrade else ('investigator-log-v1.txt' if is_log else 'investigator-v3.txt'), 'reviewed-guidance-v1.txt')]
        scope_parts = [self.session_id, version, evidence['capture']['sha256'], self.config.model,
                       self.endpoint, self.config.thinking, self.config.reasoning_effort]
        scope = hashlib.sha256(encoded(scope_parts)).hexdigest()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        previous = state_read(self.database, scope)
        workspace.restore_focus(previous)
        selected_reference = (self.response_scope or {}).get('selected_reference')
        if selected_reference:
            workspace.context['operator_selection'] = {
                'reference': selected_reference,
                'short_id': workspace.aliases.get(selected_reference),
                'purpose': 'Operator-selected focus for this exact question. Not an authorisation or a new observation; inspect relevant supplied evidence if needed.'}
        initial_selection = copy.deepcopy(workspace.context['context_selection'])
        if os.name != 'nt':
            self.database.chmod(0o600)
        workspace.context['investigation_state'] = previous or {'capture_sha256': workspace.digest,
            'note': 'New investigation. Prior model findings are unverified interpretation, never new packet evidence.'}
        input_text = json.dumps(workspace.context, ensure_ascii=False, allow_nan=False)
        context_sha = hashlib.sha256(input_text.encode()).hexdigest()
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=self.config.timeout) as transport:
            with OpenAI(api_key=self.config.api_key, base_url=self.endpoint.removesuffix('/chat/completions'),
                        timeout=self.config.timeout, max_retries=0, http_client=transport) as provider:
                model = InvestigatorModel(id=self.config.model, api_key=self.config.api_key,
                    base_url=self.config.base_url, client=provider,
                    max_tokens=self.config.max_output_tokens or 32768,
                    temperature=None if self.config.thinking == 'enabled' else 0,
                    use_thinking=self.config.thinking == 'enabled', reasoning_effort=self.config.reasoning_effort or None,
                    max_retries=0, retries=0, workspace=workspace, deadline=started+MAX_RUN_SECONDS,
                    per_request_timeout=self.config.timeout, event_callback=self.event_callback)
                database = SqliteDb(db_file=str(self.database))
                agent = Agent(id=version, name='PacketPilot', model=model, db=database,
                    session_id=scope, user_id='local-operator',
                    description='You are PacketPilot, an evidence-led network investigation assistant for Linux lab administrators.',
                    instructions=instructions, output_schema=answer_type, use_json_mode=True,
                    tools=workspace.tools,
                    tool_call_limit=MAX_TOOL_CALLS, add_history_to_context=True, num_history_runs=HISTORY_RUNS,
                    store_history_messages=False, retries=0, telemetry=False, debug_mode=False)
                try:
                    output = agent.run(input_text, metadata={'capture_sha256': workspace.digest, 'harness_version': version})
                except Exception:
                    output = None
                finally:
                    database.db_engine.dispose()
        calls = model.calls
        system = calls[0]['request']['messages'][0]['content'] if calls else ''
        last = calls[-1] if calls else {}
        record = {'harness_version': version, 'context_version': workspace.context['context_version'],
            'context_sha256': context_sha, 'context_bytes': len(input_text.encode()),
            'context_selection': initial_selection, 'final_context_selection': workspace.context['context_selection'],
            'schema_revision': '4.1' if self.workspace_upgrade else '3.0',
            'schema_sha256': WORKSPACE_SCHEMA_SHA256 if self.workspace_upgrade else SCHEMA_SHA256, 'prompt_version': version,
            'prompt_sha256': hashlib.sha256(system.encode()).hexdigest(),
            'guidance_sha256': hashlib.sha256(instructions[1].encode()).hexdigest(),
            'request': calls[0]['request'] if calls else {}, 'request_sha256': calls[0]['request_sha256'] if calls else '',
            'raw_content': last.get('raw_content', ''), 'finish_reason': last.get('finish_reason', ''),
            'requested_model': self.config.model, 'model': model.returned_model, 'usage': model.usage_total,
            'reasoning_present': any(c.get('reasoning_present') for c in calls),
            'model_calls': calls, 'tool_trace': workspace.trace, 'correction_attempts': model.corrections,
            'evidence_view': workspace.validation_context(), 'aggregate_provenance': list(workspace.aggregates.values()),
            'elapsed_seconds': round(time.monotonic()-started, 4), 'attempts': len(calls),
            'settings': {'thinking': self.config.thinking, 'reasoning_effort': self.config.reasoning_effort,
                'max_tokens': model.max_tokens, 'timeout_seconds': self.config.timeout, 'automatic_retries': 0,
                'max_model_calls': MAX_MODEL_CALLS, 'max_tool_calls': MAX_TOOL_CALLS,
                'max_run_seconds': MAX_RUN_SECONDS, 'max_run_completion_tokens': MAX_RUN_COMPLETION_TOKENS,
                'max_run_total_tokens': MAX_RUN_TOTAL_TOKENS, 'max_corrections': 1}}
        if model.error_code or model.answer is None or output is None or str(output.status.value) != 'COMPLETED' or not isinstance(output.content, answer_type):
            raise LLMError(model.error_code or 'agent_error', 'Investigation did not produce a usable final assessment. Saved attempt records explain the failure.', record)
        state = {'capture_sha256': workspace.digest, 'harness_version': version,
            'updated_at': timestamp(), 'completed_turns': previous.get('completed_turns', 0)+1,
            'last_question': question, 'inspected_record_ids': sorted(workspace.supplied),
            'evidence_focus': workspace.focus_state() if workspace.trace else previous.get('evidence_focus', {}),
            'last_model_observations': model.wire_answer['observations'], 'unresolved_questions': model.wire_answer['questions'],
            'pending_previews': model.wire_answer['recommendations'],
            'note': 'Model observations are structurally checked claims, not verified truth. No action approved or executed.'}
        state_write(self.database, scope, state)
        return {**record, 'source': 'api', 'status': 'validated_structure_and_references', 'runtime': 'Agno',
            'provider': urlsplit(self.endpoint).hostname, 'session_id': self.session_id,
            'agent_session_id': scope, 'agent_run_id': output.run_id,
            'request_message_count': len(last.get('request', {}).get('messages', [])),
            'answer': model.answer, 'investigation_state': state,
            'review_note': 'Typed structure, supplied capture-scoped references, copied measurements and preview policy checked. Tools report observations, not a threat verdict. Interpretation and claim-level citation support still require review.'}
