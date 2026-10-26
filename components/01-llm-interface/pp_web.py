"""Loopback-only operator interface, using the existing analysis workflow."""
from __future__ import annotations

import json
import base64
import hashlib
import secrets
import threading
import uuid
import asyncio
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pp_evidence import MAX_BYTES, analyse_capture, preflight
from pp_logs import analyse_input, input_fingerprint
from pp_llm import LLMError, MAX_QUESTION, clean_text
from pp_policy import preview_response, preview_assessment_action
from pp_assessment import validate_assessment
from pp_investigation_contract import validate_saved_assessment
from pp_investigator import MAX_RUN_SECONDS, MAX_MODEL_CALLS
from pp_context import build_context
from pp_samples import make_samples
from pp_sessions import ReviewStore
from pp_runs import InvestigationRuns, TERMINAL
from pp_settings import api_config
from pp_workflow import run_analysis
from pp_response_client import ResponseClient
from pp_tcp_relationships import analyse_tcp_exchanges
from pp_response_operations import CAPABILITIES, catalogue, validate_parameters, proposal_script
from pp_evidence_views import build_views, record_page
from pp_case_api import register_cases, snapshot as case_snapshot, same_case_scope
from pp_capture_api import register_capture


class NewReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample: Literal["normal", "port-check"]
    provider: Literal["rules", "api"] = "rules"


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=MAX_QUESTION)
    request_id: uuid.UUID


class RunQuestion(Question):
    selected_reference: str | None = Field(default=None, min_length=1, max_length=100)


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["investigate", "block_source", "no_action"] = "investigate"
    turn_id: uuid.UUID | None = None
    recommendation_index: int | None = Field(default=None, ge=0, le=3)


class LabCapture(BaseModel):
    model_config = ConfigDict(extra='forbid')
    provider: Literal['rules', 'api'] = 'api'


class LabProposal(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    target: Literal['10.77.0.20'] = '10.77.0.20'
    duration_seconds: int = Field(default=20, ge=5, le=120)
    reason: str = Field(min_length=1, max_length=600)


class LabApproval(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    approval_token: str = Field(min_length=20, max_length=128)
    confirmation: str = Field(min_length=1, max_length=150)


class RecommendationProposal(BaseModel):
    model_config = ConfigDict(extra='forbid')
    turn_id: uuid.UUID


def public_review(review):
    return review | {"capture": Path(review["capture"]).name}


def create_app(root, data_dir=None, config_loader=None, client_factory=None, test_mode=False, response_client=None):
    root = Path(root).resolve()
    store = ReviewStore(data_dir or root / "runtime")
    config_loader = config_loader or (lambda: api_config(root))
    if client_factory is None:
        from pp_agent import AgnoClient
        client_factory = lambda config, session: AgnoClient(config, store.directory / "agent-history.sqlite3", session)
    make_samples(root / "sample-data")
    csrf = secrets.token_urlsafe(32)
    request_lock = threading.Lock()
    runs = InvestigationRuns(store, request_lock)
    app_runs = runs
    active_request = None
    responses = response_client or ResponseClient()
    app = FastAPI(title="PacketPilot", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.runs = app_runs
    register_cases(app,store,responses)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"] + (["testserver"] if test_mode else []))

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if (request.headers.get("sec-fetch-site") == "cross-site"
                    or (origin and origin != str(request.base_url).rstrip("/"))
                    or not secrets.compare_digest(request.headers.get("x-packetpilot-token", ""), csrf)):
                return JSONResponse({"detail": "Open PacketPilot locally and refresh before submitting."}, status_code=403)
            try:
                size = int(request.headers["content-length"])
                if not 0 <= size <= MAX_BYTES + 65536:
                    raise ValueError
            except (KeyError, ValueError):
                return JSONResponse({"detail": "Request is missing its size or exceeds the 8 MiB upload limit."}, status_code=413)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ValueError)
    async def invalid(_request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(KeyError)
    async def missing(_request, _exc):
        return JSONResponse({"detail": "That saved review was not found."}, status_code=404)

    @app.exception_handler(OSError)
    async def file_error(_request, _exc):
        return JSONResponse({"detail": "A local file could not be accessed. Check the project is available."}, status_code=503)

    def ready():
        try:
            config_loader().endpoint()
            return True
        except (LLMError, ValueError, OSError):
            return False

    def create_review(capture, title, provider):
        if provider == "api" and not ready():
            raise ValueError("Add your API key inside Ubuntu before starting an AI review.")
        evidence = analyse_input(capture, "auto")
        return public_review(store.create(title, capture, provider, evidence))

    register_capture(app,store,responses,create_review,ready)

    @app.get("/")
    def index():
        built = root / 'web' / 'react' / 'index.html'
        return FileResponse(built if built.exists() else root / 'web' / 'index.html')

    @app.get("/api/config")
    def configuration():
        config = config_loader()
        return {"application": "PacketPilot", "csrf": csrf, "api_ready": ready(), "model": config.model,
                "thinking": config.thinking, "reasoning_effort": config.reasoning_effort,
                "generation_override": config.max_output_tokens,
                "runtime": "Agno", "actions": "isolated_lab_requires_explicit_approval",
                "capabilities": catalogue(), "answer_contract": "4.0", "interface": "react-workspace-1.0",
                "run_events": True,
                "history": "Last three successful turns and capture-scoped investigation state. Private provider continuity stays in local SQLite, not operator exports. Legacy contract history is separate.",
                "investigation": {"tools": ["get_packets", "get_flow", "summarize_connections", "inspect_tcp_exchanges", "inspect_service", "get_code_reference", "get_lab_status", "probe_lab_service", "prepare_response_plan"],
                                  "case_tools": ["compare_sources", "inspect_case_records"],
                                  "log_tools": ["get_log_records", "summarize_log_records", "inspect_tcp_exchanges", "inspect_service", "get_code_reference", "get_lab_status", "probe_lab_service", "prepare_response_plan"],
                                  "max_calls": MAX_MODEL_CALLS, "max_seconds": MAX_RUN_SECONDS},
                "samples": ["normal", "port-check"], "max_upload_bytes": MAX_BYTES}

    @app.get("/api/reviews")
    def reviews():
        return store.list()

    @app.post("/api/reviews", status_code=201)
    def new_review(body: NewReview):
        return create_review(root / "sample-data" / f"{body.sample}.pcap", f"{body.sample}.pcap", body.provider)

    @app.post("/api/reviews/upload", status_code=201)
    async def upload(file: UploadFile = File(...), provider: Literal["rules", "api"] = Form("rules")):
        data = await file.read(MAX_BYTES + 1)
        await file.close()
        if not data or len(data) > MAX_BYTES:
            raise ValueError("Choose a non-empty PCAP or documented TShark TSV log no larger than 8 MiB.")
        name = clean_text((file.filename or "capture.pcap").replace("\\", "/").split("/")[-1], 160)
        suffix = Path(name).suffix.lower()
        if suffix not in {'.pcap', '.tsv'}:
            raise ValueError('Choose .pcap or the documented TShark .tsv log format.')
        directory = store.directory / "captures"
        directory.mkdir(exist_ok=True)
        path = directory / f"{uuid.uuid4()}{suffix}"
        with path.open("xb") as stream:
            stream.write(data)
        try:
            return await run_in_threadpool(create_review, path, name, provider)
        except Exception:
            path.unlink(missing_ok=True)  # Only this rejected, newly-created upload copy.
            raise

    @app.get("/api/reviews/{review_id}")
    def review(review_id: uuid.UUID):
        selected = str(review_id)
        return public_review(store.get(selected)) | {'pending_request': active_request if active_request and active_request['review_id'] == selected else None}

    @app.get("/api/reviews/{review_id}/visual")
    def visual_evidence(review_id: uuid.UUID):
        """Neutral relationships over this saved evidence, not a network action."""
        evidence = store.get(str(review_id))["evidence"]
        if evidence.get("schema_version") != "2":
            return {"supported": False, "reason": "Legacy evidence has no detailed exchange records."}
        return {"supported": True, "capture_sha256": evidence["capture"]["sha256"],
                "relationships": analyse_tcp_exchanges(evidence)}

    @app.get('/api/reviews/{review_id}/views')
    def evidence_views(review_id: uuid.UUID, references: str = ''):
        selected = references.split(',') if references else []
        return build_views(store.get(str(review_id))['evidence'], selected)

    @app.get('/api/reviews/{review_id}/records')
    def evidence_records(review_id: uuid.UUID, query: str = '', sort: str = 'number', descending: bool = False,
                         offset: int = 0, limit: int = 100, protocol: str = '', status: str = ''):
        return record_page(store.get(str(review_id))['evidence'], query, sort, descending, offset, limit, protocol, status)

    @app.post("/api/reviews/{review_id}/questions")
    def ask(review_id: uuid.UUID, body: Question):
        nonlocal active_request
        if not request_lock.acquire(blocking=False):
            raise HTTPException(409, "A review is running. Wait for it to finish before asking again.")
        try:
            review = store.get(str(review_id))
            question = clean_text(body.question, MAX_QUESTION)
            path = Path(review["capture"])
            if input_fingerprint(path)["sha256"] != review["evidence"]["capture"]["sha256"]:
                raise ValueError("The capture changed. Start a new review so the evidence stays consistent.")
            previous = store.begin_request(str(body.request_id), str(review_id))
            if previous is not None:
                return previous
            active_request = {'review_id': str(review_id), 'request_id': str(body.request_id), 'question': question}
            client = None
            if review["provider"] == "api":
                try:
                    client = client_factory(config_loader(), str(review_id))
                    if hasattr(client, 'configure_workspace'):
                        client.configure_workspace({'review_id': str(review_id), 'binding': review['lab_binding'],
                                                    'inspect': lab_status,'case':case_snapshot(store,str(review_id)),
                                                    'probe':lambda:responses.call('diagnostic')})
                except LLMError:
                    raise ValueError("The API key/settings are not ready. Add the key inside Ubuntu.") from None
            result, _, run_path = run_analysis(
                path, root / "runs", question, provider=review["provider"],
                client=client, cached_evidence=review["evidence"],
            )
            store.finish_request(str(body.request_id), str(review_id), result, run_path)
            return result
        finally:
            active_request = None
            request_lock.release()

    @app.get('/api/reviews/{review_id}/runs')
    def list_runs(review_id: uuid.UUID):
        store.get(str(review_id))
        return runs.list(str(review_id))

    @app.get('/api/runs/active')
    def active_runs():
        with store.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM investigation_runs WHERE status IN ('queued','running','stopping')")]

    @app.post('/api/reviews/{review_id}/runs', status_code=202)
    def start_run(review_id: uuid.UUID, body: RunQuestion):
        saved = store.get(str(review_id))
        question = clean_text(body.question, MAX_QUESTION)
        selected_case = case_snapshot(store,str(review_id))
        path = Path(saved['capture'])
        if input_fingerprint(path)['sha256'] != saved['evidence']['capture']['sha256']:
            raise ValueError('The source changed. Import it again before investigating.')
        selected_reference = body.selected_reference
        if selected_reference:
            evidence = saved['evidence']
            allowed = {evidence['capture']['sha256']+':'+key for key in ('capture','overview','coverage')}
            allowed.update(r['id'] for key in ('packets','log_records','flows','facts') for r in evidence.get(key,[]))
            allowed.update(r['id'] for t in saved['turns'] if same_case_scope(t['explanation'].get('case_scope'),selected_case) for r in t['explanation'].get('aggregate_provenance',[]))
            if selected_reference not in allowed:
                raise ValueError('Selected context is unavailable in the current case scope. Use an original record or ask a new question with the desired source selection.')
        def runner(emit):
            client = None
            if saved['provider'] == 'api':
                client = client_factory(config_loader(), str(review_id))
                if hasattr(client, 'configure_workspace'):
                    client.configure_workspace({'review_id': str(review_id), 'binding': saved['lab_binding'], 'inspect': lab_status,
                                                'selected_reference': selected_reference,'case':selected_case,
                                                'probe':lambda:responses.call('diagnostic')})
                if hasattr(client, 'configure_events'):
                    client.configure_events(emit)
            return run_analysis(path, root / 'runs', question, provider=saved['provider'],
                                client=client, cached_evidence=saved['evidence'], selected_reference=selected_reference)
        return runs.start(str(review_id), str(body.request_id), question, runner, selected_reference)

    @app.get('/api/reviews/{review_id}/runs/{request_id}')
    def get_run(review_id: uuid.UUID, request_id: uuid.UUID, after: int = 0):
        if not 0 <= after <= 100000: raise ValueError('Invalid event cursor.')
        return runs.get(str(review_id), str(request_id), after)

    @app.post('/api/reviews/{review_id}/runs/{request_id}/cancel')
    def cancel_run(review_id: uuid.UUID, request_id: uuid.UUID):
        return runs.cancel(str(review_id), str(request_id))

    @app.get('/api/reviews/{review_id}/runs/{request_id}/events')
    async def run_events(review_id: uuid.UUID, request_id: uuid.UUID, request: Request, after: int = 0):
        try:
            after = max(after, int(request.headers.get('last-event-id', '0')))
        except ValueError:
            raise ValueError('Invalid event cursor.') from None
        if not 0 <= after <= 100000: raise ValueError('Invalid event cursor.')
        runs.get(str(review_id), str(request_id), after)
        async def stream():
            cursor = after
            heartbeat = 0
            while not await request.is_disconnected():
                snapshot = await run_in_threadpool(runs.get, str(review_id), str(request_id), cursor)
                for event in snapshot['events']:
                    cursor = event['sequence']
                    yield f'id: {cursor}\ndata: {json.dumps(event)}\n\n'
                if snapshot['status'] in TERMINAL:
                    yield 'event: settled\ndata: '+json.dumps({'status': snapshot['status'], 'turn_id': snapshot['turn_id']})+'\n\n'
                    return
                heartbeat += 1
                if heartbeat % 30 == 0: yield ': still connected\n\n'
                await asyncio.sleep(.5)
        return StreamingResponse(stream(), media_type='text/event-stream', headers={'X-Accel-Buffering': 'no'})

    @app.post("/api/reviews/{review_id}/preview")
    def preview(review_id: uuid.UUID, body: Preview):
        review = store.get(str(review_id))
        evidence = review["evidence"]
        if review['provider'] == 'api' and evidence.get('schema_version') == '2':
            turn = next((t for t in review['turns'] if t['run_id'] == str(body.turn_id)), None)
            if turn is None or body.recommendation_index is None or turn['explanation']['source'] != 'api':
                raise ValueError('Select a recommendation from a saved, validated AI assessment. No network action is available.')
            answer = turn['explanation']['answer']
            context = (turn['explanation']['evidence_view'] if answer.get('schema_version') in ('3.0', '4.0')
                       else build_context(evidence, turn['question']))
            answer = validate_saved_assessment(answer, evidence, context)
            if body.recommendation_index >= len(answer['recommendations']):
                raise ValueError('That recommendation does not exist.')
            recommendation = answer['recommendations'][body.recommendation_index]
            result = (recommendation_details(review, turn, body.recommendation_index)
                      if answer.get('schema_version') == '4.0' else preview_assessment_action(evidence, recommendation))
            result.update({'turn_id': str(body.turn_id), 'recommendation_index': body.recommendation_index,
                           'references': recommendation['references']})
        else:
            target = evidence['candidate_source'] if body.action == 'block_source' else None
            result = preview_response(evidence, body.action, target, 60, False)
            result['basis'] = 'Legacy TCP baseline preview, not an independent AI assessment.'
        store.add_preview(str(review_id), result)
        return result

    @app.get("/api/reviews/{review_id}/export")
    def export(review_id: uuid.UUID):
        saved = public_review(store.get(str(review_id)))
        if saved['response_action_ids']:
            try:
                saved['response_actions'] = linked_actions(saved)
            except ValueError:
                saved['response_actions_unavailable'] = 'Broker unavailable; action IDs are retained. Do not assume rollback succeeded.'
        return JSONResponse(saved, headers={
            "Content-Disposition": f'attachment; filename="PacketPilot-review-{review_id}.json"',
        })

    def linked_actions(saved):
        ids = saved['response_action_ids']
        return [a for a in responses.call('status')['actions'] if a['id'] in ids]

    def bound_review(review_id):
        saved = store.get(str(review_id))
        if not saved['lab_binding']:
            raise ValueError('This is an offline/uploaded capture. Start a current isolated lab capture before execution.')
        if preflight(Path(saved['capture']))['sha256'] != saved['lab_binding']['capture_sha256']:
            raise ValueError('Lab capture content changed; execution disabled.')
        return saved

    def saved_recommendation(saved, turn_id, index):
        turn = next((t for t in saved['turns'] if t['run_id'] == str(turn_id)), None)
        if not turn or turn['explanation']['source'] != 'api':
            raise ValueError('Select a recommendation from a successfully saved model answer in this review.')
        answer = turn['explanation']['answer']
        context = (turn['explanation']['evidence_view'] if answer.get('schema_version') in ('3.0', '4.0')
                   else build_context(saved['evidence'], turn['question']))
        validate_saved_assessment(answer, saved['evidence'], context)
        if index >= len(answer['recommendations']): raise ValueError('That recommendation does not exist.')
        return turn, answer['recommendations'][index]

    def recommendation_details(saved, turn, index):
        rec = turn['explanation']['answer']['recommendations'][index]
        capability = CAPABILITIES.get(rec['action'], dict(title='Unavailable operation', execution=False, unavailable=True))
        result = dict(kind='recommendation', action=rec['action'], title=capability['title'], rationale=rec['rationale'],
                      references=rec['references'], recommendation=rec, can_propose=False, executed=False,
                      turn_id=turn['run_id'], recommendation_index=index)
        if not capability['execution']:
            result.update(status='unavailable' if capability.get('unavailable') else 'advice',
                          next_step=capability.get('description', 'This operation is not implemented.'))
            return result
        if not saved['lab_binding']:
            result.update(status='offline_mapping_required', next_step='This source is saved evidence. Use Current lab capture for a fresh, authorised mapping; this recommendation will not be retargeted automatically.')
            return result
        try:
            parameters = validate_parameters(rec['action'], rec['target'], rec.get('destination'), rec.get('port'),
                                            rec.get('duration_seconds'), rec.get('rate_kbit'))
        except ValueError as exc:
            result.update(status='unsupported_scope', next_step=str(exc))
            return result
        result.update(status='ready_for_proposal', can_propose=True, parameters=parameters,
                      next_step='Prepare the exact proposal, then review and approve it separately. No change occurs during preparation.')
        return result

    @app.get('/api/reviews/{review_id}/recommendations/{index}')
    def inspect_recommendation(review_id: uuid.UUID, index: int, turn_id: uuid.UUID):
        if not 0 <= index <= 3: raise ValueError('Invalid recommendation index.')
        saved = store.get(str(review_id))
        turn, _ = saved_recommendation(saved, turn_id, index)
        return recommendation_details(saved, turn, index)

    @app.post('/api/reviews/{review_id}/recommendations/{index}/propose')
    def propose_recommendation(review_id: uuid.UUID, index: int, body: RecommendationProposal):
        if not 0 <= index <= 3: raise ValueError('Invalid recommendation index.')
        saved = bound_review(review_id)
        turn, rec = saved_recommendation(saved, body.turn_id, index)
        details = recommendation_details(saved, turn, index)
        if not details['can_propose']: raise ValueError(details['next_step'])
        p = details['parameters']
        result = responses.call('propose', dict(capture_id=saved['lab_binding']['capture_id'],
            capture_sha256=saved['lab_binding']['capture_sha256'], target=p['target'], operation=p['operation'],
            destination=p['destination'], port=p['port'], duration_seconds=p['duration_seconds'], rate_kbit=p['rate_kbit'],
            reason=rec['rationale'], origin=dict(review_id=str(review_id), turn_id=turn['run_id'],
                                              recommendation_index=index, references=rec['references'])))
        store.add_action(str(review_id), result['id'])
        return result

    @app.get('/api/reviews/{review_id}/code/{index}')
    def download_code(review_id: uuid.UUID, index: int, turn_id: uuid.UUID):
        saved = store.get(str(review_id))
        turn = next((t for t in saved['turns'] if t['run_id'] == str(turn_id) and t['explanation']['source'] == 'api'), None)
        if not turn: raise ValueError('Select code from a saved validated model answer.')
        answer = turn['explanation']['answer']
        validate_saved_assessment(answer, saved['evidence'], turn['explanation'].get('evidence_view'))
        examples = answer.get('code_suggestions', [])
        if not 0 <= index < len(examples): raise ValueError('That code example does not exist.')
        example = examples[index]
        prefix = '# UNVERIFIED EXAMPLE: not executed or approved by PacketPilot. Review assumptions and target before use.\n'
        extension = {'sh': 'sh', 'python': 'py', 'text': 'txt'}[example['language']]
        return Response(prefix+example['code']+'\n', media_type='text/plain', headers={
            'Content-Disposition': f'attachment; filename="PacketPilot-example-{turn_id}-{index}.{extension}"'})

    @app.get('/api/lab/status')
    def lab_status():
        try:
            result = responses.call('status')
            return {'available': True, 'lab': result['lab'], 'fault': result['fault'], 'capabilities': catalogue()}
        except ValueError as exc:
            return {'available': False, 'reason': str(exc)}

    @app.get('/api/actions')
    def action_overview():
        sources = {row['action_id']: row for row in store.action_sources()}
        try:
            result = responses.call('status')
            actions = [dict(action, **sources[action['id']]) for action in result['actions'] if action['id'] in sources]
            return {'available': True, 'fault': result.get('fault'), 'actions': actions,
                    'unresolved_ids': sorted(set(sources) - {a['id'] for a in actions})}
        except ValueError as exc:
            # Unavailable is not an empty history or proof of restoration.
            return {'available': False, 'reason': str(exc), 'actions': [], 'unresolved_ids': sorted(sources)}

    @app.post('/api/lab/capture', status_code=201)
    def lab_capture(body: LabCapture):
        if body.provider == 'api' and not ready():
            raise ValueError('Configure the API first, or use offline inspection.')
        result = responses.call('capture')
        raw = base64.b64decode(result.pop('pcap_base64'), validate=True)
        if not 24 < len(raw) <= MAX_BYTES or hashlib.sha256(raw).hexdigest() != result['capture_sha256']:
            raise ValueError('Lab capture transfer failed its integrity check.')
        folder = store.directory / 'captures'
        folder.mkdir(exist_ok=True)
        path = folder / (str(uuid.uuid4())+'.pcap')
        with path.open('xb') as stream: stream.write(raw)
        saved = create_review(path, 'Isolated Linux lab · current service test', body.provider)
        store.bind_lab(saved['id'], result)
        return public_review(store.get(saved['id']))

    @app.get('/api/reviews/{review_id}/actions')
    def lab_actions(review_id: uuid.UUID):
        saved = store.get(str(review_id))
        return linked_actions(saved) if saved['response_action_ids'] else []

    @app.post('/api/reviews/{review_id}/actions/propose')
    def propose_lab_action(review_id: uuid.UUID, body: LabProposal):
        saved = bound_review(review_id)
        observed = {p['ipv4']['src'] for p in saved['evidence'].get('packets', [])
                    if p.get('ipv4') and p['status'] == 'decoded'}
        if body.target not in observed: raise ValueError('Target is not observed in this lab capture.')
        result = responses.call('propose', {'capture_id': saved['lab_binding']['capture_id'],
            'capture_sha256': saved['lab_binding']['capture_sha256'], **body.model_dump()})
        store.add_action(str(review_id), result['id'])
        return result

    @app.post('/api/reviews/{review_id}/actions/{action_id}/approve')
    def approve_lab_action(review_id: uuid.UUID, action_id: uuid.UUID, body: LabApproval):
        saved = bound_review(review_id)
        if str(action_id) not in saved['response_action_ids']:
            raise ValueError('Action belongs to a different review.')
        return responses.call('approve', {'action_id': str(action_id), **body.model_dump()})

    @app.post('/api/reviews/{review_id}/actions/{action_id}/rollback')
    def rollback_lab_action(review_id: uuid.UUID, action_id: uuid.UUID):
        saved = store.get(str(review_id))
        if str(action_id) not in saved['response_action_ids']:
            raise ValueError('Action belongs to a different review.')
        return responses.call('rollback', {'action_id': str(action_id)})

    @app.post('/api/reviews/{review_id}/actions/{action_id}/cancel')
    def cancel_lab_action(review_id: uuid.UUID, action_id: uuid.UUID):
        saved = store.get(str(review_id))
        if str(action_id) not in saved['response_action_ids']: raise ValueError('Action belongs to a different review.')
        return responses.call('cancel', {'action_id': str(action_id)})

    @app.get('/api/reviews/{review_id}/actions/{action_id}/plan')
    def download_plan(review_id: uuid.UUID, action_id: uuid.UUID):
        saved = store.get(str(review_id))
        action = next((a for a in linked_actions(saved) if a['id'] == str(action_id)), None)
        if not action or 'command_plan' not in action: raise ValueError('No validated command plan belongs to this review/action.')
        return Response(proposal_script(action), media_type='text/plain', headers={
            'Content-Disposition': f'attachment; filename="PacketPilot-proposal-{action_id}.txt"'})

    app.mount("/assets", StaticFiles(directory=root / "web"), name="assets")
    if (root / 'web' / 'react').is_dir():
        app.mount('/ui', StaticFiles(directory=root / 'web' / 'react'), name='react-ui')
    return app
