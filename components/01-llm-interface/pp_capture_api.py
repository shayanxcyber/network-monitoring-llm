"""Unprivileged capture lifecycle and recorded current-service observations."""
import base64, hashlib, json, threading, uuid
from pathlib import Path
from typing import Literal
from fastapi import HTTPException
from pydantic import BaseModel,ConfigDict,Field
from pp_workflow import now

class StartCapture(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    duration_seconds:int=Field(default=6,ge=2,le=20)
    provider:Literal['rules','api']='api'
class RecordDiagnostic(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    phase:Literal['baseline','during','after']='baseline'
    profile:Literal['health','transfer']='health'
    objective:str=Field(default='Observe service reachability and first-byte timing for both lab clients.',min_length=1,max_length=240)
    action_id:str|None=None
    baseline_id:str|None=None

def register_capture(app,store,responses,create_review,ready):
    lock=threading.RLock()
    with store.connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS capture_jobs(id TEXT PRIMARY KEY,provider TEXT NOT NULL,review_id TEXT,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS service_diagnostics(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES reviews(id),record TEXT NOT NULL);''')
    def job(identity):
        with store.connect() as db:row=db.execute('SELECT * FROM capture_jobs WHERE id=?',(identity,)).fetchone()
        if not row:raise KeyError('Unknown capture.')
        return dict(row)
    def update(identity,value,review_id=None):
        with store.connect() as db:db.execute('UPDATE capture_jobs SET result=?,review_id=COALESCE(?,review_id) WHERE id=?',(json.dumps(value),review_id,identity))
        return value
    @app.post('/api/captures',status_code=202)
    def start(body:StartCapture):
        if body.provider=='api' and not ready():raise ValueError('Configure the API or select offline inspection.')
        result=responses.call('capture_start',{'duration_seconds':body.duration_seconds})
        with store.connect() as db:db.execute('INSERT INTO capture_jobs VALUES (?,?,NULL,?)',(result['id'],body.provider,json.dumps(result)))
        return result
    @app.get('/api/captures/{session_id}')
    def status(session_id:uuid.UUID):
        saved=job(str(session_id))
        if saved['review_id']:return json.loads(saved['result'])|{'review_id':saved['review_id']}
        try:result=responses.call('capture_status',{'session_id':str(session_id)})
        except ValueError as exc:result=dict(id=str(session_id),status='interrupted',error=str(exc),note='Broker state unavailable; no source was imported.')
        return update(str(session_id),result)
    @app.post('/api/captures/{session_id}/stop')
    def stop(session_id:uuid.UUID):
        job(str(session_id));return update(str(session_id),responses.call('capture_stop',{'session_id':str(session_id)}))
    @app.post('/api/captures/{session_id}/cancel')
    def cancel(session_id:uuid.UUID):
        job(str(session_id));return update(str(session_id),responses.call('capture_cancel',{'session_id':str(session_id)}))
    @app.post('/api/captures/{session_id}/import',status_code=201)
    def finish(session_id:uuid.UUID):
        identity=str(session_id)
        with lock:
            saved=job(identity)
            if saved['review_id']:return store.get(saved['review_id'])|{'capture':Path(store.get(saved['review_id'])['capture']).name}
            result=responses.call('capture_result',{'session_id':identity});capture=result['capture'];raw=base64.b64decode(capture.pop('pcap_base64'),validate=True)
            if not 24<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=capture['capture_sha256']:raise ValueError('Capture integrity check failed.')
            # Resume an interrupted import by its immutable broker capture ID.
            with store.connect() as db:bindings=db.execute('SELECT review_id,binding FROM lab_bindings').fetchall()
            existing=next((r['review_id'] for r in bindings if json.loads(r['binding'])['capture_id']==identity),None)
            if existing:review=store.get(existing)
            else:
                folder=store.directory/'captures';folder.mkdir(exist_ok=True);path=folder/(identity+'.pcap')
                if path.exists():
                    if hashlib.sha256(path.read_bytes()).hexdigest()!=capture['capture_sha256']:raise ValueError('Retained capture identity differs; nothing overwritten.')
                else:path.write_bytes(raw)
                review=create_review(path,'Service capture · '+identity[:8],saved['provider']);store.bind_lab(review['id'],capture)
            update(identity,result,review['id'])
            review=store.get(review['id']);return review|{'capture':Path(review['capture']).name}
    @app.post('/api/reviews/{review_id}/diagnostics',status_code=201)
    def diagnostic(review_id:uuid.UUID,body:RecordDiagnostic):
        review=store.get(str(review_id))
        if body.action_id and body.action_id not in review['response_action_ids']:raise ValueError('That action does not belong to this source.')
        baseline=None
        if body.baseline_id:
            if body.phase=='baseline':raise ValueError('A new baseline cannot reference an earlier cycle.')
            with store.connect() as db:
                saved=db.execute('SELECT record FROM service_diagnostics WHERE id=? AND review_id=?',
                                 (body.baseline_id,str(review_id))).fetchone()
            baseline=json.loads(saved[0]) if saved else None
            if not baseline or baseline['phase']!='baseline':raise ValueError('Choose a baseline from this source.')
            if baseline.get('profile','health')!=body.profile or baseline['objective']!=body.objective:
                raise ValueError('Baseline and follow-up must use the same check and objective.')
            if baseline.get('action_id') and baseline['action_id']!=body.action_id:
                raise ValueError('These observations belong to different response actions.')
        lab=responses.call('status')['lab']
        context=dict(generation=lab['generation'],addresses=lab['addresses'],service_port=lab['service_port'])
        if baseline and baseline.get('lab_context')!=context:
            raise ValueError('Lab identity changed or the older baseline has no identity. Record a new baseline.')
        record=dict(id=str(uuid.uuid4()),review_id=str(review_id),recorded_at=now(),phase=body.phase,profile=body.profile,objective=body.objective,
            action_id=body.action_id,baseline_id=body.baseline_id,lab_context=context,result=responses.call('diagnostic_transfer' if body.profile=='transfer' else 'diagnostic'),
            scope='New fixed-lab active observation, not historical file evidence or proof of cause. One request per client, not a performance benchmark.')
        if baseline and (baseline['recorded_at']>=record['recorded_at'] or
                         any(baseline['result'].get(k)!=record['result'].get(k) for k in ('service','path'))):
            raise ValueError('The baseline is not earlier or its service target differs. Nothing was paired.')
        with store.connect() as db:db.execute('INSERT INTO service_diagnostics VALUES (?,?,?)',(record['id'],str(review_id),json.dumps(record)))
        return record
    @app.get('/api/reviews/{review_id}/diagnostics')
    def diagnostics(review_id:uuid.UUID):
        store.get(str(review_id))
        with store.connect() as db:return [json.loads(r[0]) for r in db.execute('SELECT record FROM service_diagnostics WHERE review_id=? ORDER BY rowid',(str(review_id),))]
