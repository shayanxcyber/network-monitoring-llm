"""Case endpoints and self-contained human-readable evidence export."""
import html
import json
import uuid
from fastapi import Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from pp_logs import input_fingerprint
from pp_service_evidence import compare_service, service_facts

class NewCase(BaseModel):
    model_config=ConfigDict(extra='forbid')
    title:str=Field(min_length=1,max_length=160)
class LinkSource(BaseModel):
    model_config=ConfigDict(extra='forbid')
    review_id:uuid.UUID
    role:str=Field(pattern='^(baseline|problem|after|reference)$')
class SelectSources(BaseModel):
    model_config=ConfigDict(extra='forbid')
    review_ids:list[uuid.UUID]=Field(min_length=1,max_length=6)
class SourceRole(BaseModel):
    model_config=ConfigDict(extra='forbid')
    role:str=Field(pattern='^(baseline|problem|after|reference)$')

def same_case_scope(previous,current):
    if not previous or not current:return not previous and not current
    def identities(value):return {(s['review_id'],s['sha256']) for s in value['sources']}
    return previous['id']==current['id'] and identities(previous)==identities(current)

def snapshot(store,review_id):
    case=store.case_snapshot(review_id)
    for source in (case or {}).get('sources',[]):
        saved=store.get(source['review_id'])
        if input_fingerprint(saved['capture'])['sha256']!=source['sha256']:raise ValueError('A related source changed; import it again before comparing or investigating.')
    return case

def case_export(store,case,actions):
    sources=[]
    for s in case['sources']:
        review=store.get(s['review_id'])
        if input_fingerprint(review['capture'])['sha256']!=s['sha256']:raise ValueError('A retained source changed; no report was exported under the old identity.')
        answers=[]
        for t in review['turns']:
            explanation=t['explanation'];failure=explanation.get('api_error')
            answers.append(dict(run_id=t['run_id'],question=t['question'],recorded_at=t.get('recorded_at'),
                source=explanation.get('source'),status=explanation.get('status'),api_error=failure,
                answer=None if failure else explanation.get('answer'),
                fallback_baseline=explanation.get('answer') if failure else None,
                case_scope=explanation.get('case_scope'),aggregate_provenance=explanation.get('aggregate_provenance',[])))
        with store.connect() as db:
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE name='service_diagnostics'").fetchone()
            diagnostics=[json.loads(r[0]) for r in db.execute('SELECT record FROM service_diagnostics WHERE review_id=? ORDER BY rowid',(s['review_id'],))] if exists else []
        sources.append(dict(**s,evidence=review['evidence'],turns=answers,service=service_facts(review['evidence']),diagnostics=diagnostics))
    allowed={s['review_id'] for s in case['sources']}
    selected=[s for s in sources if s['selected']]
    comparisons=[dict(baseline_review_id=a['review_id'],comparison_review_id=b['review_id'],**compare_service(a['evidence'],b['evidence']))
        for a in selected if a['role']=='baseline' for b in selected if b['review_id']!=a['review_id'] and b['role']!='baseline']
    return dict(format_version='case-1.0',case=case,sources=sources,comparisons=comparisons,
        actions=[{k:v for k,v in a.items() if k not in ('approval_token','approval_hash')} for a in actions if a.get('review_id') in allowed],
        note='Saved sources, measured comparisons, model assessments and recorded response outcomes. Interpretations remain subject to the original evidence and its coverage limits.')

def readable_report(value):
    esc=lambda s:html.escape(str(s),quote=True)
    display=lambda v:'Unavailable' if v is None else format(v,'.6g') if type(v)is float else str(v)
    def table(headers,rows):
        return '<table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(display(v))+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table>'
    def client_observation(r,role):
        value=r['result']['clients'][role];state='HTTP reachable' if value['reachable'] else 'No successful response'
        if r.get('profile')=='transfer':
            if value.get('complete') is not True:
                status='check timed out' if value.get('failure_type')=='TimeoutExpired' else 'transfer incomplete'
                return state+'; '+status+(' after '+display(value['total_seconds'])+'s' if value.get('total_seconds') is not None else '')
            elapsed=display(value['total_seconds'])+'s' if value.get('total_seconds') is not None else 'timing unavailable'
            rate=', '+display(value['payload_kbit_per_second'])+'kbit/s' if value.get('payload_kbit_per_second') is not None else ''
            return state+'; complete transfer '+elapsed+rate
        return state+('; first byte '+display(value['first_byte_seconds'])+'s' if value.get('first_byte_seconds') is not None else '; first-byte timing unavailable')
    metrics=[('record_count','Decoded records'),('duration_seconds','Observed span (s)'),('records_per_second','Records / observed s'),('frame_bytes_per_second','Frame bytes / observed s'),('syn_records','SYN without ACK records'),('reset_records','Reset records'),('candidate_pairs','Candidate reply pairs'),('mean_candidate_reply_seconds','Mean candidate reply delay (s)')]
    out=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        '<title>PacketPilot investigation report</title><style>body{font:16px/1.6 system-ui;color:#20263a;background:#faf9f6;max-width:1100px;margin:40px auto;padding:0 24px}h1,h2{letter-spacing:-.03em}section{background:white;border:1px solid #dce1e8;border-radius:16px;padding:24px;margin:20px 0}table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;border-bottom:1px solid #e4e8ed;padding:9px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 monospace}a{color:#3058bb}small{color:#596174}details{margin:12px 0}nav a{margin-right:18px}</style>',
        '<h1>'+esc(value['case']['title'])+'</h1><p>PacketPilot investigation report</p><p>'+esc(value['note'])+'</p><nav>']
    for s in value['sources']:out.append('<a href="#s-'+esc(s['review_id'])+'">'+esc(s['title'])+'</a>')
    out.append('</nav>')
    out.append('<section><h2>Selected-source comparison</h2><p>Each comparison retains its service-port filter. Source roles are operator context, not a diagnosis.</p>')
    titles={s['review_id']:s['title'] for s in value['sources']}
    for comparison in value.get('comparisons',[]):
        out.append('<h3>'+esc(titles[comparison['baseline_review_id']])+' compared with '+esc(titles[comparison['comparison_review_id']])+'</h3>')
        out.append('<p>Service-port filter: '+esc(comparison['baseline']['service_port'] or 'all supported ports')+'</p>')
        out.append(table(['Measurement','Baseline','Comparison','Change'],[(label,comparison['baseline'][key],comparison['comparison'][key],comparison['delta'].get(key)) for key,label in metrics]))
        out+=['<p>'+esc(text)+'</p>' for text in [comparison['policy'],*comparison['qualifications']]]
    if not value.get('comparisons'):out.append('<p>No selected baseline/comparison pair. Individual observations follow.</p>')
    out.append('</section>')
    for s in value['sources']:
        out+=['<section id="s-'+esc(s['review_id'])+'"><h2>'+esc(s['title'])+'</h2><p>'+esc(s['role'])+' · '+esc(s['input_kind'])+'</p><small>SHA256 '+esc(s['sha256'])+'</small>',
              '<p>'+('Selected for new questions.' if s['selected'] else 'Retained in this case, not selected for new questions.')+'</p>',
              '<h3>Observed service measurements</h3>'+table(['Measurement','Value'],[(label,s['service'][key]) for key,label in metrics]),
              '<details><summary>Coverage, source references and calculation limits</summary><pre>'+esc(json.dumps(s['service'],indent=2))+'</pre></details>']
        out+=['<h3>Current service observations</h3>',table(['Observation / phase','Baseline identity','Observed at','Selected client','Control client','Objective'],[(r.get('id','Legacy observation')+' / '+r['phase']+' / '+r.get('profile','health'),r.get('baseline_id') or 'Not linked',r['recorded_at'],client_observation(r,'source'),client_observation(r,'control'),r['objective']) for r in s['diagnostics']]),
              '<p>New active requests, not the historical state of this capture. Single observations do not establish a representative performance change.</p>',
              '<details><summary>Original diagnostic records</summary><pre>'+esc(json.dumps(s['diagnostics'],indent=2))+'</pre></details>']
        for turn in s['turns']:
            out+=['<h3>'+esc(turn['question'])+'</h3>','<p>'+esc((turn['answer'] or {}).get('summary','No usable model assessment was retained.'))+'</p>',
                  '<details><summary>Findings, uncertainty, source scope and exact references</summary><pre>'+esc(json.dumps(turn,indent=2))+'</pre></details>']
            answer=turn['answer'] or {}
            if turn.get('api_error'):
                out.append('<p><strong>Model assessment unavailable.</strong> '+esc(turn['api_error'].get('message','The attempt failed validation.'))+' Any retained fallback in the structured details is an offline baseline, not an accepted model answer.</p>')
            elif turn.get('source')=='rules':
                out.append('<p><strong>Offline rule baseline.</strong> This is not a model interpretation of the question.</p>')
            out+=['<p>'+esc(o['text'])+'</p>' for o in answer.get('observations',[])]
            if answer.get('interpretation'):out.append('<p><strong>Interpretation:</strong> '+esc(answer['interpretation'])+'</p>')
            out+=['<p><strong>Uncertainty:</strong> '+esc(text)+'</p>' for text in answer.get('uncertainty',[])]
            out+=['<p><strong>Suggested next step:</strong> '+esc(r['rationale'])+'</p>' for r in answer.get('recommendations',[])]
        evidence=s['evidence'];rows=evidence.get('log_records',[]) if s['input_kind']=='network_log' else evidence.get('packets',[])
        cited=json.dumps(s['turns'])
        retained=[r for i,r in enumerate(rows) if i<100 or r['id'] in cited]
        out+=['<h3>Original record details</h3><p>'+str(len(retained))+' of '+str(len(rows))+' retained records shown, including cited records. The structured case export retains the complete evidence.</p>']
        for r in retained:out.append('<details id="'+esc(r['id'])+'"><summary>'+esc(r['id'])+'</summary><pre>'+esc(json.dumps(r,indent=2))+'</pre></details>')
        out.append('</section>')
    out.append('<section><h2>Actions, measurements and restoration</h2>')
    out.append(table(['Operation','Selected target','Service','State'],[(a.get('operation','Unavailable'),a.get('target'),str(a.get('destination',''))+':'+str(a.get('port','')),a.get('state',a.get('status','Unavailable'))) for a in value['actions']]))
    for action in value['actions']:out.append('<details><summary>'+esc(action.get('id',action.get('status','Action record')))+'</summary><pre>'+esc(json.dumps(action,indent=2))+'</pre></details>')
    out.append('</section></html>')
    return ''.join(out)

def register_cases(app,store,responses):
    @app.get('/api/reviews/{review_id}/case')
    def review_case(review_id:uuid.UUID):
        store.get(str(review_id));return store.case_for(str(review_id))
    @app.post('/api/reviews/{review_id}/case',status_code=201)
    def create_case(review_id:uuid.UUID,body:NewCase):return store.create_case(str(review_id),body.title.strip())
    @app.get('/api/cases/{case_id}')
    def get_case(case_id:uuid.UUID):return store.case(str(case_id))
    @app.post('/api/cases/{case_id}/sources')
    def link(case_id:uuid.UUID,body:LinkSource):return store.link_case(str(case_id),str(body.review_id),body.role)
    @app.post('/api/cases/{case_id}/selection')
    def selection(case_id:uuid.UUID,body:SelectSources):return store.select_case(str(case_id),list(map(str,body.review_ids)))
    @app.post('/api/cases/{case_id}/sources/{review_id}/role')
    def role(case_id:uuid.UUID,review_id:uuid.UUID,body:SourceRole):
        return store.change_case_role(str(case_id),str(review_id),body.role)
    @app.post('/api/cases/{case_id}/sources/{review_id}/unlink')
    def unlink(case_id:uuid.UUID,review_id:uuid.UUID):
        return store.unlink_case(str(case_id),str(review_id))
    @app.get('/api/reviews/{review_id}/service')
    def service(review_id:uuid.UUID,port:int=Query(default=0,ge=0,le=65535)):
        return service_facts(store.get(str(review_id))['evidence'],port)
    @app.get('/api/cases/{case_id}/comparison')
    def comparison(case_id:uuid.UUID,baseline_id:uuid.UUID,comparison_id:uuid.UUID,port:int=Query(default=0,ge=0,le=65535)):
        case=store.case(str(case_id));allowed={s['review_id'] for s in case['sources'] if s['selected']}
        if not {str(baseline_id),str(comparison_id)}<=allowed:raise ValueError('Both sources must be selected in this case.')
        snapshot(store,str(baseline_id))
        return dict(baseline_review_id=str(baseline_id),comparison_review_id=str(comparison_id),**compare_service(store.get(str(baseline_id))['evidence'],store.get(str(comparison_id))['evidence'],port))
    @app.get('/api/cases/{case_id}/export')
    def export(case_id:uuid.UUID,format:str='html',baseline_id:uuid.UUID|None=None,comparison_id:uuid.UUID|None=None,port:int=Query(default=0,ge=0,le=65535)):
        if format not in ('html','json'):raise ValueError('Choose html or json.')
        case=store.case(str(case_id));actions=[];availability=True
        try:
            linked={a['action_id']:a for a in store.action_sources()}
            actions=[dict(a,review_id=linked[a['id']]['review_id']) for a in responses.call('status')['actions'] if a['id'] in linked]
        except ValueError:availability=False
        value=case_export(store,case,actions);value['action_history_available']=availability
        if (baseline_id is None)!=(comparison_id is None):raise ValueError('Choose both comparison sources.')
        if baseline_id is not None:value['comparisons']=[comparison(case_id,baseline_id,comparison_id,port)]
        if not availability:value['actions']=[{'status':'unavailable','note':'Broker unavailable; absence of results is not proof that all actions were restored.'}]
        return Response(readable_report(value) if format=='html' else json.dumps(value,ensure_ascii=False,allow_nan=False),
            media_type='text/html' if format=='html' else 'application/json',headers={'Content-Disposition':f'attachment; filename="PacketPilot-case-{case_id}.{format}"'})
