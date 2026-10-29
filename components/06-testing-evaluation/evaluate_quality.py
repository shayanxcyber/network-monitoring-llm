"""Exclusive baseline/refinement records; expected labels never enter the model."""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_logs import analyse_input
from pp_settings import api_config
from pp_llm import LLMError
from pp_investigator import VERSION,timestamp
from pp_investigation_tools import EvidenceWorkspace
from pp_log_tools import LogWorkspace
from quality_cases import quality_cases

def save(path,value):
    with path.open('x',encoding='utf-8') as f: json.dump(value,f,indent=2,ensure_ascii=False,allow_nan=False)

def prepare(destination):
    destination.mkdir(parents=True,exist_ok=False)
    definitions=[]
    for d in quality_cases():
        file=destination/(d['id']+'.pcap');file.write_bytes(d['raw'])
        definitions.append({k:v for k,v in d.items() if k!='raw'}|{'file':file.name,'sha256':hashlib.sha256(d['raw']).hexdigest()})
    # Q06 must be exported by the actual Ubuntu TShark command before live mode.
    definitions.append({'id':'Q06','file':'Q06.tsv','source_capture':'Q02.pcap','label':'saved-log contrast',
        'question':'Which services are contacted in these exported rows and how do they respond? Explain what the log can and cannot establish.',
        'expected_observations':['Eight valid exported rows; four SYN target services and four reverse reset/ack rows.',
                                 'Cite original log lines or aggregates, not packet IDs; seq/ack, payload and real export completeness are not provided.']})
    save(destination/'manifest.json',{'created_at':timestamp(),'cases':definitions,'repetitions_per_arm':2,'workers':2,
        'arms':['baseline','refined'],'labels_withheld':True,'accuracy_benchmark':False})

def main():
    p=argparse.ArgumentParser();p.add_argument('--prepare');p.add_argument('--cases');p.add_argument('--output');p.add_argument('--arm',choices=['baseline','refined']);p.add_argument('--live',action='store_true');a=p.parse_args()
    if a.prepare: prepare(Path(a.prepare));print('Prepared synthetic cases; no traffic sent or model called.');return
    if not a.live or not a.cases or not a.output or not a.arm:p.error('Live arms require --live --cases --output --arm.')
    source=Path(a.cases);cases=json.loads((source/'manifest.json').read_text())['cases']
    config=api_config(ROOT);config.endpoint()
    destination=Path(a.output);destination.mkdir(parents=True,exist_ok=False)
    prepared=[]
    for d in cases:
        folder=destination/d['id'];folder.mkdir();path=source/d['file']
        raw=path.read_bytes();evidence=analyse_input(path,'scapy')
        workspace=(LogWorkspace if evidence.get('input_kind')=='network_log' else EvidenceWorkspace)(evidence,d['question'])
        save(folder/'evidence.json',evidence);save(folder/'initial-context.json',workspace.context)
        for repetition in (1,2):prepared.append((d,folder,evidence,repetition))
    hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'components').rglob('*') if p.is_file() and p.suffix in ('.py','.txt','.json') and '__pycache__' not in p.parts}
    save(destination/'manifest.json',{'started_at':timestamp(),'arm':a.arm,'harness':VERSION,'sources':hashes,'plan':[(d['id'],r) for d,f,e,r in prepared],
        'settings':{'model':config.model,'thinking':config.thinking,'reasoning_effort':config.reasoning_effort,'max_tokens':config.max_output_tokens,'timeout':config.timeout},
        'environment':{'os':platform.system(),'python':platform.python_version(),**{n:importlib.metadata.version(n) for n in ('agno','openai','scapy','pydantic')}},
        'input_hashes':{d['id']:hashlib.sha256((source/d['file']).read_bytes()).hexdigest() for d in cases},'expected_labels_in_model_input':False,'workers':2})
    def run(item):
        d,folder,evidence,r=item;session=str(uuid.uuid4());start=timestamp()
        save(folder/f'attempt-{r}-started.json',{'started_at':start,'session_id':session,'question':d['question']})
        try: record={'successful':True,'result':AgnoClient(config,folder/f'private-history-{r}.sqlite3',session).explain(evidence,d['question'])}
        except LLMError as exc:record={'successful':False,'error':{'code':exc.code,'message':str(exc)},'attempt':exc.record}
        record.update(case_id=d['id'],repetition=r,started_at=start,finished_at=timestamp(),semantic_review='pending')
        save(folder/f'attempt-{r}.json',record);v=record.get('result',record.get('attempt',{}))
        row={'case':d['id'],'repetition':r,'successful':record['successful'],'calls':v.get('attempts'),'tools':len(v.get('tool_trace',[])),
             'corrections':v.get('correction_attempts'),'usage':v.get('usage'),'elapsed':v.get('elapsed_seconds')}
        print(json.dumps(row),flush=True);return row
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows=[f.result() for f in as_completed([pool.submit(run,item) for item in prepared])]
    save(destination/'summary.json',{'finished_at':timestamp(),'rows':sorted(rows,key=lambda x:(x['case'],x['repetition'])),'semantic_review_complete':False})

if __name__=='__main__':main()
