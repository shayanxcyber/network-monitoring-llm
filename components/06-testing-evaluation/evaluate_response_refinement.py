"""Six predeclared development investigations; limit experiment, not accuracy proof."""
import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_settings import api_config
from pp_evidence import analyse_capture
from pp_llm import LLMError
from pp_investigator import VERSION,timestamp
from evaluation_cases import cases


def save(path,value):
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2,ensure_ascii=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();folder=Path(args.output);folder.mkdir(parents=True,exist_ok=False)
    definitions={d['id']:d for d in cases()};config=api_config(ROOT)
    plan=[('C01',32768,180,1),('C01',65536,300,1),('C01',32768,180,2),('C01',65536,300,2),('C04',65536,300,1),('C06',65536,300,1)]
    save(folder/'manifest.json',{'started_at':timestamp(),'version':VERSION,'plan':plan,'workers':2,
        'interpretation':'Both generation allowance and request timeout vary between arms. Same revised instructions and inputs; only two repeats per normal-case arm, no reliable causal/accuracy claim. All attempts retained, no extra retries.',
        'model':config.model,'thinking':config.thinking,'reasoning_effort':config.reasoning_effort,
        'prompt_hashes':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'components/01-llm-interface/prompts').glob('*.txt')}})
    def run(item):
        case_id,budget,timeout,repetition=item; name=f'{case_id}-{budget}-{repetition}';output=folder/name;output.mkdir()
        definition=definitions[case_id];capture=output/'capture.pcap';capture.write_bytes(definition['raw'])
        evidence=analyse_capture(capture,'auto');save(output/'evidence.json',evidence)
        save(output/'started.json',{'at':timestamp(),'question':definition['question'],'capture_sha256':evidence['capture']['sha256']})
        client=AgnoClient(replace(config,max_output_tokens=budget,timeout=timeout),output/'private-history.sqlite3',str(uuid.uuid4()))
        try: result={'successful':True,'result':client.explain(evidence,definition['question'])}
        except LLMError as exc:result={'successful':False,'error':{'code':exc.code,'message':str(exc)},'attempt':exc.record}
        result.update(case_id=case_id,max_output_tokens=budget,timeout=timeout,repetition=repetition,finished_at=timestamp())
        save(output/'attempt.json',result)
        detail=result.get('result',result.get('attempt',{}))
        row={'case':name,'successful':result['successful'],'calls':detail.get('attempts'), 'usage':detail.get('usage'), 'elapsed':detail.get('elapsed_seconds')}
        print(json.dumps(row),flush=True);return row
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures=[executor.submit(run,item) for item in plan];rows=[f.result() for f in as_completed(futures)]
    save(folder/'summary.json',{'finished_at':timestamp(),'rows':rows,'semantic_review':'pending'})


if __name__=='__main__':main()
