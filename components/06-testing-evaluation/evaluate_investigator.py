"""Declared investigator evaluation; exclusive records, independent conversations."""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_evidence import analyse_capture
from pp_investigation_tools import EvidenceWorkspace
from pp_investigator import VERSION, timestamp, MAX_MODEL_CALLS
from pp_llm import LLMError
from pp_settings import api_config
from evaluation_cases import cases, RUBRIC
from investigation_cases import contrasting_cases


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--suite', choices=['smoke', 'comparison'], required=True)
    args = parser.parse_args()
    destination = Path(args.output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    definitions = cases() + contrasting_cases()
    if args.suite == 'smoke':
        definitions = [contrasting_cases()[1]]
    prepared = []
    config = api_config(ROOT) if args.live else None
    if config:
        config.endpoint()
    for definition in definitions:
        folder = destination/definition['id']
        folder.mkdir()
        capture = folder/'capture.pcap'
        capture.write_bytes(definition['raw'])
        evidence = analyse_capture(capture, 'auto')
        write(folder/'evidence.json', evidence)
        write(folder/'initial-context.json', EvidenceWorkspace(evidence, definition['question']).context)
        for repetition in range(1, (3 if definition['id'].startswith('C') else 1)+1):
            prepared.append((definition, folder, evidence, repetition))
    source_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted((ROOT/'components').rglob('*'))
                     if p.is_file() and p.suffix in ('.py', '.txt', '.json') and '__pycache__' not in p.parts}
    rubric = RUBRIC | {'repair_policy': 'At most one retained final-contract correction, no transport retry; all tool/provider calls counted.',
        'tool_correctness': 'Inspect actual calls/results; V02 requires unseen tail packets. No tool needed when initial evidence suffices.',
        'continuity': 'Separate smoke follow-up verifies genuine provider reasoning/tool history and capture-specific state.',
        'review': 'Read every final answer, including failed attempts, against facts and claim-level cited records. Developer review, not independent human detection accuracy.'}
    write(destination/'manifest.json', {'started_at': timestamp(), 'suite': args.suite, 'harness_version': VERSION,
        'sources': source_hashes, 'rubric': rubric, 'live': args.live, 'investigations_planned': len(prepared),
        'max_model_calls_per_investigation': MAX_MODEL_CALLS, 'workers': 1 if args.suite == 'smoke' else 3,
        'configuration': {'model': config.model, 'thinking': config.thinking, 'reasoning_effort': config.reasoning_effort,
                          'max_output_tokens': config.max_output_tokens, 'timeout': config.timeout} if config else None,
        'environment': {'os': platform.system(), 'python': platform.python_version(),
                        **{n: importlib.metadata.version(n) for n in ('agno', 'openai', 'scapy', 'pydantic')}},
        'cases': [{k: v for k, v in d.items() if k != 'raw'} for d in definitions]})
    if not args.live:
        print('Prepared cases and manifest; no model calls.')
        return
    def run(item):
        definition, folder, evidence, repetition = item
        session = str(uuid.uuid4())
        start = timestamp()
        write(folder/f'attempt-{repetition}-started.json', {'started_at': start, 'session': session})
        client = AgnoClient(config, folder/f'private-history-{repetition}.sqlite3', session)
        try:
            result = client.explain(evidence, definition['question'])
            record = {'successful': True, 'result': result}
        except LLMError as exc:
            record = {'successful': False, 'error': {'code': exc.code, 'message': str(exc)}, 'attempt': exc.record}
        record.update(case_id=definition['id'], repetition=repetition, session_id=session,
                      started_at=start, finished_at=timestamp(), semantic_review='pending')
        write(folder/f'attempt-{repetition}.json', record)
        detail = record.get('result', record.get('attempt', {}))
        status = {'case_id': definition['id'], 'repetition': repetition, 'successful': record['successful'],
                  'model_calls': detail.get('attempts', 0), 'tool_calls': len(detail.get('tool_trace', [])),
                  'corrections': detail.get('correction_attempts', 0)}
        print(json.dumps(status), flush=True)
        if args.suite == 'smoke' and record['successful']:
            followup_start = timestamp()
            write(folder/'followup-started.json', {'started_at': followup_start, 'session': session})
            try:
                followup = {'successful': True, 'result': client.explain(evidence, 'Summarise what we established about those two packets and what remains uncertain. Do not repeat unnecessary inspections.')}
            except LLMError as exc:
                followup = {'successful': False, 'error': {'code': exc.code, 'message': str(exc)}, 'attempt': exc.record}
            write(folder/'followup.json', followup | {'started_at': followup_start, 'finished_at': timestamp()})
            print('Smoke follow-up successful: '+str(followup['successful']), flush=True)
        return status
    with ThreadPoolExecutor(max_workers=1 if args.suite == 'smoke' else 3) as executor:
        futures = [executor.submit(run, item) for item in prepared]
        statuses = [future.result() for future in as_completed(futures)]
    write(destination/'summary.json', {'finished_at': timestamp(), 'results': sorted(statuses, key=lambda x:(x['case_id'], x['repetition'])),
                                      'semantic_review_complete': False})


if __name__ == '__main__':
    main()
