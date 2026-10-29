"""Bounded actual Agno evaluation, with predeclared cases and immutable attempt files."""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_context import build_context
from pp_evidence import analyse_capture
from pp_llm import LLMError
from pp_settings import api_config
from evaluation_cases import cases, RUBRIC

def now():
    return datetime.now(timezone.utc).isoformat()

def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--live', action='store_true', help='Explicitly authorises the bounded 18 API attempts.')
    args = parser.parse_args()
    destination = Path(args.output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    definitions = cases()
    sources = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted((ROOT / 'components').rglob('*'))
               if p.is_file() and p.suffix in ('.py', '.json', '.txt') and '__pycache__' not in p.parts}
    config = api_config(ROOT) if args.live else None
    if config:
        config.endpoint()  # validates without exposing the key
    manifest = {'recorded_at': now(), 'rubric': RUBRIC, 'source_sha256': sources,
                'environment': {'os': platform.system(), 'python': platform.python_version(),
                                **{name: importlib.metadata.version(name) for name in ('agno', 'openai', 'jsonschema', 'scapy')}},
                'configuration': {'requested_model': config.model, 'thinking': config.thinking,
                                  'reasoning_effort': config.reasoning_effort,
                                  'max_output_tokens': config.max_output_tokens,
                                  'timeout_seconds': config.timeout} if config else None,
                'live': args.live, 'repetitions': 3, 'traffic_timestamps': 'Synthetic scenario clock, not activity dates.',
                'cases': []}
    prepared = []
    for definition in definitions:
        folder = destination / definition['id']
        folder.mkdir()
        capture = folder / 'capture.pcap'
        capture.write_bytes(definition['raw'])
        evidence = analyse_capture(capture, 'auto')
        context = build_context(evidence, definition['question'])
        write(folder / 'evidence.json', evidence)
        write(folder / 'context.json', context)
        manifest['cases'].append({k: v for k, v in definition.items() if k != 'raw'} | {'sha256': evidence['capture']['sha256']})
        prepared.append((definition, folder, evidence))
    # Written before any call. Labels/scoring stay in this file, not request context.
    write(destination / 'manifest.json', manifest)
    if not args.live:
        print('Prepared six cases and fixed rubric; no API calls.', flush=True)
        return
    outcomes = []
    for definition, folder, evidence in prepared:
        for repetition in range(1, 4):
            path = folder / f'attempt-{repetition}.json'
            session = str(uuid.uuid4())
            start = now()
            # Durable start record permits interrupted attempts to be identified, not silently repeated.
            write(folder / f'attempt-{repetition}-started.json', {'started_at': start, 'session_id': session})
            client = AgnoClient(config, destination / 'isolated-agent-history.sqlite3', session)
            try:
                result = client.explain(evidence, definition['question'])
                record = {'successful': True, 'result': result}
            except LLMError as exc:
                record = {'successful': False, 'error': {'code': exc.code, 'message': str(exc)}, 'attempt': exc.record}
            record.update({'case_id': definition['id'], 'repetition': repetition, 'started_at': start, 'finished_at': now(), 'session_id': session,
                           'input_sha256': evidence['capture']['sha256'], 'semantic_review': 'pending; structural success is not evidence-support proof'})
            write(path, record)
            outcomes.append({'case_id': definition['id'], 'repetition': repetition, 'successful': record['successful'], 'file': str(path.relative_to(destination))})
            print(f'{definition["id"]} / {repetition}: {"structure accepted" if record["successful"] else record["error"]["code"]}', flush=True)
    write(destination / 'attempts-summary.json', {'finished_at': now(), 'attempts': outcomes, 'attempt_count': len(outcomes), 'semantic_review_complete': False})
    print('All 18 attempts recorded. Semantic review still required.', flush=True)

if __name__ == '__main__':
    main()
