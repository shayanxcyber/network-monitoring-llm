"""Read retained attempts; never calls a model or modifies the original result."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_llm import validate_explanation

parser = argparse.ArgumentParser()
parser.add_argument('directory')
parser.add_argument('--answers', action='store_true')
args = parser.parse_args()
for path in sorted(Path(args.directory).glob('C*/attempt-?.json')):
    item = json.loads(path.read_text())
    result = item.get('result', item.get('attempt', {}))
    evidence = json.loads((path.parent / 'evidence.json').read_text())
    context = json.loads((path.parent / 'context.json').read_text())
    raw = result.get('raw_content', '')
    try:
        validate_explanation(raw, evidence, context)
        checked = 'accepted'
    except (ValueError, KeyError) as exc:
        checked = str(exc)
    print(json.dumps({'case': item['case_id'], 'run': item['repetition'], 'original_success': item['successful'],
                      'current_validator': checked, 'finish': result.get('finish_reason'), 'tokens': result.get('usage'),
                      'seconds': result.get('elapsed_seconds'), 'answer': raw if args.answers else None}))
