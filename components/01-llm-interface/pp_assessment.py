"""Mechanical output checks, not a claim that every interpretation is true."""
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from jsonschema import Draft202012Validator
from pp_context import build_context, reference_registry
from pp_policy import preview_assessment_action

SCHEMA_PATH = Path(__file__).with_name('assessment-v2.schema.json')
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
SCHEMA_VERSION = '2.1'
SCHEMA_SHA256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()

def validate_assessment(value, evidence, context=None, *, allow_suggestions=False):
    if not VALIDATOR.is_valid(value):
        raise ValueError('Assessment JSON does not match the versioned schema.')
    context = context or build_context(evidence, 'Validate saved assessment.')
    if value['capture_sha256'] != evidence['capture']['sha256']:
        raise ValueError('Assessment refers to a different capture.')
    registry = reference_registry(context)
    for item in [*value['observations'], *value['recommendations']]:
        if not set(item['references']) <= set(registry):
            raise ValueError('Assessment cites absent or cross-capture evidence.')
    if evidence.get('input_kind') == 'network_log':
        partial = evidence['coverage']['decoded_records'] != evidence['coverage']['total_records']
    else:
        partial = evidence['coverage']['decoded_packets'] != evidence['capture']['packet_count']
    partial = partial or not context['context_selection']['all_detail_included']
    if value['coverage']['status'] != ('partial' if partial else 'complete_supported'):
        raise ValueError('Coverage disclosure does not match available evidence/context.')
    seen = set()
    for item in value['measurements']:
        pair = (item['reference'], item['field'])
        if pair in seen or item['reference'] not in registry:
            raise ValueError('Measurement is duplicated or references unknown evidence.')
        seen.add(pair)
        actual = registry[item['reference']]
        try:
            for key in item['field'].split('.'):
                actual = actual[key]
        except (KeyError, TypeError):
            raise ValueError('Measurement field was not supplied.') from None
        if isinstance(actual, (dict, list)) or type(actual) is not type(item['value']) or actual != item['value']:
            if not (type(actual) in (int, float) and type(item['value']) in (int, float) and actual == item['value']):
                raise ValueError('Measurement conflicts with the supplied field.')
    for recommendation in value['recommendations']:
        if not preview_assessment_action(evidence, recommendation)['allowed_preview']:
            raise ValueError('Recommendation is outside the typed preview policy.')
    def check_text(item):
        if isinstance(item, str):
            if not item.strip() or any(unicodedata.category(c).startswith('C') and c not in '\n\t' for c in item):
                raise ValueError('Invalid output text.')
            if not allow_suggestions and re.search(r'```|\b(?:sudo\s+|iptables\s+-|nft\s+add|tc\s+qdisc|rm\s+-rf|curl\s+https?://)', item, re.I):
                raise ValueError('Executable command text is not supported in advice.')
        elif isinstance(item, dict):
            for child in item.values():
                check_text(child)
        elif isinstance(item, list):
            for child in item:
                check_text(child)
    check_text(value)
    return value
