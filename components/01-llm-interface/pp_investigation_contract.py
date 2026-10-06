"""Typed v3 wire output; short refs resolved before the existing domain checks."""
import copy
import hashlib
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pp_assessment import validate_assessment
from pp_context import encoded
from pp_llm import strict_json

Text = Annotated[str, Field(min_length=1, max_length=1400)]
Reference = Annotated[str, Field(min_length=1, max_length=20, pattern=r'^(capture|overview|coverage|p[1-9][0-9]*|f[1-9][0-9]*|l[1-9][0-9]*|a[a-f0-9]{16})$')]
References = Annotated[list[Reference], Field(min_length=1, max_length=16)]
Texts = Annotated[list[Text], Field(max_length=5)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Observation(StrictModel):
    text: Text = Field(description='One directly checkable observation. Every clause must be supported by the attached references; interpretations belong in interpretation.')
    references: References = Field(description='Supplied IDs supporting the ENTIRE observation. Comparisons require all involved records or an aggregate explicitly calculating the relationship.')


class Measurement(StrictModel):
    reference: Reference
    field: Annotated[str, Field(max_length=120, pattern=r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$', description='Existing scalar field path from that exact supplied record; consult measurement_fields. No invented paths or list indices.')]
    value: int | float | bool | Annotated[str, Field(max_length=120)]


class Recommendation(StrictModel):
    action: Literal['investigate', 'no_action', 'block_source']
    target: Annotated[str, Field(max_length=15)] | None
    duration_seconds: Annotated[int, Field(ge=1, le=120)] | None
    rationale: Text
    references: References


class Coverage(StrictModel):
    status: Literal['partial', 'complete_supported']
    limitations: Annotated[list[Text], Field(min_length=1, max_length=5)]


class InvestigationAnswer(StrictModel):
    schema_version: Literal['3.0']
    capture_sha256: Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
    assessment: Literal['normal_observations', 'suspicious_observations', 'inconclusive']
    summary: Text = Field(description='Direct answer to the operator question, normally two short sentences; do not repeat every observation or add unsupported details.')
    observations: Annotated[list[Observation], Field(min_length=1, max_length=8)]
    interpretation: Text = Field(description='Meaning of the supported observations, with relevant alternatives qualified as hypotheses; never treat unknown intent as established.')
    alternatives: Texts
    uncertainty: Annotated[list[Text], Field(min_length=1, max_length=5)]
    coverage: Coverage
    measurements: Annotated[list[Measurement], Field(max_length=12)]
    recommendations: Annotated[list[Recommendation], Field(min_length=1, max_length=4)]
    questions: Texts


class Recommendation4(StrictModel):
    action: Annotated[str, Field(pattern=r'^[a-z][a-z_]{1,40}$')]
    target: Annotated[str, Field(max_length=15)] | None = None
    destination: Annotated[str, Field(max_length=15)] | None = None
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    duration_seconds: Annotated[int, Field(ge=5, le=120)] | None = None
    rate_kbit: Annotated[int, Field(ge=256, le=2048)] | None = None
    rationale: Text
    references: References


class CodeSuggestion(StrictModel):
    title: Annotated[str, Field(min_length=1, max_length=100)]
    language: Literal['sh', 'python', 'text']
    code: Annotated[str, Field(min_length=1, max_length=6000)]
    target: Annotated[str, Field(max_length=120)] | None = None
    assumptions: Texts
    expected_effect: Text
    reversal: Text
    references: References
    # This label is fixed, not something the model may upgrade to executable.
    status: Literal['unverified_example'] = 'unverified_example'


class WorkspaceAnswer(StrictModel):
    """v4 permits conversation without fake observations; investigations stay cited."""
    schema_version: Literal['4.0']
    kind: Literal['conversation', 'investigation']
    capture_sha256: Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
    summary: Text
    assessment: Literal['normal_observations', 'suspicious_observations', 'inconclusive'] | None = None
    observations: Annotated[list[Observation], Field(max_length=8)] = []
    interpretation: Text | None = None
    alternatives: Texts = []
    uncertainty: Annotated[list[Text], Field(max_length=5)] = []
    coverage: Coverage | None = None
    measurements: Annotated[list[Measurement], Field(max_length=12)] = []
    recommendations: Annotated[list[Recommendation4], Field(max_length=4)] = []
    questions: Texts = []
    code_suggestions: Annotated[list[CodeSuggestion], Field(max_length=3)] = []
    views: Annotated[list['EvidenceView'], Field(max_length=3)] = []


class EvidenceView(StrictModel):
    type: Literal['table', 'timeline', 'map', 'comparison', 'bar', 'line', 'area']
    references: Annotated[list[Reference], Field(max_length=16)] = []


WorkspaceAnswer.model_rebuild()


SCHEMA_SHA256 = hashlib.sha256(encoded(InvestigationAnswer.model_json_schema())).hexdigest()
WORKSPACE_SCHEMA_SHA256 = hashlib.sha256(encoded(WorkspaceAnswer.model_json_schema())).hexdigest()


def validate_final(raw, workspace):
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 32_000:
        raise ValueError('Final JSON must be present and at most 32000 bytes.')
    try:
        parsed = strict_json(raw)
        model = WorkspaceAnswer if parsed.get('schema_version') == '4.0' else InvestigationAnswer
        value = model.model_validate(parsed).model_dump()
    except ValidationError as exc:
        # Do not echo arbitrary model text in corrective instructions.
        fields = [('.'.join(map(str, e['loc'])), e['type']) for e in exc.errors(include_input=False, include_url=False)]
        raise ValueError('Schema errors (field, constraint): ' + str(fields[:8])) from None
    original = copy.deepcopy(value)
    for row in [*value['observations'], *value['recommendations'], *value.get('code_suggestions', [])]:
        row['references'] = [_resolve(ref, workspace) for ref in row['references']]
    for row in value['measurements']:
        row['reference'] = _resolve(row['reference'], workspace)
    for view in value.get('views', []):
        view['references'] = [_resolve(ref, workspace) for ref in view['references']]
    if value['schema_version'] == '4.0':
        validate_workspace_domain(value, workspace.evidence, workspace.validation_context())
        return value, original
    value['schema_version'] = '2.0'
    validate_assessment(value, workspace.evidence, workspace.validation_context())
    value['schema_version'] = '3.0'
    return value, original


def _resolve(ref, workspace):
    if ref not in workspace.supplied:
        raise ValueError('Reference was not supplied by current context/tools. Cite known short IDs only.')
    return workspace.supplied[ref]['id']


def validate_saved_assessment(value, evidence, context):
    """Validate canonical v3 refs against the turn's retained supplied-evidence view."""
    if value.get('schema_version') == '4.0':
        wire = copy.deepcopy(value)
        flow_aliases = {flow['id']: f'f{i}' for i, flow in enumerate(evidence.get('flows', []), 1)}
        def short_ref(reference):
            return flow_aliases.get(reference, reference.rsplit(':', 1)[-1])
        for row in [*wire['observations'], *wire['recommendations'], *wire['code_suggestions']]:
            row['references'] = [short_ref(ref) for ref in row['references']]
        for row in wire['measurements']: row['reference'] = short_ref(row['reference'])
        for view in wire.get('views', []): view['references'] = [short_ref(ref) for ref in view['references']]
        WorkspaceAnswer.model_validate(wire)
        validate_workspace_domain(value, evidence, context)
        return value
    if value.get('schema_version') != '3.0':
        return validate_assessment(value, evidence, context)
    checked = copy.deepcopy(value)
    checked['schema_version'] = '2.0'
    validate_assessment(checked, evidence, context)
    return value


def validate_workspace_domain(value, evidence, context):
    """Canonical-reference checks; old v2/v3 evidence remains under its old rules."""
    from pp_context import reference_registry
    from pp_response_operations import CAPABILITIES, validate_parameters
    import ipaddress
    import unicodedata
    if value['capture_sha256'] != evidence['capture']['sha256']:
        raise ValueError('Answer refers to another selected source.')
    if value['kind'] == 'conversation':
        if (any(value.get(k) for k in ('observations', 'recommendations', 'measurements', 'code_suggestions',
                                 'alternatives', 'uncertainty', 'questions', 'views'))
                or any(value[k] is not None for k in ('assessment', 'interpretation', 'coverage'))):
            raise ValueError('A conversational reply cannot contain an unsupported investigation report or action.')
        return value
    if not value['observations'] or value['coverage'] is None or value['assessment'] is None or not value['interpretation'] or not value['uncertainty']:
        raise ValueError('An investigation needs observations, assessment, interpretation, uncertainty and exact coverage.')
    registry = reference_registry(context)
    for view in value.get('views', []):
        # Rendering selections may inspect original records/flows only, not
        # model-authored values or an aggregate as if it were a raw packet.
        raw_ids = {r['id'] for r in evidence.get('packets', []) + evidence.get('log_records', []) + evidence.get('flows', [])}
        if len(set(view['references'])) != len(view['references']) or not set(view['references']) <= raw_ids & set(registry):
            raise ValueError('View selections must use unique supplied original record or flow IDs.')
    for row in [*value['observations'], *value['recommendations'], *value['code_suggestions']]:
        refs = row['references']
        if not refs or len(set(refs)) != len(refs) or not set(refs) <= set(registry):
            raise ValueError('References must be unique and supplied for this source/turn.')
    for recommendation in value['recommendations']:
        operation = recommendation['action']
        if operation not in CAPABILITIES: raise ValueError('Use a supplied capability ID; unsupported requests need an unavailable capability explanation.')
        if operation in ('block_source', 'rate_limit_service'):
            # Offline examples may recommend another observed host, but are not executable.
            observed = set()
            for p in evidence.get('packets', []):
                if p.get('ipv4') and p.get('status') == 'decoded': observed.add(p['ipv4']['src'])
            for row in evidence.get('log_records', []):
                if row.get('ip_src'): observed.add(row['ip_src'])
                if row.get('ipv4'): observed.add(row['ipv4']['src'])
            if recommendation['target'] not in observed:
                raise ValueError('Recommended source must be observed, not an invented execution target.')
            ipaddress.IPv4Address(recommendation['target'])
            if recommendation['destination'] is None or recommendation['port'] is None or recommendation['duration_seconds'] is None:
                raise ValueError('An actionable recommendation needs an explicit service, port and duration.')
            ipaddress.IPv4Address(recommendation['destination'])
            if operation == 'rate_limit_service' and recommendation['rate_kbit'] is None:
                raise ValueError('A rate-limit recommendation needs an explicit rate.')
            if operation == 'block_source' and recommendation['rate_kbit'] is not None:
                raise ValueError('A block cannot carry a rate.')
        elif any(recommendation[k] is not None for k in ('target', 'destination', 'port', 'duration_seconds', 'rate_kbit')):
            raise ValueError('Non-executing advice must not carry unrelated execution parameters.')
    # Reuse the mature exact coverage/measurement checks, without the historical command ban.
    checked = {k: copy.deepcopy(value[k]) for k in InvestigationAnswer.model_fields if k != 'schema_version'}
    checked['schema_version'] = '2.0'
    checked['recommendations'] = [dict(action='investigate', target=None, duration_seconds=None,
                                     rationale=r['rationale'], references=r['references']) for r in value['recommendations']]
    if not checked['recommendations']:
        checked['recommendations'] = [dict(action='no_action', target=None, duration_seconds=None,
                                         rationale='No change requested.', references=value['observations'][0]['references'])]
    validate_assessment(checked, evidence, context, allow_suggestions=True)
    def text_check(item):
        if isinstance(item, str) and any(unicodedata.category(c).startswith('C') and c not in '\n\t' for c in item):
            raise ValueError('Control characters are not allowed in suggested code or text.')
        if isinstance(item, dict):
            for child in item.values(): text_check(child)
        if isinstance(item, list):
            for child in item: text_check(child)
    text_check(value)
    return value
