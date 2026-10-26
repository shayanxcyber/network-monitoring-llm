"""Exact per-observation grounding and narrow reproduced-claim guards.

These checks do not solve natural-language entailment or classify threats.
Only new live replies require grounding; saved historical answers remain readable.
"""
import ast
import re
from pp_context import reference_registry

VERSION = 'packetpilot-claim-checks-1.9'

def exact_scalar(record, field, value):
    try:
        actual=record
        for key in field.split('.'):actual=actual[key]
    except (KeyError,TypeError):raise ValueError('Observation support field was not supplied: '+field+'. Use exact JSON field paths, not TShark export names.') from None
    if type(actual) is not type(value) or actual != value:
        if not (type(actual) in (int,float) and type(value) in (int,float) and actual==value):
            raise ValueError('Observation support must copy the exact supplied field/value, without coercion.')
    if type(actual) not in (int,float,bool,str):raise ValueError('Observation support needs a named scalar field, not a list or object.')

def validate_grounding(value, context, *, required=False):
    registry=reference_registry(context)
    errors=[]
    for number,row in enumerate(value.get('observations',[]),1):
        support=row.get('support',[])
        if required and not support:raise ValueError('Each observation needs support: one or more exact {reference, field, value} entries from its cited records. Use an aggregate calculating the whole property for whole-set claims.')
        seen=set()
        for fact in support:
            ref,field=fact['reference'],fact['field']
            if ref not in row['references'] or ref not in registry:raise ValueError('Observation '+str(number)+' support '+ref.rsplit(':',1)[-1]+' must also be one of that observation\'s supplied citations. Add the referenced record if it supports the text, or remove the unsupported fact.')
            if (ref,field) in seen:raise ValueError('Duplicate observation support field.')
            seen.add((ref,field))
            try:exact_scalar(registry[ref],field,fact['value'])
            except ValueError as error:errors.append(ref.rsplit(':',1)[-1]+'.'+field+': '+str(error))
        text=row['text'].lower()
        mentioned=set(re.findall(r'\b[pl][1-9][0-9]*\b',text))
        cited={r.rsplit(':',1)[-1].lower() for r in row['references']}
        if required and re.search(r'\bboth (?:rows|directions)\b|\bbidirectional (?:header|payload|data|traffic|flag)',text) and not re.search(r"\b(?:not|cannot|can't)\b",text):
            originals=[registry[r] for r in row['references'] if registry.get(r,{}).get('ipv4')]
            directions={(r['ipv4']['src'],r['ipv4']['dst']) for r in originals}
            for ref in row['references']:
                directions.update((r['source'],r['destination']) for r in registry.get(ref,{}).get('directions',[]) if 'source' in r and 'destination' in r)
            reverse=any((dst,src) in directions for src,dst in directions if src!=dst)
            if ('both rows' in text and len(originals)<2) or ('both directions' in text or 'bidirectional' in text) and not reverse:
                raise ValueError('A both-rows/both-directions observation needs both relevant original citations, or a scoped aggregate establishing the two directions. One reverse record alone cannot support the comparison.')
        if required and mentioned-cited:
            raise ValueError('Observation names original records without citing them: '+', '.join(sorted(mentioned-cited))+'. Cite every named original, or shorten the observation to the cited selection.')
        if required and context.get('input_kind')=='network_log':
            for low,high in re.findall(r'\bframe(?:s|\s+numbers?|\s+identities)?\s+([0-9]+)\s*[-\u2013]\s*([0-9]+)',text):
                low,high=int(low),int(high)
                original_values={registry[r].get('source_frame_number') for r in row['references'] if r in registry and 'source_frame_number' in registry[r]}
                aggregate=any(registry[r].get('source_frame_number_min')==low and registry[r].get('source_frame_number_max')==high and registry[r].get('source_frame_number_distinct_count')==high-low+1 for r in row['references'] if r in registry)
                if high<low or high-low>10000 or not aggregate and not set(range(low,high+1))<=original_values:
                    raise ValueError('An exported-frame range needs every supporting original or a cited aggregate with matching source_frame_number_min/max/distinct_count. A decoded-row count and one example do not prove the frame values.')
        if required and re.search(r'\b(?:all|every|each|none of)\b',text) and re.search(r'\b(?:no|zero|0|without)\s+(?:tcp\s+)?payload|payload[- ]free',text):
            aggregate_zero=any(f['field'] in ('payload_bytes_total','max_payload_bytes') and f['value']==0
                               and registry[f['reference']].get('member_count',0)>0 for f in support)
            records=[registry[r] for r in row['references'] if r in registry and ':p' in r]
            originals=context.get('packets',[])
            all_originals=(originals and {r['id'] for r in records}=={r['id'] for r in originals}
                           and not context.get('context_selection',{}).get('packets_omitted',0)
                           and all((r.get('tcp') or r.get('udp') or {}).get('payload_bytes')==0 for r in records))
            if not aggregate_zero and not all_originals:raise ValueError('A whole-set zero-payload claim needs a cited aggregate exposing payload_bytes_total/max=0 for the claimed selection, or all original member records. Relationship counts or two packet examples do not establish this property.')
    if errors:raise ValueError('Observation support errors: '+'; '.join(errors[:6]))

def narrative_texts(value):
    texts=[value.get('summary'),value.get('interpretation'),*value.get('alternatives',[]),*value.get('uncertainty',[]),*value.get('questions',[])]
    texts += [r['text'] for r in value.get('observations',[])]
    texts += [r['rationale'] for r in value.get('recommendations',[])]
    texts += (value.get('coverage') or {}).get('limitations',[])
    return [t for t in texts if isinstance(t,str)]

def validate_claim_language(value,evidence):
    from pp_semantics import validate_preview_quotes,validate_subset_cadence
    validate_preview_quotes(narrative_texts(value),evidence)
    validate_subset_cadence(narrative_texts(value),evidence)
    # Scope qualifiers stay in the same sentence/clause, not a later disclaimer.
    qualified=re.compile(r"\b(?:not|nothing|neither|nor|cannot|can't|doesn't|whether|candidate|consistent with|suggests?|may|might|could|hypothesis|hypothetical|would|insufficient)\b",re.I)
    # Match affirmative evidence assertions, not any sentence containing both
    # 'shows' and 'application success'. Questions/advice and 'unsupported' scope
    # statements are not assertions of successful application execution.
    evidence_proves_app=re.compile(r'\b(?:capture|headers?|packets?|records?|logs?|acknowledgements?|evidence|sequence|exchange|this|it)\b.{0,35}?\b(?:proves?|confirms?|establish(?:es)?|demonstrates?|shows?)\s+(?:that\s+)?(?:the\s+)?(?:application(?:-level)?\s+(?:success|(?:request\s+)?(?:succeeded|was successful|was accepted|completed successfully))|(?:http|transaction|request)\s+(?:success|succeeded|was successful|was accepted|completed successfully))\b',re.I)
    app_succeeded=re.compile(r'\b(?:application(?:-level)?(?:\s+request)?|http(?:\s+request)?|transaction|request)\s+(?:has\s+)?(?:succeeded|was\s+(?:successful|accepted)|completed\s+successfully)\b',re.I)
    log_handshake=re.compile(r'\b(?:completed?|established|successful)\s+(?:tcp\s+)?(?:handshake|connection)|\b(?:handshake|connection)\s+(?:is|was|has been)\s+(?:completed?|established|successful)',re.I)
    for text in narrative_texts(value):
        from pp_semantics import validate_semantic_wording
        validate_semantic_wording(text,evidence.get('input_kind','pcap'),evidence)
        for clause in re.split(r'[.!?;]\s+',text):
            if evidence.get('input_kind')=='network_log':
                log_payload=re.search(r'\b(?:data|payload)[- ]bearing\s+(?:segments?|traffic|packets?)|\b(?:segments?|rows?|packets?).{0,35}\b(?:carry|carried|contain|contained|transmit|transmitted)\s+(?:tcp\s+)?(?:data|payload|bytes)\b',clause,re.I)
                if log_payload and not re.search(r"\b(?:not|cannot|can't|doesn't|don't|rather than|instead of|no|may|might|could|whether|unknown)\b",clause,re.I):
                    raise ValueError('This field-log schema has no TCP payload-length field. PSH/ACK flags establish header activity, not data-bearing segments or byte delivery. Keep payload content/length unknown.')
            for proto in ('tcp','udp'):
                zero_claim=re.search(r'\bzero[- ]payload\s+'+proto+r'\b|\b'+proto+r'\b.{0,12}\b(?:carries|has|with)\s+zero\s+payload\b',clause,re.I)
                records=[p for p in evidence.get('packets',[]) if p.get('status')=='decoded' and p.get(proto)]
                if zero_claim and records and not any(p[proto]['payload_bytes']==0 for p in records) and not re.search(r"\b(?:not|no|nothing|cannot|can't|may|might|could|whether)\b",clause,re.I):
                    raise ValueError('The decoded '+proto.upper()+' records contain no zero-payload member. Do not add a contradictory zero-payload claim in another section.')
            delivery=re.search(r'\bbidirectional\s+(?:(?:byte|data|payload)\s+)?delivery\b|\b(?:byte|data|payload)\s+delivery\s+in\s+both\s+directions\b',clause,re.I)
            if delivery and not re.search(r'\b(?:not|cannot|nothing|no evidence|may|might|could|whether)\b',clause,re.I) and not all_payloads_have_candidate_ack(evidence):
                raise ValueError('Bidirectional payload transmission is not established bidirectional delivery: at least one payload has no captured candidate acknowledgement. Describe the observed segments and the exact ACK scope instead.')
            if qualified.search(clause):continue
            if evidence_proves_app.search(clause) or app_succeeded.search(clause):
                raise ValueError('Supported headers cannot establish application success. State the actual header observation and keep the application outcome unknown in the same sentence.')
            if evidence.get('input_kind')=='network_log' and log_handshake.search(clause):
                raise ValueError('A sequence-free saved field log supports a candidate/consistent-with handshake, not an unqualified completed or established connection. Keep that qualification in every section.')

def all_payloads_have_candidate_ack(evidence):
    """Conservative necessary header check, not application or stream proof."""
    records=evidence.get('packets',[])
    payloads=[(i,p) for i,p in enumerate(records) if p.get('status')=='decoded' and (p.get('tcp') or {}).get('payload_bytes',0)>0]
    if not payloads or len(payloads)>256:return False
    for index,p in payloads:
        t=p['tcp'];start=(t['sequence']+bool(t['flags']&2))%(2**32);length=t['payload_bytes'];matched=False
        for r in records[index+1:]:
            q=r.get('tcp');ip=r.get('ipv4')
            if r.get('status')!='decoded' or not q or not ip or not q['flags']&16:continue
            if (ip['src'],ip['dst'],q['src_port'],q['dst_port'])!=(p['ipv4']['dst'],p['ipv4']['src'],t['dst_port'],t['src_port']):continue
            advance=(q['acknowledgement']-start)%(2**32)
            if length<=advance<2**31:matched=True;break
        if not matched:return False
    return True

def validate_code_examples(value,context):
    registry=reference_registry(context)
    for row in value.get('code_suggestions',[]):
        if row['language']=='python':
            try:ast.parse(row['code'])
            except (SyntaxError,ValueError):raise ValueError('Suggested Python must parse; omit broken code rather than presenting it.') from None
        templates=[registry[r] for r in row['references'] if registry.get(r,{}).get('kind')=='reviewed_code_reference']
        if templates and not any(row['code']==t['code'] for t in templates):
            raise ValueError('When citing a reviewed code reference, copy its complete exact code unchanged. Adapted code cannot inherit its tested provenance.')
        if row['language']=='python' and 'frame.number' in row['code'] and ('frame.time_epoch' in row['code'] or 'tcp.srcport' in row['code']) and not templates:
            raise ValueError('For a supported TSV checker, obtain get_code_reference(topic="tsv_checker") and copy its exact complete code with that reference. Do not reinvent a partial checker or claim parser equivalence.')
