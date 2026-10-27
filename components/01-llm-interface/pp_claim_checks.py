"""Exact per-observation grounding and narrow reproduced-claim guards.

These checks do not solve natural-language entailment or classify threats.
Only new live replies require grounding; saved historical answers remain readable.
"""
import ast
import re
from pp_context import reference_registry

VERSION = 'packetpilot-claim-checks-3.17'


def claim_clauses(text):
    """Public sentence boundaries without splitting addresses or DNS labels.

    Original IDs legitimately start sentences in lowercase. Their local subject
    must not inherit a whole-source subject from the preceding sentence.
    """
    return re.split(r'[!?;]\s*|\.(?=\s+(?:[A-Z]|[pl][1-9][0-9]*\b))',text)


def negative_proof_prefix(prefix):
    """Explicit lack-of-proof governs only the caller's local assertion.

    Modifiers such as by itself do not turn a negated proof into a positive
    event. Callers still separate independent subjects before using this check.
    """
    proof=r'(?:prov(?:e|ing)|show(?:ing)?|establish(?:ing)?|confirm(?:ing)?|demonstrat(?:e|ing))'
    modifiers=r'(?:(?:by itself|on its own|alone|independently|necessarily|directly|actually|fully|yet)\s+){0,2}'
    if re.search(r'\b(?:(?:does|do|did)\s+not|cannot|can\x27t)\s+'+modifiers+proof+r'\b',prefix,re.I):return True
    if re.search(r'\brather\s+than\s+'+modifiers+proof+r'\b',prefix,re.I):return True
    return bool(re.search(r'\b(?:no|without|not)\s+(?:a\s+)?(?:proof|evidence|proving|showing|confirming|establishing|demonstrating)\b',prefix,re.I))


def _qualified_udp_receipt(clause, match):
    """Receipt uncertainty belongs to this assertion, not an earlier fact.

    Unknown capture placement does not negate a later receipt claim. Preserve
    explicit lack-of-proof wording, including qualification after the object.
    This narrow guard is not a general natural-language entailment checker.
    """
    prefix=clause[:match.start('receipt')]
    tail=clause[match.end():]
    if re.search(r'\b(?:whether|hypothetical)\b',prefix,re.I):return True
    if re.search(r'\b(?:may|might|could)\s+(?:not\s+)?(?:have\s+)?(?:been\s+)?$',prefix,re.I):return True
    if re.search(r'\b(?:not|never)\s+(?:actually\s+|yet\s+)?$',prefix,re.I):return True
    if re.search(r'\bnot\s+that\b',prefix,re.I):return True
    if re.search(r'\brather\s+than\s+(?:proof|evidence)\s+(?:that\s+)?',prefix,re.I):return True
    if negative_proof_prefix(prefix):return True
    if re.search(r'\b(?:rather\s+than|not)\s+(?:proven|confirmed|established|known)(?:\s+to\s+(?:have\s+been|be))?\s*$',prefix,re.I):return True
    return bool(re.search(r'^\s*(?:is|was|has\s+been|remains?)\s+(?:not\s+(?:established|proven|confirmed|known|shown)|unknown|unconfirmed)\b',tail,re.I))


def validate_observation_bounds(text,evidence):
    """Narrow checks for reproduced observation/receipt/window contradictions.

    This is not a general language or causal judge. Only identify a numerical
    end offset when the anchor record or unambiguous last-kind is available.
    Preserve legitimate field listings, unknown values and qualified hypotheses.
    """
    from decimal import Decimal
    log=evidence.get('input_kind')=='network_log'
    originals=evidence.get('log_records' if log else 'packets',[])
    dated=[r for r in originals if r.get('timestamp') is not None]
    if not dated:return
    end=max(Decimal(r['timestamp']) for r in dated)
    tcp=[r for r in originals if r.get('status')=='decoded' and r.get('tcp')]
    udp=[r for r in originals if r.get('status')=='decoded' and r.get('udp')]
    qualified=re.compile(r"\b(?:not|no|nothing|neither|nor|cannot|can't|whether|unknown|unconfirmed|may|might|could|hypothetical)\b",re.I)
    offset=re.compile(r'\b(?:window|capture|source)\s+(?:ends?|ended|stops?|stopped)\s+(?:only\s+|about\s+|approximately\s+)?([0-9]+(?:\.[0-9]+)?)\s*(milliseconds?|microseconds?|seconds?|ms|us|s)\s+(?:after|beyond|past)\s+(?:the\s+)?((?:(?:final|last|client|server|service|handshake)(?:[\u2019\']s)?\s+)*)?(ACK|acknowledgement|response|reply|[pl][1-9][0-9]*)\b',re.I)
    # A fully qualified DNS name can end in a dot followed by "and received".
    # Do not lose its subject by treating that DNS suffix as a sentence end.
    for clause in re.split(r'[!?;]\s+|\.(?=\s+[A-Z])',text):
        automation=re.search(r'\b(?:cadence|spacing|repetition|identical requests|regular pattern)\s+(?:alone\s+|only\s+)?(?:proves?|demonstrates?|establishes?|confirms?|indicates?)\s+(?:automation|automated (?:origin|activity|generation))\b',clause,re.I)
        if automation and not qualified.search(clause[max(0,automation.start()-30):automation.start()]):
            raise ValueError('Observed regularity does not prove automation or traffic origin. Keep the measured repetition/spacing and describe automation as a consistent-with hypothesis, not an established fact.')
        offset_clause=re.sub(r'\b(window|capture|source)\s+starts?\b.{0,180}?\band\s+(ends?|ended|stops?|stopped)\b',r'\1 \2',clause,flags=re.I)
        for m in offset.finditer(offset_clause):
            # An earlier independent "capture point is not established" does
            # not negate a later affirmative numeric claim joined with "and".
            prefix=re.split(r'\b(?:and|but)\b|,\s+',offset_clause[:m.start()],flags=re.I)[-1]
            if qualified.search(prefix[-60:]):continue
            anchor=m[4].lower()
            if re.fullmatch(r'[pl][1-9][0-9]*',anchor):
                candidates=[r for r in dated if r['id'].rsplit(':',1)[-1].lower()==anchor]
            elif anchor in ('ack','acknowledgement'):
                candidates=[r for r in tcp if r.get('timestamp') is not None and r['tcp']['flags']==16]
                descriptor=(m[3] or '').lower()
                if 'handshake' in descriptor:
                    from pp_tcp_relationships import analyse_tcp_exchanges
                    final_ids={x.get('final_ack_reference') for x in analyse_tcp_exchanges(evidence).get('exchanges',[])}
                    candidates=[r for r in candidates if r['id'] in final_ids]
                if re.search(r'\b(?:client|server|service)\b',descriptor):
                    def key(r):return (r['ipv4']['src'],r['ipv4']['dst'],r['tcp']['src_port'],r['tcp']['dst_port'])
                    initiators={key(r) for r in tcp if r['tcp']['flags'] & 0x12==2}
                    allowed=initiators if 'client' in descriptor else {(d,s,dp,sp) for s,d,sp,dp in initiators}
                    candidates=[r for r in candidates if key(r) in allowed]
            else:
                candidates=[r for r in dated if (r.get('application') or {}).get('message')=='response' or (r.get('application') or {}).get('response') is True]
            if not candidates or len(candidates)>1 and not m[3]:continue
            actual=end-max(Decimal(r['timestamp']) for r in candidates)
            unit=m[2].lower();scale=Decimal('0.001') if unit.startswith('m') else Decimal('0.000001') if unit.startswith('u') else Decimal(1)
            stated=Decimal(m[1])*scale
            rounding=Decimal(1).scaleb(Decimal(m[1]).as_tuple().exponent)*scale/2
            if abs(actual-stated)>rounding:
                raise ValueError('The stated interval after the final observed record conflicts with the source end. Subtract the actual identified anchor timestamp from source_window_last_timestamp; source duration or reply delay is not extra time after that record.')
        # Require a finite verb agreeing with its subject. "A documented
        # session close" names an event; it does not assert that event occurred.
        closures=re.finditer(r'\b(?:(?:session|connection)\s+(?:ends|ended|closes|closed|terminates|terminated)|(?:sessions|connections)\s+(?:end|ended|close|closed|terminate|terminated)|(?:session|connection)\s+(?:end|close|termination)\s+(?:that\s+)?(?:coincides|occurs|happens|matches))\b',clause,re.I)
        for closure in closures:
            prefix=clause[:closure.start()]
            governing=re.split(r'\b(?:and|but|however|yet)\b',prefix,flags=re.I)[-1]
            following=re.split(r'\b(?:but|however|yet)\b',clause[closure.end():closure.end()+120],flags=re.I)[0]
            unresolved=bool(re.search(r'\b(?:how|when|whether)\b',governing[-40:],re.I) and re.search(r'\b(?:unknown|unobserved|unestablished|not established|not observed|outside\s+(?:(?:this|the|saved|observed)\s+){0,3}(?:evidence|observations|window|capture))\b',following,re.I))
            unresolved=unresolved or bool(re.search(r'\b(?:how|when|whether)\b',governing[-40:],re.I) and re.search(r"\b(?:nothing|no evidence|cannot|does not|do not|not established)\b",governing,re.I))
            negated_proof=bool(re.search(r'\b(?:rather than\s+(?:proof|evidence)|not\s+(?:a\s+)?(?:proof|proven)|no\s+(?:proof|evidence))\b',governing,re.I))
            negated_proof=negated_proof or bool(re.search(r'\b(?:does|do|did)\s+not\s+(?:show|establish|prove|confirm|demonstrate)\b',governing,re.I))
            if not unresolved and not negated_proof and not qualified.search(governing[-50:]+closure[0]) and tcp and not any(r['tcp']['flags']&5 for r in tcp):
                raise ValueError('A last observed record is not a session close. No FIN/RST is observed in these decoded TCP records; describe the observation-window boundary without asserting connection termination.')
        outside=re.search(r'\bteardown\s+(?:lies?|falls?|sits?|occurs?|is|was|would\s+(?:lie|fall|sit|occur|be))\s+(?:outside|beyond)\s+(?:(?:the|this|that)\s+)?(?:(?:saved|capture|observation|collection|time)\s+){0,2}(?:window|period|time bounds)\b',clause,re.I)
        if outside and not qualified.search(clause[max(0,outside.start()-40):outside.end()]) and tcp and not any(r['tcp']['flags']&5 for r in tcp):
            raise ValueError('Missing captured teardown does not prove teardown happened outside the window. It is unobserved; missing capture visibility may also occur within the collection period.')
        if udp and (not tcp or re.search(r'\b(?:UDP|DNS|datagram)\b',clause,re.I)):
            receiver=r'(?:client|requester|host|(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
            # Do not let a qualified first assertion license an independently
            # asserted receipt after "but" or "and the client".
            parts=re.split(r'\b(?:but|however|yet)\b|\band\s+(?=(?:the\s+)?'+receiver+r'\b)|,\s*(?:(?:and|so)\s+)?(?=(?:the\s+)?'+receiver+r'\b)',clause,flags=re.I)
            for part in parts:
                delivered=re.finditer(r'\b'+receiver+r'\b.{0,320}?\b(?P<receipt>received|receives|gets|got|obtained)\b.{0,70}?\b(?:response|reply|answer|datagram|it)\b',part,re.I)
                if any(not _qualified_udp_receipt(part,m) for m in delivered):
                    raise ValueError('A captured UDP response addressed to the client does not establish client receipt at an unknown capture point. Describe the observed matching response and timestamp gap; endpoint reception needs separate evidence.')


def validate_window_end_claims(text,evidence):
    """Check explicit service/window assertions, not general natural language.

    A tuple can end before the source ends. A later ACK might be absent because
    of filtering/loss even while other flows remain visible. No hidden scenario
    label or expected model finding is used.
    """
    from decimal import Decimal
    rows=[r for r in evidence.get('packets',[]) if r.get('status')=='decoded' and r.get('tcp')]
    if not rows:return
    originals=evidence.get('packets',[])
    times=[Decimal(r['timestamp']) for r in originals if r.get('timestamp') is not None]
    if not times:return
    end=max(times)
    starts=[r for r in rows if r['tcp']['flags'] & 0x12==2]
    def tuple_key(r):return (r['ipv4']['src'],r['ipv4']['dst'],r['tcp']['src_port'],r['tcp']['dst_port'])
    services={}
    for syn in starts:
        src,dst,sp,dp=tuple_key(syn);keys={(src,dst,sp,dp),(dst,src,dp,sp)}
        last=max(Decimal(r['timestamp']) for r in rows if tuple_key(r) in keys)
        services.setdefault(dp,[]).append(last)
    for clause in re.split(r'[;!?]|\.(?=\s+[A-Z])',text):
        if re.search(r'\b(?:not|cannot|could|may|might|whether|hypothetical)\b',clause,re.I):continue
        ending=re.search(r'\bends?\s+(?:with|at)\s+(?:the\s+)?(?:capture|(?:saved\s+)?(?:observation\s+)?window)\b',clause,re.I)
        if ending:
            patterns=(r'\b(?:port[- ]*|TCP/)([0-9]+)\s+(?:flow|connection|exchange)\b',r'\b(?:flow|connection|exchange)\s+(?:on|to|using)\s+(?:TCP/|port\s*)([0-9]+)\b')
            ports=[int(m[1]) for p in patterns for m in re.finditer(p,clause,re.I)]
            for port in ports:
                if port in services and all(last<end for last in services[port]):
                    raise ValueError('The named service flow does not end with the saved source. Keep tuple_last_timestamp and source_window_last_timestamp distinct, and keep the same service/flow in observations and interpretation.')
        forced=re.search(r'\b(?:any|all|every)\b.{0,80}\back(?:nowledg(?:e)?ment)?s?\b.{0,100}\b(?:would|must)\b.{0,35}\boutside\b',clause,re.I)
        if forced and any((r['tcp'].get('payload_bytes') or 0)>0 and Decimal(r['timestamp'])<end for r in rows):
            raise ValueError('A missing ACK for every earlier payload is not forced outside the entire source window. Some payloads precede its end; filtering/loss or other missing visibility remain possible. Only a specifically identified final record bounds its own later ACK.')


def named_zero_payload_subject(text, cited_records):
    """A literal listed subject is a subset, not an assertion about all frames.

    Only an initial pN list directly quantified by each/all is recognised. A
    whole-capture assertion followed by a few examples cannot use this path.
    Every listed original must be cited and actually have known zero payload.
    """
    names=r'p[1-9][0-9]*(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+|\s*/\s*)p[1-9][0-9]*)*'
    match=re.match(r'^\s*('+names+r')\s+(?:each|all)\b',text,re.I)
    if not match:match=re.match(r'^\s*(?:each|all)\s+of\s+('+names+r')\b',text,re.I)
    if not match:return False
    labels=set(re.findall(r'\bp[1-9][0-9]*\b',match[1].lower()))
    by_name={r['id'].rsplit(':',1)[-1].lower():r for r in cited_records}
    return bool(labels) and labels<=set(by_name) and all(
        (by_name[name].get('tcp') or by_name[name].get('udp') or {}).get('payload_bytes')==0 for name in labels)


def payload_role_lengths(evidence):
    """Observed initiator/responder payload sizes, never inferred from IP order."""
    rows=[r for r in evidence.get('packets',[]) if r.get('status')=='decoded' and r.get('tcp')]
    def key(r):return (r['ipv4']['src'],r['ipv4']['dst'],r['tcp']['src_port'],r['tcp']['dst_port'])
    starts={key(r) for r in rows if r['tcp']['flags'] & 0x12 == 2}
    reverse={(d,s,dp,sp) for s,d,sp,dp in starts}
    result={'client':set(),'server':set()}
    for r in rows:
        k=key(r);n=r['tcp']['payload_bytes']
        # A tuple can occur in both roles after reuse/simultaneous initiation.
        # Do not impose a client/server label on an ambiguous selection.
        if not n or k in starts and k in reverse:continue
        if k in starts:result['client'].add(n)
        elif k in reverse:result['server'].add(n)
    return result


def validate_explicit_payload_origin(text, roles):
    """Catch explicit role/size reversals across every answer section.

    Narrow necessary check only. It does not classify intent, prove receipt or
    determine general prose entailment. ACK-sender statements are not ownership.
    """
    patterns=[
        (re.compile(r"\b(client|server)['\u2019]s\s+own\s+(?:bytes|payload|data)(?:\s+(?:exist|are))?\s*(?:\(\s*(?:the\s+)?)?([0-9]+)[- ]byte",re.I),False),
        (re.compile(r"\b(client|server)['\u2019]s\s+(?:own\s+)?([0-9]+)[- ]byte\s+(?:responses?|requests?|payload|data|segments?|bodies)\b",re.I),False),
        (re.compile(r'\b(client|server)[- ]origin(?:ated|ating)?\s+([0-9]+)[- ]byte',re.I),False),
        (re.compile(r'\b([0-9]+)[- ]byte\s+(client|server)[- ]origin(?:ated|ating)?\b',re.I),True),
    ]
    for expression,inverse in patterns:
        for match in expression.finditer(text):
            role,n=(match[2].lower(),int(match[1])) if inverse else (match[1].lower(),int(match[2]))
            before=text[max(0,match.start()-36):match.start()]
            if re.search(r"\b(?:not|no|cannot|could|may|might|hypothetical|whether)\b",before,re.I):continue
            other='server' if role=='client' else 'client'
            if n not in roles[role] and n in roles[other]:
                raise ValueError('Explicit '+role+'-origin '+str(n)+'-byte payload conflicts with the observed SYN-direction payload roles. ACK sender and byte origin differ: inspect the actual data origin and keep that direction consistent in every section.')


def http_status_source_counts(cited,originals,code):
    """Known status counts per original source, not pooled across operands.

    Case comparisons contain two explicitly labelled service-fact branches.
    A single branch/example cannot certify a both-sources claim.
    """
    counts={};ids={}
    for r in originals:
        if (r.get('application') or {}).get('status_code')==code:
            digest=r['id'].split(':')[0];ids.setdefault(digest,set()).add(r['id'])
    counts.update({digest:len(members) for digest,members in ids.items()})
    for r in cited:
        facts=r.get('original',r)
        branches=[facts]+[facts[k] for k in ('baseline','comparison') if isinstance(facts.get(k),dict)]
        for branch in branches:
            digest=branch.get('source_sha256')
            if not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest):continue
            n=branch.get('visible_http_response_status_counts',{}).get('status_'+str(code),0)
            if type(n) is int and n>=0:counts[digest]=max(counts.get(digest,0),n)
            exchanges=branch.get('candidate_exchanges',[])
            members={x['response'] for x in exchanges if x.get('protocol')=='HTTP' and x.get('status_code')==code}
            counts[digest]=max(counts.get(digest,0),len(members))
    return counts


def validate_relational_support(row, registry, context):
    """Necessary, narrow citation checks, not a general entailment judge."""
    cited=[registry[r] for r in row['references'] if r in registry]
    originals=[r.get('original',r) for r in cited if r.get('ipv4') or r.get('kind')=='case_original_record']
    log=context.get('input_kind')=='network_log'
    handshake=re.compile(r'\b(?:complete(?:d)?|successful|established)\s+(?:the\s+)?(?:tcp\s+)?(?:three-way\s+)?handshake\b|\b(?:completes?|completing|establish(?:es|ing))\s+(?:the\s+)?(?:tcp\s+)?(?:three-way\s+)?handshake\b|\bhandshake\s+(?:is|was|has been)\s+(?:completed?|established)\b',re.I)
    for clause in re.split(r'[.!?;]\s+',row['text']):
        claim=handshake.search(clause)
        if claim and not re.search(r"\b(?:no|not|neither|without|cannot|unverified|unconfirmed)\b",clause[max(0,claim.start()-28):claim.start()],re.I):
            log=context.get('input_kind')=='network_log'
            key='syns_with_candidate_handshake' if log else 'syns_with_sequence_matched_handshake'
            aggregate_matched=any(type(r.get(key)) is int and r[key]>0 for r in cited)
            matched=aggregate_matched;original_count=0
            if not aggregate_matched and originals:
                from pp_tcp_relationships import analyse_tcp_exchanges
                groups={}
                for r in originals:groups.setdefault(r['id'].split(':')[0],[]).append(r)
                for digest,members in groups.items():
                    selected={'capture':{'sha256':digest},'input_kind':'network_log' if log else 'pcap','log_records' if log else 'packets':members}
                    original_count+=analyse_tcp_exchanges(selected)[key]
                matched=original_count>0
            if not matched:
                raise ValueError('A handshake-completion observation needs its supporting SYN, reverse SYN-ACK and final ACK citations, or a cited inspector aggregate with the matching handshake result. The final ACK alone cannot support the whole relationship.')
            quantified=re.search(r'\ball\s+(?:the\s+)?(two|three|four|five|six|seven|eight|nine|ten|[0-9]+)\b',clause,re.I)
            words={'two':2,'three':3,'four':4,'five':5,'six':6,'seven':7,'eight':8,'nine':9,'ten':10}
            needed=words.get(quantified[1].lower(),int(quantified[1]) if quantified and quantified[1].isdigit() else 0) if quantified else 0
            if needed and not aggregate_matched and original_count<needed:
                raise ValueError('A quantified all-handshakes claim needs all claimed triplets or the scoped matching inspector aggregate. A single completed example does not support the whole count, including in recommendation rationale.')
        # Positive relationship verbs, not a noun field such as
        # "acknowledgement 119, 40 payload bytes" on a single packet.
        ack_relation=re.search(r'\backnowledg(?:e[sd]?|ing)\s+(?:(?:the|those|these|its|their|all|both|client[\u2019\'s]*|server[\u2019\'s]*|request|response|[0-9]+)[ -]+){0,6}(?:bytes|payload|data)\b|\bmatch(?:es|ing)?\b.{0,40}\bsequence endpoints?\b|\back(?:nowledgement)?(?:\s+(?:number|value))?\s+[0-9]+\s+(?:covers?|equals?|matches?)\b.{0,60}\b(?:payload|bytes|sequence)\b',clause,re.I)
        ack_relation=ack_relation or re.search(r'\b(?:bytes|payload|data)\b.{0,45}?\b(?:is|are|was|were|has been|have been)\s+acknowledged\b',clause,re.I)
        negative=re.search(r'\b(?:no|not|cannot|unverified|unconfirmed|could|may|might)\b',clause,re.I)
        if ack_relation and not negative:
            from pp_tcp_relationships import tcp_segment_facts
            aggregates=[r.get('segment_facts',r) for r in cited if not r.get('ipv4') and r.get('kind')!='case_original_record']
            paired=any(any(x.get('candidate_ack_reference') for x in r.get('payload_ack_relations',[])) for r in aggregates)
            groups={}
            for r in originals:groups.setdefault(r['id'].split(':')[0],[]).append(r)
            for members in groups.values():
                tcp_members=[r for r in members if r.get('tcp') and r.get('ipv4')]
                if tcp_members and any(x.get('candidate_ack_reference') for x in tcp_segment_facts(tcp_members,log).get('payload_ack_relations',[])):paired=True
            if not paired:raise ValueError('An observed payload/ACK-range relationship needs both the data-origin and reverse ACK originals, or the scoped inspector aggregate calculating that relationship. An ACK record alone supports its own number, not the peer byte endpoint.')
            # "p5 acknowledges bytes carried by p4" names p5 as ACK sender,
            # not p4. Keep active subjects and passive ACK locations separate
            # from a data-origin phrase such as "carried by".
            named_acks=re.findall(r'\b([pl][1-9][0-9]*)\s+(?:(?:also|then|later|directly|explicitly)\s+)?acknowledg(?:ed|es|ing)\b.{0,65}?\b(?:bytes|payload|data)\b',clause,re.I)
            named_acks+=re.findall(r'\backnowledg(?:ed|es|ing)\b.{0,65}?\b(?:bytes|payload|data)\b\s+(?:in|by|with)\s+([pl][1-9][0-9]*)\b',clause,re.I)
            named_acks+=re.findall(r'\b(?:bytes|payload|data)\b.{0,45}?\backnowledged\s+(?:in|by|with)\s+([pl][1-9][0-9]*)\b',clause,re.I)
            if named_acks:
                relations=[x for a in aggregates for x in a.get('payload_ack_relations',[])]
                for members in groups.values():
                    tcp_members=[r for r in members if r.get('tcp') and r.get('ipv4')]
                    if tcp_members:relations+=tcp_segment_facts(tcp_members,log).get('payload_ack_relations',[])
                proven={x.get('candidate_ack_reference','').rsplit(':',1)[-1].lower() for x in relations if x.get('candidate_ack_reference')}
                for name in {n.lower() for n in named_acks}-proven:
                    for ack in originals:
                        if ack['id'].rsplit(':',1)[-1].lower()!=name:continue
                        members=[r for r in groups[ack['id'].split(':')[0]] if r.get('tcp') and r.get('ipv4')]
                        checked=tcp_segment_facts(members,log,ack_reference=ack['id'])
                        if any(x.get('candidate_ack_reference')==ack['id'] for x in checked['payload_ack_relations']):
                            proven.add(name)
                if any(name.lower() not in proven for name in named_acks):
                    raise ValueError('Each named byte-ACK packet needs its own cited data origin or a complete scoped ACK calculation. A different valid ACK pair elsewhere in the sentence cannot support this relationship.')
        # TCP exchange counts cannot certify HTTP response status. The named
        # service aggregate or the relevant response originals can do so.
        statuses=re.finditer(r'\b([1-5][0-9]{2})\s+(?:OK|responses?|replies|status)\b|\b(?:HTTP/1\.[01]\s+|status(?:\s+code)?\s+)([1-5][0-9]{2})\b',clause,re.I)
        for status in statuses:
            prefix=clause[:status.start()]
            if re.search(r'\b(?:no|zero|not|without)\s+(?:(?:visible|captured|observed|matching|HTTP|status|code)\s*){0,3}$',prefix,re.I) or re.search(r'\b(?:if|whether|could|may|might)\b',prefix[-35:],re.I):continue
            code=int(status[1] or status[2])
            words={'one':1,'two':2,'three':3,'four':4,'five':5,'six':6,'seven':7,'eight':8,'nine':9,'ten':10}
            count_words=r'one|two|three|four|five|six|seven|eight|nine|ten|[0-9]+'
            quantifiers=[words.get(x.lower(),int(x) if x.isdigit() else 0) for x in re.findall(r'\b('+count_words+r')\s+(?:(?:captured|visible|short|small|completed|matched|answered|HTTP)\s+){0,3}(?:handshakes|connections|sessions|checks|requests|responses|replies|exchanges|flows)\b',prefix[-160:],re.I)]
            trailing=re.search(r'\b('+count_words+r')\s+(?:(?:visible|captured|HTTP)\s*){0,2}$',prefix,re.I)
            if trailing:quantifiers.append(words.get(trailing[1].lower(),int(trailing[1]) if trailing[1].isdigit() else 0))
            quantifiers=[n for n in quantifiers if 1<=n<=32]
            needed=quantifiers[-1] if quantifiers else 1
            counts=http_status_source_counts(cited,originals,code)
            both=re.search(r'\b(?:both|each)\s+(?:selected\s+)?(?:sources|source|captures|capture)\b|\bper source\b|\bbaseline and comparison\b',clause,re.I)
            enough=sum(n>=needed for n in counts.values())>=(2 if both else 1)
            if not enough:
                raise ValueError('The HTTP-status claim needs its response originals or a scoped service aggregate with the matching status count. TCP handshake/ACK counts do not establish HTTP status, including in recommendation rationale. Cite every claimed response or inspect_service, or scope the statement to the cited example.')
        if re.search(r'\b(?:[0-9]+(?:\.[0-9]+)?|one|two|three|four|five|six|seven|eight|nine|ten)\s*(?:ms|s|seconds?|milliseconds?|microseconds?)\s+(?:later|after|before)\b',clause,re.I):
            timestamps={(r.get('timestamp'),r.get('id')) for r in originals if r.get('timestamp') is not None}
            timed_aggregate=any(any(k.endswith('_seconds') and type(v) in (int,float) for k,v in r.items()) and not r.get('ipv4') and r.get('kind')!='case_original_record' for r in cited)
            if len(timestamps)<2 and not timed_aggregate:
                raise ValueError('An interval observation needs both cited original timestamp endpoints or a cited aggregate that calculates the interval. One timestamp alone does not establish how much later it occurred.')
    for lo,hi in re.findall(r'\bsource\s+ports?\s+([0-9]+)\s*[-\u2013]\s*([0-9]+)',row['text'],re.I):
        lo,hi=int(lo),int(hi)
        aggregates=[r.get('tcp_segments',r.get('segment_facts',{})) for r in cited]
        process_scope=re.search(r'\bfrom\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s*\(\s*(?:the\s+)?process\b[^)]*\bsource ports?\b',row['text'],re.I)
        syn_subject=bool(process_scope or re.search(r'\b(?:SYNs?|initiating|initiators?|clients?)\b',row['text'],re.I))
        aggregate=any(r.get('source_port_min')==lo and r.get('source_port_max')==hi for r in aggregates) if not syn_subject else any(r.get('syn_source_port_min')==lo and r.get('syn_source_port_max')==hi for r in aggregates)
        if syn_subject and not aggregate:
            for r in cited:
                exchanges=r.get('exchanges',[])
                if not exchanges or r.get('exchange_details_omitted')!=0 or r.get('member_numbers_omitted')!=0:continue
                ports=[x.get('source_port') for x in exchanges if not process_scope or x.get('source')==process_scope[1]]
                if ports and all(type(n) is int for n in ports) and min(ports)==lo and max(ports)==hi:aggregate=True
        all_rows=context.get('log_records' if context.get('input_kind')=='network_log' else 'packets',[])
        complete=(not context.get('context_selection',{}).get('packets_omitted',0) and not context.get('context_selection',{}).get('records_omitted',0))
        values=[r['tcp']['src_port'] for r in originals if r.get('tcp') and (not syn_subject or r['tcp']['flags'] & 0x12==2)]
        all_cited=complete and all_rows and {r['id'] for r in originals}=={r['id'] for r in all_rows}
        if not aggregate and not (all_cited and values and min(values)==lo and max(values)==hi):
            raise ValueError('A whole-selection source-port range needs a cited aggregate exposing source_port_min/max or all original members. First and last packet examples alone do not establish the selection bounds.')

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
        if required:
            try:validate_relational_support(row,registry,context)
            except ValueError as error:raise ValueError('Observation '+str(number)+': '+str(error)) from None
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
            def proves_zero(fact):
                ref=registry[fact['reference']];path=fact['field'];parts=path.split('.')
                if fact['value']!=0 or parts[-1] not in ('payload_bytes_total','max_payload_bytes','payload_bearing_record_count'):return False
                if path in ('payload_bytes_total','max_payload_bytes'):return ref.get('member_count',0)>0
                if len(parts)!=2 or parts[0] not in ('tcp_segments','segment_facts'):return False
                facts=ref.get(parts[0],{})
                if facts.get('member_count',facts.get('tcp_record_count',0))<=0 or facts.get('payload_length_available') is not True:return False
                originals=context.get('packets',[])
                zero=re.search(r'\b(?:no|zero|0|without)\s+(?:tcp\s+)?payload|payload[- ]free',row['text'],re.I)
                protocol,_=explicit_negative_scope(row['text'],zero.start(),zero.end()) if zero else (None,False)
                tcp_scope=protocol=='tcp' or bool(zero and re.search(r'\bTCP\s+payload\b',zero[0],re.I))
                whole_tcp=bool(originals) and all(r.get('status')=='decoded' and r.get('tcp') for r in originals)
                return tcp_scope or whole_tcp
            aggregate_zero=any(proves_zero(f) for f in support)
            records=[registry[r] for r in row['references'] if r in registry and ':p' in r]
            originals=context.get('packets',[])
            all_originals=(originals and {r['id'] for r in records}=={r['id'] for r in originals}
                           and not context.get('context_selection',{}).get('packets_omitted',0)
                           and all((r.get('tcp') or r.get('udp') or {}).get('payload_bytes')==0 for r in records))
            named_subset=named_zero_payload_subject(row['text'],records)
            if not aggregate_zero and not all_originals and not named_subset:raise ValueError('Observation '+str(number)+': A whole-set zero-payload claim needs a cited aggregate exposing payload_bytes_total/max=0 for the claimed selection, or all original member records. An explicitly listed pN subset needs every listed original and its known zero payload. Relationship counts or two examples do not certify the whole capture.')
    if required:
        for number,row in enumerate(value.get('recommendations',[]),1):
            try:validate_relational_support({'text':row['rationale'],'references':row['references']},registry,context)
            except ValueError as error:raise ValueError('Recommendation '+str(number)+' rationale: '+str(error)) from None
    if errors:raise ValueError('Observation support errors: '+'; '.join(errors[:6]))

def narrative_entries(value):
    entries=[(key,value.get(key)) for key in ('summary','interpretation')]
    for key in ('alternatives','uncertainty','questions'):
        entries.extend((key+'['+str(i)+']',text) for i,text in enumerate(value.get(key,[])))
    for key,field in (('observations','text'),('recommendations','rationale')):
        entries.extend((key+'['+str(i)+'].'+field,row[field]) for i,row in enumerate(value.get(key,[])))
    entries.extend(('coverage.limitations['+str(i)+']',text) for i,text in enumerate((value.get('coverage') or {}).get('limitations',[])))
    return [(path,text) for path,text in entries if isinstance(text,str)]


def narrative_texts(value):
    return [text for _,text in narrative_entries(value)]

def explicit_negative_scope(clause,start,end):
    """Read explicit grammatical selection qualifiers, not general entailment.

    A later independent source assertion cannot borrow an earlier TCP/decoded
    subject. Postposed selection qualifiers are as valid as leading ones.
    """
    prefix=clause[:start];tail=clause[end:end+100]
    local=re.split(r'\b(?:but|however|whereas)\b',prefix,flags=re.I)[-1]
    transports=list(re.finditer(r'\b(TCP|UDP)\s+(?:records?|packets?|segments?|selection|subset|traffic)\b',local,re.I))
    decoded=list(re.finditer(r'\bdecoded\s+(?:(?:TCP|UDP|transport|matching|selected|valid)\s+){0,3}(?:records?|packets?|segments?|rows?|evidence|selection|subset)\b',local,re.I))
    rebound=list(re.finditer(r'\b(?:(?:the|this|that|whole|entire|saved)\s+){0,3}(?:source|capture|sample|window|all records)\s+(?:also\s+)?(?:has|have|contains?|carries|holds?|shows?|includes?)\b',local,re.I))
    last_global=rebound[-1].start() if rebound else -1
    protocol=transports[-1][1].lower() if transports and transports[-1].start()>last_global else None
    decoded_scope=bool(decoded and decoded[-1].start()>last_global)
    scoped_tail=re.search(r'\b(?:among|within|in|across|from)\s+(?:(?:the|these|those|one|two|three|four|five|six|seven|eight|nine|ten|[0-9]+)\s+){0,3}(decoded\s+)?(?:(TCP|UDP)\s+)?(?:(?:transport|matching|selected|valid)\s+){0,2}(?:records?|packets?|segments?|rows?|evidence|selection|subset)\b',tail,re.I)
    if scoped_tail and scoped_tail[2]:protocol=scoped_tail[2].lower()
    return protocol,decoded_scope or bool(scoped_tail and scoped_tail[1])


def validate_unknown_transport_absence(text,evidence):
    """Unknown saved flags cannot certify a global no-reset/reply/teardown."""
    if not any(r.get('status')!='decoded' for r in evidence.get('packets',[])):return
    for clause in re.split(r'[!?;]\s+|\.(?=\s+[A-Z])',text):
        # Coverage notes are public facts too. An enumerated later noun must
        # not transfer a decoded-only absence to the whole saved file.
        for match in re.finditer(r'\bno\s+([^.!?;]{0,150}?)\b(?:exists?|appears?|occurs?)\b',clause,re.I):
            nouns=match[1]
            if not re.search(r'\b(?:teardown|reset|FIN|RST|ACK|reply|replies|response|stream data|payload)\b',nouns,re.I):continue
            if re.match(r'(?:(?:validated|decoded|confirmed|interpretable)\s+|evidence\s+(?:of|for)\b)',nouns,re.I):continue
            prefix=clause[:match.start()]
            if re.search(r"\b(?:whether|cannot|could|may|might|unknown|not proof|does not prove)\b",prefix[-60:],re.I):continue
            _,decoded=explicit_negative_scope(clause,match.start(),match.end())
            if not decoded:
                raise ValueError('Unknown saved transport remains unknown in every section, including coverage notes. An enumerated whole-file absence cannot be inferred from decoded-only counts; state the actual decoded selection or the absence of validated fields.')
        for match in re.finditer(r'\bno\s+(?:(?:captured|saved|observed|TCP)\s+){0,2}(?:teardown|reset|FIN|RST|ACK|reply|replies|response)\b',clause,re.I):
            prefix=clause[:match.start()]
            if re.search(r'\b(?:whether|cannot|could|may|might|unknown|not proof|does not prove)\b',prefix[-60:],re.I):continue
            tail=clause[match.end():match.end()+100]
            if not re.search(r'\b(?:exists?|appears?|occurs?|captured|observed|observable)\b',tail,re.I):continue
            _,decoded=explicit_negative_scope(clause,match.start(),match.end())
            if not decoded:
                raise ValueError('Undecoded saved transport flags remain unknown. Scope negative reply/reset/teardown observations to decoded records; missing validated flags do not establish whole-source absence.')


def validate_comparison_scope(value,context):
    registry=reference_registry(context)
    comparisons=[r for r in registry.values() if isinstance(r.get('baseline'),dict) and isinstance(r.get('comparison'),dict) and isinstance(r.get('delta'),dict)]
    if not comparisons:return
    for path,text in narrative_entries(value):
        # A cited pair governs its row. Never pick the first of several pairs
        # to validate an unscoped statement about source equality.
        match=re.match(r'(observations|recommendations)\[([0-9]+)\]',path)
        refs=value[match[1]][int(match[2])].get('references',[]) if match else []
        selected=[r for r in comparisons if r.get('id') in refs]
        selected=selected or (comparisons if len(comparisons)==1 else [])
        for clause in re.split(r'[!?;]\s+|\.(?=\s+[A-Z])',text):
            validate_equal_frame_bytes(clause,selected,path)
            claim=re.search(r'\b(?:the\s+)?(?:only|sole)\s+(?:measured\s+)?(?:change|difference)\s+(?:is|was|lies|falls|consists)\b.{0,90}\b(?:time|timing|interval|latency|delay)\b|\bchange\s+(?:is|was)\s+confined\s+to\s+(?:timing|latency|delay)\b|\bno other\s+(?:(?:saved|observed|packet|exchange)\s+){0,3}(?:field|exchange|record)s?\s+(?:has\s+|had\s+)?changed\b',clause,re.I)
            if not claim:
                claim=re.search(r'\bdiffer(?:s|ed|ing)?\s+only\s+in\b',clause,re.I)
                if claim and re.search(r'\b(?:named|reported|selected)\s+(?:(?:count|timing|profile)\s+)?metrics?\s*$',clause[:claim.start()],re.I):continue
            if not claim:continue
            if re.search(r"\b(?:not|cannot|can't|doesn't|whether|unknown|could|may|might)\b",clause[max(0,claim.start()-60):claim.start()],re.I):continue
            raise ValueError('A named-metric comparison does not establish an only-change or all-field equality claim. Report the actual count/profile/timing differences and their scope. Equal counts or bytes do not prove every other saved field is unchanged.')


def validate_equal_frame_bytes(clause,comparisons,path):
    """Check explicit equality premises against available named byte operands.

    This does not infer workload equivalence or grade arbitrary prose. Payload
    bytes, hypothetical equality and negated equality are not frame-byte claims.
    A negative conclusion does not negate its affirmative equality premise.
    """
    metric=r'(?:frame[- ]byte(?:\s+(?:totals?|counts?))?|(?:frame\s+)?byte\s+(?:totals?|counts?|volumes?)|bytes)'
    qualifier=r'(?:equal|identical|matching|unchanged|(?:the\s+)?same)'
    preceding=re.compile(r'\b'+qualifier+r'\s+(?:(?:(?:request|record|packet)\s+)?counts?\s*(?:,|and|&)\s*)?'+metric+r'\b',re.I)
    following=re.compile(r'\b'+metric+r'\b\s*(?:,?\s+and\s+(?:the\s+)?(?:(?:visible|request|method/path)\s+)*(?:profiles?|counts?))?\s+(?:(?:are|were|remain|remained)\s+)?(?:equal|identical|unchanged|the same|match(?:ed)?)\b',re.I)
    for assertion in list(preceding.finditer(clause))+list(following.finditer(clause)):
        prefix=re.split(r'\b(?:but|however|whereas|yet)\b',clause[:assertion.start()],flags=re.I)[-1]
        if re.search(r'\b(?:payload|TCP|UDP|request|response)\s*$',prefix,re.I):continue
        if re.search(r'\b(?:if|whether|hypothetical|could|may|might)\b',prefix,re.I):continue
        if re.search(r'\b(?:not|never|no longer)\s*(?:necessarily\s*)?$',prefix,re.I):continue
        if re.search(r'\b(?:cannot|does not|do not|did not)\s+(?:assume|establish|show|prove|claim)\s+(?:that\s+)?(?:the\s+)?$',prefix,re.I):continue
        for pair in comparisons:
            before=pair['baseline'].get('frame_bytes');after=pair['comparison'].get('frame_bytes')
            if type(before) in (int,float) and type(after) in (int,float) and before!=after:
                raise ValueError(path+': Equal frame-byte totals were asserted but the cited comparison supplies different baseline.frame_bytes and comparison.frame_bytes ('+str(before)+' versus '+str(after)+'). Copy the actual named operands. A statement that equality would not prove identical workloads must be conditional if equality is not observed.')


def validate_source_payload_zero(text,evidence):
    """Reject a global zero that contradicts a known captured payload.

    Unknown log lengths stay unknown. A named SYN/packet or an explicitly TCP
    selection is not the whole mixed-protocol source. This narrow check does
    not infer unobserved bytes or determine a threat verdict.
    """
    originals=evidence.get('packets',[])
    rows=[r for r in originals if r.get('status')=='decoded']
    nonzero={proto for proto in ('tcp','udp') if any((r.get(proto) or {}).get('payload_bytes',0)>0 for r in rows)}
    unknown=any(r.get('status')!='decoded' for r in originals)
    if not nonzero and not unknown:return
    for clause in claim_clauses(text):
        for match in re.finditer(r'(?<![\w-])(?:no|zero)\s+(?:(?:captured|observed|transport)\s+)?(?:(?:handshake|setup)\s*,\s*)?(?:(TCP|UDP)\s+)?(?:payload|data(?:\s+transfer)?)\b',clause,re.I):
            prefix=clause[:match.start()]
            # "Non-zero" is a positive length, not a zero-payload assertion.
            # Keep this lexical boundary distinct from transport/subject scope.
            if re.search(r'\b(?:non|not)\s+$',prefix,re.I):continue
            if re.match(r'\s+(?:delivery\s+)?acknowledg(?:e)?ments?\b',clause[match.end():],re.I):continue
            if re.match(r'\s+(?:(?:is|was|has been)\s+)?(?:established|confirmed|proven|validated)\b',clause[match.end():],re.I):continue
            if re.search(r"\b(?:cannot|could|may|might|whether|unknown|not proof|does not prove)\b",prefix[-60:],re.I):continue
            quantified=re.search(r'\b(?:all|every|both|[0-9]+|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:(?:decoded|captured|saved|header-only|transport)\s+){0,3}(?:records?|packets?|frames?|segments?)\b',prefix,re.I)
            named=re.match(r'^\s*(?:original\s+)?([pl][1-9][0-9]*)\b',clause,re.I)
            rebound=re.search(r'\b(?:(?:the|this|whole|entire)\s+)+(?:source|capture|sample|window|selection|records)\b',prefix,re.I)
            if named and not rebound:
                original=next((r for r in originals if r['id'].rsplit(':',1)[-1].lower()==named[1].lower()),None)
                if original:
                    n=(original.get('tcp') or original.get('udp') or {}).get('payload_bytes')
                    if n==0:continue
                    raise ValueError('The named original does not have a known zero transport payload. Keep its actual length or unknown status distinct from other records.')
            global_subject=not prefix.strip() or quantified or re.search(r'\b(?:source(?!\s+(?:port|address))|file|capture|sample|window|selection|whole set|all records)\b',prefix,re.I)
            if not global_subject:continue
            if re.search(r'\b(?:[pl][1-9][0-9]*|one (?:SYN|packet|segment)|a SYN)\b',prefix[-60:],re.I) and not re.search(r'\b(?:all|whole|entire)\b',prefix[-60:],re.I):continue
            protocol=match[1].lower() if match[1] else None
            scoped_protocol,decoded_scope=explicit_negative_scope(clause,match.start(),match.end())
            protocol=protocol or scoped_protocol
            if not protocol and re.search(r'\b(?:all|the|decoded|selected|[0-9]+|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:bare\s+)?SYN(?:s| records?| packets?| segments?)\b',prefix,re.I):continue
            if nonzero and (not protocol or protocol in nonzero):
                raise ValueError('A whole-source zero-payload statement contradicts a known decoded payload. Keep the explicit transport/selection scope in every section; zero TCP payload does not erase a separate UDP payload.')
            if unknown and not decoded_scope:
                raise ValueError('Undecoded source records have unknown transport payload. A zero-payload claim must explicitly cover the decoded selection, not either direction or the whole saved source.')


def validate_unanswered_syn_arrival(text,evidence):
    rows=[r for r in evidence.get('log_records' if evidence.get('input_kind')=='network_log' else 'packets',[]) if r.get('status')=='decoded' and r.get('tcp')]
    if not rows or any(r['tcp']['flags'] & 0x12!=2 for r in rows):return
    for clause in re.split(r'[!?;]\s+|\.(?=\s+[A-Z])',text):
        m=re.search(r'\bSYN(?:s| segments?| packets?| records?)\b.{0,100}?\b(?:reached|arrived (?:at|on)|(?:were|was) delivered to)\s+(?:(?:the|their)\s+)?(?:server|service|destination|target|endpoint|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b',clause,re.I)
        if not m:m=re.search(r'\b(?:host|client|source|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b.{0,65}?\breached\s+(?:(?:the|[0-9]+|one|two|three|four|five|six|seven|eight|nine|ten|different|distinct)\s+){0,3}(?:services?|servers?|destinations?|endpoints?|ports?)\b',clause,re.I)
        if not m:continue
        prefix=re.split(r'\b(?:and|but)\b|,\s+',clause[:m.start()],flags=re.I)[-1]
        if re.search(r"\b(?:not|no evidence|cannot|whether|unknown|could|may|might|unconfirmed)\b",prefix[-60:]+' '+m[0],re.I):continue
        raise ValueError('Captured SYNs addressed to a destination do not establish endpoint arrival at an unknown capture point. These decoded TCP records contain no reverse response; say addressed to/attempted,or keep arrival explicitly unresolved.')


def validate_visible_tcp_events(text,evidence):
    """Visible controls cannot be erased by generic absence boilerplate.

    This checks observed FIN/reset presence, not full connection closure.
    Unresolved unnamed subsets cannot be compared with whole-source counts.
    """
    originals=evidence.get('log_records' if evidence.get('input_kind')=='network_log' else 'packets',[])
    tcp=[r for r in originals if r.get('status')=='decoded' and r.get('tcp')]
    if not tcp:return
    for clause in claim_clauses(text):
        def conditional(match):
            governing=re.split(r'\b(?:but|however|yet)\b',clause[:match.start()],flags=re.I)[-1]
            return bool(re.search(r'\b(?:if|whether|hypothetical)\b',governing,re.I))
        selected=tcp
        named=re.search(r'\b(?:among|within|in|across)\s+([pl][1-9][0-9]*(?:(?:\s*,\s*|\s+and\s+)[pl][1-9][0-9]*)*)\b',clause,re.I)
        if named:
            ids=set(re.findall(r'\b[pl][1-9][0-9]*\b',named[1].lower()))
            selected=[r for r in tcp if r['id'].rsplit(':',1)[-1].lower() in ids]
        elif re.search(r'\b(?:selected|named|this|that)\s+(?:flow|tuple|exchange|subset)\b',clause,re.I):
            continue
        fin=any(r['tcp']['flags']&1 for r in selected)
        rst=any(r['tcp']['flags']&4 for r in selected)
        absence=re.search(r'\bno\s+((?:(?:captured|observed|saved|TCP)\s+)*(?:FIN|RST|reset|teardown)\b[^.!?;]{0,55})',clause,re.I)
        if absence and not conditional(absence):
            nouns=re.split(r'\b(?:appears?|occurs?|exists?|is|was|were|among|within|in)\b',absence[1],flags=re.I)[0]
            if fin and re.search(r'\b(?:FIN|teardown)\b',nouns,re.I) or rst and re.search(r'\b(?:RST|reset)\b',nouns,re.I):
                raise ValueError('The named decoded selection contains an observed FIN/reset control event. Report its actual presence instead of claiming no control event; a FIN/reset alone still does not establish complete closure or business success.')
        missing=re.search(r'\b(?:missing|absent)\s+teardown\b|\bteardown\s+(?:is|was|remains?)\s+(?:unobserved|not\s+(?:observed|captured))\b',clause,re.I)
        missing_not_assumed=re.search(r'\bmissing teardown\s+is\s+not\s+(?:assumed|established|asserted)\b',clause,re.I)
        if fin and missing and not conditional(missing) and not missing_not_assumed:
            raise ValueError('FIN-bearing records are present in this decoded selection. Do not assume teardown is missing or unobserved; distinguish the observed control events from any unverified complete connection state.')
        for lifetime in re.finditer(r'\bshort[- ]lived\s+(?:TCP\s+)?(?:connections?|sessions?)\b|\b(?:connection|session)\s+(?:is|was|has been)\s+short[- ]lived\b',clause,re.I):
            if not fin and not rst:
                prefix=re.split(r'\b(?:but|however|yet)\b',clause[:lifetime.start()],flags=re.I)[-1]
                if re.match(r'(?:connection|session)\b',lifetime[0],re.I):
                    prefix=re.split(r'\band\s+(?:the|a|this|that)\s*$',prefix,flags=re.I)[-1]
                tail=clause[lifetime.end():]
                if negative_proof_prefix(prefix) or re.search(r'\b(?:whether|unknown|hypothetical)\b|\b(?:may|might|could)\s+(?:be|have been)\s*$',prefix,re.I) or re.search(r'^\s+is\s+(?:(?:one|a)\s+)?(?:possible|hypothetical)\s+explanation\b',tail,re.I):continue
                raise ValueError('A short observation window does not establish a short-lived connection. No FIN/RST is observed in this selection; describe the captured interval and keep actual session lifetime unestablished.')


def validate_claim_language(value,evidence):
    """Keep the public section path in the single correction diagnostic."""
    for path,text in narrative_entries(value):
        try:_validate_claim_language({'summary':text},evidence)
        except ValueError as error:raise ValueError(path+': '+str(error)) from None


def _validate_claim_language(value,evidence):
    from pp_semantics import validate_preview_quotes,validate_subset_cadence,validate_syn_cadence,validate_syn_timestamp_bounds
    validate_preview_quotes(narrative_texts(value),evidence)
    validate_subset_cadence(narrative_texts(value),evidence)
    validate_syn_cadence(narrative_texts(value),evidence)
    validate_syn_timestamp_bounds(narrative_texts(value),evidence)
    # Scope qualifiers stay in the same sentence/clause, not a later disclaimer.
    qualified=re.compile(r"\b(?:not|nothing|neither|nor|cannot|can't|doesn't|whether|candidate|consistent with|suggests?|may|might|could|hypothesis|hypothetical|would|insufficient)\b",re.I)
    # Match affirmative evidence assertions, not any sentence containing both
    # 'shows' and 'application success'. Questions/advice and 'unsupported' scope
    # statements are not assertions of successful application execution.
    evidence_proves_app=re.compile(r'\b(?:capture|headers?|packets?|records?|logs?|acknowledgements?|evidence|sequence|exchange|this|it)\b.{0,35}?\b(?:proves?|confirms?|establish(?:es)?|demonstrates?|shows?)\s+(?:that\s+)?(?:the\s+)?(?:application(?:-level)?\s+(?:success|(?:request\s+)?(?:succeeded|was successful|was accepted|completed successfully))|(?:http|transaction|request)\s+(?:success|succeeded|was successful|was accepted|completed successfully))\b',re.I)
    app_succeeded=re.compile(r'\b(?:application(?:-level)?(?:\s+request)?|http(?:\s+request)?|transaction|request)\s+(?:has\s+)?(?:succeeded|was\s+(?:successful|accepted)|completed\s+successfully)\b',re.I)
    log_handshake=re.compile(r'\b(?:completed?|established|successful)\s+(?:tcp\s+)?(?:handshake|connection)|\b(?:handshake|connection)\s+(?:is|was|has been)\s+(?:completed?|established|successful)',re.I)
    roles=payload_role_lengths(evidence)
    for text in narrative_texts(value):
        validate_visible_tcp_events(text,evidence)
        validate_source_payload_zero(text,evidence)
        validate_unknown_transport_absence(text,evidence)
        validate_unanswered_syn_arrival(text,evidence)
        validate_observation_bounds(text,evidence)
        validate_window_end_claims(text,evidence)
        validate_explicit_payload_origin(text,roles)
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
