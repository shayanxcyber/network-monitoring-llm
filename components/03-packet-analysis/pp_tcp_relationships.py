"""Neutral bounded header relationships, not stream reassembly or detection."""
from collections import defaultdict
from bisect import bisect_left
from decimal import Decimal
import hashlib
from pp_context import encoded

VERSION = 'packetpilot-tcp-relationships-1.11'
MAX_EXCHANGES = 32


def tcp_flag_facts(rows, is_log=False):
    """Whole-selection flag counts, explicitly separate from payload knowledge.

    ACK-bearing includes SYN/ACK and data/ACK. An ACK-only *flag mask* is
    observable in a field log, but its absent payload column cannot prove an
    empty segment. No connection, delivery or intent verdict is inferred.
    """
    tcp = [r for r in rows if r.get('status') == 'decoded' and r.get('tcp')]
    source_ports = sorted({r['tcp']['src_port'] for r in tcp})
    number='line_number' if is_log else 'packet'
    syns=sorted((r for r in tcp if r['tcp']['flags'] & 0x12==2),key=lambda r:r[number])
    gaps=[Decimal(b['timestamp'])-Decimal(a['timestamp']) for a,b in zip(syns,syns[1:])
          if a.get('timestamp') is not None and b.get('timestamp') is not None]
    syn_times=[r['timestamp'] for r in syns if r.get('timestamp') is not None]
    syn_ports={r['tcp']['src_port'] for r in syns}
    return {
        'tcp_record_count': len(tcp),
        'syn_without_ack_record_count':len(syns),
        'syn_first_record_reference':syns[0]['id'] if syns else None,
        'syn_last_record_reference':syns[-1]['id'] if syns else None,
        'syn_first_record_timestamp':syns[0].get('timestamp') if syns else None,
        'syn_last_record_timestamp':syns[-1].get('timestamp') if syns else None,
        'syn_timestamp_min':min(syn_times,key=Decimal) if syn_times else None,
        'syn_timestamp_max':max(syn_times,key=Decimal) if syn_times else None,
        'syn_source_port_min':min(syn_ports) if syn_ports else None,
        'syn_source_port_max':max(syn_ports) if syn_ports else None,
        'syn_source_port_distinct_count':len(syn_ports),
        'syn_bounds_scope':'Decoded SYN-without-ACK members only. First/last follows original record order, timestamp min/max covers known timestamps only; missing timestamps are counted separately. Source-port bounds describe these SYN senders, not every TCP sender or every client after tuple reuse.',
        'syn_arrival_gap_count':len(gaps),
        'syn_arrival_gap_min_seconds':float(min(gaps)) if gaps else None,
        'syn_arrival_gap_max_seconds':float(max(gaps)) if gaps else None,
        'syn_timestamps_missing':sum(r.get('timestamp') is None for r in syns),
        'syn_arrival_gap_scope':'Adjacent decoded SYN-without-ACK records in original capture/physical-line order within this TCP selection; excludes intervening UDP, ACK and other records.',
        'ack_bearing_record_count': sum(bool(r['tcp']['flags'] & 16) for r in tcp),
        'ack_flag_only_record_count': sum(r['tcp']['flags'] == 16 for r in tcp),
        'fin_bearing_record_count': sum(bool(r['tcp']['flags'] & 1) for r in tcp),
        'rst_bearing_record_count': sum(bool(r['tcp']['flags'] & 4) for r in tcp),
        'payload_length_available': not is_log,
        'ack_only_empty_segment_count': None if is_log else sum(
            r['tcp']['flags'] == 16 and r['tcp']['payload_bytes'] == 0 for r in tcp),
        'payload_bearing_record_count': None if is_log else sum(
            r['tcp']['payload_bytes'] > 0 for r in tcp),
        'payload_ack_bearing_record_count': None if is_log else sum(
            bool(r['tcp']['flags'] & 16) and r['tcp']['payload_bytes'] > 0 for r in tcp),
        'payload_bytes_total': None if is_log else sum(r['tcp']['payload_bytes'] for r in tcp),
        'min_payload_bytes': None if is_log or not tcp else min(r['tcp']['payload_bytes'] for r in tcp),
        'max_payload_bytes': None if is_log or not tcp else max(r['tcp']['payload_bytes'] for r in tcp),
        'source_port_min': min(source_ports) if source_ports else None,
        'source_port_max': max(source_ports) if source_ports else None,
        'source_port_distinct_count': len(source_ports),
        'source_ports': source_ports[:64],
        'source_ports_omitted': max(0,len(source_ports)-64),
    }


def tcp_segment_facts(rows, is_log=False, *, ack_reference=None):
    """Bounded exact endpoint ACK candidates, not stream reconstruction.

    Only ACK values equal to an observed payload/segment endpoint are
    paired. Later cumulative ACKs, overlaps, retransmissions and missing segments
    require stream analysis and are not silently treated as disproof of receipt.
    The ACK sender and acknowledged byte origin are independently explicit.
    An optional exact ACK selector rechecks a named cited ACK while retaining
    all original data/restart/ambiguity bounds. Default tools still report the
    earliest candidate. A later exact ACK is not disproved by an earlier one.
    """
    number = 'line_number' if is_log else 'packet'
    selected = sorted(rows, key=lambda r: (Decimal(r['timestamp']), r[number]))
    result = tcp_flag_facts(selected, is_log)
    numbers = [r[number] for r in selected]
    first = selected[0]['timestamp'] if selected else None
    last = selected[-1]['timestamp'] if selected else None
    result.update(member_count=len(numbers), member_numbers=numbers[:96],
        first_observed_timestamp=first, last_observed_timestamp=last,
        member_numbers_omitted=max(0, len(numbers)-96),
        membership_sha256=hashlib.sha256(encoded(numbers)).hexdigest(),
        scope='All decoded TCP records in the requested directional tuples and their reverse tuples, including flows without a captured SYN.',
        ack_count_definition='ACK-bearing is any ACK bit; ACK flag-only is flags exactly 0x10. Empty ACK-only additionally requires known zero TCP payload.',
        payload_ack_relations=[], payload_relations_inspected=0,
        payload_relations_omitted=0,
        limits=['Exact endpoint ACK candidates are header assertions, not application acceptance, business success or full stream delivery.',
                'No matching candidate means none in this selected decoded window, not no receipt or no later cumulative ACK.',
                'ACK values acknowledge reverse-direction sequence space. The ACK sender is not the origin of the bytes it acknowledges.'])
    if is_log:
        result['limits'].append('This field log lacks payload length and sequence/acknowledgement values; no data ACK relation is calculated.')
        return result
    tuples = defaultdict(list)
    ack_index = defaultdict(list)
    for r in selected:
        t, ip = r['tcp'], r['ipv4']
        key = (ip['src'], ip['dst'], t['src_port'], t['dst_port'])
        tuples[key].append(r)
        if t['flags'] & 16 and not t['flags'] & (2 | 4) and (ack_reference is None or r['id']==ack_reference):
            ack_index[key + (t['acknowledgement'],)].append(r)
    payloads = [r for r in selected if r['tcp']['payload_bytes'] > 0]
    result['payload_relations_inspected'] = min(len(payloads), 16)
    result['payload_relations_omitted'] = max(0, len(payloads)-16)
    for data in payloads[:16]:
        t, ip = data['tcp'], data['ipv4']
        key = (ip['src'], ip['dst'], t['src_port'], t['dst_port'])
        reverse = (key[1], key[0], key[3], key[2])
        start = Decimal(data['timestamp'])
        # SYN/FIN consume sequence units, but are not payload bytes.
        payload_start = (t['sequence'] + bool(t['flags'] & 2)) % 2**32
        payload_end = (payload_start + t['payload_bytes']) % 2**32
        endpoint = (payload_end + bool(t['flags'] & 1)) % 2**32
        restarts = [Decimal(r['timestamp']) for k in (key, reverse) for r in tuples[k]
                    if r['tcp']['flags'] & 0x12 == 2 and Decimal(r['timestamp']) > start]
        boundary = min(restarts) if restarts else None
        starts = [Decimal(r['timestamp']) for k in (key, reverse) for r in tuples[k]
                  if r['tcp']['flags'] & 0x12 == 2 and Decimal(r['timestamp']) <= start]
        beginning = max(starts) if starts else None
        tuple_window = [r for k in (key,reverse) for r in tuples[k]
                        if (beginning is None or Decimal(r['timestamp']) >= beginning)
                        and (boundary is None or Decimal(r['timestamp']) < boundary)]
        tuple_last = max(tuple_window,key=lambda r:Decimal(r['timestamp']))['timestamp']
        candidates = [r for position in {payload_end,endpoint} for r in ack_index.get(reverse + (position,), [])
                      if Decimal(r['timestamp']) >= start
                      and (boundary is None or Decimal(r['timestamp']) < boundary)]
        candidates.sort(key=lambda r:(Decimal(r['timestamp']),r[number]))
        repeated = [r for r in tuples[key] if r['tcp']['sequence'] == t['sequence']
                    and r['tcp']['payload_bytes'] == t['payload_bytes']
                    and (boundary is None or Decimal(r['timestamp']) < boundary)]
        candidate = candidates[0] if candidates else None
        ambiguous = len(repeated) > 1 or bool(candidate and Decimal(candidate['timestamp']) == start)
        result['payload_ack_relations'].append({
            'data_reference': data['id'],
            'data_origin': {'address': key[0], 'port': key[2]},
            'data_destination': {'address': key[1], 'port': key[3]},
            'payload_bytes': t['payload_bytes'], 'payload_sequence_start': payload_start,
            'payload_sequence_endpoint': payload_end,
            'data_timestamp': data['timestamp'],
            'selected_window_last_timestamp': last,
            'data_to_selected_window_end_seconds': float(Decimal(last)-start),
            'tuple_window_last_timestamp': tuple_last,
            'data_to_tuple_window_end_seconds': float(Decimal(tuple_last)-start),
            'next_sequence_endpoint_including_control_bits': endpoint,
            'candidate_ack_reference': candidate['id'] if candidate else None,
            'ack_sender': {'address': reverse[0], 'port': reverse[2]} if candidate else None,
            'acknowledged_byte_origin': {'address': key[0], 'port': key[2]} if candidate else None,
            'candidate_ack_value': candidate['tcp']['acknowledgement'] if candidate else None,
            'candidate_ack_covers_segment_controls': candidate['tcp']['acknowledgement']==endpoint if candidate else None,
            'candidate_ack_count': len(candidates), 'ambiguous': ambiguous,
            'supporting_references': [data['id']] + ([candidate['id']] if candidate else []),
            'matching_basis': 'Reverse four-tuple, non-earlier timestamp and exact payload/segment endpoint; bounded by the next captured new SYN. A payload endpoint may be acknowledged without a co-carried FIN.',
        })
    return result


def scalar_paths(value, prefix=''):
    """Only named scalar paths supported by our measurement contract, no list indices."""
    paths = []
    for key, item in value.items():
        if not isinstance(key, str) or not key.replace('_', '').isalnum() or key[0].isdigit():
            continue
        path = prefix + key
        if isinstance(item, dict):
            paths.extend(scalar_paths(item, path + '.'))
        elif type(item) in (int, float, bool, str) and (not isinstance(item, str) or len(item) <= 120):
            paths.append(path)
    return paths


def analyse_tcp_exchanges(evidence, source='', destination='', destination_port=0):
    """Compute relationships only from this detached input; no file/OS access.

    Match reversed four-tuples and observation-window timestamps. PCAP checks
    sequence/ack fields when supplied. Logs expose candidate flag sequences,
    never invented sequence numbers. Repeated SYN keys remain ambiguous.
    """
    is_log = evidence.get('input_kind') == 'network_log'
    originals = evidence['log_records'] if is_log else evidence['packets']
    source_last = max((r['timestamp'] for r in originals if r.get('timestamp') is not None),key=Decimal,default=None)
    source_first = min((r['timestamp'] for r in originals if r.get('timestamp') is not None),key=Decimal,default=None)
    number = 'line_number' if is_log else 'packet'
    rows = [r for r in originals if r['status'] == 'decoded' and r.get('tcp')]
    def endpoints(r):
        return r['ipv4']['src'], r['ipv4']['dst'], r['tcp']['src_port'], r['tcp']['dst_port']
    def tm(r): return Decimal(r['timestamp'])
    def order(r): return tm(r), r[number]
    by_tuple = defaultdict(list)
    for r in sorted(rows, key=order): by_tuple[endpoints(r)].append(r)
    tuple_orders = {key:[order(r) for r in values] for key,values in by_tuple.items()}
    def window(key,start,end=None):
        values=by_tuple.get(key,[]);orders=tuple_orders.get(key,[])
        return values[bisect_left(orders,start):bisect_left(orders,end) if end is not None else len(values)]
    def requested(r):
        s, d, sp, dp = endpoints(r)
        return (not source or source == s) and (not destination or destination == d) and (not destination_port or dp == destination_port)
    syns = [r for r in sorted(rows, key=order) if r['tcp']['flags'] & 0x12 == 2 and requested(r)]
    keys = {endpoints(r) for r in syns}
    reverse_keys = {(d,s,dp,sp) for s,d,sp,dp in keys}
    members = [r for r in rows if endpoints(r) in keys | reverse_keys]
    duplicate_keys = defaultdict(list)
    for r in syns:
        key = endpoints(r) + (() if is_log else (r['tcp']['sequence'],))
        duplicate_keys[key].append(r)
    tuple_syns=defaultdict(list)
    for r in rows:
        if r['tcp']['flags'] & 0x12 == 2:tuple_syns[endpoints(r)].append(r)
    next_syn={}
    for values in tuple_syns.values():
        values.sort(key=order)
        next_syn.update({r['id']:order(values[i+1]) if i+1<len(values) else None for i,r in enumerate(values)})
    exchanges = []
    totals = {'syn_record_count': len(syns), 'syn_destination_port_count': len({r['tcp']['dst_port'] for r in syns}),
              'syns_with_candidate_reset': 0, 'syns_with_candidate_syn_ack': 0,
              'syns_with_sequence_matched_reset': 0, 'syns_with_sequence_matched_handshake': 0,
              'syns_with_candidate_handshake': 0, 'syns_without_candidate_reply': 0, 'ambiguous_syn_records': 0}
    for syn in syns:
        src,dst,sport,dport = endpoints(syn)
        key = endpoints(syn)
        duplicate = duplicate_keys[key + (() if is_log else (syn['tcp']['sequence'],))]
        # New SYN with the same tuple bounds this candidate observation window.
        boundary = next_syn[syn['id']]
        candidates = [r for r in window((dst,src,dport,sport),order(syn),boundary)
                      if r['tcp']['flags'] & 0x17 == 0x12 or r['tcp']['flags'] & 4]
        reply = candidates[0] if candidates else None
        ambiguous = len(duplicate) > 1 or len(candidates) > 1 or bool(reply and tm(reply)==tm(syn))
        sequence_checked = False
        acknowledgement_matched = False
        final_ack = None
        if reply:
            sequence_checked = not is_log and bool(reply['tcp']['flags'] & 16)
            acknowledgement_matched = sequence_checked and reply['tcp']['acknowledgement'] == (syn['tcp']['sequence']+1) % (2**32)
            if reply['tcp']['flags'] & 0x17 == 0x12:
                acks = [r for r in window(key,order(reply),boundary) if r['tcp']['flags'] & 0x17 == 0x10]
                if not is_log:
                    acks = [r for r in acks if r['tcp']['sequence'] == (syn['tcp']['sequence']+1) % (2**32)
                            and r['tcp']['acknowledgement'] == (reply['tcp']['sequence']+1) % (2**32)]
                final_ack = acks[0] if acks else None
                # Later ACKs (including the first data segment) can legitimately
                # acknowledge the same SYN-ACK. They do not create competing
                # handshakes: retain the earliest observed completion. Equal-time
                # candidates still cannot be ordered from timestamps alone.
                ambiguous = ambiguous or bool(final_ack and (
                    tm(final_ack) == tm(reply)
                    or sum(tm(r) == tm(final_ack) for r in acks) > 1))
            reset = bool(reply['tcp']['flags'] & 4)
            totals['syns_with_candidate_reset'] += reset
            totals['syns_with_candidate_syn_ack'] += reply['tcp']['flags'] & 0x17 == 0x12
            totals['syns_with_sequence_matched_reset'] += reset and acknowledgement_matched and not ambiguous
            totals['syns_with_candidate_handshake'] += bool(final_ack)
            totals['syns_with_sequence_matched_handshake'] += bool(final_ack) and acknowledgement_matched and not ambiguous
        else:
            totals['syns_without_candidate_reply'] += 1
        totals['ambiguous_syn_records'] += ambiguous
        support = [syn] + ([reply] if reply else []) + ([final_ack] if final_ack else [])
        tuple_rows = window(key,order(syn),boundary) + window((dst,src,dport,sport),order(syn),boundary)
        tuple_last = max(tuple_rows,key=order)
        exchanges.append({'source':src,'destination':dst,'source_port':sport,'destination_port':dport,
            'initiator':{'address':src,'port':sport}, 'responder_service':{'address':dst,'port':dport},
            'reply_direction':{'source':dst,'source_port':dport,'destination':src,'destination_port':sport} if reply else None,
            'final_ack_direction':{'source':src,'source_port':sport,'destination':dst,'destination_port':dport} if final_ack else None,
            'syn_reference':syn['id'],'candidate_reply_reference':reply['id'] if reply else None,
            'candidate_reply_flags':reply['tcp']['flags'] if reply else None,
            'final_ack_reference':final_ack['id'] if final_ack else None,
            'supporting_references':[r['id'] for r in support],
            'reply_delay_seconds':float(tm(reply)-tm(syn)) if reply else None,
            'final_ack_delay_seconds':float(tm(final_ack)-tm(reply)) if final_ack else None,
            'handshake_elapsed_seconds':float(tm(final_ack)-tm(syn)) if final_ack else None,
            'tuple_last_reference':tuple_last['id'],'tuple_last_timestamp':tuple_last['timestamp'],
            'source_window_last_timestamp':source_last,
            'tuple_last_coincides_with_source_end':tm(tuple_last)==Decimal(source_last),
            'tuple_last_to_source_end_seconds':float(Decimal(source_last)-tm(tuple_last)),
            'sequence_fields_available':not is_log,'reply_acknowledgement_matches_syn':acknowledgement_matched if sequence_checked else None,
            'ambiguous':ambiguous,'matching_basis':'reverse tuple/timestamps/flags only' if is_log else 'reverse tuple/timestamps/flags and supplied sequence fields'})
    query = {'analysis':'tcp_exchanges','source':source,'destination':destination,'destination_port':destination_port}
    # Segment facts also work when capture starts midstream. Filters select
    # directional tuples, then retain both directions; never infer roles by IP sort.
    segment_keys = {endpoints(r) for r in rows if requested(r)}
    segment_keys |= {(d,s,dp,sp) for s,d,sp,dp in segment_keys.copy()}
    segment_rows = [r for r in rows if endpoints(r) in segment_keys]
    alias = 'a'+hashlib.sha256(encoded(query)).hexdigest()[:16]
    # Named scalar timing paths can be copied into grounded observations. Array
    # members are not valid scalar-support paths in the public answer contract.
    timing = {}
    for field in ('reply_delay_seconds','final_ack_delay_seconds','handshake_elapsed_seconds'):
        values = [x[field] for x in exchanges if x[field] is not None]
        # The familiar singular name is valid only for one observed exchange.
        # Multi-exchange summaries retain explicitly labelled min/max fields.
        timing[field] = values[0] if len(exchanges)==1 and len(values)==1 else None
        timing[field.removesuffix('_seconds')+'_min_seconds'] = min(values) if values else None
        timing[field.removesuffix('_seconds')+'_max_seconds'] = max(values) if values else None
    # Common singular facts must really be singular. Do not make the model copy
    # an arbitrary array member into a nonexistent aggregate scalar path.
    singular = {}
    for field in ('tuple_last_reference','tuple_last_timestamp',
                  'tuple_last_coincides_with_source_end','tuple_last_to_source_end_seconds',
                  'reply_acknowledgement_matches_syn','syn_reference',
                  'candidate_reply_reference','final_ack_reference'):
        singular[field] = exchanges[0][field] if len(exchanges)==1 else None
    for field, reference in (('reply_to_source_end_seconds','candidate_reply_reference'),
                             ('final_ack_to_source_end_seconds','final_ack_reference')):
        match = next((r for r in originals if len(exchanges)==1 and r['id']==exchanges[0][reference]),None)
        singular[field] = float(Decimal(source_last)-Decimal(match['timestamp'])) if match else None
    distances=[x['tuple_last_to_source_end_seconds'] for x in exchanges]
    singular['tuple_last_to_source_end_min_seconds']=min(distances) if distances else None
    singular['tuple_last_to_source_end_max_seconds']=max(distances) if distances else None
    return {'id':evidence['capture']['sha256']+':'+alias,'analysis_version':VERSION,'query':query,
        'input_kind':'network_log' if is_log else 'pcap','scope':'Selected decoded TCP SYN header observations and their candidate reverse tuple replies within this saved input.',
        **totals,**timing,**singular,'sequence_fields_available':not is_log,'selected_tcp_record_count':len(members),
        'source_window_first_timestamp':source_first,
        'source_window_last_timestamp':source_last,
        'source_window_duration_seconds':float(Decimal(source_last)-Decimal(source_first)) if source_last is not None else None,
        'exchanges_ending_at_source_window_end':sum(x['tuple_last_coincides_with_source_end'] for x in exchanges),
        'matching_basis':'reverse tuple/timestamps/flags only' if is_log else 'reverse tuple/timestamps/flags and supplied sequence fields',
        'singular_timing_scope':'Named singular intervals and tuple fields apply only when one exchange is selected; min/max describe the selected set. Source duration is not extra time after its final record. Last observation is not connection closure.',
        'segment_facts':tcp_segment_facts(segment_rows,is_log),
        'syn_destination_ports':sorted({r['tcp']['dst_port'] for r in syns})[:64],
        'syn_destination_ports_omitted':max(0,totals['syn_destination_port_count']-64),
        'unknown_input_record_count':sum(r['status']!='decoded' for r in originals),
        'exchanges':exchanges[:MAX_EXCHANGES],'exchange_details_omitted':max(0,len(exchanges)-MAX_EXCHANGES),
        'member_numbers':[r[number] for r in members[:96]],'member_numbers_omitted':max(0,len(members)-96),
        'membership_sha256':hashlib.sha256(encoded([r[number] for r in members])).hexdigest(),
        'limits':['SYN records are not automatically unique connection attempts; retransmissions and multiple candidates can be ambiguous.',
                  'No candidate reply means none among the decoded matching rows in this observation window, not no reply in the network or an undecodable frame.',
                  'A matching header sequence does not establish application success, intent, authorisation or current network state.',
                  'Log matching lacks sequence/ack numbers and raw packets; flags and timing support only candidate relationships.' if is_log else 'This is bounded header matching, not full TCP reassembly; packet timestamps and capture order can differ.']}
