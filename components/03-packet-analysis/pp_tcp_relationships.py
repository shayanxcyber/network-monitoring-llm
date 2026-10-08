"""Neutral bounded header relationships, not stream reassembly or detection."""
from collections import defaultdict
from bisect import bisect_left
from decimal import Decimal
import hashlib
from pp_context import encoded

VERSION = 'packetpilot-tcp-relationships-1.0'
MAX_EXCHANGES = 32


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
                ambiguous = ambiguous or len(acks) > 1
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
        exchanges.append({'source':src,'destination':dst,'source_port':sport,'destination_port':dport,
            'syn_reference':syn['id'],'candidate_reply_reference':reply['id'] if reply else None,
            'candidate_reply_flags':reply['tcp']['flags'] if reply else None,
            'final_ack_reference':final_ack['id'] if final_ack else None,
            'supporting_references':[r['id'] for r in support],
            'reply_delay_seconds':float(tm(reply)-tm(syn)) if reply else None,
            'final_ack_delay_seconds':float(tm(final_ack)-tm(reply)) if final_ack else None,
            'sequence_fields_available':not is_log,'reply_acknowledgement_matches_syn':acknowledgement_matched if sequence_checked else None,
            'ambiguous':ambiguous,'matching_basis':'reverse tuple/timestamps/flags only' if is_log else 'reverse tuple/timestamps/flags and supplied sequence fields'})
    query = {'analysis':'tcp_exchanges','source':source,'destination':destination,'destination_port':destination_port}
    alias = 'a'+hashlib.sha256(encoded(query)).hexdigest()[:16]
    return {'id':evidence['capture']['sha256']+':'+alias,'analysis_version':VERSION,'query':query,
        'input_kind':'network_log' if is_log else 'pcap','scope':'Selected decoded TCP SYN header observations and their candidate reverse tuple replies within this saved input.',
        **totals,'sequence_fields_available':not is_log,'selected_tcp_record_count':len(members),
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
