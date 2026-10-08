"""Bounded, neutral presentation calculations over retained evidence only.

No model-authored numbers, network operations, threat labels or new raw-packet
identities. Physical log lines remain distinct from exported frame numbers.
"""
from collections import Counter, defaultdict
from decimal import Decimal
import hashlib
import math
from pp_context import encoded

VIEW_TYPES = ('table', 'timeline', 'map', 'comparison', 'bar', 'line', 'area')


def source_rows(evidence):
    return evidence.get('log_records', []) if evidence.get('input_kind') == 'network_log' else evidence.get('packets', [])


def records(evidence):
    rows = source_rows(evidence)
    times = [Decimal(r['timestamp']) for r in rows if r.get('timestamp') is not None]
    origin = min(times) if times else None
    result = []
    log = evidence.get('input_kind') == 'network_log'
    for row in rows:
        ip, transport = row.get('ipv4') or {}, row.get('tcp') or row.get('udp') or {}
        stamp = Decimal(row['timestamp']) if row.get('timestamp') is not None else None
        result.append({'id': row['id'], 'number': row.get('line_number') if log else row.get('packet'),
            'kind': 'log_line' if log else 'packet', 'source_frame_number': row.get('source_frame_number') if log else None,
            'timestamp': row.get('timestamp'), 'relative_seconds': float(stamp-origin) if stamp is not None and origin is not None else None,
            'protocol': row.get('protocol', 'UNKNOWN'), 'status': row['status'],
            'source': ip.get('src', ''), 'destination': ip.get('dst', ''),
            'source_port': transport.get('src_port'), 'destination_port': transport.get('dst_port'),
            'flags': (row.get('tcp') or {}).get('flag_names', []),
            'bytes': row.get('reported_frame_length') if log else row.get('captured_bytes'),
            'byte_unit': 'reported frame bytes' if log else 'captured frame bytes',
            'issues': row.get('issues') or [row.get('reason', '')], 'flow_id': row.get('flow_id')})
    return result


def record_page(evidence, query='', sort='number', descending=False, offset=0, limit=100, protocol='', status=''):
    if sort not in {'number', 'relative_seconds', 'protocol', 'source', 'destination', 'status', 'bytes'}:
        raise ValueError('Unknown table sort.')
    if not 0 <= offset <= 10000 or not 1 <= limit <= 200 or len(query) > 160:
        raise ValueError('Table query exceeds its bounds.')
    rows = records(evidence)
    if len(protocol) > 24 or len(status) > 24:
        raise ValueError('Record filter exceeds its bounds.')
    if protocol:
        rows = [r for r in rows if r['protocol'] == protocol]
    if status:
        rows = [r for r in rows if r['status'] == status]
    query = query.strip().lower()
    if query:
        rows = [r for r in rows if query in ' '.join(str(v) for v in r.values()).lower()]
    rows.sort(key=lambda r: (r[sort] is None, r[sort] if r[sort] is not None else '', r['number']), reverse=descending)
    return {'rows': rows[offset:offset+limit], 'total_matching': len(rows), 'total_source': len(source_rows(evidence)),
            'offset': offset, 'limit': limit, 'sort': sort, 'descending': descending,
            'capture_sha256': evidence['capture']['sha256']}


def build_views(evidence, references=None):
    references = references or []
    if len(references) > 16 or len(set(references)) != len(references):
        raise ValueError('Use at most 16 unique original references.')
    original = source_rows(evidence)
    all_rows = records(evidence)
    wanted = set(references)
    allowed = {r['id'] for r in original}
    flows = {f['id']: f for f in evidence.get('flows', [])}
    allowed |= set(flows)
    if wanted and not wanted <= allowed:
        raise ValueError('View selection must name original records or retained flows in this source.')
    if wanted:
        members = set(wanted)
        for ref in wanted & set(flows):
            # Retained flow membership is original packet NUMBER, not an ID.
            members.update(evidence['capture']['sha256']+':p'+str(n) for n in flows[ref].get('packet_refs', []))
        all_rows = [r for r in all_rows if r['id'] in members]
        original = [r for r in original if r['id'] in members]
    decoded = [r for r in all_rows if r['status'] == 'decoded' and r['source'] and r['destination']]
    origin = min((Decimal(r['timestamp']) for r in decoded if r['timestamp'] is not None), default=None)
    end = max((Decimal(r['timestamp']) for r in decoded if r['timestamp'] is not None), default=None)
    span = float(end-origin) if origin is not None and end is not None else 0
    groups = defaultdict(list)
    edges = defaultdict(list)
    for row in decoded:
        groups[(row['protocol'], row['source'], row['source_port'], row['destination'], row['destination_port'])].append(row)
        edges[(row['source'], row['destination'], row['protocol'])].append(row)
    def membership(rows):
        return {'references': [r['id'] for r in rows[:96]], 'references_omitted': max(0, len(rows)-96),
                'membership_sha256': hashlib.sha256(encoded([r['id'] for r in rows])).hexdigest()}
    comparison = []
    composition = []
    for protocol in sorted({row['protocol'] for row in all_rows}):
        members = [row for row in all_rows if row['protocol'] == protocol]
        composition.append({'protocol': protocol, 'count': len(members), **membership(members)})
    for (protocol, source, sp, destination, dp), rows in sorted(groups.items()):
        comparison.append({'protocol': protocol, 'source': source, 'source_port': sp,
            'destination': destination, 'destination_port': dp, 'count': len(rows), **membership(rows)})
    communication = [{'source': s, 'destination': d, 'protocol': p, 'count': len(rows), **membership(rows)}
                     for (s, d, p), rows in sorted(edges.items())]
    # A bar is expressly SYN header records by destination service port, not
    # unique attempts. Reply-side ephemeral ports never enter this grouping.
    syn_groups = defaultdict(list)
    for raw, row in zip(original, all_rows):
        if raw.get('tcp') and raw['status'] == 'decoded' and raw['tcp']['flags'] & 0x12 == 2:
            syn_groups[(row['destination'], row['destination_port'])].append(row)
    bars = [{'label': f'{dst}:{port}', 'count': len(rows), **membership(rows)}
            for (dst, port), rows in sorted(syn_groups.items())][:64]
    series = []
    bins = min(24, max(4, int(math.sqrt(len(decoded))))) if len(decoded) >= 16 and span > 0 else 0
    if bins:
        bin_rows = [[] for _ in range(bins)]
        for row in decoded:
            position = min(bins-1, int(float(Decimal(row['timestamp'])-origin) / span * bins))
            bin_rows[position].append(row)
        for i, rows in enumerate(bin_rows):
            series.append({'start_seconds': span*i/bins, 'end_seconds': span*(i+1)/bins, 'count': len(rows),
                           'protocols': dict(Counter(r['protocol'] for r in rows)), **membership(rows)})
    identity = hashlib.sha256(encoded({'version': 'evidence-views-1.1', 'source': evidence['capture']['sha256'], 'selection': references})).hexdigest()
    return {'version': '1.1', 'result_id': identity, 'capture_sha256': evidence['capture']['sha256'],
        'selection': references or ['all retained records'], 'units': 'decoded original records',
        'reference_kind': 'physical log lines' if evidence.get('input_kind') == 'network_log' else 'original packets',
        'window': {'first_timestamp': str(origin) if origin is not None else None,
                   'last_timestamp': str(end) if end is not None else None, 'duration_seconds': span},
        'coverage': {'selected_records': len(all_rows), 'decoded_records': len(decoded),
                     'excluded_records': len(all_rows)-len(decoded), 'source': evidence.get('coverage', {})},
        'table': {'rows': all_rows[:100], 'total_matching': len(all_rows), 'total_source': len(source_rows(evidence))},
        'timeline': sorted(decoded, key=lambda r: (Decimal(r['timestamp']), r['number']))[:96],
        'timeline_omitted': max(0, len(decoded)-96),
        'composition': composition,
        'map': {'nodes': sorted({r[k] for r in decoded for k in ('source', 'destination')})[:32],
                'nodes_omitted': max(0, len({r[k] for r in decoded for k in ('source', 'destination')})-32),
                'edges': communication[:64], 'edges_omitted': max(0, len(communication)-64)},
        'comparison': comparison[:64], 'comparison_omitted': max(0, len(comparison)-64),
        'bar': {'unit': 'SYN-without-ACK header records', 'data': bars},
        'series': {'unit': 'decoded original records per bin', 'bin_seconds': span/bins if bins else None, 'data': series,
                   'reason': None if bins else 'A table or timeline better represents this short or undated source.'},
        'limits': ['Observed communication, not physical network topology or whole-network coverage.',
                   'SYN records may include retransmissions; counts are not unique connection attempts.',
                   'Zero in a bin means no matching decoded rows in this retained source, not network inactivity.',
                   'Captured/reported frame length is distinct from payload bytes and full on-wire traffic.']}
