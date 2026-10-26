"""Neutral, source-qualified service facts. No threat or root-cause verdict."""
from collections import Counter
from decimal import Decimal
import hashlib
import re

VERSION = 'service-evidence-1.0'

def application_fields(payload, protocol, source_port, destination_port):
    """Inspect a complete saved segment/datagram, never reassemble or decrypt."""
    if protocol == 'UDP' and 53 in (source_port, destination_port) and 12 <= len(payload) <= 4096:
        try:
            from scapy.layers.dns import DNS
            dns = DNS(payload)
            if dns.qdcount != 1 or not dns.qd or int(dns.opcode) != 0: return None
            name = bytes(dns.qd[0].qname).decode('ascii')
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', name): return None
            return dict(protocol='DNS', transaction_id=int(dns.id), response=bool(dns.qr),
                        response_code=int(dns.rcode), query=name, query_type=int(dns.qd[0].qtype),
                        answer_count=int(dns.ancount), scope='One saved unencrypted DNS datagram; no service intent established.')
        except (ValueError, TypeError, AttributeError, IndexError, UnicodeError): return None
    if protocol != 'TCP' or not payload or len(payload) > 262144: return None
    first = payload.split(b'\r\n', 1)[0]
    if len(first) > 512: return None
    match = re.fullmatch(rb'(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) ([\x21-\x7e]{1,300}) HTTP/(1\.[01])', first)
    reply = re.fullmatch(rb'HTTP/(1\.[01]) ([1-5][0-9]{2})(?: [\x20-\x7e]{0,100})?', first)
    if not match and not reply: return None
    row = dict(protocol='HTTP', message='request' if match else 'response',
               header_complete=b'\r\n\r\n' in payload[:8192],
               scope='Visible HTTP/1 start line in one saved TCP segment; no stream reassembly or business-success inference.')
    if match: row.update(method=match[1].decode(), path=match[2].decode(), version=match[3].decode())
    else: row.update(version=reply[1].decode(), status_code=int(reply[2]))
    return row

def service_facts(evidence, destination_port=0):
    if type(destination_port) is not int or not 0 <= destination_port <= 65535: raise ValueError('Invalid port.')
    log = evidence.get('input_kind') == 'network_log'
    originals = evidence.get('log_records', []) if log else evidence.get('packets', [])
    rows = [r for r in originals if r.get('status') == 'decoded' and r.get('ipv4')]
    decoded_count=len(rows)
    if destination_port:
        rows = [r for r in rows if destination_port in ((r.get('tcp') or r.get('udp') or {}).get('src_port'),
                                                      (r.get('tcp') or r.get('udp') or {}).get('dst_port'))]
    stamps = [Decimal(r['timestamp']) for r in rows]
    duration = float(max(stamps)-min(stamps)) if stamps else None
    sizes = [r.get('reported_frame_length') if log else r.get('captured_bytes') for r in rows]
    total_bytes = sum(v for v in sizes if type(v) is int)
    tcp = [r for r in rows if r.get('tcp')]
    apps = [r for r in rows if r.get('application')]
    exchanges, pending = [], {}
    for r in sorted(apps, key=lambda r: (Decimal(r['timestamp']), r.get('packet', 0))):
        a, ip, t = r['application'], r['ipv4'], r.get('tcp') or r.get('udp')
        key = (ip['src'], t['src_port'], ip['dst'], t['dst_port'], a['protocol'], a.get('transaction_id'))
        reverse = (ip['dst'], t['dst_port'], ip['src'], t['src_port'], a['protocol'], a.get('transaction_id'))
        response = a.get('message') == 'response' or a.get('response') is True
        if not response: pending.setdefault(key, []).append(r)
        elif len(pending.get(reverse, [])) == 1:
            request = pending.pop(reverse)[0]
            if a['protocol']=='DNS' and (a['query'],a['query_type'])!=(request['application']['query'],request['application']['query_type']):continue
            # HTTP association is only an observed tuple/time candidate; no sequence/reassembly proof.
            exchanges.append(dict(protocol=a['protocol'], request=request['id'], response=r['id'],
                delay_seconds=float(Decimal(r['timestamp'])-Decimal(request['timestamp'])),
                status_code=a.get('status_code'), response_code=a.get('response_code'),
                association='Candidate pair by reversed tuple, order and no other pending visible request.'))
    delays = [x['delay_seconds'] for x in exchanges]
    fingerprint = hashlib.sha256(repr([(Decimal(r['timestamp']).normalize(),r['ipv4']['src'],r['ipv4']['dst'],
        (r.get('tcp') or r.get('udp')).get('src_port'),(r.get('tcp') or r.get('udp')).get('dst_port'),
        r['protocol'],r.get('wire_bytes',r.get('reported_frame_length'))) for r in rows]).encode()).hexdigest()
    return dict(version=VERSION, source_sha256=evidence['capture']['sha256'], input_kind='network_log' if log else 'pcap',
        service_port=destination_port, record_count=len(rows), source_records=len(originals),
        excluded_records=len(originals)-decoded_count,filter_excluded_records=decoded_count-len(rows),
        duration_seconds=duration, frame_bytes=total_bytes,
        byte_unit='reported frame bytes' if log else 'captured frame bytes',
        records_per_second=len(rows)/duration if duration else None,
        frame_bytes_per_second=total_bytes/duration if duration else None,
        syn_records=sum(r['tcp']['flags']&0x12==2 for r in tcp),
        syn_ack_records=sum(r['tcp']['flags']&0x12==0x12 for r in tcp),
        reset_records=sum(bool(r['tcp']['flags']&4) for r in tcp),
        directional_counts=dict(Counter(r['ipv4']['src']+' -> '+r['ipv4']['dst'] for r in rows)),
        application_available=bool(apps), visible_http_requests=sum(r['application'].get('message')=='request' for r in apps),
        visible_http_responses=sum(r['application'].get('message')=='response' for r in apps),
        visible_dns_datagrams=sum(r['application']['protocol']=='DNS' for r in apps),
        candidate_pairs=len(exchanges), mean_candidate_reply_seconds=sum(delays)/len(delays) if delays else None,
        candidate_exchanges=exchanges[:32], candidate_exchanges_omitted=max(0,len(exchanges)-32),
        records_fingerprint=fingerprint, references=[r['id'] for r in rows[:96]], references_omitted=max(0,len(rows)-96),
        limits=['Counts describe selected decoded records, not unique attempts or whole-network activity.',
                'Rates use first-to-last observed record time, not a known collection duration; very short windows are unstable.',
                'Candidate reply timing is not pure server processing time or proof of cause. HTTP is not reassembled.',
                'No matching observed reply does not prove no reply occurred. Logs have no application payload fields.'])

def compare_service(left, right, destination_port=0):
    a,b=service_facts(left,destination_port),service_facts(right,destination_port)
    if a['source_sha256']==b['source_sha256']: raise ValueError('Choose different original sources, not the same input twice.')
    reasons=[]
    if a['records_fingerprint']==b['records_fingerprint']: reasons.append('Records coincide; these may be duplicate or derived evidence, not independent observations.')
    if not a['duration_seconds'] or not b['duration_seconds']: reasons.append('A selected window has no measurable positive duration; rate comparison unavailable.')
    elif a['duration_seconds']!=b['duration_seconds']:reasons.append('Observed spans differ; raw counts do not represent equal collection exposure. Rates use each source\'s own first-to-last span.')
    if a['byte_unit']!=b['byte_unit']: reasons.append('Captured and reported frame-byte units differ; byte-rate delta is unavailable.')
    if a['excluded_records'] or b['excluded_records']: reasons.append('Excluded source records limit the comparison.')
    if any(x['duration_seconds'] is not None and x['duration_seconds']<1 for x in (a,b)): reasons.append('At least one observed window is shorter than one second; rates are descriptive, not a representative workload baseline.')
    keys=('record_count','frame_bytes','syn_records','syn_ack_records','reset_records','visible_http_requests','visible_http_responses','visible_dns_datagrams','candidate_pairs')
    delta={key:b[key]-a[key] for key in keys}
    for key in ('duration_seconds','records_per_second','frame_bytes_per_second','mean_candidate_reply_seconds'):
        delta[key]=b[key]-a[key] if a[key] is not None and b[key] is not None and (key!='frame_bytes_per_second' or a['byte_unit']==b['byte_unit']) else None
    return dict(version=VERSION,baseline=a,comparison=b,delta=delta,qualification='limited' if reasons else 'descriptive',
        qualifications=reasons,policy='Difference between selected retained observations; no causal, maliciousness or authorisation verdict. Capture locations, filters and workloads must be comparable.')
