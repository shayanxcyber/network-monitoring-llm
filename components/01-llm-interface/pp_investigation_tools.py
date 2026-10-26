"""Capture-bound, read-only Python tools. No shell, paths or live network access."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import time
from functools import wraps
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal

from pp_context import build_context, encoded, MAX_CONTEXT_BYTES, required_coverage_status
from pp_tcp_relationships import analyse_tcp_exchanges, scalar_paths
from pp_semantics import field_semantics

TOOL_VERSION = 'packetpilot-evidence-tools-3.6'
MAX_TOOL_CALLS = 8
MAX_TOOL_BYTES = 48_000
DISCLOSURE_RESERVE = 1024


def json_tool(function):
    """Preserve Agno's signature/doc schema; present canonical JSON on the wire."""
    @wraps(function)
    def invoke(*args, **kwargs):
        return encoded(function(*args, **kwargs)).decode('utf-8')
    return invoke


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class EvidenceWorkspace:
    """One detached evidence snapshot for one question; state cannot select a path."""

    @property
    def tool_names(self):
        return {'get_packets', 'get_flow', 'summarize_connections', 'inspect_tcp_exchanges', 'get_code_reference'}

    @property
    def tools(self):
        return [json_tool(f) for f in (self.get_packets, self.get_flow, self.summarize_connections, self.inspect_tcp_exchanges,self.get_code_reference)]

    def __init__(self, evidence, question, deadline=None):
        self.evidence = copy.deepcopy(evidence)
        self.digest = evidence['capture']['sha256']
        self.deadline = deadline or (time.monotonic() + 300)
        self.trace = []
        self.supplied = {}
        self.aggregates = {}
        self.packets = {p['packet']: p for p in self.evidence['packets']}
        self.flows = {f'f{i}': f for i, f in enumerate(self.evidence['flows'], 1)}
        self.aliases = {self.digest + ':' + k: k for k in ('capture', 'overview', 'coverage')}
        self.aliases.update({p['id']: f'p{p["packet"]}' for p in self.packets.values()})
        self.aliases.update({f['id']: key for key, f in self.flows.items()})
        self.context = build_context(self.evidence, question)
        self.context['context_version'] = 'packetpilot-investigation-context-3.2'
        self.context['reference_policy'] = 'Use the short id of a supplied record. Backend resolves it to this capture; never construct a hash or another record id.'
        self.context['tool_policy'] = {'version': TOOL_VERSION, 'max_calls': MAX_TOOL_CALLS,
                                       'scope': 'Selected saved evidence only; no filesystem or network actions.'}
        for key in ('capture', 'overview', 'coverage'):
            self.context[key] = self._supply(self.context[key])
        for key in ('packets', 'flows'):
            self.context[key] = [self._supply(row) for row in self.context[key]]
        aggregate = self._aggregate('all', '', '', 0)
        self.context['connections'] = self._supply(aggregate)
        self.context['measurement_fields'] = {key: scalar_paths(self.context[key]) for key in ('capture','overview','coverage','connections')}
        self.context['evidence_capabilities'] = {'packet_sequence_fields':True,
            'application_success_supported':False,
            'tcp_relationships':'Use inspect_tcp_exchanges for a bounded SYN/reply/ACK relationship calculation with its supporting references.',
            'missing_scope':'Unknown/malformed records and omitted detail are different limitations; neither proves traffic never occurred.'}
        self.context['field_semantics'] = field_semantics('pcap')
        # Keep complete small captures. The existing 96-record/180k policy bounds
        # large captures; omitted records remain retrievable, not discarded.
        while len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES and (self.context['flows'] or self.context['packets']):
            key = 'flows' if self.context['flows'] else 'packets'
            removed = self.context[key].pop()
            self.supplied.pop(removed['id'], None)
        if len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES:
            raise ValueError('Initial investigation context exceeds its byte limit.')
        self.initial_packet_numbers = frozenset(p['packet'] for p in self.context['packets'])
        self.initial_flow_ids = frozenset(f['id'] for f in self.context['flows'])
        self._selection()

    def _aggregate_alias(self, full_id):
        # Persist canonical query/capture hashes; use small local selectors only
        # on the model wire. Never guess or accept an unsupplied reference.
        if full_id not in self.aliases:
            self.aliases[full_id] = 'a' + str(1 + sum(v.startswith('a') for v in self.aliases.values()))
        return self.aliases[full_id]

    def coverage_disclosure(self):
        return {'required_status': required_coverage_status(self.evidence, self.context),
                'context_selection': copy.deepcopy(self.context['context_selection']),
                'meaning': 'Supported decode and supplied-detail coverage only; not application success, payload preview completeness or network-wide visibility.'}

    def _selection(self):
        packets = sum(key.startswith('p') and key[1:].isdigit() for key in self.supplied)
        flows = sum(key.startswith('f') and key[1:].isdigit() for key in self.supplied)
        supplied_numbers={int(k[1:]) for k in self.supplied if k.startswith('p') and k[1:].isdigit()}
        initial=self.initial_packet_numbers
        retrieved=supplied_numbers-initial
        omitted=sorted(set(self.packets)-supplied_numbers)
        self.context['context_selection'].update(
            selection='initial prefix plus read-only inspected original records' if retrieved else 'initial capture-order prefix',
            initial_packets_included=len(initial), initial_flows_included=len(self.initial_flow_ids),
            retrieved_packets_included=len(retrieved),
            omitted_packet_numbers=omitted[:96],omitted_packet_numbers_omitted=max(0,len(omitted)-96),
            packets_included=packets, packets_omitted=len(self.packets) - packets,
            flows_included=flows, flows_omitted=len(self.flows) - flows,
            all_detail_included=packets == len(self.packets) and flows == len(self.flows))
        self.context['coverage_disclosure'] = self.coverage_disclosure()

    def _shorten(self, value):
        if isinstance(value, dict):
            result = {k: self._shorten(v) for k, v in value.items()}
            if 'directions' in result and isinstance(result.get('packet_refs'), list) and len(result['packet_refs']) > 96:
                result['packet_refs_omitted'] = len(result['packet_refs'])-96
                result['packet_refs'] = result['packet_refs'][:96]
            return result
        if isinstance(value, list):
            return [self._shorten(v) for v in value]
        return self.aliases.get(value, value) if isinstance(value, str) else value

    def _supply(self, row):
        alias = self.aliases[row['id']]
        self.supplied[alias] = copy.deepcopy(row)
        return self._shorten(row)

    def _aggregate(self, protocol, source, destination, destination_port):
        query = {'protocol': protocol, 'source': source, 'destination': destination,
                 'destination_port': destination_port}
        identity = hashlib.sha256(encoded(query)).hexdigest()[:16]
        full_id = self.digest + ':a' + identity
        self._aggregate_alias(full_id)
        selected = []
        for p in self.packets.values():
            if p['status'] != 'decoded':
                continue
            ip, transport = p['ipv4'], p['tcp'] or p['udp']
            if protocol != 'all' and p['protocol'] != protocol:
                continue
            if source and ip['src'] != source or destination and ip['dst'] != destination:
                continue
            if destination_port and transport['dst_port'] != destination_port:
                continue
            selected.append(p)
        groups = defaultdict(list)
        for p in selected:
            groups[(p['protocol'], p['ipv4']['src'], p['ipv4']['dst'])].append(p)
        directions = []
        for (proto, src, dst), rows in sorted(groups.items()):
            syn = [p for p in rows if p['tcp'] and p['tcp']['flags'] & 0x12 == 0x02]
            ports = sorted({(p['tcp'] or p['udp'])['dst_port'] for p in rows})
            syn_ports = sorted({p['tcp']['dst_port'] for p in syn})
            refs = [p['packet'] for p in rows]
            directions.append({'protocol': proto, 'source': src, 'destination': dst,
                'packet_count': len(rows), 'destination_port_count': len(ports),
                'destination_ports': ports[:64], 'destination_ports_omitted': max(0, len(ports)-64),
                'syn_without_ack_count': len(syn), 'syn_destination_port_count': len(syn_ports),
                'syn_destination_ports': syn_ports[:64], 'syn_ports_omitted': max(0, len(syn_ports)-64),
                'rst_count': sum(bool(p['tcp'] and p['tcp']['flags'] & 4) for p in rows),
                'packet_numbers': refs[:64], 'member_numbers_omitted': max(0, len(refs)-64)})
        times = [Decimal(p['timestamp']) for p in selected]
        gaps = [b-a for a,b in zip(times,times[1:])]
        members = [p['packet'] for p in selected]
        payloads = [p['payload']['length'] for p in selected]
        flags = Counter(name for p in selected if p['tcp'] for name in p['tcp']['flag_names'])
        by_hash=defaultdict(list)
        for p in selected:by_hash[p['frame_sha256']].append(p)
        hash_groups=[]
        for digest,rows in by_hash.items():
            gt=[Decimal(p['timestamp']) for p in rows];gg=[b-a for a,b in zip(gt,gt[1:])]
            hash_groups.append({'frame_sha256':digest,'member_count':len(rows),
                'member_numbers':[p['packet'] for p in rows[:96]],'member_numbers_omitted':max(0,len(rows)-96),
                'arrival_gap_count':len(gg),'arrival_gap_min_seconds':float(min(gg)) if gg else 0,
                'arrival_gap_max_seconds':float(max(gg)) if gg else 0})
        hash_groups.sort(key=lambda g:(-g['member_count'],g['member_numbers'][0]))
        largest=hash_groups[0] if hash_groups else {}
        result = {'id': full_id, 'query': query, 'scope': 'All decoded packets matching these directional filters, not network-wide traffic.',
            'packet_count': len(selected), 'decoded_capture_packets': self.evidence['coverage']['decoded_packets'],
            'excluded_capture_packets': len(self.packets)-self.evidence['coverage']['decoded_packets'],
            'protocol_counts': dict(sorted(Counter(p['protocol'] for p in selected).items())),
            'tcp_flag_counts': dict(sorted(flags.items())),
            'distinct_frame_hash_count': len({p['frame_sha256'] for p in selected}),
            'frame_hash_groups':hash_groups[:16],'frame_hash_groups_omitted':max(0,len(hash_groups)-16),
            'largest_identical_frame_group_count':largest.get('member_count',0),
            'largest_identical_frame_group_gap_count':largest.get('arrival_gap_count',0),
            'largest_identical_frame_group_gap_min_seconds':largest.get('arrival_gap_min_seconds',0),
            'largest_identical_frame_group_gap_max_seconds':largest.get('arrival_gap_max_seconds',0),
            'payload_bytes_total': sum(payloads),
            'min_payload_bytes': min(payloads) if payloads else 0,
            'max_payload_bytes': max(payloads) if payloads else 0,
            'syn_without_ack_count': sum(bool(p['tcp'] and p['tcp']['flags'] & 0x12 == 0x02) for p in selected),
            'syn_destination_port_count': len({p['tcp']['dst_port'] for p in selected if p['tcp'] and p['tcp']['flags'] & 0x12 == 0x02}),
            'rst_count': sum(bool(p['tcp'] and p['tcp']['flags'] & 4) for p in selected),
            'duration_seconds': float(max(times)-min(times)) if times else 0,
            'arrival_gap_order': 'Selected records in original capture order; negative gaps are possible, not sorted or unique sessions.',
            'arrival_gap_count': len(gaps),
            'arrival_gap_min_seconds': float(min(gaps)) if gaps else 0,
            'arrival_gap_max_seconds': float(max(gaps)) if gaps else 0,
            'directional_group_count': len(directions), 'directions': directions[:32],
            'directional_groups_omitted': max(0, len(directions)-32),
            'member_count': len(members), 'member_numbers': members[:96],
            'member_numbers_omitted': max(0, len(members)-96),
            'membership_sha256': hashlib.sha256(encoded(members)).hexdigest(),
            'limits': 'A SYN without ACK is a header observation, not proof of a unique attempt. Reply ephemeral ports are not destination-service scans. No threat verdict is calculated.'}
        self.aggregates[full_id] = result | {'complete_member_numbers': members}
        return result

    def _run(self, name, arguments, operation):
        entry = {'tool': name, 'arguments': arguments, 'started_at': timestamp(), 'capture_sha256': self.digest}
        started = time.monotonic()
        if len(self.trace) >= MAX_TOOL_CALLS:
            return {'ok': False, 'error': 'tool_limit', 'message': 'Investigation tool budget exhausted; answer with the evidence already obtained.'}
        self.trace.append(entry)
        callback = getattr(self, 'event_callback', None)
        if callback: callback('tool_started', {'tool': name, 'arguments': arguments, 'index': len(self.trace)})
        try:
            if time.monotonic() >= self.deadline:
                raise ValueError('Investigation time budget exhausted.')
            records, extra = operation()
            # Do not mark a record supplied until its complete tool response fits.
            result = {'ok': True, 'capture_sha256': self.digest,
                      'records': [self._shorten(row) for row in records], **extra}
            result['measurement_fields'] = {self.aliases[row['id']]: scalar_paths(row) for row in records}
            if len(encoded(result)) + len(encoded(self.coverage_disclosure())) + 256 > MAX_TOOL_BYTES:
                raise ValueError('Result exceeds byte limit; request fewer packets or a narrower filter.')
            for row in records:
                self._supply(row)
            self._selection()
            result['coverage_disclosure'] = self.coverage_disclosure()
            entry.update(ok=True, result=result)
            return result
        except (ValueError, KeyError, TypeError):
            result = {'ok': False, 'error': 'invalid_or_unavailable_query',
                      'message': 'Use known short record IDs, original record numbers, valid lab addresses and bounded pagination. No external data was accessed.'}
            entry.update(ok=False, result=result)
            return result
        finally:
            entry['finished_at'] = timestamp()
            # Public, capture-bound result metadata only. Never forward raw
            # provider reasoning, payload content or untrusted exception text.
            rows = entry.get('result', {}).get('records', [])
            references = []
            for row in rows:
                supplied = self.supplied.get(row.get('id')) if isinstance(row, dict) else None
                identity = supplied.get('id') if supplied else None
                if isinstance(identity, str) and identity.startswith(self.digest + ':'):
                    references.append(identity)
            if callback: callback('tool_finished', {'tool': name, 'index': len(self.trace),
                'ok': entry.get('ok', False), 'elapsed_seconds': round(time.monotonic()-started, 4),
                'returned_records': len(rows), 'references': references[:8],
                'references_omitted': max(0, len(references)-8)})

    def get_packets(self, packet_numbers: list[int]) -> dict:
        """Inspect 1-16 exact packet numbers in the selected saved capture, including flags and direction. No paths accepted.

        Args:
            packet_numbers: Unique positive packet numbers, for example [1, 2, 3].
        """
        def operation():
            if (not isinstance(packet_numbers, list) or not 1 <= len(packet_numbers) <= 16
                    or any(type(n) is not int or n not in self.packets for n in packet_numbers)
                    or len(set(packet_numbers)) != len(packet_numbers)):
                raise ValueError('Invalid packet numbers.')
            return [self.packets[n] for n in packet_numbers], {'scope': 'Only these packets.'}
        return self._run('get_packets', {'packet_numbers': packet_numbers}, operation)

    def get_code_reference(self,topic:str='tsv_checker')->dict:
        """Retrieve reviewed standalone read-only example source, not execute it.

        Args:
            topic: tsv_checker for the supported eleven-column lab TSV checker, including LF/CRLF, blank lines and optional transport fields.
        """
        def operation():
            from pp_code_reference import code_reference
            row=code_reference(topic)
            full_id=self.digest+':a'+hashlib.sha256(encoded(row)).hexdigest()[:16]
            row['id']=full_id;self._aggregate_alias(full_id);self.aggregates[full_id]=copy.deepcopy(row)
            return [row],{'authority':'Read-only code reference, no filesystem or network execution. Copy exact code if citing its reviewed provenance.'}
        return self._run('get_code_reference',{'topic':topic},operation)

    def get_flow(self, flow_id: str, offset: int = 0, limit: int = 16) -> dict:
        """Inspect a known short flow ID (f1 etc.), its endpoint direction counts and paginated packet sequence. Endpoint A is sorted, NOT automatically the initiator.

        Args:
            flow_id: Short flow ID supplied by the current capture context.
            offset: Zero-based offset in the flow's capture-order packet sequence.
            limit: Number of packet details, between 1 and 16.
        """
        def operation():
            if (flow_id not in self.flows or type(offset) is not int or type(limit) is not int
                    or not 0 <= offset < len(self.flows[flow_id]['packet_refs']) or not 1 <= limit <= 16):
                raise ValueError('Invalid flow page.')
            flow = self.flows[flow_id]
            numbers = flow['packet_refs'][offset:offset+limit]
            return [flow, *[self.packets[n] for n in numbers]], {
                'offset': offset, 'returned_packets': len(numbers),
                'next_offset': offset+limit if offset+limit < flow['packet_count'] else None,
                'scope': 'Flow aggregate covers all members; packet details are this page only. Capture order can differ from timestamp order.'}
        return self._run('get_flow', {'flow_id': flow_id, 'offset': offset, 'limit': limit}, operation)

    def summarize_connections(self, protocol: str = 'all', source: str = '', destination: str = '', destination_port: int = 0) -> dict:
        """Compute neutral directional counts across ALL decoded records, including those omitted from initial context. Filters use packet direction, not assumed initiator. No detection verdict.

        Args:
            protocol: all, TCP or UDP.
            source: Optional source IPv4 within 10.77.0.0/24; empty means any.
            destination: Optional destination IPv4 within 10.77.0.0/24; empty means any.
            destination_port: Destination port 1-65535, or 0 for any.
        """
        def operation():
            if protocol not in ('all', 'TCP', 'UDP') or type(destination_port) is not int or not 0 <= destination_port <= 65535:
                raise ValueError('Invalid filter.')
            for address in (source, destination):
                if not isinstance(address, str) or address and ipaddress.ip_address(address) not in ipaddress.ip_network('10.77.0.0/24'):
                    raise ValueError('Invalid lab address.')
            return [self._aggregate(protocol, source, destination, destination_port)], {}
        return self._run('summarize_connections', {'protocol': protocol, 'source': source,
                         'destination': destination, 'destination_port': destination_port}, operation)

    def validation_context(self):
        """Canonical IDs for application validation; only actually supplied records."""
        context = copy.deepcopy(self.context)
        context.update({key: self.supplied[key] for key in ('capture', 'overview', 'coverage')})
        context['packets'] = [v for k, v in self.supplied.items() if k.startswith('p') and k[1:].isdigit()]
        context['flows'] = [v for k, v in self.supplied.items() if k.startswith('f') and k[1:].isdigit()]
        context['additional_records'] = [v for k, v in self.supplied.items() if k.startswith('a')]
        return context

    def inspect_tcp_exchanges(self, source: str = '', destination: str = '', destination_port: int = 0) -> dict:
        """Check SYN service breadth and candidate replies/ACKs in the selected input. Returns supporting refs and exact scope; logs lack sequence numbers. No threat verdict.

        Args:
            source: Optional initiating source in 10.77.0.0/24; empty means any.
            destination: Optional SYN destination in 10.77.0.0/24; empty means any.
            destination_port: SYN destination service port 1-65535, or 0 for any.
        """
        def operation():
            if type(destination_port) is not int or not 0 <= destination_port <= 65535:
                raise ValueError('Invalid service port.')
            for address in (source, destination):
                if not isinstance(address, str) or address and ipaddress.ip_address(address) not in ipaddress.ip_network('10.77.0.0/24'):
                    raise ValueError('Invalid lab address.')
            row = analyse_tcp_exchanges(self.evidence, source, destination, destination_port)
            self._aggregate_alias(row['id'])
            self.aggregates[row['id']] = copy.deepcopy(row)
            return [row], {}
        return self._run('inspect_tcp_exchanges',dict(source=source,destination=destination,destination_port=destination_port),operation)

    def focus_state(self):
        """Keep only bounded retrieval selectors, never model-authored facts."""
        ids = []
        queries = []
        for step in self.trace:
            if not step.get('ok'):
                continue
            ids.extend(row['id'] for row in step['result'].get('records', []))
            if step['tool'] == 'summarize_connections':
                queries.append(step['arguments'])
        return {'ids': list(dict.fromkeys(ids))[-48:], 'queries': queries[-4:],
                'relationship_queries':[s['arguments'] for s in self.trace if s.get('ok') and s['tool']=='inspect_tcp_exchanges'][-4:]}

    def _restore_relationships(self, focus):
        records = []
        for query in focus.get('relationship_queries', [])[-4:]:
            try:
                validate_tool_arguments('inspect_tcp_exchanges', json_dumps(query))
                result = self.inspect_tcp_exchanges(**query)
                self.trace.pop()
                if result['ok']:
                    records.extend(self.supplied[row['id']] for row in result['records'])
            except (ValueError,TypeError,KeyError):
                continue
        return records

    def restore_focus(self, state):
        """Rebuild prior inspected facts from this immutable evidence, not memory prose."""
        if not state or state.get('capture_sha256') != self.digest:
            return
        focus = state.get('evidence_focus', {})
        records = self._restore_relationships(focus)
        for alias in focus.get('ids', [])[-48:]:
            if not isinstance(alias, str) or alias in self.supplied:
                continue
            if alias.startswith('p') and alias[1:].isdigit() and int(alias[1:]) in self.packets:
                records.append(self.packets[int(alias[1:])])
            elif alias in self.flows:
                records.append(self.flows[alias])
        for query in focus.get('queries', [])[-4:]:
            try:
                validate_tool_arguments('summarize_connections', json_dumps(query))
                # Reuse validated filter logic without spending a model tool call.
                result = self.summarize_connections(**query)
                self.trace.pop()
                if result['ok']:
                    records.extend(self.supplied[row['id']] for row in result['records'])
            except (ValueError, TypeError, KeyError):
                continue
        self.context['previously_inspected_evidence'] = [self._supply(row) for row in records]
        # Drop ordinary prefix detail, not the requested focus, if needed.
        focus_ids = {row['id'] for row in self.context['previously_inspected_evidence']}
        while len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES and (self.context['flows'] or self.context['packets']):
            key = 'flows' if self.context['flows'] else 'packets'
            removed = self.context[key].pop()
            if removed['id'] not in focus_ids:
                self.supplied.pop(removed['id'], None)
        if len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES:
            raise ValueError('Focused context exceeds byte limit.')
        self._selection()


def json_dumps(value):
    return encoded(value).decode('utf-8')


def validate_tool_arguments(name, raw):
    """Validate raw provider arguments before Agno can coerce booleans/numbers."""
    from pp_llm import strict_json
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 2048:
        raise ValueError('Tool arguments exceed the byte limit.')
    value = strict_json(raw)
    fields = {'get_lab_status': {},'get_code_reference':{'topic':str},
              'inspect_service':{'destination_port':int},
              'compare_sources':{'baseline_id':str,'comparison_id':str,'destination_port':int},
              'inspect_case_records':{'review_id':str,'numbers':list},
              'probe_lab_service':{},
              'prepare_response_plan': {'operation': str, 'target': str, 'destination': str, 'port': int,
                                        'duration_seconds': int, 'rate_kbit': int},
              'get_packets': {'packet_numbers': list},
              'inspect_tcp_exchanges': {'source': str, 'destination': str, 'destination_port': int},
              'get_log_records': {'line_numbers': list},
              'summarize_log_records': {'protocol': str, 'source': str, 'destination': str, 'destination_port': int},
              'get_flow': {'flow_id': str, 'offset': int, 'limit': int},
              'summarize_connections': {'protocol': str, 'source': str, 'destination': str, 'destination_port': int}}
    if name not in fields or not isinstance(value, dict) or set(value)-set(fields[name]):
        raise ValueError('Unknown tool arguments.')
    if any(type(v) is not fields[name][k] for k, v in value.items()):
        raise ValueError('Tool argument types must match exactly.')
    if name == 'prepare_response_plan' and not {'operation', 'target', 'destination', 'port', 'duration_seconds'} <= set(value):
        raise ValueError('Explicit operation, source, service, port and duration are required.')
    if name=='compare_sources' and not {'baseline_id','comparison_id'}<=set(value):raise ValueError('Two selected source IDs required.')
    if name=='inspect_case_records' and ('review_id' not in value or not isinstance(value.get('numbers'),list) or any(type(n)is not int for n in value['numbers'])):raise ValueError('Exact source ID and integer record numbers required.')
    if name == 'get_packets' and (not 1 <= len(value.get('packet_numbers', [])) <= 16
            or any(type(n) is not int for n in value['packet_numbers'])):
        raise ValueError('Packet numbers must be integers, not booleans or strings.')
    if name == 'get_flow' and 'flow_id' not in value:
        raise ValueError('Flow ID required.')
    if name == 'get_log_records' and (not 1 <= len(value.get('line_numbers', [])) <= 16
            or any(type(n) is not int for n in value['line_numbers'])):
        raise ValueError('Log line numbers must be integers, not booleans or strings.')
