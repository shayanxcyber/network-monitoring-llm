"""Read-only tools for the detached, selected field log; never execute commands."""
import copy
import hashlib
import ipaddress
import time
from collections import Counter, defaultdict
from decimal import Decimal

from pp_context import encoded, MAX_CONTEXT_BYTES, HISTORY_RUNS
from pp_investigation_tools import EvidenceWorkspace, MAX_TOOL_CALLS, DISCLOSURE_RESERVE, validate_tool_arguments, json_dumps, json_tool
from pp_logs import LIMITATIONS
from pp_tcp_relationships import scalar_paths
from pp_semantics import field_semantics


def build_log_context(evidence, question):
    digest = evidence['capture']['sha256']
    context = {'context_version': 'packetpilot-log-context-1.5', 'input_kind': 'network_log',
        'question': question, 'user_context': 'User intent and prior answers are unverified context, not log facts.',
        'capture': {'id': digest+':capture', **copy.deepcopy(evidence['capture'])},
        'overview': {'id': digest+':overview', **copy.deepcopy(evidence['overview'])},
        'coverage': {'id': digest+':coverage', **copy.deepcopy(evidence['coverage'])},
        'packets': [], 'flows': [], 'log_records': copy.deepcopy(evidence['log_records'][:96]),
        'limitations': list(LIMITATIONS), 'context_selection': {},
        'history_policy': {'recent_successful_runs': HISTORY_RUNS, 'note': 'Previous answers are interpretation, not new evidence.'}}
    # Packet-only compatibility zeros are not facts about traffic in this log.
    # The underlying persisted evidence remains unchanged.
    context['capture'].pop('packet_count', None)
    context['coverage'].pop('decoded_packets', None)
    while len(encoded(context)) > MAX_CONTEXT_BYTES and context['log_records']:
        context['log_records'].pop()
    if len(encoded(context)) > MAX_CONTEXT_BYTES:
        raise ValueError('Log overview exceeds the context limit.')
    included = len(context['log_records'])
    context['context_selection'] = {'selection': 'original-line prefix; omitted lines are available through read-only tools',
        'records_included': included, 'records_omitted': len(evidence['log_records'])-included,
        'packets_included': 0, 'packets_omitted': 0, 'flows_included': 0, 'flows_omitted': 0,
        'all_detail_included': included == len(evidence['log_records']), 'max_utf8_bytes': MAX_CONTEXT_BYTES}
    return context


class LogWorkspace(EvidenceWorkspace):
    """Reuse audited byte/call/trace controls, but keep log rows distinct from packets."""
    def __init__(self, evidence, question, deadline=None):
        self.evidence = copy.deepcopy(evidence)
        self.digest = evidence['capture']['sha256']
        self.deadline = deadline or time.monotonic()+300
        self.trace, self.supplied, self.aggregates = [], {}, {}
        self.rows = {r['line_number']: r for r in self.evidence['log_records']}
        self.packets, self.flows = {}, {}
        self.aliases = {self.digest+':'+k: k for k in ('capture', 'overview', 'coverage')}
        self.aliases.update({r['id']: f'l{n}' for n, r in self.rows.items()})
        self.context = build_log_context(evidence, question)
        self.context['reference_policy'] = 'Cite supplied short log line IDs lN; never pN for log data. The backend resolves every ID to this log hash.'
        self.context['field_semantics'] = field_semantics('network_log')
        self.context['tool_policy'] = {'version': 'packetpilot-log-tools-1.2', 'max_calls': MAX_TOOL_CALLS,
                                       'scope': 'Only this saved log; no file paths, commands, live network or action authority.'}
        for key in ('capture', 'overview', 'coverage'):
            self.context[key] = self._supply(self.context[key])
        self.context['log_records'] = [self._supply(r) for r in self.context['log_records']]
        self.context['connections'] = self._supply(self._aggregate('all', '', '', 0))
        self.context['measurement_fields'] = {key:scalar_paths(self.context[key]) for key in ('capture','overview','coverage','connections')}
        self.context['evidence_capabilities'] = {'packet_sequence_fields':False,'application_success_supported':False,
            'tcp_relationships':'inspect_tcp_exchanges supplies candidate reverse tuple/flags/timing relationships, not verified sequence acknowledgements.',
            'missing_scope':'Only valid exported rows are known; invalid rows, unexported fields and real-network traffic remain unknown.',
            'tsv_validation':{'common_required':['frame.number','frame.time_epoch','frame.len'],
                'ipv4_required':['ip.src','ip.dst','ip.proto'],
                'tcp_required':['tcp.srcport','tcp.dstport','tcp.flags'],
                'udp_required':['udp.srcport','udp.dstport'],
                'blank_unused_transport_fields_valid':True,
                'rules':'Exact documented header/order; each physical data line counts, including blank or malformed. Positive bounded frame number/length, finite bounded timestamp, lab IPv4, numeric protocol, hex TCP flags and bounded ports. NON_IPV4 and other protocols are unsupported, not decoded. A small example is not the production parser.'}}
        while len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES and self.context['log_records']:
            self.supplied.pop(self.context['log_records'].pop()['id'], None)
        if len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES:
            raise ValueError('Log context exceeds its byte limit.')
        self._selection()

    @property
    def tool_names(self):
        return {'get_log_records', 'summarize_log_records', 'inspect_tcp_exchanges','get_code_reference'}

    @property
    def tools(self):
        return [json_tool(f) for f in (self.get_log_records, self.summarize_log_records, self.inspect_tcp_exchanges,self.get_code_reference)]

    def _selection(self):
        count = sum(k.startswith('l') and k[1:].isdigit() for k in self.supplied)
        self.context['context_selection'].update(records_included=count, records_omitted=len(self.rows)-count,
                                                all_detail_included=count == len(self.rows))
        self.context['coverage_disclosure'] = self.coverage_disclosure()

    def _aggregate(self, protocol, source, destination, destination_port):
        query = dict(protocol=protocol, source=source, destination=destination, destination_port=destination_port)
        alias = 'a'+hashlib.sha256(encoded(query)).hexdigest()[:16]
        identity = self.digest+':'+alias
        self._aggregate_alias(identity)
        selected = []
        for row in self.rows.values():
            if row['status'] != 'decoded' or protocol != 'all' and row['protocol'] != protocol:
                continue
            if source and row['ipv4']['src'] != source or destination and row['ipv4']['dst'] != destination:
                continue
            if destination_port and (row['tcp'] or row['udp'])['dst_port'] != destination_port:
                continue
            selected.append(row)
        groups = defaultdict(list)
        for row in selected:
            groups[(row['protocol'], row['ipv4']['src'], row['ipv4']['dst'])].append(row)
        directions = []
        for (proto, src, dst), rows in sorted(groups.items()):
            ports = sorted({(r['tcp'] or r['udp'])['dst_port'] for r in rows})
            directions.append({'protocol': proto, 'source': src, 'destination': dst,
                'record_count': len(rows), 'destination_port_count': len(ports), 'destination_ports': ports[:64],
                'destination_ports_omitted': max(0, len(ports)-64),
                'syn_without_ack_count': sum(bool(r['tcp'] and r['tcp']['flags'] & 0x12 == 2) for r in rows),
                'rst_count': sum(bool(r['tcp'] and r['tcp']['flags'] & 4) for r in rows),
                'line_numbers': [r['line_number'] for r in rows[:64]], 'member_numbers_omitted': max(0, len(rows)-64)})
        times = [Decimal(r['timestamp']) for r in selected]
        numbers = [r['line_number'] for r in selected]
        frames=[r['source_frame_number'] for r in selected]
        result = {'id': identity, 'query': query, 'scope': 'All valid saved log rows matching these directional filters; not raw packets or network-wide activity.',
            'record_count': len(selected), 'decoded_log_records': self.evidence['coverage']['decoded_records'],
            'source_frame_number_min':min(frames) if frames else 0,
            'source_frame_number_max':max(frames) if frames else 0,
            'source_frame_number_distinct_count':len(set(frames)),
            'source_frame_numbers':frames[:96],'source_frame_numbers_omitted':max(0,len(frames)-96),
            'excluded_log_records': len(self.rows)-self.evidence['coverage']['decoded_records'],
            'protocol_counts': dict(sorted(Counter(r['protocol'] for r in selected).items())),
            'duration_seconds': float(max(times)-min(times)) if times else 0,
            'directional_group_count': len(directions), 'directions': directions[:32],
            'directional_groups_omitted': max(0, len(directions)-32),
            'member_count': len(numbers), 'member_numbers': numbers[:96], 'member_numbers_omitted': max(0, len(numbers)-96),
            'membership_sha256': hashlib.sha256(encoded(numbers)).hexdigest(),
            'limits': 'Only exported fields. No payload, independent frame hashes, authorisation or threat verdict.'}
        self.aggregates[identity] = result | {'complete_member_numbers': numbers}
        return result

    def get_log_records(self, line_numbers: list[int]) -> dict:
        """Inspect 1-16 original physical TSV line numbers (header is line 1). Returns fields, byte/line provenance and source frame identifiers, not raw frames.

        Args:
            line_numbers: Unique positive original data-line numbers, for example [2, 3].
        """
        def operation():
            if not isinstance(line_numbers, list) or not 1 <= len(line_numbers) <= 16 or len(set(line_numbers)) != len(line_numbers) or any(type(n) is not int or n not in self.rows for n in line_numbers):
                raise ValueError('Invalid log line numbers.')
            return [self.rows[n] for n in line_numbers], {'scope': 'Only the requested original log lines.'}
        return self._run('get_log_records', {'line_numbers': line_numbers}, operation)

    def summarize_log_records(self, protocol: str = 'all', source: str = '', destination: str = '', destination_port: int = 0) -> dict:
        """Compute neutral directional totals from all valid log rows, including rows omitted from initial context. No verdict or external access.

        Args:
            protocol: all, TCP or UDP.
            source: Optional lab IPv4 address; empty means any.
            destination: Optional lab IPv4 address; empty means any.
            destination_port: 1-65535 or 0 for any destination port.
        """
        def operation():
            if protocol not in ('all', 'TCP', 'UDP') or type(destination_port) is not int or not 0 <= destination_port <= 65535:
                raise ValueError('Invalid log filter.')
            for address in (source, destination):
                if not isinstance(address, str) or address and ipaddress.ip_address(address) not in ipaddress.ip_network('10.77.0.0/24'):
                    raise ValueError('Invalid lab address.')
            return [self._aggregate(protocol, source, destination, destination_port)], {}
        return self._run('summarize_log_records', dict(protocol=protocol, source=source, destination=destination, destination_port=destination_port), operation)

    def validation_context(self):
        context = copy.deepcopy(self.context)
        context.update({key: self.supplied[key] for key in ('capture', 'overview', 'coverage')})
        context['log_records'] = [r for k, r in self.supplied.items() if k.startswith('l') and k[1:].isdigit()]
        context['additional_records'] = [r for k, r in self.supplied.items() if k.startswith('a')]
        return context

    def focus_state(self):
        good = [s for s in self.trace if s.get('ok')]
        return {'ids': list(dict.fromkeys(r['id'] for s in good for r in s['result'].get('records', [])))[-48:],
                'queries': [s['arguments'] for s in good if s['tool'] == 'summarize_log_records'][-4:],
                'relationship_queries':[s['arguments'] for s in good if s['tool']=='inspect_tcp_exchanges'][-4:]}

    def restore_focus(self, state):
        if not state or state.get('capture_sha256') != self.digest:
            return
        focus = state.get('evidence_focus', {})
        records = self._restore_relationships(focus)
        for alias in focus.get('ids', [])[-48:]:
            if isinstance(alias, str) and alias.startswith('l') and alias[1:].isdigit() and int(alias[1:]) in self.rows:
                records.append(self.rows[int(alias[1:])])
        for query in focus.get('queries', [])[-4:]:
            try:
                validate_tool_arguments('summarize_log_records', json_dumps(query))
                result = self.summarize_log_records(**query)
                self.trace.pop()
                if result['ok']:
                    records.extend(self.supplied[r['id']] for r in result['records'])
            except (ValueError, TypeError, KeyError):
                continue
        self.context['previously_inspected_evidence'] = [self._supply(r) for r in records]
        focus_ids = {r['id'] for r in self.context['previously_inspected_evidence']}
        while len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES and self.context['log_records']:
            removed = self.context['log_records'].pop()
            if removed['id'] not in focus_ids:
                self.supplied.pop(removed['id'], None)
        if len(encoded(self.context)) + DISCLOSURE_RESERVE > MAX_CONTEXT_BYTES:
            raise ValueError('Focused log context exceeds its limit.')
        self._selection()
