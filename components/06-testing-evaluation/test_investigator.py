"""Real Agno/SDK dispatch against controlled responses; no external inference."""
import copy
import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_evidence import analyse_capture
from pp_llm import APIConfig, LLMError
from pp_investigation_tools import EvidenceWorkspace, MAX_TOOL_CALLS
from pp_investigation_contract import validate_final
from investigation_cases import contrasting_cases
from assessment_fixtures import stub_answer
from evaluation_cases import cases

KEY = 'protocol-only-key-do-not-persist'
PRIVATE = 'private-provider-reasoning-for-continuity'


class WorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-tools-')
        cls.evidence = {}
        for case in cases():
            path = Path(cls.temp.name) / (case['id'] + '.pcap')
            path.write_bytes(case['raw'])
            cls.evidence[case['id']] = analyse_capture(path, 'scapy')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.workspace = EvidenceWorkspace(self.evidence['C04'], 'Investigate.')

    def test_direction_counts_distinguish_single_service_and_reply_ports(self):
        record = self.workspace.summarize_connections('TCP', '10.77.0.20', '10.77.0.10')['records'][0]
        self.assertEqual(record['packet_count'], 4)
        self.assertEqual(record['directions'][0]['syn_destination_port_count'], 1)
        self.assertEqual(record['directions'][0]['syn_destination_ports'], [8443])
        reverse = self.workspace.summarize_connections('TCP', '10.77.0.10')['records'][0]
        self.assertEqual(reverse['rst_count'], 4)
        self.assertEqual(reverse['syn_without_ack_count'], 0)

    def test_mixed_protocols_retained_and_filtered(self):
        workspace = EvidenceWorkspace(self.evidence['C03'], 'Inspect.')
        result = workspace.summarize_connections()['records'][0]
        self.assertEqual(result['protocol_counts'], {'TCP': 8, 'UDP': 1})
        self.assertEqual(workspace.summarize_connections('UDP')['records'][0]['packet_count'], 1)

    def test_partial_coverage_not_lost(self):
        workspace = EvidenceWorkspace(self.evidence['C06'], 'Inspect.')
        result = workspace.summarize_connections()['records'][0]
        self.assertEqual(result['packet_count'], 8)
        self.assertEqual(result['excluded_capture_packets'], 1)

    def test_flow_pagination_and_direction(self):
        result = self.workspace.get_flow('f1', 0, 1)
        self.assertTrue(result['ok'])
        self.assertEqual(result['returned_packets'], 1)
        self.assertEqual(result['next_offset'], 1)
        next_page = self.workspace.get_flow('f1', 1, 1)
        self.assertIsNone(next_page['next_offset'])

    def test_unknown_ids_paths_duplicates_and_bool_rejected(self):
        for values in ([1, 1], [True], [99999], [], ['../../etc/passwd']):
            self.assertFalse(self.workspace.get_packets(values)['ok'])
        self.assertFalse(self.workspace.get_flow('../../etc/passwd')['ok'])
        self.assertFalse(self.workspace.get_flow('otherhash:f1')['ok'])

    def test_no_out_of_scope_or_shell_filters(self):
        for kwargs in ({'source': '8.8.8.8'}, {'source': '127.0.0.1'}, {'protocol': 'TCP; cat .env'},
                       {'destination_port': True}, {'destination_port': 65536}, {'destination': '../.env'}):
            self.assertFalse(self.workspace.summarize_connections(**kwargs)['ok'])

    def test_read_only_detached_and_trace(self):
        before = json.dumps(self.evidence['C04'], sort_keys=True)
        self.workspace.get_packets([1, 2])
        self.workspace.context['question'] = 'changed detached data'
        self.assertEqual(before, json.dumps(self.evidence['C04'], sort_keys=True))
        self.assertEqual(self.workspace.trace[0]['capture_sha256'], self.evidence['C04']['capture']['sha256'])
        self.assertIn('finished_at', self.workspace.trace[0])

    def test_public_tool_result_metadata_is_original_bounded_and_payload_free(self):
        events = []
        self.workspace.event_callback = lambda kind, data: events.append((kind, data))
        result = self.workspace.get_packets([1, 2])
        self.assertTrue(result['ok'])
        kind, data = events[-1]
        self.assertEqual(kind, 'tool_finished')
        self.assertEqual(data['returned_records'], 2)
        self.assertEqual(data['references'], [self.workspace.digest+':p1', self.workspace.digest+':p2'])
        self.assertGreaterEqual(data['elapsed_seconds'], 0)
        self.assertEqual(data['references_omitted'], 0)
        self.assertNotIn('records', data)
        self.assertNotIn('payload', json.dumps(data))
        self.assertEqual(data['index'], events[0][1]['index'])

    def test_failed_public_tool_event_does_not_claim_records(self):
        events = []
        self.workspace.event_callback = lambda kind, data: events.append((kind, data))
        self.workspace.get_packets([99999])
        data = events[-1][1]
        self.assertFalse(data['ok'])
        self.assertEqual(data['returned_records'], 0)
        self.assertEqual(data['references'], [])
        self.assertNotIn('message', data)

    def test_public_results_cap_reference_buttons_without_losing_count(self):
        events = []
        source = Path(self.temp.name)/'public-flow.pcap'
        source.write_bytes(contrasting_cases()[1]['raw'])
        other = EvidenceWorkspace(analyse_capture(source, 'scapy'), 'Inspect.')
        other.event_callback = lambda kind, data: events.append((kind, data))
        result = other.get_packets(sorted(other.packets)[:16])
        self.assertTrue(result['ok'])
        data = events[-1][1]
        self.assertEqual(data['returned_records'], len(result['records']))
        self.assertLessEqual(len(data['references']), 8)
        self.assertGreater(data['references_omitted'], 0)
        self.assertEqual(data['references_omitted'], max(0, len(result['records'])-8))

    def test_tool_budget_and_timeout(self):
        for _ in range(MAX_TOOL_CALLS):
            self.assertTrue(self.workspace.get_packets([1])['ok'])
        self.assertEqual(self.workspace.get_packets([1])['error'], 'tool_limit')
        other = EvidenceWorkspace(self.evidence['C04'], 'Inspect.', time.monotonic()-1)
        self.assertFalse(other.get_packets([1])['ok'])

    def test_short_refs_resolve_without_relaxing_validation(self):
        answer = stub_answer(self.workspace.context) | {'schema_version': '3.0'}
        canonical, wire = validate_final(json.dumps(answer), self.workspace)
        self.assertEqual(canonical['observations'][0]['references'], [self.workspace.digest+':overview'])
        self.assertEqual(wire['observations'][0]['references'], ['overview'])
        for ref in ('p9999', 'otherhash:p1', 'overviewoverview'):
            answer['observations'][0]['references'] = [ref]
            with self.assertRaises(ValueError):
                validate_final(json.dumps(answer), self.workspace)

    def test_aggregate_scalar_measurement_and_exact_membership(self):
        aggregate = self.workspace.summarize_connections('TCP', '10.77.0.20')['records'][0]
        answer = stub_answer(self.workspace.context) | {'schema_version': '3.0'}
        answer['measurements'] = [{'reference': aggregate['id'], 'field': 'packet_count', 'value': 4}]
        validate_final(json.dumps(answer), self.workspace)
        answer['measurements'][0]['value'] = 5
        with self.assertRaises(ValueError):
            validate_final(json.dumps(answer), self.workspace)
        full = self.workspace.aggregates[self.workspace.supplied[aggregate['id']]['id']]
        self.assertEqual(full['complete_member_numbers'], [1, 3, 5, 7])

    def test_focus_rehydrates_previously_retrieved_tail_packets(self):
        source = Path(self.temp.name)/'long.pcap'
        source.write_bytes(contrasting_cases()[1]['raw'])
        evidence = analyse_capture(source, 'scapy')
        first = EvidenceWorkspace(evidence, 'Inspect tail.')
        self.assertNotIn('p97', first.supplied)
        self.assertTrue(first.get_packets([97, 98])['ok'])
        self.assertTrue(first.get_flow('f1')['ok'])
        state = {'capture_sha256': first.digest, 'evidence_focus': first.focus_state()}
        next_turn = EvidenceWorkspace(evidence, 'Follow-up.')
        next_turn.restore_focus(state)
        self.assertIn('p97', next_turn.supplied)
        self.assertIn('p98', next_turn.supplied)
        self.assertTrue(next_turn.context['context_selection']['all_detail_included'])
        self.assertEqual(next_turn.trace, [])
        self.assertEqual(next_turn.evidence['overview']['duration_seconds'], 2.05)
        answer = stub_answer(next_turn.context) | {'schema_version': '3.0'}
        answer['observations'][0]['references'] = ['p97', 'p98']
        validate_final(json.dumps(answer), next_turn)

    def test_raw_tool_argument_coercion_rejected(self):
        from pp_investigation_tools import validate_tool_arguments
        for args in ('{"packet_numbers":[true]}', '{"packet_numbers":["1"]}', '{"path":"/etc/passwd"}', '{"packet_numbers":[1],"packet_numbers":[2]}'):
            with self.assertRaises(ValueError):
                validate_tool_arguments('get_packets', args)

    def test_provider_wall_clock_wait_is_bounded(self):
        from pp_investigator import bounded_request
        from types import SimpleNamespace
        def delayed(**kwargs):
            time.sleep(.05)
            return 'late-response'
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=delayed)))
        with self.assertRaises(TimeoutError):
            bounded_request(client, {}, .005)

    def test_source_focus_cannot_cross_capture(self):
        state = {'capture_sha256': 'f'*64, 'evidence_focus': {'ids': ['p999'], 'queries': []}}
        before = copy.deepcopy(self.workspace.supplied)
        self.workspace.restore_focus(state)
        self.assertEqual(before, self.workspace.supplied)


class InvestigatorProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.received = []
        cls.mode = 'valid'
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                cls.received.append(payload)
                contexts = []
                for message in payload['messages']:
                    if message['role'] == 'user':
                        try:
                            context = json.loads(message['content'])
                            if isinstance(context, dict) and 'context_version' in context:
                                contexts.append(context)
                        except (ValueError, TypeError):
                            pass
                context = contexts[-1]
                answer = stub_answer(context) | {'schema_version': '3.0'}
                correction = payload['messages'][-1]['content'].startswith('Correct the previous') if isinstance(payload['messages'][-1]['content'], str) else False
                if cls.mode == 'invalid' or cls.mode == 'repair' and not correction:
                    answer['observations'][0]['references'] = ['p99999']
                message = {'role': 'assistant', 'content': json.dumps(answer)}
                reason = 'stop'
                have_result = payload['messages'][-1]['role'] == 'tool'
                if cls.mode == 'exchanges' and have_result:
                    aggregate=json.loads(payload['messages'][-1]['content'])['records'][0]
                    answer['observations']=[{'text':'The decoded SYN records contact one destination service.', 'references':[aggregate['id']]}]
                    answer['measurements']=[{'reference':aggregate['id'],'field':'syn_destination_port_count','value':aggregate['syn_destination_port_count']}]
                    message['content']=json.dumps(answer)
                if cls.mode in ('tools', 'unknown_tool', 'loop', 'parallel','exchanges', 'high_usage_tools') and (not have_result or cls.mode == 'loop'):
                    name = 'run_shell' if cls.mode == 'unknown_tool' else ('inspect_tcp_exchanges' if cls.mode=='exchanges' else 'get_packets')
                    call = {'id': 'call-'+str(len(cls.received)), 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps({} if cls.mode=='exchanges' else {'packet_numbers': [1, 2]})}}
                    calls = [call]
                    if cls.mode == 'parallel':
                        calls.append({'id': 'call-extra', 'type': 'function', 'function': {'name': 'summarize_connections', 'arguments': '{}'}})
                    message = {'role': 'assistant', 'content': None, 'tool_calls': calls}
                    reason = 'tool_calls'
                if payload.get('thinking') == {'type': 'enabled'}:
                    message['reasoning_content'] = PRIVATE
                if cls.mode == 'length':
                    reason = 'length'
                response = {'id': 'stub', 'object': 'chat.completion', 'created': 1,
                    'model': 'protocol-stub', 'choices': [{'index': 0, 'finish_reason': reason, 'message': message}],
                    'usage': {'prompt_tokens': 20, 'completion_tokens': 30, 'total_tokens': 50,
                              'completion_tokens_details': {'reasoning_tokens': 12}}}
                if cls.mode == 'high_usage_tools':
                    response['usage'] = {'prompt_tokens': 200000, 'completion_tokens': 80000,
                                         'total_tokens': 280000,
                                         'completion_tokens_details': {'reasoning_tokens': 79000}}
                status = 200
                if cls.mode in ('auth', 'rate_limit'):
                    status, response = (401 if cls.mode == 'auth' else 429), {'error': {'message': KEY}}
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *_):
                pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-investigator-')
        self.folder = Path(self.temp.name)
        source = self.folder/'sample.pcap'
        source.write_bytes(cases()[3]['raw'])
        self.evidence = analyse_capture(source, 'scapy')
        self.database = self.folder/'private-history.sqlite3'
        self.session = str(uuid.uuid4())
        self.config = APIConfig(f'http://127.0.0.1:{self.server.server_port}', 'protocol-model', KEY,
            thinking='enabled', reasoning_effort='max', timeout=180, max_output_tokens=32768,
            retries=0, allow_loopback_http=True)
        type(self).mode = 'valid'
        type(self).received.clear()

    def tearDown(self):
        self.temp.cleanup()

    def client(self, session=None):
        return AgnoClient(self.config, self.database, session or self.session, workspace_upgrade=False)

    def test_composed_policy_guidance_schema_and_four_tools_reach_provider(self):
        result = self.client().explain(self.evidence, 'Investigate.')
        request = self.received[0]
        system = request['messages'][0]['content']
        self.assertIn('PacketPilot investigation policy 3.3', system)
        self.assertIn('Reviewed investigation guidance 1.17', system)
        self.assertIn('handshake_elapsed_seconds for a single selected exchange', system)
        self.assertIn('Literal source byte-offset numbers are allowed ONLY in measurements', system)
        self.assertIn('schema_version', system)
        self.assertEqual({t['function']['name'] for t in request['tools']}, {'get_packets', 'get_flow', 'summarize_connections', 'inspect_tcp_exchanges','get_code_reference'})
        self.assertEqual(request['thinking'], {'type': 'enabled'})
        self.assertEqual(request['reasoning_effort'], 'max')
        self.assertEqual(request['response_format'], {'type': 'json_object'})
        self.assertEqual(result['answer']['schema_version'], '3.0')
        self.assertEqual(result['attempts'], 1)
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(KEY, json.dumps(result))

    def test_real_agno_tool_dispatch_and_reasoning_replay(self):
        type(self).mode = 'tools'
        result = self.client().explain(self.evidence, 'Inspect exact packets.')
        self.assertEqual(len(self.received), 2)
        self.assertEqual(len(result['tool_trace']), 1)
        self.assertTrue(result['tool_trace'][0]['ok'])
        self.assertEqual(result['usage']['total_tokens'], 100)
        second = self.received[1]
        self.assertTrue(any(m.get('reasoning_content') == PRIVATE for m in second['messages']))
        self.assertTrue(any(m['role'] == 'tool' and 'records' in m['content'] for m in second['messages']))
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_thinking_low_high_max_serialize_without_token_override(self):
        for effort in ('low', 'high', 'max'):
            with self.subTest(effort=effort):
                self.received.clear()
                config = replace(self.config, reasoning_effort=effort, max_output_tokens=None)
                result = AgnoClient(config, self.database, str(uuid.uuid4()), workspace_upgrade=False).explain(self.evidence, 'Inspect.')
                self.assertEqual(self.received[0]['thinking'], {'type':'enabled'})
                self.assertEqual(self.received[0]['reasoning_effort'], effort)
                self.assertNotIn('max_tokens', self.received[0])
                self.assertIsNone(result['settings']['max_run_completion_tokens'])
                self.assertIsNone(result['settings']['max_run_total_tokens'])
                self.assertEqual(result['settings']['max_run_seconds'], 300)
                self.assertGreaterEqual(result['timings']['provider_wall_seconds'], 0)

    def test_provider_usage_accounted_without_application_token_quota(self):
        type(self).mode = 'high_usage_tools'
        config = replace(self.config, max_output_tokens=None)
        result = AgnoClient(config, self.database, str(uuid.uuid4()), workspace_upgrade=False).explain(self.evidence, 'Inspect.')
        self.assertEqual(result['attempts'], 2)
        self.assertEqual(result['usage']['completion_tokens'], 160000)
        self.assertEqual(result['usage']['total_tokens'], 560000)
        self.assertNotIn('max_tokens', self.received[-1])

    def test_parallel_tools_and_tool_budget(self):
        type(self).mode = 'parallel'
        result = self.client().explain(self.evidence, 'Inspect.')
        self.assertEqual(len(result['tool_trace']), 2)
        type(self).mode = 'loop'
        with self.assertRaises(LLMError) as caught:
            self.client(str(uuid.uuid4())).explain(self.evidence, 'Keep inspecting.')
        self.assertEqual(caught.exception.code, 'investigation_limit')
        self.assertEqual(caught.exception.record['attempts'], 6)

    def test_native_exchange_dispatch_and_aggregate_reference(self):
        type(self).mode='exchanges'
        try:
            result=self.client().explain(self.evidence,'Check exchange relationships.')
        except LLMError as exc:
            self.fail('Native exchange error '+exc.code+'; validation '+str([c.get('validation_error') for c in exc.record.get('model_calls',[])]))
        self.assertEqual(len(self.received),2)
        self.assertEqual(result['tool_trace'][0]['tool'],'inspect_tcp_exchanges')
        self.assertTrue(result['tool_trace'][0]['ok'])
        self.assertEqual(result['answer']['measurements'][0]['value'],1)
        self.assertTrue(result['answer']['observations'][0]['references'][0].startswith(self.evidence['capture']['sha256']))
        self.assertTrue(any(m.get('reasoning_content')==PRIVATE for m in self.received[1]['messages']))

    def test_one_correction_retains_invalid_answer_and_no_transport_retry(self):
        type(self).mode = 'repair'
        result = self.client().explain(self.evidence, 'Inspect.')
        self.assertEqual(result['correction_attempts'], 1)
        self.assertEqual(result['attempts'], 2)
        self.assertIn('validation_error', result['model_calls'][0])
        self.assertNotIn('tools', self.received[1])
        self.assertTrue(any(m.get('reasoning_content') == PRIVATE for m in self.received[1]['messages']))

    def test_failed_correction_never_becomes_successful_history_or_state(self):
        type(self).mode = 'invalid'
        with self.assertRaises(LLMError) as caught:
            self.client().explain(self.evidence, 'Failed-history-marker.')
        self.assertEqual(caught.exception.code, 'invalid_response')
        self.assertEqual(caught.exception.record['attempts'], 2)
        type(self).mode = 'valid'
        result = self.client().explain(self.evidence, 'Fresh question.')
        self.assertNotIn('Failed-history-marker', json.dumps(self.received[-1]))
        self.assertEqual(result['investigation_state']['completed_turns'], 1)

    def test_history_state_and_private_reasoning_survive_new_client(self):
        self.client().explain(self.evidence, 'First-question-marker.')
        result = self.client().explain(self.evidence, 'Explain the previous answer.')
        payload = self.received[-1]
        self.assertIn('First-question-marker', json.dumps(payload))
        self.assertTrue(any(m.get('reasoning_content') == PRIVATE for m in payload['messages']))
        self.assertEqual(result['investigation_state']['completed_turns'], 2)
        with sqlite3.connect(self.database) as db:
            stored = '\n'.join(db.iterdump())
        db.close()
        self.assertIn(PRIVATE, stored)
        self.assertNotIn(KEY, stored)
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_capture_session_and_configuration_isolation(self):
        self.client().explain(self.evidence, 'Must-not-cross-boundaries.')
        self.client(str(uuid.uuid4())).explain(self.evidence, 'Different review.')
        self.assertNotIn('Must-not-cross-boundaries', json.dumps(self.received[-1]))
        other = self.folder/'other.pcap'
        other.write_bytes(cases()[0]['raw'])
        self.client().explain(analyse_capture(other, 'scapy'), 'Different capture.')
        self.assertNotIn('Must-not-cross-boundaries', json.dumps(self.received[-1]))
        self.config = replace(self.config, thinking='disabled', reasoning_effort='')
        self.client().explain(self.evidence, 'Different configuration.')
        self.assertNotIn('Must-not-cross-boundaries', json.dumps(self.received[-1]))

    def test_unknown_tools_refusals_and_provider_errors_stop(self):
        for mode, code in [('unknown_tool', 'invalid_tool_request'), ('length', 'invalid_response'),
                           ('auth', 'authentication'), ('rate_limit', 'http_error')]:
            with self.subTest(mode=mode):
                type(self).mode = mode
                count = len(self.received)
                with self.assertRaises(LLMError) as caught:
                    self.client().explain(self.evidence, 'Inspect.')
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(self.received)-count, 1)
                self.assertNotIn(KEY, json.dumps(caught.exception.record))
                self.assertNotIn(PRIVATE, json.dumps(caught.exception.record))


if __name__ == '__main__':
    unittest.main()
