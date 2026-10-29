"""Focused review regressions. Local fixtures, no external model or network actions."""
import copy
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import packetpilot
from pp_web import create_app
from pp_llm import APIConfig
import test_investigation_depth as depth_tests


class CaseCorrectionTests(unittest.TestCase):
    setUp=depth_tests.CaseTests.setUp
    tearDown=depth_tests.CaseTests.tearDown
    def test_role_edit_and_unlink_preserve_original_and_saved_scope(self):
        snapshot=copy.deepcopy(self.store.case_snapshot(self.a['id']))
        before=self.store.get(self.b['id'])
        changed=self.store.change_case_role(self.case['id'],self.b['id'],'after')
        self.assertEqual(next(s for s in changed['sources'] if s['review_id']==self.b['id'])['role'],'after')
        self.assertEqual(len(self.store.unlink_case(self.case['id'],self.b['id'])['sources']),1)
        self.assertEqual(self.store.get(self.b['id']),before)
        self.assertEqual(len(snapshot['sources']),2)
        self.assertEqual(next(s for s in snapshot['sources'] if s['review_id']==self.b['id'])['role'],'baseline')
        self.assertIsNone(self.store.case_for(self.b['id']))
        self.store.link_case(self.case['id'],self.b['id'],'baseline')
        self.assertEqual(len(self.store.case(self.case['id'])['sources']),2)
    def test_correction_rejects_wrong_membership_invalid_role_and_last_selected_source(self):
        with self.assertRaises(ValueError):self.store.change_case_role(self.case['id'],self.b['id'],'arbitrary')
        self.store.unlink_case(self.case['id'],self.b['id'])
        with self.assertRaises(ValueError):self.store.unlink_case(self.case['id'],self.a['id'])
        with self.assertRaises(ValueError):self.store.change_case_role(self.case['id'],self.b['id'],'after')
    def test_picker_metadata_identifies_assigned_source_without_exposing_capture_paths(self):
        row=next(r for r in self.store.list() if r['id']==self.b['id'])
        self.assertEqual(row['case_id'],self.case['id'])
        self.assertEqual(row['sha256'],self.b['evidence']['capture']['sha256'])
        self.assertNotIn('capture',row)


class Diagnostics:
    def __init__(self):self.calls=0;self.generation='test-generation'
    def call(self,operation,*args):
        if operation=='status':return dict(lab=dict(generation=self.generation,addresses=dict(source='10.77.0.20',control='10.77.0.30',service='10.77.0.10'),service_port=8080))
        if operation not in ('diagnostic','diagnostic_transfer'):raise ValueError('Controlled fixture only')
        self.calls+=1
        return dict(service='10.77.0.10:8080',path='/',clients={r:dict(reachable=True,complete=True,total_seconds=.1,first_byte_seconds=.05) for r in ('source','control')})


class DiagnosticAssociationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        shutil.copytree(ROOT/'web',root/'web');self.responses=Diagnostics()
        self.app=create_app(root,test_mode=True,response_client=self.responses,config_loader=lambda:APIConfig('https://example.invalid','stub','test-only'))
        self.client=TestClient(self.app);self.client.__enter__()
        self.headers={'X-PacketPilot-Token':self.client.get('/api/config').json()['csrf']}
        self.review=self.client.post('/api/reviews',headers=self.headers,json={'sample':'normal','provider':'rules'}).json()
        self.path='/api/reviews/'+self.review['id']+'/diagnostics'
    def tearDown(self):self.client.__exit__(None,None,None);self.temp.cleanup()
    def record(self,**value):return self.client.post(self.path,headers=self.headers,json=value)
    def test_explicit_baseline_is_retained_and_old_rows_are_not_rewritten(self):
        baseline=self.record(phase='baseline',objective='Restore').json()
        after=self.record(phase='after',objective='Restore',baseline_id=baseline['id'])
        self.assertEqual(after.status_code,201);self.assertEqual(after.json()['baseline_id'],baseline['id'])
        self.assertEqual(self.client.get(self.path).json()[0],baseline)
    def test_wrong_objective_profile_and_unknown_baseline_fail_before_network_call(self):
        baseline=self.record(phase='baseline',objective='Restore').json()
        for changes in [dict(objective='Different'),dict(profile='transfer'),dict(baseline_id='not-an-id')]:
            body=dict(phase='after',objective='Restore',baseline_id=baseline['id']);body.update(changes)
            response=self.record(**body);self.assertEqual(response.status_code,400,response.text)
        self.assertEqual(self.responses.calls,1)
    def test_baseline_from_another_review_is_rejected(self):
        baseline=self.record(phase='baseline').json()
        other=self.client.post('/api/reviews',headers=self.headers,json={'sample':'port-check'}).json()
        result=self.client.post('/api/reviews/'+other['id']+'/diagnostics',headers=self.headers,json=dict(phase='after',baseline_id=baseline['id']))
        self.assertEqual(result.status_code,400);self.assertEqual(self.responses.calls,1)
    def test_new_baseline_cannot_point_to_an_earlier_cycle(self):
        baseline=self.record(phase='baseline').json()
        self.assertEqual(self.record(phase='baseline',baseline_id=baseline['id']).status_code,400)
    def test_changed_lab_generation_rejects_pairing_before_a_probe(self):
        baseline=self.record(phase='baseline').json();self.responses.generation='new-generation'
        response=self.record(phase='after',baseline_id=baseline['id'])
        self.assertEqual(response.status_code,400);self.assertEqual(self.responses.calls,1)
    def test_role_and_unlink_routes_require_csrf(self):
        case=self.client.post('/api/reviews/'+self.review['id']+'/case',headers=self.headers,json={'title':'Test case'}).json()
        route='/api/cases/'+case['id']+'/sources/'+self.review['id']
        self.assertEqual(self.client.post(route+'/role',json={'role':'after'}).status_code,403)
        self.assertEqual(self.client.post(route+'/unlink',json={}).status_code,403)
        self.assertEqual(self.client.post(route+'/role',headers=self.headers,json={'role':'reference'}).status_code,200)

class ProtocolClosureTests(unittest.TestCase):
    """Neutral calculated facts for the reproduced semantic failure families."""
    def test_receipt_negative_modal_and_rather_than_evidence_scopes(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for r in e['packets']:
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':53,'dst_port':45000,'payload_bytes':20}
        for text in ('This shows a DNS pair,not that the client received the reply.',
                     'The client might not have received the answer.',
                     'The datagram is addressed to the client rather than evidence that the client received it.'):
            with self.subTest(text=text):validate_claim_language({'summary':text},e)
        with self.assertRaisesRegex(ValueError,'summary:.*client receipt'):
            validate_claim_language({'summary':'The client may not have received the reply,but the client got the answer.'},e)

    def test_receipt_negative_proof_modifier_does_not_license_later_positive(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for r in e['packets']:
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':53,'dst_port':45000,'payload_bytes':20}
        for phrase in ('does not by itself prove','does not independently establish',
                       'cannot on its own show','does not necessarily confirm'):
            text='The reply '+phrase+' that the client received the response.'
            validate_claim_language({'interpretation':text},e)
            for join in (',but the client got the answer.',',and the client got the answer.'):
                with self.assertRaisesRegex(ValueError,'client receipt'):
                    validate_claim_language({'interpretation':text.rstrip('.')+join},e)

    def test_lifetime_lack_of_proof_does_not_license_independent_finite_claim(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for phrase in ('does not establish','does not independently establish','cannot by itself confirm'):
            text='It '+phrase+' a short-lived connection.'
            validate_claim_language({'interpretation':text},e)
            for join in (',but the connection was short-lived.',',and the connection was short-lived.'):
                with self.assertRaisesRegex(ValueError,'short observation window'):
                    validate_claim_language({'interpretation':text.rstrip('.')+join},e)

    def test_visible_fin_absence_keeps_original_subset_and_conditional_scope(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only();e['packets'][-1]['tcp']['flags']|=1
        for text in ('No FIN or RST appears in this source.','Teardown is unobserved in this capture.',
                     'Missing teardown is unobserved rather than placed outside the window.',
                     'No FIN appears among p2 and p3.'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'observed FIN|FIN-bearing'):
                validate_claim_language({'summary':text},e)
        for text in ('No FIN or RST appears among p1 and p2.','No RST appears in this source.',
                     'If teardown is missing,it remains unobserved.','Full closure is not established by FIN flags alone.',
                     'Missing teardown is not assumed here;the source contains FIN-bearing records.'):
            with self.subTest(text=text):validate_claim_language({'summary':text},e)
        changed=copy.deepcopy(e);changed['packets'].reverse()
        with self.assertRaisesRegex(ValueError,'observed FIN'):
            validate_claim_language({'summary':'No FIN appears in this source.'},changed)

    def test_brief_capture_is_not_actual_short_connection_lifetime(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for text in ('These are short-lived TCP connections.','The connection was short-lived.'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'short observation window'):
                validate_claim_language({'summary':text},e)
        for text in ('The observation window is short.','Whether the connection was short-lived is unknown.',
                     'A short-lived connection is one possible explanation.'):
            with self.subTest(text=text):validate_claim_language({'summary':text},e)

    def test_unknown_session_ending_outside_evidence_is_not_positive_closure(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for text in ('How the session ended is outside this evidence.',
                     'Whether the connection closed remains outside the observed evidence.'):
            validate_claim_language({'interpretation':text},e)
        with self.assertRaisesRegex(ValueError,'session close'):
            validate_claim_language({'interpretation':'How the session ended is unknown,but the connection closed at the source end.'},e)

    def test_syn_range_does_not_borrow_independent_source_subject(self):
        from pp_semantics import validate_syn_timestamp_bounds
        e=self.setup_only()
        for text in ('The source runs from 100.000000 to 100.002000: one SYN,a reverse SYNACK and ACK.',
                     'The SYN timestamp is100.000000;the whole source spans from100.000000 to100.002000.',
                     'The SYN timestamp is 100.000000;the whole source spans from 100.000000 to 100.002000.'):
            validate_syn_timestamp_bounds([text],e)
        with self.assertRaisesRegex(ValueError,'SYN/client timestamp'):
            validate_syn_timestamp_bounds(['The source spans from 100.000000 to 100.002000,but SYN timestamps span from 100.000000 to 100.002000.'],e)
        with self.assertRaisesRegex(ValueError,'SYN/client timestamp'):
            validate_syn_timestamp_bounds(['The SYN-without-ACK arrival gaps in capture order span source timestamps from 100.000000 to 100.002000.'],e)

    def test_original_id_sentence_start_does_not_inherit_whole_source_zero(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only();e['packets'][1]['status']='malformed';e['packets'][1]['tcp']=None
        for text in ('The source holds three frames. p1 has zero TCP payload bytes.',
                     'The source holds three frames;p1 has zero TCP payload bytes.'):
            validate_claim_language({'summary':text},e)
        with self.assertRaisesRegex(ValueError,'unknown transport payload'):
            validate_claim_language({'summary':'p1 has zero TCP payload bytes. The whole source has no payload.'},e)

    def test_correction_reports_exact_public_field_path(self):
        from pp_claim_checks import validate_claim_language
        e=self.exchange()
        with self.assertRaisesRegex(ValueError,r'alternatives\[0\]:.*whole-source zero'):
            validate_claim_language({'alternatives':['The capture carries no payload.']},e)
        with self.assertRaisesRegex(ValueError,r'recommendations\[0\].rationale:.*whole-source zero'):
            validate_claim_language({'recommendations':[{'rationale':'The capture carries no payload.'}]},e)

    def test_service_facts_and_comparison_expose_neutral_fin_counts(self):
        from pp_service_evidence import service_facts,compare_service
        a=self.setup_only();b=copy.deepcopy(a);b['capture']['sha256']='b'*64
        b['packets'][-1]['tcp']['flags']|=1
        self.assertEqual(service_facts(a)['fin_records'],0)
        self.assertEqual(service_facts(b)['fin_records'],1)
        self.assertEqual(compare_service(a,b)['delta']['fin_records'],1)

    def evidence(self, rows):
        from scapy.all import Ether,IP,TCP,Raw,wrpcap
        from pp_evidence import analyse_capture
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        packets=[]
        for index,(src,dst,sport,dport,flags,seq,ack,payload) in enumerate(rows):
            p=Ether(src='02:00:00:00:00:20',dst='02:00:00:00:00:10')/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags=flags,seq=seq,ack=ack)
            if payload:p=p/Raw(payload)
            p.time=100+index/1000;packets.append(p)
        path=Path(self.temp.name)/'records.pcap';wrpcap(str(path),packets)
        return analyse_capture(path,'scapy')
    def exchange(self,seq=100,server_ack=True,client_ack=False):
        rows=[('10.77.0.20','10.77.0.10',44000,8080,'PA',seq,501,b'GET /\r\n')]
        if server_ack:rows.append(('10.77.0.10','10.77.0.20',8080,44000,'A',501,(seq+7)%2**32,b''))
        rows.append(('10.77.0.10','10.77.0.20',8080,44000,'PA',501,(seq+7)%2**32,b'OK'))
        if client_ack:rows.append(('10.77.0.20','10.77.0.10',44000,8080,'A',(seq+7)%2**32,503,b''))
        return self.evidence(rows)
    def test_ack_sender_is_not_byte_origin(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        facts=analyse_tcp_exchanges(self.exchange())['segment_facts'];a,b=facts['payload_ack_relations']
        self.assertEqual(a['ack_sender']['address'],'10.77.0.10')
        self.assertEqual(a['acknowledged_byte_origin']['address'],'10.77.0.20')
        self.assertIsNone(b['candidate_ack_reference'])
        self.assertEqual(facts['ack_bearing_record_count'],3)
        self.assertEqual(facts['ack_only_empty_segment_count'],1)
    def test_bidirectional_payloads_can_both_have_candidates(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        facts=analyse_tcp_exchanges(self.exchange(client_ack=True))['segment_facts']
        self.assertTrue(all(r['candidate_ack_reference'] for r in facts['payload_ack_relations']))
        self.assertEqual(facts['payload_ack_bearing_record_count'],2)
    def test_sequence_endpoint_wraps(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        facts=analyse_tcp_exchanges(self.exchange(seq=2**32-3))['segment_facts']
        self.assertEqual(facts['payload_ack_relations'][0]['candidate_ack_value'],4)
    def test_wrong_ack_endpoint_not_matched(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();e['packets'][1]['tcp']['acknowledgement']=108;e['packets'][2]['tcp']['acknowledgement']=108
        self.assertIsNone(analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]['candidate_ack_reference'])
    def test_ack_before_data_not_used(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();e['packets'][1]['timestamp']='99';e['packets'][2]['tcp']['acknowledgement']=0
        self.assertIsNone(analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]['candidate_ack_reference'])
    def test_simultaneous_candidates_ambiguous(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();e['packets'][1]['timestamp']=e['packets'][0]['timestamp']
        self.assertTrue(analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]['ambiguous'])
    def test_retransmitted_range_is_ambiguous(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();extra=copy.deepcopy(e['packets'][0]);extra['packet']=4;extra['id']=e['capture']['sha256']+':p4';extra['timestamp']='100.0005';e['packets'].append(extra)
        self.assertTrue(analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]['ambiguous'])
    def test_new_syn_bounds_old_tuple(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();new=copy.deepcopy(e['packets'][0]);new['packet']=4;new['id']=e['capture']['sha256']+':p4';new['timestamp']='100.0005';new['tcp'].update(flags=2,payload_bytes=0,sequence=900);e['packets'].append(new)
        self.assertIsNone(analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]['candidate_ack_reference'])
    def test_filtered_midstream_retains_reverse_but_not_other_service(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();extra=copy.deepcopy(e['packets'][0]);extra['packet']=4;extra['id']=e['capture']['sha256']+':p4';extra['tcp']['dst_port']=9090;e['packets'].append(extra)
        facts=analyse_tcp_exchanges(e,'10.77.0.20','10.77.0.10',8080)['segment_facts']
        self.assertEqual(facts['member_count'],3);self.assertEqual(facts['member_numbers'],[1,2,3])
    def test_log_flags_do_not_establish_payload(self):
        from pp_tcp_relationships import tcp_flag_facts
        facts=tcp_flag_facts(self.exchange()['packets'],True)
        self.assertEqual(facts['ack_flag_only_record_count'],1)
        self.assertIsNone(facts['ack_only_empty_segment_count']);self.assertIsNone(facts['payload_bearing_record_count'])
    def test_initial_aggregate_has_whole_selection_ack_counts(self):
        from pp_investigation_tools import EvidenceWorkspace
        w=EvidenceWorkspace(self.exchange(),'What was acknowledged?')
        facts=w.context['connections']['tcp_segments']
        self.assertEqual(facts['ack_bearing_record_count'],3)
        result=w.inspect_tcp_exchanges();self.assertTrue(result['ok'])
        self.assertIn('segment_facts.ack_bearing_record_count',result['measurement_fields'][result['records'][0]['id']])
    def test_bounded_relations_are_not_whole_payload_proof(self):
        from pp_tcp_relationships import tcp_segment_facts
        e=self.exchange();row=e['packets'][0];rows=[]
        for n in range(20):
            r=copy.deepcopy(row);r['packet']=n+1;r['id']='p'+str(n+1);r['timestamp']=str(100+n);rows.append(r)
        facts=tcp_segment_facts(rows)
        self.assertEqual(facts['payload_relations_inspected'],16);self.assertEqual(facts['payload_relations_omitted'],4)
    def test_timing_endpoints_do_not_localise_delay(self):
        from pp_service_evidence import service_facts
        with tempfile.TemporaryDirectory() as folder:
            _,e=depth_tests.capture(folder,'timing.pcap',.3)
            facts=service_facts(e);self.assertIn('forward path',facts['candidate_exchanges'][0]['included_effects'])
            self.assertIn('Capture point is not established',facts['timing_interpretation'])
    def test_handshake_has_no_payload_relations_and_not_teardown(self):
        from scapy.all import Ether,IP,TCP,wrpcap
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b'')])
        facts=analyse_tcp_exchanges(e)
        self.assertEqual(facts['syns_with_sequence_matched_handshake'],1)
        self.assertEqual(facts['segment_facts']['fin_bearing_record_count'],0)
        self.assertEqual(facts['segment_facts']['payload_relations_inspected'],0)
    def test_global_and_tuple_endpoints_are_distinct(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();last=copy.deepcopy(e['packets'][0]);last['packet']=4;last['id']=e['capture']['sha256']+':p4';last['timestamp']='101';last['tcp']['src_port']=45000;e['packets'].append(last)
        facts=analyse_tcp_exchanges(e)['segment_facts'];first=facts['payload_ack_relations'][0]
        self.assertEqual(first['selected_window_last_timestamp'],'101')
        self.assertAlmostEqual(first['data_to_selected_window_end_seconds'],1)
        self.assertEqual(first['tuple_window_last_timestamp'],'100.002000')
        self.assertAlmostEqual(first['data_to_tuple_window_end_seconds'],.002)
        response=facts['payload_ack_relations'][1]
        self.assertEqual(response['data_to_tuple_window_end_seconds'],0)
    def test_relational_citation_checks_need_endpoints_and_complete_setup(self):
        from pp_claim_checks import validate_relational_support
        from pp_investigation_tools import EvidenceWorkspace
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b'')])
        w=EvidenceWorkspace(e,'Inspect');context=w.validation_context();registry={r['id']:r for r in e['packets']}
        def check(text,refs):return validate_relational_support(dict(text=text,references=[e['packets'][i]['id'] for i in refs]),registry,context)
        with self.assertRaisesRegex(ValueError,'handshake-completion'):check('This ACK completes the TCP handshake.',[2])
        check('The three records show a complete TCP handshake.',[0,1,2])
        check('This single ACK does not prove a complete TCP handshake.',[2])
        with self.assertRaisesRegex(ValueError,'timestamp endpoints'):check('The SYN-ACK arrives 0.001s later.',[1])
        check('The SYN-ACK arrives 0.001s later.',[0,1])
    def test_source_port_range_has_actual_whole_selection_support(self):
        from pp_claim_checks import validate_relational_support
        from pp_investigation_tools import EvidenceWorkspace
        e=self.exchange();w=EvidenceWorkspace(e,'Inspect');context=w.validation_context()
        registry={r['id']:r for r in context['packets']+context['additional_records']}
        row=dict(text='The TCP source ports 8080-44000 bound this selection.',references=[e['packets'][0]['id'],e['packets'][1]['id']])
        with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,registry,context)
        row['references']=[w.supplied[w.context['connections']['id']]['id']];validate_relational_support(row,registry,context)
    def test_view_catalog_excludes_aggregates_but_keeps_inspected_originals(self):
        from pp_investigation_tools import EvidenceWorkspace
        w=EvidenceWorkspace(self.exchange(),'Inspect');w.inspect_tcp_exchanges()
        catalog=w.view_reference_catalog();self.assertIn('p1',catalog['allowed_short_ids'])
        self.assertFalse(catalog['aggregate_ids_allowed'])
        self.assertFalse(any(x.startswith('a') for x in catalog['allowed_short_ids']))
    def test_timing_scalars_can_be_grounded_without_array_indices(self):
        from pp_tcp_relationships import analyse_tcp_exchanges,scalar_paths
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b'')])
        facts=analyse_tcp_exchanges(e)
        self.assertAlmostEqual(facts['handshake_elapsed_min_seconds'],.002)
        self.assertIn('handshake_elapsed_min_seconds',scalar_paths(facts))
        self.assertAlmostEqual(facts['handshake_elapsed_seconds'],.002)
    def test_payload_can_be_acked_without_co_carried_fin(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'FA',100,501,b'abc'),
            ('10.77.0.10','10.77.0.20',8080,44000,'A',501,103,b'')])
        relation=analyse_tcp_exchanges(e)['segment_facts']['payload_ack_relations'][0]
        self.assertEqual(relation['candidate_ack_value'],103)
        self.assertEqual(relation['payload_sequence_endpoint'],103)
        self.assertEqual(relation['next_sequence_endpoint_including_control_bits'],104)
        self.assertFalse(relation['candidate_ack_covers_segment_controls'])
    def test_singular_interval_is_not_a_multi_exchange_measurement(self):
        from pp_tcp_relationships import analyse_tcp_exchanges,scalar_paths
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b''),
            ('10.77.0.20','10.77.0.10',44001,8080,'S',300,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44001,'SA',700,301,b''),
            ('10.77.0.20','10.77.0.10',44001,8080,'A',301,701,b'')])
        facts=analyse_tcp_exchanges(e);self.assertIsNone(facts['handshake_elapsed_seconds'])
        self.assertNotIn('handshake_elapsed_seconds',scalar_paths(facts))
        self.assertIn('handshake_elapsed_max_seconds',scalar_paths(facts))
    def test_schema_failure_diagnostics_collect_other_reference_and_field_errors(self):
        from pp_investigator import correction_diagnostics
        from pp_investigation_tools import EvidenceWorkspace
        w=EvidenceWorkspace(self.exchange(),'Inspect')
        value={'observations':[{'text':'p1 and p2 contain fields.','references':['p1'],'support':[{'reference':'p1','field':'invented','value':3}]}],
            'measurements':[{'reference':'not-a-reference'}],'recommendations':[{'action':'no_action'}],'views':[{'references':[w.context['connections']['id']]}]}
        import json
        hints=correction_diagnostics(json.dumps(value),w)
        self.assertTrue(any('p2' in h for h in hints));self.assertTrue(any('invented' in h for h in hints))
        self.assertTrue(any('recommendations' in h for h in hints));self.assertTrue(any('rendering' in h for h in hints))
    def test_correction_diagnostics_never_accept_or_crash_on_malformed_shapes(self):
        from pp_investigator import correction_diagnostics
        from pp_investigation_tools import EvidenceWorkspace
        w=EvidenceWorkspace(self.exchange(),'Inspect')
        for raw in ('invalid','[]','{"observations":9,"views":true,"recommendations":{}}','{"observations":[{"support":9,"references":false,"text":8}]}'):
            self.assertIsInstance(correction_diagnostics(raw,w),list)
    def test_explicit_payload_origin_reversal_is_checked_in_all_sections(self):
        from pp_claim_checks import validate_claim_language
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'PA',101,501,b'abc'),
            ('10.77.0.10','10.77.0.20',8080,44000,'PA',501,104,b'response')])
        for text in ("The client's own bytes exist (the 8-byte response segments).",'These are client-origin 8-byte payloads.',"The server's 3-byte request is visible."):
            for section in ('summary','interpretation'):
                with self.assertRaisesRegex(ValueError,'byte origin'):validate_claim_language({section:text},e)
            with self.assertRaisesRegex(ValueError,'byte origin'):validate_claim_language({'recommendations':[{'rationale':text}]},e)
        for text in ("The server's 8-byte response and client's 3-byte request are visible.",'The server ACK acknowledges 3 bytes sent by the client.','The client could acknowledge the server-origin 8-byte response.','It is not a client-origin 8-byte payload.'):
            validate_claim_language({'summary':text},e)
    def test_payload_roles_follow_initiator_not_numeric_address(self):
        from pp_claim_checks import payload_role_lengths
        e=self.evidence([('10.77.0.10','10.77.0.20',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',44000,8080,'PA',101,501,b'abc'),
            ('10.77.0.20','10.77.0.10',8080,44000,'PA',501,104,b'response')])
        self.assertEqual(payload_role_lengths(e),{'client':{3},'server':{8}})
    def test_named_zero_payload_subset_does_not_claim_whole_capture_zero(self):
        from pp_claim_checks import validate_grounding
        from pp_investigation_tools import EvidenceWorkspace
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'PA',101,501,b'abc')])
        w=EvidenceWorkspace(e,'Inspect');a,b,c=[r['id'] for r in e['packets']]
        def check(text,refs):return validate_grounding({'observations':[{'text':text,'references':refs,'support':[{'reference':a,'field':'tcp.payload_bytes','value':0}]}]},w.validation_context(),required=True)
        check('p1 and p2 each carry zero payload bytes.',[a,b])
        check('Each of p1, p2 has zero payload.',[a,b])
        with self.assertRaises(ValueError):check('All decoded packets carry zero payload; p1 and p2 are examples.',[a,b])
        with self.assertRaises(ValueError):check('p1, p2 and p3 each carry zero payload bytes.',[a,b,c])
    def test_early_schema_error_diagnostics_also_report_literal_offsets(self):
        from pp_investigator import correction_diagnostics
        from pp_investigation_tools import EvidenceWorkspace
        import json
        w=EvidenceWorkspace(self.exchange(),'Inspect')
        value={'uncertainty':'Wrong list shape','observations':[{'text':'The source file_offset 338 is retained.','references':['p1'],'support':[{'reference':'p1','field':'tcp.flags','value':24}]}]}
        hints=correction_diagnostics(json.dumps(value),w)
        self.assertTrue(any('Literal source byte offsets' in h for h in hints))
        self.assertEqual(value['uncertainty'],'Wrong list shape')

    def test_service_tuple_end_is_not_whole_source_end(self):
        from pp_tcp_relationships import analyse_tcp_exchanges
        from pp_claim_checks import validate_claim_language
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,443,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',443,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,443,'A',101,501,b''),
            ('10.77.0.20','10.77.0.10',44001,80,'S',200,0,b''),
            ('10.77.0.10','10.77.0.20',80,44001,'SA',600,201,b''),
            ('10.77.0.20','10.77.0.10',44001,80,'A',201,601,b'')])
        facts=analyse_tcp_exchanges(e)
        self.assertFalse(facts['exchanges'][0]['tuple_last_coincides_with_source_end'])
        self.assertTrue(facts['exchanges'][1]['tuple_last_coincides_with_source_end'])
        self.assertEqual(facts['exchanges_ending_at_source_window_end'],1)
        self.assertAlmostEqual(facts['exchanges'][0]['tuple_last_to_source_end_seconds'],.003)
        with self.assertRaisesRegex(ValueError,'named service flow'):validate_claim_language({'interpretation':'The port-443 flow ends with the capture.'},e)
        validate_claim_language({'interpretation':'The port-80 flow ends with the capture.'},e)
        validate_claim_language({'interpretation':'The port-443 flow may end with the capture in a hypothetical other file.'},e)

    def test_missing_ack_not_forced_beyond_whole_multiflow_window(self):
        from pp_claim_checks import validate_claim_language
        e=self.exchange()
        with self.assertRaisesRegex(ValueError,'not forced outside'):validate_claim_language({'uncertainty':['Any client cumulative ACK for the responses would fall outside this saved window.']},e)
        validate_claim_language({'uncertainty':['A client ACK could lie outside this capture point or after the last record.']},e)

    def test_window_check_does_not_invent_unavailable_timestamps(self):
        from pp_claim_checks import validate_window_end_claims
        e=self.exchange()
        for r in e['packets']:r.pop('timestamp')
        validate_window_end_claims('The port-8080 flow ends with the capture.',e)

    def test_payload_ack_observation_needs_both_sides_or_relation_aggregate(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        from pp_tcp_relationships import analyse_tcp_exchanges
        e=self.exchange();w=EvidenceWorkspace(e,'Inspect');context=w.validation_context()
        a,b=e['packets'][:2];text='The server segment acknowledges the client payload bytes and matches their sequence endpoint.'
        def check(refs):validate_relational_support({'text':text,'references':refs},reference_registry(context),context)
        with self.assertRaisesRegex(ValueError,'data-origin'):check([b['id']])
        check([a['id'],b['id']])
        fact=analyse_tcp_exchanges(e);context['additional_records'].append(fact);check([fact['id']])
        datagram=copy.deepcopy(a);datagram['id']=e['capture']['sha256']+':p4';datagram['packet']=4;datagram['tcp']=None;datagram['udp']={'src_port':5000,'dst_port':5001,'payload_bytes':1};context['packets'].append(datagram)
        check([a['id'],b['id'],datagram['id']])
        validate_relational_support({'text':'The ACK field has the displayed value.','references':[b['id']]},reference_registry(context),context)

    def test_recommendation_all_handshakes_not_supported_by_one_example(self):
        from pp_claim_checks import validate_grounding
        from pp_investigation_tools import EvidenceWorkspace
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,80,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',80,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,80,'A',101,501,b''),
            ('10.77.0.20','10.77.0.10',44001,80,'S',200,0,b''),
            ('10.77.0.10','10.77.0.20',80,44001,'SA',600,201,b''),
            ('10.77.0.20','10.77.0.10',44001,80,'A',201,601,b'')])
        context=EvidenceWorkspace(e,'Inspect').validation_context()
        def check(refs):validate_grounding({'recommendations':[{'rationale':'All two checks complete the TCP handshake, so no change is supported.','references':refs}]},context,required=True)
        with self.assertRaisesRegex(ValueError,'single completed example'):check([r['id'] for r in e['packets'][:3]])
        check([r['id'] for r in e['packets']])

    def setup_only(self):
        return self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b'')])

    def test_singular_window_scalars_are_actual_end_differences(self):
        from pp_tcp_relationships import analyse_tcp_exchanges,scalar_paths
        e=self.setup_only();f=analyse_tcp_exchanges(e)
        self.assertEqual(f['tuple_last_reference'],e['packets'][-1]['id'])
        self.assertEqual(f['final_ack_to_source_end_seconds'],0)
        self.assertAlmostEqual(f['source_window_duration_seconds'],.002)
        self.assertAlmostEqual(f['reply_to_source_end_seconds'],.001)
        self.assertTrue(f['reply_acknowledgement_matches_syn'])
        self.assertIn('tuple_last_to_source_end_seconds',scalar_paths(f))
        e['packets']+=copy.deepcopy(e['packets'])
        f=analyse_tcp_exchanges(e)
        self.assertIsNone(f['tuple_last_timestamp'])
        self.assertNotIn('tuple_last_timestamp',scalar_paths(f))

    def test_numeric_source_end_offset_rejects_wrong_and_accepts_actual(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('The window ends 2 ms after the final ACK.',
                     'The capture stops 0.001 seconds after p3.'):
            with self.assertRaisesRegex(ValueError,'actual identified anchor'):validate_observation_bounds(text,e)
        validate_observation_bounds('The window ends 0 ms after the final ACK.',e)
        validate_observation_bounds('The window ends 1 ms after p2.',e)
        validate_observation_bounds('The window could end 2 ms after the final ACK in another capture.',e)

    def test_numeric_response_end_offset_on_udp(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for i,r in enumerate(e['packets'][:2]):
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':45000 if not i else 53,'dst_port':53 if not i else 45000,'payload_bytes':20}
            r['application']={'protocol':'DNS','response':bool(i)}
        e['packets']=e['packets'][:2]
        with self.assertRaisesRegex(ValueError,'actual identified anchor'):validate_observation_bounds('The observed window ends 8ms after the response.',e)
        validate_observation_bounds('The window ends 0 seconds after the response.',e)

    def test_window_observation_not_unqualified_session_termination(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('The session ends at the capture window.','The connection closed after setup.',
                     'The sessions close at the final record.',
                     'There is a session end that coincides with the capture window.'):
            with self.assertRaisesRegex(ValueError,'not a session close'):validate_observation_bounds(text,e)
        for text in ('The last observed tuple record is at source end.',
                     'The session may have closed outside the saved window.',
                     'It is unknown whether the connection closed.',
                     'The TCP handshake completed.'):
            validate_observation_bounds(text,e)
        for text in ('No session close is asserted.',
                     'How the connection ended later is simply unknown.',
                     'Nothing is claimed about how or when the session ended.',
                     'It is not evidence that no request was sent or that the session ended there.'):
            validate_observation_bounds(text,e)
        validate_observation_bounds('Nothing here describes an HTTP request, an application outcome, or how the session ended.',e)
        validate_observation_bounds("The capture vantage is unestablished, and each flow's last record is the end of observation rather than a documented session close.",e)
        with self.assertRaisesRegex(ValueError,'Missing captured teardown'):
            validate_observation_bounds('Teardown lies outside the saved window.',e)
        validate_observation_bounds('Teardown may lie outside the saved window.',e)
        e['packets'][-1]['tcp']['flags']|=1
        validate_observation_bounds('The connection closed in this window.',e)

    def test_captured_udp_does_not_establish_endpoint_receipt(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for r in e['packets']:
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':53,'dst_port':45000,'payload_bytes':20}
        for text in ('The client received the DNS response after 8 ms.',
                     '10.77.0.20 asked for the name and 8 ms later received a response.',
                     '10.77.0.20 asked 10.77.0.10 for the A record of service.lab. and received an NXDOMAIN reply 8 ms later.',
                     'The client received it within 8 ms.'):
            with self.assertRaisesRegex(ValueError,'does not establish client receipt'):validate_observation_bounds(text,e)
        for text in ('A matching DNS response addressed to the client was observed 8 ms later.',
                     'Whether the client received the response is unknown.',
                     'The client may have received the response.'):
            validate_observation_bounds(text,e)
        validate_observation_bounds('The client received the response.',self.exchange())

    def test_udp_receipt_explicit_lack_of_proof_is_not_positive_receipt(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for r in e['packets']:
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':53,'dst_port':45000,'payload_bytes':20}
        for text in (
            'The reply is addressed to 10.77.0.20 rather than proven received by it.',
            'The reply is addressed to 10.77.0.20 rather than confirmed to have been received by it.',
            'The reply is observed as addressed to 10.77.0.20 without proving that host received it.',
            'The reply was addressed to the client without evidence that the client received the response.',
            'That the client received the reply is not established.',
            'Whether the client received the reply remains unknown.',
            'The client received the response is not confirmed by these headers.',
            'The captured reply does not prove the client received the response.',
            'It is protocol evidence only,not proof the client received the datagram or acted on it.',
            'It is not a proof that the client received the response.',
            'The client may have received the response,but the captured destination alone does not prove receipt.'):
            with self.subTest(text=text):validate_observation_bounds(text,e)

    def test_udp_receipt_unrelated_uncertainty_does_not_license_positive_claim(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for r in e['packets']:
            r['tcp']=None;r['protocol']='UDP';r['udp']={'src_port':53,'dst_port':45000,'payload_bytes':20}
        for text in (
            'The client rather than the server received the response.',
            'The client received the reply rather than ignoring it.',
            'The client without authentication received the reply.',
            'The capture point is unknown,so the client received the response.',
            'The capture point is not established,so the client got the reply.',
            'It is not proof that the client received the reply,and the client got the response.',
            'Whether the client received the reply is unknown,and the client got a response.',
            'The reply was addressed to the client without proving that host received it,and the client got the response.',
            'The reply is addressed to 10.77.0.20 rather than proven received by it,but the client received the reply.'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'does not establish client receipt'):
                validate_observation_bounds(text,e)

    def test_regular_spacing_is_not_proven_automation(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        with self.assertRaisesRegex(ValueError,'regularity does not prove'):
            validate_observation_bounds('Identical requests and regular spacing only demonstrate automation, not its purpose.',e)
        with self.assertRaisesRegex(ValueError,'regularity does not prove'):
            validate_observation_bounds('Regular cadence indicates automation only, not purpose or origin.',e)
        for text in ('Regular spacing is consistent with automation.',
                     'Regular spacing does not demonstrate automation.',
                     'Operator context says this is automated; the captured gaps are regular.'):
            validate_observation_bounds(text,e)

    def test_ack_number_and_own_payload_listing_is_not_relationship(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.exchange();w=EvidenceWorkspace(e,'Inspect');context=w.validation_context()
        r=e['packets'][-1]
        for text in ('The record has acknowledgement 103 and 8 payload bytes.',
                     'The acknowledgement value is 103; its own payload is 8 bytes.',
                     'The SYN has acknowledgement 0, flags 2 and zero transport payload bytes.'):
            validate_relational_support({'text':text,'references':[r['id']]},reference_registry(context),context)
        with self.assertRaisesRegex(ValueError,'data-origin'):
            validate_relational_support({'text':'The server acknowledges the client payload bytes.',
                'references':[e['packets'][1]['id']]},reference_registry(context),context)

    def test_service_comparison_exposes_actual_path_difference(self):
        from pp_service_evidence import service_facts,compare_service
        with tempfile.TemporaryDirectory() as folder:
            _,a=depth_tests.capture(folder,'left.pcap',.015)
            _,b=depth_tests.capture(folder,'right.pcap',.315)
            for r in b['packets']:
                if (r.get('application') or {}).get('message')=='request':r['application']['path']='/other'
            f=service_facts(a);self.assertEqual(f['only_http_request_method'],'GET')
            self.assertEqual(f['visible_http_request_signature_count'],1)
            result=compare_service(a,b)
            self.assertTrue(result['visible_http_request_workload_changed'])
            self.assertTrue(any('method/path/count' in x for x in result['qualifications']))
            for r in b['packets']:
                if (r.get('application') or {}).get('message')=='request':r['application']['path']=f['only_http_request_path']
            self.assertFalse(compare_service(a,b)['visible_http_request_workload_changed'])

    def test_workload_comparison_uses_complete_not_truncated_signature_list(self):
        from pp_service_evidence import compare_service
        with tempfile.TemporaryDirectory() as folder:
            _,a=depth_tests.capture(folder,'left.pcap',.015)
            _,b=depth_tests.capture(folder,'right.pcap',.315)
            request=next(r for r in a['packets'] if (r.get('application') or {}).get('message')=='request')
            for e in (a,b):
                rows=[]
                for n in range(30):
                    r=copy.deepcopy(request);r['packet']=100+n;r['id']=e['capture']['sha256']+':p'+str(100+n)
                    r['application']['path']='/'+str(n).zfill(2);rows.append(r)
                e['packets']=rows
            b['packets'][-1]['application']['path']='/99'
            facts=compare_service(a,b)
            self.assertEqual(facts['baseline']['visible_http_request_signatures_omitted'],6)
            def shown_counts(side):return [(r['method'],r['path'],r['count']) for r in facts[side]['visible_http_request_signatures']]
            self.assertEqual(shown_counts('baseline'),shown_counts('comparison'))
            self.assertTrue(facts['visible_http_request_workload_changed'])

    def test_http_status_claim_cannot_use_only_tcp_setup_support(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        with tempfile.TemporaryDirectory() as folder:
            _,e=depth_tests.capture(folder,'status.pcap',.015)
            w=EvidenceWorkspace(e,'Inspect');w.inspect_tcp_exchanges();context=w.validation_context()
            tcp=next(r for r in context['additional_records'] if 'syns_with_candidate_handshake' in r)
            text='One handshake was answered by a visible 200 OK response.'
            with self.assertRaisesRegex(ValueError,'HTTP-status claim'):
                validate_relational_support(dict(text=text,references=[tcp['id']]),reference_registry(context),context)
            responses=[r['id'] for r in e['packets'] if (r.get('application') or {}).get('status_code')==200]
            validate_relational_support(dict(text=text,references=responses),reference_registry(context),context)
            from pp_case_tools import CaseWorkspace
            CaseWorkspace(w).inspect_service();context=w.validation_context()
            service=next(r for r in context['additional_records'] if 'visible_http_response_status_counts' in r)
            validate_relational_support(dict(text=text,references=[service['id']]),reference_registry(context),context)
            validate_relational_support(dict(text='One 18-byte request to 10.77.0.10:8080 had a 200 OK response.',references=[service['id']]),reference_registry(context),context)
            with self.assertRaisesRegex(ValueError,'HTTP-status claim'):
                validate_relational_support(dict(text='Three handshakes answered by 200 OK responses.',references=responses[:1]),reference_registry(context),context)
            validate_relational_support(dict(text='No visible 503 response is established by these TCP fields.',references=[tcp['id']]),reference_registry(context),context)

    def test_nested_zero_payload_aggregate_keeps_transport_scope(self):
        from pp_claim_checks import validate_grounding
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');w.summarize_connections();context=w.validation_context()
        aggregate=next(r for r in context['additional_records'] if 'tcp_segments' in r)
        def check(text,ctx,ref):
            row=dict(text=text,references=[ref],support=[dict(reference=ref,field='tcp_segments.payload_bytes_total',value=0)])
            validate_grounding({'observations':[row]},ctx,required=True)
        check('All three decoded TCP records carry zero payload.',context,aggregate['id'])
        check('All three decoded records carry zero payload.',context,aggregate['id'])
        r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=44000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        w=EvidenceWorkspace(e,'Inspect');w.summarize_connections();context=w.validation_context()
        aggregate=next(r for r in context['additional_records'] if 'tcp_segments' in r)
        check('All decoded TCP records carry zero payload.',context,aggregate['id'])
        with self.assertRaisesRegex(ValueError,'whole-set zero-payload'):
            check('All decoded records carry zero payload.',context,aggregate['id'])
        aggregate['tcp_segments']['payload_length_available']=False
        with self.assertRaisesRegex(ValueError,'whole-set zero-payload'):
            check('All decoded TCP records carry zero payload.',context,aggregate['id'])

    def test_case_status_aggregates_keep_each_source_separate(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        from pp_service_evidence import compare_service
        with tempfile.TemporaryDirectory() as folder:
            _,a=depth_tests.capture(folder,'left.pcap',.015)
            _,b=depth_tests.capture(folder,'right.pcap',.315)
            w=EvidenceWorkspace(b,'Inspect');context=w.validation_context()
            facts=compare_service(a,b);facts.update(id=b['capture']['sha256']+':a0123456789abcdef',kind='case_comparison')
            context['additional_records'].append(facts)
            def check(text,refs):validate_relational_support(dict(text=text,references=refs),reference_registry(context),context)
            check('Both sources have one visible HTTP 200 response.',[facts['id']])
            one=next(r['id'] for r in b['packets'] if (r.get('application') or {}).get('status_code')==200)
            with self.assertRaisesRegex(ValueError,'HTTP-status claim'):
                check('All three captured sessions have visible 200 OK responses.',[one])
            for branch,count in (('baseline',0),('comparison',6)):
                facts[branch]['visible_http_response_status_counts']['status_200']=count
                facts[branch]['candidate_exchanges']=[]
            with self.assertRaisesRegex(ValueError,'HTTP-status claim'):
                check('Both sources have three visible HTTP 200 responses.',[facts['id']])
            for branch in ('baseline','comparison'):facts[branch]['visible_http_response_status_counts']['status_200']=3
            facts['baseline']['source_sha256']=facts['comparison']['source_sha256']
            with self.assertRaisesRegex(ValueError,'HTTP-status claim'):
                check('Each source has three visible HTTP 200 responses.',[facts['id']])

    def test_multiword_window_anchor_preserves_sender_and_handshake(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'SA',500,101,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',101,501,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'PA',101,501,b'abc'),
            ('10.77.0.10','10.77.0.20',8080,44000,'A',501,104,b''),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',104,501,b'')])
        for text in ("The window ends 0 ms after the client's final ACK.",
                     "The capture ends 1 ms after the server's last ACK.",
                     'The source ends 3 ms after the handshake final ACK.'):
            validate_observation_bounds(text,e)
        for text in ("The window ends 1 ms after the client's final ACK.",
                     "The source ends 0 ms after the server's last ACK.",
                     "Capture placement is not established, and the window ends 1 ms after the client's final ACK."):
            with self.assertRaisesRegex(ValueError,'actual identified anchor'):validate_observation_bounds(text,e)
        validate_observation_bounds("It is unknown whether the window ends 1 ms after the client's final ACK.",e)

    def test_whole_source_zero_does_not_erase_known_udp_payload(self):
        from pp_claim_checks import validate_source_payload_zero,validate_claim_language
        e=self.setup_only();r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=44000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        bad='This offline header-only sample supports no network change: no handshake, payload or service impact was observed.'
        for section in ('summary','interpretation'):
            with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):validate_claim_language({section:bad},e)
        with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
            validate_claim_language({'recommendations':[dict(rationale=bad)]},e)
        for text in ('The source has no TCP payload; a UDP datagram has 22 bytes.',
                     'All decoded TCP records in this capture carry zero payload.',
                     'The capture contains one SYN with no payload and a separate UDP payload.',
                     'Whether the source contains no payload is unknown.'):
            validate_source_payload_zero(text,e)
        validate_source_payload_zero('The source has no payload.',dict(input_kind='network_log',log_records=[]))

    def test_nonzero_payload_is_not_a_zero_payload_assertion(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=44000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        for adjective in ('non-zero','nonzero','non zero','not zero'):
            with self.subTest(adjective=adjective):
                validate_source_payload_zero('The capture has '+adjective+' transport payload in one UDP datagram.',e)
        validate_source_payload_zero('The TCP selection carries zero TCP payload. Separately, the source has non-zero UDP payload.',e)
        for text in ('The capture has zero transport payload.',
                     'The sample contains no payload.',
                     'The source has non-zero frame bytes but zero payload.'):
            with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
                validate_source_payload_zero(text,e)

    def test_correction_diagnostics_identify_recommendation_not_valid_observation(self):
        import json
        from pp_claim_checks import validate_grounding
        from pp_investigator import correction_diagnostics
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');context=w.validation_context()
        ids=[r['id'] for r in e['packets']]
        value=dict(observations=[dict(text='The TCP handshake completed.',references=ids,support=[dict(reference=ids[0],field='tcp.flags',value=2)])],
                   recommendations=[dict(rationale='A completed handshake supports no network change.',references=[ids[0]])])
        with self.assertRaisesRegex(ValueError,'Recommendation 1 rationale'):
            validate_grounding(value,context,required=True)
        short=copy.deepcopy(value)
        for row in short['observations']+short['recommendations']:row['references']=[r.rsplit(':',1)[-1] for r in row['references']]
        short['observations'][0]['support'][0]['reference']='p1'
        before=copy.deepcopy(short);hints=correction_diagnostics(json.dumps(short),w)
        self.assertTrue(any('recommendations[0].rationale' in h for h in hints))
        self.assertEqual(short,before)

    def test_operator_purpose_is_context_not_packet_or_execution_permission(self):
        policy=(ROOT/'components/01-llm-interface/prompts/workspace-v4.txt').read_text(encoding='utf-8')
        self.assertIn('attributed business context',policy)
        self.assertIn('not as a\n  packet fact or execution permission',policy)
        self.assertIn('genuine contradictions',policy)

    def mixed_syn_cadence(self):
        e=self.evidence([('10.77.0.20','10.77.0.10',44000+n,8080+n,'S',100+n,0,b'') for n in range(4)])
        udp=e['packets'][1];udp['tcp']=None;udp['udp']=dict(src_port=45000,dst_port=9999,payload_bytes=3);udp['protocol']='UDP'
        for r,t in zip(e['packets'],('100.000000','100.000500','100.001000','100.002000')):r['timestamp']=t;r['time']=float(t)
        return e

    def test_syn_gap_facts_exclude_intervening_udp_and_other_records(self):
        from pp_tcp_relationships import tcp_flag_facts
        from pp_investigation_tools import EvidenceWorkspace
        e=self.mixed_syn_cadence();f=tcp_flag_facts(e['packets'])
        self.assertEqual(f['tcp_record_count'],3)
        self.assertEqual(f['syn_arrival_gap_count'],2)
        self.assertEqual(f['syn_arrival_gap_min_seconds'],.001)
        self.assertEqual(f['syn_arrival_gap_max_seconds'],.001)
        w=EvidenceWorkspace(e,'Inspect');r=w.inspect_tcp_exchanges()['records'][0]
        self.assertEqual(r['segment_facts']['syn_arrival_gap_min_seconds'],.001)
        self.assertEqual(r['segment_facts']['syn_timestamps_missing'],0)

    def test_syn_gap_facts_keep_capture_order_and_missing_timestamp_holes(self):
        from pp_tcp_relationships import tcp_flag_facts
        e=self.mixed_syn_cadence();e['packets'][-1]['timestamp']='99.999000'
        f=tcp_flag_facts(e['packets']);self.assertEqual(f['syn_arrival_gap_min_seconds'],-.002)
        e['packets'][2]['timestamp']=None
        f=tcp_flag_facts(e['packets']);self.assertEqual(f['syn_timestamps_missing'],1)
        self.assertEqual(f['syn_arrival_gap_count'],0)
        self.assertIsNone(f['syn_arrival_gap_min_seconds'])

    def test_filtered_syn_cadence_is_not_whole_source_cadence(self):
        from pp_semantics import validate_syn_cadence
        e=self.mixed_syn_cadence()
        bad='The whole source has unequal gaps, so the SYNs are not evenly spaced at one fixed interval.'
        with self.assertRaisesRegex(ValueError,'filtered SYN records'):validate_syn_cadence([bad],e)
        validate_syn_cadence(['The SYNs are evenly spaced at 0.001 seconds.'],e)
        validate_syn_cadence(['The whole source records are not evenly spaced.'],e)
        validate_syn_cadence(['Whether the SYNs are not evenly spaced is unknown.'],e)
        e['packets'][-1]['timestamp']='100.004000'
        validate_syn_cadence(['The SYNs are not evenly spaced.'],e)
        with self.assertRaisesRegex(ValueError,'stated SYN spacing'):
            validate_syn_cadence(['The SYNs are evenly spaced at 0.001 seconds.'],e)
        e['packets'][2]['timestamp']=None
        validate_syn_cadence(['The SYNs are not evenly spaced.'],e)

    def test_unanswered_syn_destination_is_not_observed_endpoint_arrival(self):
        from pp_claim_checks import validate_unanswered_syn_arrival
        e=self.mixed_syn_cadence()
        for text in ('Three bare TCP SYN segments from 10.77.0.20 reached 10.77.0.10.',
                     'The SYNs arrived at the server.',
                     'Capture point is unknown, and the SYNs reached the service.'):
            with self.assertRaisesRegex(ValueError,'endpoint arrival'):validate_unanswered_syn_arrival(text,e)
        for text in ('The SYNs were addressed to 10.77.0.10.',
                     'Whether these SYNs reached the service is unknown.',
                     'The SYNs could have reached the service.',
                     'The SYNs reached the capture point.'):
            validate_unanswered_syn_arrival(text,e)
        validate_unanswered_syn_arrival('The SYN reached the service.',self.setup_only())

    def test_filtered_syn_bounds_do_not_use_reverse_reset_or_full_sender_ports(self):
        from pp_tcp_relationships import tcp_flag_facts
        e=self.evidence([('10.77.0.20','10.77.0.10',42000,22,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',22,42000,'RA',0,101,b''),
            ('10.77.0.20','10.77.0.10',42001,80,'S',200,0,b''),
            ('10.77.0.10','10.77.0.20',80,42001,'RA',0,201,b'')])
        f=tcp_flag_facts(e['packets']);self.assertEqual(f['syn_timestamp_max'],'100.002000')
        self.assertEqual(f['syn_source_port_min'],42000);self.assertEqual(f['source_port_min'],22)
        self.assertEqual(f['syn_source_port_max'],42001);self.assertEqual(f['syn_without_ack_record_count'],2)
        e['packets'][2]['timestamp']='99.999000';f=tcp_flag_facts(e['packets'])
        self.assertEqual(f['syn_last_record_timestamp'],'99.999000');self.assertEqual(f['syn_timestamp_max'],'100.000000')
        e['packets'][0]['timestamp']=None;f=tcp_flag_facts(e['packets'])
        self.assertIsNone(f['syn_first_record_timestamp']);self.assertEqual(f['syn_timestamps_missing'],1)

    def test_named_syn_range_rejects_reset_endpoint_but_not_source_or_unknown(self):
        from pp_semantics import validate_syn_timestamp_bounds
        e=self.evidence([('10.77.0.20','10.77.0.10',42000,22,'S',100,0,b''),
            ('10.77.0.10','10.77.0.20',22,42000,'RA',0,101,b''),
            ('10.77.0.20','10.77.0.10',42001,80,'S',200,0,b''),
            ('10.77.0.10','10.77.0.20',80,42001,'RA',0,201,b'')])
        validate_syn_timestamp_bounds(['SYN records span source timestamps from 100.000000 to 100.002000.'],e)
        with self.assertRaisesRegex(ValueError,'filtered original'):
            validate_syn_timestamp_bounds(['SYN records span source timestamps from 100.000000 to 100.003000.'],e)
        validate_syn_timestamp_bounds(['The source timestamps run from 100.000000 to 100.003000.'],e)
        e['packets'][0]['timestamp']=None
        validate_syn_timestamp_bounds(['SYN timestamp bounds from 100.000000 to 100.003000 are unknown.'],e)

    def test_quantified_zero_payload_keeps_transport_and_later_global_scope(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=45000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        for count in ('3','three','Nine'):
            with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
                validate_source_payload_zero(count+' header-only records with no payload.',e)
        for text in ('The decoded TCP records have no payload.','Two SYN records have no payload.',
                     'The source has non-zero UDP payload.'):
            validate_source_payload_zero(text,e)
        with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
            validate_source_payload_zero('The TCP records have no TCP payload. The three saved records have no payload.',e)

    def test_unknown_record_prevents_global_absence_but_not_decoded_scope(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        for text in ('No payload in either direction.','The capture has no payload.',
                     'All three saved records contain zero payload.'):
            with self.assertRaisesRegex(ValueError,'unknown transport payload'):validate_source_payload_zero(text,e)
        for text in ('Among the decoded TCP records there is no payload.',
                     'No payload was observed among decoded TCP packets.',
                     'Whether the source has no payload is unknown.',
                     'The source contains one SYN with no payload.'):
            validate_source_payload_zero(text,e)

    def test_elliptical_source_end_uses_named_final_ack_not_request_time(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        validate_observation_bounds('The capture starts at the first SYN and ends 0 ms after the last client ACK.',e)
        with self.assertRaisesRegex(ValueError,'actual identified anchor'):
            validate_observation_bounds('The capture starts at the first SYN and ends 2 ms after the last client ACK.',e)
        e['packets'].append(copy.deepcopy(e['packets'][0]));r=e['packets'][-1];r['timestamp']='100.005000';r['tcp']=None
        validate_observation_bounds('The source starts at the SYN and ends 3 ms after the last client ACK.',e)

    def test_long_negated_closure_does_not_hide_independent_positive(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('These are absent observations rather than proof the service refused or that the connection ended.',
                     'This is not a proven service failure, a scan or a closed connection.',
                     'The missing details are unobserved rather than evidence the attempt failed or that a session closed.'):
            validate_observation_bounds(text,e)
        for text in ('There is no proof of service failure, but the connection ended.',
                     'No session closed, and the connection ended.',
                     'The session ended, though the reason is unknown.'):
            with self.assertRaisesRegex(ValueError,'session close'):validate_observation_bounds(text,e)

    def test_one_valid_ack_pair_does_not_certify_a_different_named_ack(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.evidence([('10.77.0.20','10.77.0.10',44000,8080,'PA',101,501,b'abc'),
            ('10.77.0.10','10.77.0.20',8080,44000,'A',501,104,b''),
            ('10.77.0.10','10.77.0.20',8080,44000,'PA',501,104,b'hello'),
            ('10.77.0.20','10.77.0.10',44000,8080,'A',104,506,b'')])
        w=EvidenceWorkspace(e,'Inspect');ctx=w.validation_context()
        row=dict(text='The service acknowledged request bytes in p2 and the client acknowledged p3 in p4.',references=[r['id'] for r in e['packets'][1:]])
        with self.assertRaisesRegex(ValueError,'Each named byte-ACK'):validate_relational_support(row,reference_registry(ctx),ctx)
        row['references'].append(e['packets'][0]['id']);validate_relational_support(row,reference_registry(ctx),ctx)

    def test_missing_observation_is_not_a_claim_about_event_time(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('Any teardown lies outside the supplied observation and is unobserved.',
                     'The teardown is outside these supplied tool results.',
                     'Whether teardown lies outside the saved window is unknown.'):
            validate_observation_bounds(text,e)
        for text in ('The teardown lies outside the saved window.',
                     'Teardown is beyond the capture period.'):
            with self.assertRaisesRegex(ValueError,'teardown happened outside'):validate_observation_bounds(text,e)

    def test_word_interval_needs_same_endpoints_as_numeric(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');ctx=w.validation_context();registry=reference_registry(ctx)
        for amount in ('one millisecond','1 ms'):
            row=dict(text='P2 is '+amount+' later.',references=[e['packets'][1]['id']])
            with self.assertRaisesRegex(ValueError,'both cited original'):validate_relational_support(row,registry,ctx)
            row['references']=[r['id'] for r in e['packets'][:2]];validate_relational_support(row,registry,ctx)

    def test_client_port_bounds_require_complete_filtered_inspector(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');w.inspect_tcp_exchanges();ctx=w.validation_context()
        aggregate=next(r for r in ctx['additional_records'] if 'exchanges' in r)
        row=dict(text='The client source ports 44000-44000 occur in the SYN selection.',references=[aggregate['id']])
        validate_relational_support(row,reference_registry(ctx),ctx)
        aggregate['segment_facts'].pop('syn_source_port_min');aggregate['segment_facts'].pop('syn_source_port_max')
        validate_relational_support(row,reference_registry(ctx),ctx)
        aggregate['exchange_details_omitted']=1
        with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,reference_registry(ctx),ctx)
        aggregate['exchange_details_omitted']=0;row['text']='The client source ports 44000-44001 occur in the SYN selection.'
        with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,reference_registry(ctx),ctx)

    def test_explicit_transport_selection_does_not_borrow_later_global_scope(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=45000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        for noun in ('selection','subset','records','traffic'):
            validate_source_payload_zero('The TCP '+noun+' carries zero payload bytes.',e)
            validate_source_payload_zero('The TCP '+noun+' shows no data transfer.',e)
        validate_source_payload_zero('The source has no data transfer confirmed at the receiver.',e)
        with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
            validate_source_payload_zero('The capture has no data transfer.',e)
        for text in ('The TCP selection carries zero payload,but the whole source has no payload.',
                     'The decoded TCP records carry zero TCP payload,and the whole source has no payload.'):
            with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):validate_source_payload_zero(text,e)

    def test_postposed_and_quantified_decoded_absence_scope(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        for text in ('No payload or teardown is observable among decoded records.',
                     'No payload or teardown appears in the one decoded TCP record.',
                     'No payload is observable in the 1 decoded TCP record.',
                     'The decoded matching rows contain no payload.'):
            validate_source_payload_zero(text,e)
        with self.assertRaisesRegex(ValueError,'unknown transport payload'):
            validate_source_payload_zero('The decoded records contain no payload,but the whole source also has no payload.',e)

    def test_compound_payload_acknowledgement_is_not_payload_absence(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();r=e['packets'][-1];r['tcp']=None;r['udp']=dict(src_port=45000,dst_port=9999,payload_bytes=22);r['protocol']='UDP'
        for text in ('The source has no transport handshake,payload delivery acknowledgement or teardown.',
                     'The source has no payload acknowledgement.'):
            validate_source_payload_zero(text,e)
        with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
            validate_source_payload_zero('The source has no handshake,payload or teardown.',e)

    def test_unknown_record_does_not_prove_global_no_teardown(self):
        from pp_claim_checks import validate_unknown_transport_absence
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        for text in ('No teardown or later records exist in this capture.',
                     'No reset was captured.',
                     'The decoded records show no reset,but the whole source has no teardown observed.'):
            with self.assertRaisesRegex(ValueError,'unknown'):validate_unknown_transport_absence(text,e)
        for text in ('No teardown was observed among the one decoded TCP record.',
                     'Among decoded TCP records,no reset was captured.',
                     'No reset is established for the unknown reverse record.'):
            validate_unknown_transport_absence(text,e)
        validate_unknown_transport_absence('No teardown was captured.',self.setup_only())

    def test_long_unresolved_closure_not_observed_is_not_positive(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        validate_observation_bounds('No FIN or RST appears,and the capture ends on the final client ACK,so how these sessions closed,or whether they were still open,is not observed.',e)
        with self.assertRaisesRegex(ValueError,'session close'):
            validate_observation_bounds('How these sessions closed is not observed,but the connection ended.',e)

    def test_comparison_scope_cannot_exclude_other_changed_fields(self):
        from pp_claim_checks import validate_comparison_scope
        from pp_investigation_tools import EvidenceWorkspace
        from pp_service_evidence import compare_service
        with tempfile.TemporaryDirectory() as folder:
            _,a=depth_tests.capture(folder,'before.pcap',.015);_,b=depth_tests.capture(folder,'after.pcap',.215)
            ctx=EvidenceWorkspace(b,'Compare').validation_context();r=compare_service(a,b)
            r.update(id=b['capture']['sha256']+':a0123456789abcdef',kind='case_comparison');ctx['additional_records'].append(r)
            for text in ('The only measured change is a 0.2 s reply interval.',
                         'The change is confined to timing.',
                         'The sources differ only in requested path and observed interval.',
                         'These captures are differing only in latency.',
                         'No other saved exchange changed.'):
                with self.assertRaisesRegex(ValueError,'all-field equality'):validate_comparison_scope({'recommendations':[{'rationale':text}]},ctx)
            for text in ('The main measured difference is a 0.2 s reply interval.',
                         'Counts match in these metrics,while the request-to-response interval differs.',
                         'The named count metrics differ only in their values.',
                         'Whether the sources differ only in timing is unknown.',
                         'This does not establish that the only measured change is latency.'):
                validate_comparison_scope({'summary':text},ctx)

    def test_temporal_offsets_keep_byte_provenance_rules(self):
        from pp_investigation_contract import validate_source_offset_prose
        for text in ('The window ends at offset 0.0 seconds.','Source offset 4 ms is relative time.','Time offsets are 3 microseconds.'):
            validate_source_offset_prose({'summary':text})
        for text in ('Byte offset 4 seconds.','File offset 4.','Offset 40.','Source offset 128 bytes.'):
            with self.assertRaisesRegex(ValueError,'byte offsets'):validate_source_offset_prose({'summary':text})

    def test_named_record_zero_scope_does_not_expire_or_leak(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        text='P1 is the original SYN with source port 44000 and destination port 8080, sequence field 100 and a captured transport header, with zero payload bytes.'
        validate_source_payload_zero(text,e)
        with self.assertRaisesRegex(ValueError,'unknown transport payload'):
            validate_source_payload_zero(text+',and the whole source has no payload.',e)
        changed=copy.deepcopy(e);changed['packets'][0]['tcp']['payload_bytes']=7
        with self.assertRaisesRegex(ValueError,'named original'):validate_source_payload_zero(text,changed)
        changed['packets'][0]['tcp']=None;changed['packets'][0]['status']='malformed'
        with self.assertRaisesRegex(ValueError,'named original'):validate_source_payload_zero(text,changed)

    def test_postposed_protocol_scope_and_independent_global_claim(self):
        from pp_claim_checks import validate_source_payload_zero
        e=self.mixed_syn_cadence()
        for text in ('No payload appears in the TCP records.','No payload or reset occurs across those eight TCP packets.'):
            validate_source_payload_zero(text,e)
        with self.assertRaisesRegex(ValueError,'whole-source zero-payload'):
            validate_source_payload_zero('No payload appears in the TCP records,but the whole capture also has no payload.',e)

    def test_udp_payload_and_layer_lengths_changed_values(self):
        from pp_semantics import validate_semantic_wording
        for n in (13,31):
            e={'packets':[dict(id='a'*64+':p3',status='decoded',captured_bytes=n+42,wire_bytes=n+42,ipv4=dict(total_bytes=n+28),udp=dict(length=n+8,payload_bytes=n),payload=dict(length=n))]}
            for text in (f'P3 is a {n}-byte UDP datagram.',f'A {n}-byte IPv4 packet.',f'A {n}-byte frame.'):
                with self.assertRaisesRegex(ValueError,'payload length'):validate_semantic_wording(text,'pcap',e)
            for text in (f'A {n+8}-byte UDP datagram.',f'A {n+28}-byte IPv4 packet.',f'A {n+42}-byte frame.',f'The UDP datagram has {n} payload bytes.',f'Not a {n}-byte UDP datagram.'):
                validate_semantic_wording(text,'pcap',e)
            # A legitimate whole-layer size can equal another member's payload.
            other=copy.deepcopy(e['packets'][0]);other['id']='a'*64+':p4';other['payload']['length']=n+8;other['udp']['payload_bytes']=n+8
            e['packets'].append(other);validate_semantic_wording(f'P3 is a {n+8}-byte UDP datagram.','pcap',e)

    def test_transport_decode_status_not_application_interpretation(self):
        from pp_semantics import validate_semantic_wording
        e={'packets':[dict(id='a'*64+':p9',status='decoded',udp=dict(payload_bytes=13,length=21),ipv4={})]}
        for text in ('An undecoded UDP datagram.','The malformed UDP record was retained.','A truncated UDP packet.'):
            with self.assertRaisesRegex(ValueError,'transport records are decoded'):validate_semantic_wording(text,'pcap',e)
        for text in ('UDP headers are decoded, application content is not interpreted.','No malformed UDP record is reported.','An undecoded application protocol is possible.','All records decoded without unsupported, malformed or truncated records.'):
            validate_semantic_wording(text,'pcap',e)
        partial=copy.deepcopy(e);partial['packets'][0]['status']='malformed'
        validate_semantic_wording('A malformed UDP record.','pcap',partial)

    def test_future_capture_is_not_historical_recovery(self):
        from pp_semantics import validate_semantic_wording
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        for text in ('A new attempt could show what the reverse frame actually carried.','An additional capture could classify it.'):
            with self.assertRaisesRegex(ValueError,'earlier incomplete frame'):validate_semantic_wording(text,'pcap',e)
        for text in ('A new attempt could show current service behaviour, not what the historical frame carried.',
                     'A new capture cannot reveal what the original record carried.',
                     'An existing fuller original could help, if available.'):
            validate_semantic_wording(text,'pcap',e)

    def test_udp_receipt_verbs_preserve_observed_response(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only();e['packets'][0]['tcp']=None;e['packets'][0]['udp']={};e['packets'][1]['tcp']=None;e['packets'][1]['udp']=dict(payload_bytes=3)
        for verb in ('received','receives','gets','got','obtained'):
            with self.assertRaisesRegex(ValueError,'UDP response'):validate_observation_bounds('The client '+verb+' a DNS NOERROR answer.',e)
        for text in ('The client may have received the reply.','A reply addressed to the client was captured.','Whether the client got a reply is unknown.'):
            validate_observation_bounds(text,e)

    def test_host_reached_services_is_not_unanswered_arrival(self):
        from pp_claim_checks import validate_unanswered_syn_arrival
        e=self.mixed_syn_cadence()
        for text in ('One host reached eight different services.','The client reached the service.'):
            with self.assertRaisesRegex(ValueError,'endpoint arrival'):validate_unanswered_syn_arrival(text,e)
        for text in ('One host sent SYNs addressed to eight services.','It is unknown whether the host reached the service.','The host may have reached the service.'):
            validate_unanswered_syn_arrival(text,e)

    def test_zero_payload_member_count_requires_known_complete_lengths(self):
        from pp_claim_checks import validate_grounding
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');w.summarize_connections();ctx=w.validation_context()
        aggregate=next(r for r in ctx['additional_records'] if 'tcp_segments' in r)
        field='tcp_segments.payload_bearing_record_count'
        row=dict(text='All TCP records have zero payload.',references=[aggregate['id']],support=[dict(reference=aggregate['id'],field=field,value=0)])
        validate_grounding({'observations':[row]},ctx,required=True)
        aggregate['tcp_segments']['payload_length_available']=False
        with self.assertRaisesRegex(ValueError,'whole-set zero-payload'):validate_grounding({'observations':[row]},ctx,required=True)
        aggregate['tcp_segments']['payload_length_available']=True;row['support'][0]['field']='tcp_segments.payload_ack_bearing_record_count'
        with self.assertRaises(ValueError):validate_grounding({'observations':[row]},ctx,required=True)

    def test_process_source_ports_use_complete_source_qualified_members(self):
        from pp_claim_checks import validate_relational_support
        from pp_investigation_tools import EvidenceWorkspace
        from pp_context import reference_registry
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');w.inspect_tcp_exchanges();ctx=w.validation_context()
        a=next(r for r in ctx['additional_records'] if 'exchanges' in r)
        a['segment_facts'].pop('syn_source_port_min');a['segment_facts'].pop('syn_source_port_max')
        row=dict(text='Get records from 10.77.0.20 (process that opened source ports 44000-44000).',references=[a['id']])
        validate_relational_support(row,reference_registry(ctx),ctx)
        a['member_numbers_omitted']=1
        with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,reference_registry(ctx),ctx)
        a['member_numbers_omitted']=0;row['text']=row['text'].replace('10.77.0.20','10.77.0.30')
        with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,reference_registry(ctx),ctx)

    def test_plural_initiator_subject_uses_filtered_port_bounds(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();w=EvidenceWorkspace(e,'Inspect');w.inspect_tcp_exchanges();ctx=w.validation_context()
        a=next(r for r in ctx['additional_records'] if 'exchanges' in r)
        for subject in ('SYN','SYNs','SYN records','initiators','clients'):
            row=dict(text='The '+subject+' use source ports 44000-44000.',references=[a['id']])
            validate_relational_support(row,reference_registry(ctx),ctx)
            row['text']=row['text'].replace('44000-44000','44000-44001')
            with self.assertRaisesRegex(ValueError,'source-port range'):validate_relational_support(row,reference_registry(ctx),ctx)

    def test_enumerated_unknown_record_absence_keeps_grammatical_scope(self):
        from pp_claim_checks import validate_unknown_transport_absence
        e=self.setup_only();e['packets'][-1]['status']='malformed';e['packets'][-1]['tcp']=None
        for text in ('No stream data, teardown, or application evidence exists in this file.',
                     'No payload, reset, or ACK appears in the source.',
                     'Among decoded records no reset appears,but no payload or teardown exists in the whole file.'):
            with self.assertRaisesRegex(ValueError,'Unknown|unknown'):validate_unknown_transport_absence(text,e)
        for text in ('Among decoded records no stream data, teardown, or application evidence exists.',
                     'No payload, reset, or ACK appears among decoded records.',
                     'No validated evidence of teardown exists for the unknown record.',
                     'It is unknown whether any payload or teardown exists in that record.'):
            validate_unknown_transport_absence(text,e)
        validate_unknown_transport_absence('No payload or teardown exists in this source.',self.setup_only())

    def identity_wire_answer(self,workspace):
        from assessment_fixtures import stub_answer
        answer=stub_answer(workspace.context)|dict(schema_version='4.0',kind='investigation')
        answer['observations']=[dict(text='The original packet identifies its flow.',references=['p1'],
            support=[dict(reference='p1',field='flow_id',value=workspace.context['packets'][0]['flow_id'])])]
        return answer

    def test_wire_identity_scalars_round_trip_without_rewriting_model_draft(self):
        import json
        from pp_investigation_tools import EvidenceWorkspace
        from pp_investigation_contract import validate_live_final,validate_saved_assessment
        w=EvidenceWorkspace(self.setup_only(),'Inspect');answer=self.identity_wire_answer(w)
        alias=answer['observations'][0]['support'][0]['value'];canonical=w.supplied['p1']['flow_id']
        answer['measurements']=[dict(reference='p1',field='flow_id',value=alias)]
        before=copy.deepcopy(w.supplied)
        checked,original=validate_live_final(json.dumps(answer),w)
        self.assertEqual(checked['observations'][0]['support'][0]['value'],canonical)
        self.assertEqual(checked['measurements'][0]['value'],canonical)
        self.assertEqual(original['observations'][0]['support'][0]['value'],alias)
        self.assertEqual(w.supplied,before)
        validate_saved_assessment(checked,w.evidence,w.validation_context())

    def test_wire_identity_resolution_does_not_coerce_other_scalar_values(self):
        import json
        from pp_investigation_tools import EvidenceWorkspace
        from pp_investigation_contract import validate_live_final,canonical_scalar_value
        w=EvidenceWorkspace(self.setup_only(),'Inspect');answer=self.identity_wire_answer(w)
        for field,value in (('flow_id','f999'),('flow_id','b'*64+':f1'),('tcp.flags','2'),('tcp.flags',True),('ipv4.src','f1')):
            wrong=copy.deepcopy(answer);wrong['observations'][0]['support']=[dict(reference='p1',field=field,value=value)]
            with self.assertRaisesRegex(ValueError,'exact supplied'):validate_live_final(json.dumps(wrong),w)
        self.assertEqual(canonical_scalar_value('p1','missing.path','f1',w),'f1')
        w.supplied['p1']['ordinary_text']='f1'
        self.assertEqual(canonical_scalar_value('p1','ordinary_text','f1',w),'f1')

    def test_visible_identity_value_does_not_supply_flow_citation_authority(self):
        import json
        from pp_investigation_tools import EvidenceWorkspace
        from pp_investigation_contract import validate_live_final
        w=EvidenceWorkspace(self.setup_only(),'Inspect');w.supplied.pop('f1');w._selection()
        answer=self.identity_wire_answer(w)
        checked,_=validate_live_final(json.dumps(answer),w)
        self.assertEqual(checked['observations'][0]['support'][0]['value'],w.supplied['p1']['flow_id'])
        self.assertNotIn('f1',w.supplied)
        answer['observations'][0]['references'].append('f1')
        with self.assertRaisesRegex(ValueError,'not supplied'):validate_live_final(json.dumps(answer),w)

    def test_correction_diagnostics_use_the_same_identity_wire_contract(self):
        import json
        from pp_investigation_tools import EvidenceWorkspace
        from pp_investigator import correction_diagnostics
        w=EvidenceWorkspace(self.setup_only(),'Inspect');answer=self.identity_wire_answer(w)
        self.assertFalse(any('flow_id' in hint for hint in correction_diagnostics(json.dumps(answer),w)))
        answer['observations'][0]['support'][0]['value']='f999'
        self.assertTrue(any('flow_id' in hint for hint in correction_diagnostics(json.dumps(answer),w)))

    def test_counted_zero_decode_status_lists_remain_negative(self):
        from pp_semantics import validate_decode_status_wording
        e=self.setup_only()
        for text in ('Both records are decoded,with zero unsupported,malformed or truncated packets.',
                     'There are 0 malformed and 0 truncated records.',
                     'Zero truncated,malformed or unsupported records were retained.',
                     'All packets decoded without malformed or truncated records.',
                     'Malformed record count is zero.','Truncated packets are 0.'):
            validate_decode_status_wording(text,e)

    def test_zero_status_list_does_not_hide_later_affirmative_status(self):
        from pp_semantics import validate_decode_status_wording
        e=self.setup_only()
        for text in ('No malformed records,and the truncated packet was retained.',
                     'Zero unsupported records,but one malformed packet exists.',
                     'There are 0 malformed records,however a truncated frame was captured.',
                     'A malformed packet was saved with zero application errors.'):
            with self.assertRaisesRegex(ValueError,'transport records are decoded'):validate_decode_status_wording(text,e)

    def test_long_negated_reporting_verb_keeps_session_state_unknown(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('It does not show that the client received or acted on the response,that the session closed,or why the traffic occurred.',
                     'The source does not establish how the client processed the response or that the connection ended.'):
            validate_observation_bounds(text,e)
            with self.assertRaisesRegex(ValueError,'session close'):validate_observation_bounds(text+' The session closed.',e)
        with self.assertRaisesRegex(ValueError,'session close'):
            validate_observation_bounds('It does not show application success,but the connection ended.',e)

    def test_active_ack_subject_is_not_the_carried_by_data_origin(self):
        from pp_claim_checks import validate_relational_support
        from pp_context import reference_registry
        from pp_investigation_tools import EvidenceWorkspace
        e=self.exchange(client_ack=True);w=EvidenceWorkspace(e,'Inspect');ctx=w.validation_context();registry=reference_registry(ctx)
        refs=[p['id'] for p in e['packets']]
        for text in ('p2 acknowledges the bytes carried by p1,and the response p3 follows later.',
                     'The bytes carried by p1 are acknowledged by p2.',
                     'p2 directly acknowledges request bytes,and p4 acknowledges response bytes.',
                     'p3 acknowledges the bytes carried by p1.'):
            validate_relational_support(dict(text=text,references=refs),registry,ctx)
        for text in ('p1 acknowledges the bytes carried by p3.',
                     'The response bytes are acknowledged by p1.'):
            with self.assertRaisesRegex(ValueError,'Each named byte-ACK'):
                validate_relational_support(dict(text=text,references=refs),registry,ctx)

    def test_unobserved_teardown_would_sit_outside_is_not_established(self):
        from pp_claim_checks import validate_observation_bounds
        e=self.setup_only()
        for text in ('Request content and teardown would sit beyond this window.',
                     'The teardown occurs outside the saved window.',
                     'Teardown was beyond that observation period.'):
            with self.assertRaisesRegex(ValueError,'teardown happened outside'):validate_observation_bounds(text,e)
        for text in ('Teardown could occur beyond this window or could have been missed within it.',
                     'Whether teardown would sit beyond this window is unknown.',
                     'The source ends at its final ACK;teardown remains unobserved.'):
            validate_observation_bounds(text,e)

    def test_named_later_ack_recheck_keeps_endpoint_time_tuple_and_restart_bounds(self):
        from pp_tcp_relationships import tcp_segment_facts
        for seq in (100,2**32-3):
            e=self.exchange(seq=seq,client_ack=True);rows=e['packets'];target=rows[2]['id']
            relation=tcp_segment_facts(rows,ack_reference=target)['payload_ack_relations'][0]
            self.assertEqual(relation['candidate_ack_reference'],target)
            self.assertEqual(relation['candidate_ack_value'],(seq+7)%2**32)
            for change in ('wrong_endpoint','earlier','wrong_tuple','new_syn'):
                altered=copy.deepcopy(rows)
                if change=='wrong_endpoint':altered[2]['tcp']['acknowledgement']=(seq+8)%2**32
                elif change=='earlier':altered[2]['timestamp']='99'
                elif change=='wrong_tuple':altered[2]['tcp']['src_port']=9090
                else:
                    restart=copy.deepcopy(altered[0]);restart['packet']=5;restart['id']=e['capture']['sha256']+':p5'
                    restart['timestamp']='100.0015';restart['tcp'].update(flags=2,sequence=900,payload_bytes=0)
                    altered.append(restart)
                selected=tcp_segment_facts(altered,ack_reference=target)['payload_ack_relations']
                original=next(r for r in selected if r['data_reference']==rows[0]['id'])
                self.assertIsNone(original['candidate_ack_reference'],change)

    def test_comparison_byte_equality_premises_use_actual_named_operands(self):
        from pp_claim_checks import validate_comparison_scope
        from pp_investigation_tools import EvidenceWorkspace
        ctx=EvidenceWorkspace(self.setup_only(),'Compare').validation_context()
        ref=self.setup_only()['capture']['sha256']+':a0123456789abcdef'
        pair=dict(id=ref,baseline=dict(frame_bytes=291),comparison=dict(frame_bytes=307),delta=dict(frame_bytes=16))
        ctx['additional_records'].append(pair)
        wrong=('Equal request counts and byte totals do not make the two workloads identical.',
               'Both sources have equal frame-byte totals.',
               'The frame-byte totals match.',
               'Matching byte totals do not establish identical workloads.',
               'The sources have the same bytes.')
        for text in wrong:
            for section in ('summary','interpretation','observations','recommendations','uncertainty','coverage'):
                if section=='observations':value={section:[dict(text=text,references=[ref])]}
                elif section=='recommendations':value={section:[dict(rationale=text,references=[ref])]}
                elif section=='uncertainty':value={section:[text]}
                elif section=='coverage':value={section:dict(limitations=[text])}
                else:value={section:text}
                with self.subTest(text=text,section=section),self.assertRaisesRegex(ValueError,'different baseline.frame_bytes'):
                    validate_comparison_scope(value,ctx)
        for before,after in ((999,1003),(307,291)):
            pair['baseline']['frame_bytes']=before;pair['comparison']['frame_bytes']=after
            with self.assertRaisesRegex(ValueError,'different baseline.frame_bytes'):
                validate_comparison_scope({'summary':wrong[0]},ctx)
        pair['baseline']['frame_bytes']=pair['comparison']['frame_bytes']=436
        for text in wrong:validate_comparison_scope({'summary':text},ctx)

    def test_comparison_byte_equality_keeps_hypothetical_negative_and_payload_scope(self):
        from pp_claim_checks import validate_comparison_scope
        from pp_investigation_tools import EvidenceWorkspace
        ctx=EvidenceWorkspace(self.setup_only(),'Compare').validation_context()
        ctx['additional_records'].append(dict(id='a'*64+':a0123456789abcdef',baseline=dict(frame_bytes=291),comparison=dict(frame_bytes=307),delta=dict(frame_bytes=16)))
        for text in ('If equal byte totals were observed,they would not prove identical workloads.',
                     'Whether byte totals match is unknown.',
                     'The byte totals are not equal.',
                     'These are not equal frame-byte totals.',
                     'We cannot assume equal byte totals.',
                     'Equal payload byte totals do not establish equal frame lengths.',
                     'Frame-byte totals differ:291 versus307.'):
            with self.subTest(text=text):validate_comparison_scope({'summary':text},ctx)
        with self.assertRaisesRegex(ValueError,'different baseline.frame_bytes'):
            validate_comparison_scope({'summary':'Whether counts match is unknown,but the byte totals match.'},ctx)

    def test_comparison_byte_equality_uses_cited_pair_not_an_arbitrary_first_pair(self):
        from pp_claim_checks import validate_comparison_scope
        from pp_investigation_tools import EvidenceWorkspace
        ctx=EvidenceWorkspace(self.setup_only(),'Compare').validation_context()
        one=dict(id='a'*64+':a0123456789abcdef',baseline=dict(frame_bytes=291),comparison=dict(frame_bytes=307),delta=dict(frame_bytes=16))
        two=dict(id='a'*64+':a1123456789abcdef',baseline=dict(frame_bytes=400),comparison=dict(frame_bytes=400),delta=dict(frame_bytes=0))
        ctx['additional_records'].extend([one,two])
        def row(ref):return dict(observations=[dict(text='The frame-byte totals match.',references=[ref])])
        validate_comparison_scope(row(two['id']),ctx)
        with self.assertRaisesRegex(ValueError,'different baseline.frame_bytes'):validate_comparison_scope(row(one['id']),ctx)
        ctx['additional_records'].reverse();validate_comparison_scope(row(two['id']),ctx)
        # No explicit pair and several available pairs: no invented selection.
        validate_comparison_scope({'summary':'The frame-byte totals match.'},ctx)

    def test_tcp_zero_proof_uses_the_same_explicit_selection_scope(self):
        from pp_claim_checks import validate_grounding,validate_claim_language
        from pp_investigation_tools import EvidenceWorkspace
        e=self.mixed_syn_cadence();w=EvidenceWorkspace(e,'Inspect')
        ctx=w.validation_context();ref=w.supplied[w.context['connections']['id']]['id']
        def value(text):return dict(observations=[dict(text=text,references=[ref],support=[dict(reference=ref,field='tcp_segments.payload_bytes_total',value=0)])])
        for text in ('Every record in this TCP selection carries zero payload bytes.',
                     'All TCP records have zero payload.',
                     'All records in the TCP subset have no payload.',
                     'Every TCP segment has zero TCP payload.'):
            validate_grounding(value(text),ctx,required=True);validate_claim_language(value(text),e)
        for text in ('Every record in the source carries zero payload bytes.',
                     'All UDP records have zero payload.',
                     'All records have no payload.'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'Observation 1:.*whole-set zero'):
                validate_grounding(value(text),ctx,required=True)
        changed=copy.deepcopy(ctx)
        aggregate=next(r for r in changed['additional_records'] if r['id']==ref)
        aggregate['tcp_segments']['payload_length_available']=False
        with self.assertRaisesRegex(ValueError,'whole-set zero'):
            validate_grounding(value('All TCP records have zero payload.'),changed,required=True)

    def test_rather_than_lifetime_negative_does_not_hide_an_independent_positive(self):
        from pp_claim_checks import validate_claim_language
        e=self.setup_only()
        for proof in ('showing','proving','establishing','confirming','demonstrating'):
            text='No FIN or reset was observed,which leaves teardown unobserved rather than '+proof+' a short-lived connection.'
            validate_claim_language({'interpretation':text},e)
            for join in (',but the connection was short-lived.',',and the connection was short-lived.'):
                with self.assertRaisesRegex(ValueError,'short observation window'):
                    validate_claim_language({'interpretation':text.rstrip('.')+join},e)

    def test_singular_exchange_identity_fields_are_available_without_choosing_first(self):
        from pp_tcp_relationships import analyse_tcp_exchanges,scalar_paths
        from pp_investigation_tools import EvidenceWorkspace
        e=self.setup_only();facts=analyse_tcp_exchanges(e)
        self.assertEqual(facts['syn_reference'],e['packets'][0]['id'])
        self.assertEqual(facts['candidate_reply_reference'],e['packets'][1]['id'])
        for field in ('syn_reference','candidate_reply_reference','final_ack_reference'):
            self.assertIn(field,scalar_paths(facts))
        result=EvidenceWorkspace(e,'Inspect').inspect_tcp_exchanges()
        self.assertIn('syn_reference',result['measurement_fields'][result['records'][0]['id']])
        lone=copy.deepcopy(e);lone['packets']=lone['packets'][:1]
        f=analyse_tcp_exchanges(lone);self.assertIsNone(f['candidate_reply_reference'])
        self.assertNotIn('candidate_reply_reference',scalar_paths(f))
        many=copy.deepcopy(e)
        for r in copy.deepcopy(e['packets']):
            r['packet']+=3;r['id']=e['capture']['sha256']+':p'+str(r['packet'])
            r['timestamp']=str(float(r['timestamp'])+1)
            if r['ipv4']['src']=='10.77.0.20':r['tcp']['src_port']+=1
            else:r['tcp']['dst_port']+=1
            many['packets'].append(r)
        f=analyse_tcp_exchanges(many)
        for field in ('syn_reference','candidate_reply_reference','final_ack_reference'):
            self.assertIsNone(f[field]);self.assertNotIn(field,scalar_paths(f))

if __name__=='__main__':unittest.main()
