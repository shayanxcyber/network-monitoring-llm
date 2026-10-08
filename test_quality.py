"""Actual exchange/tool/contract coverage, not external inference accuracy."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import packetpilot
from pp_evidence import analyse_capture
from pp_logs import analyse_log,FIELDS
from pp_investigation_tools import EvidenceWorkspace,validate_tool_arguments,MAX_TOOL_CALLS
from pp_log_tools import LogWorkspace
from pp_investigation_contract import validate_final
from pp_tcp_relationships import analyse_tcp_exchanges,scalar_paths
from quality_cases import quality_cases
from assessment_fixtures import stub_answer
from pp_samples import pcap_bytes


class QualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-quality-');cls.folder=Path(cls.temp.name);cls.evidence={}
        for d in quality_cases():
            p=cls.folder/(d['id']+'.pcap');p.write_bytes(d['raw']);cls.evidence[d['id']]=analyse_capture(p,'scapy')
        e=cls.evidence['Q02'];rows=['\t'.join(FIELDS)]
        for r in e['packets']:
            tcp=r['tcp'];rows.append('\t'.join(map(str,[r['packet'],r['timestamp'],r['wire_bytes'],r['ipv4']['src'],r['ipv4']['dst'],6,tcp['src_port'],tcp['dst_port'],hex(tcp['flags']),'',''])))
        p=cls.folder/'log.tsv';p.write_text('\n'.join(rows)+'\n',encoding='utf-8');cls.log=analyse_log(p)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_single_service_not_reply_ephemeral_breadth(self):
        r=analyse_tcp_exchanges(self.evidence['Q01']);self.assertEqual(r['syn_destination_ports'],[9443]);self.assertEqual(r['syns_with_sequence_matched_reset'],4)
        self.assertEqual(r['syns_without_candidate_reply'],0);self.assertEqual(r['selected_tcp_record_count'],8)
    def test_multi_service_counts(self):
        r=analyse_tcp_exchanges(self.evidence['Q02']);self.assertEqual(r['syn_destination_port_count'],4);self.assertEqual(r['syns_with_candidate_reset'],4)
    def test_roles_come_from_syn_and_exact_three_way_references(self):
        r=analyse_tcp_exchanges(self.evidence['Q03']);e=r['exchanges'][0];self.assertEqual((e['source'],e['destination_port']),('10.77.0.10',9090));self.assertEqual(r['syns_with_sequence_matched_handshake'],1)
        self.assertEqual(len(e['supporting_references']),3);self.assertAlmostEqual(e['reply_delay_seconds'],.04);self.assertAlmostEqual(e['final_ack_delay_seconds'],.05)
    def test_wrong_reply_ack_not_sequence_matched(self):
        e=copy.deepcopy(self.evidence['Q03']);e['packets'][1]['tcp']['acknowledgement']+=99;r=analyse_tcp_exchanges(e)
        self.assertEqual(r['syns_with_sequence_matched_handshake'],0);self.assertFalse(r['exchanges'][0]['reply_acknowledgement_matches_syn'])
    def test_wrong_final_ack_not_handshake(self):
        e=copy.deepcopy(self.evidence['Q03']);e['packets'][2]['tcp']['acknowledgement']+=1;r=analyse_tcp_exchanges(e);self.assertEqual(r['syns_with_candidate_handshake'],0)
    def test_partial_records_remain_unknown(self):
        r=analyse_tcp_exchanges(self.evidence['Q04']);self.assertEqual(r['unknown_input_record_count'],1);self.assertEqual(r['syns_without_candidate_reply'],2)
        self.assertIn('undecodable',r['limits'][1]);self.assertEqual(r['syn_record_count'],2)
    def test_tail_can_be_retrieved_and_relationships_cover_it(self):
        w=EvidenceWorkspace(self.evidence['Q05'],'Inspect TCP.');self.assertNotIn('p97',w.supplied);self.assertTrue(w.get_packets([97,98,99])['ok'])
        r=w.inspect_tcp_exchanges()['records'][0];self.assertEqual(r['syns_with_sequence_matched_handshake'],1);self.assertEqual(r['syn_destination_ports'],[7070])
        self.assertEqual(r['selected_tcp_record_count'],3)
    def test_log_relationships_never_invent_sequence_verification(self):
        w=LogWorkspace(self.log,'Inspect.');r=w.inspect_tcp_exchanges()['records'][0]
        self.assertEqual(r['syns_with_candidate_reset'],4);self.assertEqual(r['syns_with_sequence_matched_reset'],0);self.assertFalse(r['sequence_fields_available'])
        self.assertTrue(all(x['syn_reference'].startswith('l') for x in r['exchanges']));self.assertTrue(all(x['reply_acknowledgement_matches_syn'] is None for x in r['exchanges']))
    def test_scalar_catalog_paths_are_actual_values(self):
        w=LogWorkspace(self.log,'Inspect.');self.assertIn('record_count',w.context['measurement_fields']['connections']);self.assertNotIn('packet_count',w.context['measurement_fields']['connections'])
        self.assertEqual(scalar_paths({'x':1,'d':{'v':False},'list':[1],'nothing':None}),['x','d.v'])
    def test_aggregate_reference_validated_and_copied_measurement(self):
        w=EvidenceWorkspace(self.evidence['Q03'],'Inspect.');r=w.inspect_tcp_exchanges()['records'][0];answer=stub_answer(w.context)|{'schema_version':'3.0'}
        answer['observations'][0]['references']=[r['id']];answer['measurements']=[{'reference':r['id'],'field':'syns_with_sequence_matched_handshake','value':1}]
        accepted,_=validate_final(json.dumps(answer),w);self.assertTrue(accepted['observations'][0]['references'][0].startswith(w.digest))
        answer['measurements'][0]['value']=2
        with self.assertRaises(ValueError):validate_final(json.dumps(answer),w)
    def test_focus_recalculates_relationships_without_model_claims(self):
        w=EvidenceWorkspace(self.evidence['Q03'],'Inspect.');w.inspect_tcp_exchanges(source='10.77.0.10');state={'capture_sha256':w.digest,'evidence_focus':w.focus_state()}
        other=EvidenceWorkspace(self.evidence['Q03'],'Follow up.');other.restore_focus(state);self.assertEqual(other.trace,[])
        self.assertTrue(any(x.get('analysis_version') for x in other.context['previously_inspected_evidence']))
    def test_log_focus_recalculates_relationships(self):
        w=LogWorkspace(self.log,'Inspect.');w.inspect_tcp_exchanges();other=LogWorkspace(self.log,'Followup.');other.restore_focus({'capture_sha256':w.digest,'evidence_focus':w.focus_state()})
        self.assertEqual(other.trace,[]);self.assertTrue(any(x.get('analysis_version') for x in other.context['previously_inspected_evidence']))
    def test_filter_is_initiator_direction_and_service(self):
        r=analyse_tcp_exchanges(self.evidence['Q02'],'10.77.0.91','10.77.0.92',445);self.assertEqual(r['syn_record_count'],1);self.assertEqual(r['selected_tcp_record_count'],2)
    def test_retransmitted_same_syn_remains_ambiguous(self):
        e=copy.deepcopy(self.evidence['Q01']);e['packets'][2]['tcp'].update(src_port=53000,sequence=100);r=analyse_tcp_exchanges(e)
        self.assertGreaterEqual(r['ambiguous_syn_records'],2);self.assertLess(r['syns_with_sequence_matched_reset'],4)
    def test_same_timestamp_order_does_not_prove_matching(self):
        e=copy.deepcopy(self.evidence['Q03']);e['packets'][1]['timestamp']=e['packets'][0]['timestamp'];r=analyse_tcp_exchanges(e)
        self.assertEqual(r['ambiguous_syn_records'],1);self.assertEqual(r['syns_with_sequence_matched_handshake'],0)
    def test_raw_arguments_cannot_supply_paths_or_coerced_values(self):
        for raw in ('{"destination_port":true}','{"source":123}','{"path":"/etc/passwd"}','{"destination_port":1,"destination_port":2}'):
            with self.assertRaises(ValueError):validate_tool_arguments('inspect_tcp_exchanges',raw)
        validate_tool_arguments('inspect_tcp_exchanges','{}')
    def test_tool_scope_and_budget_still_apply(self):
        w=EvidenceWorkspace(self.evidence['Q03'],'Inspect.');self.assertFalse(w.inspect_tcp_exchanges(source='8.8.8.8')['ok']);self.assertFalse(w.inspect_tcp_exchanges(destination_port=True)['ok'])
        while len(w.trace)<MAX_TOOL_CALLS:w.inspect_tcp_exchanges()
        self.assertEqual(w.inspect_tcp_exchanges()['error'],'tool_limit')
    def test_details_are_bounded_and_not_all_claims_are_sampled(self):
        e=copy.deepcopy(self.evidence['Q02']);base=e['packets'][0];e['packets']=[]
        for i in range(60):
            r=copy.deepcopy(base);r.update(packet=i+1,id=e['capture']['sha256']+f':p{i+1}',timestamp=str(100+i));r['tcp'].update(src_port=59000+i,dst_port=1000+i);e['packets'].append(r)
        r=analyse_tcp_exchanges(e);self.assertEqual(r['syn_record_count'],60);self.assertEqual(len(r['exchanges']),32);self.assertEqual(r['exchange_details_omitted'],28)

if __name__=='__main__':unittest.main()
