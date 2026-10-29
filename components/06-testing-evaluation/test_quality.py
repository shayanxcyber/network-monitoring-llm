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
from pp_investigation_contract import validate_final,validate_saved_assessment
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
    def test_later_acknowledging_data_does_not_make_handshake_ambiguous(self):
        e=copy.deepcopy(self.evidence['Q03']);ack=copy.deepcopy(e['packets'][2])
        ack.update(id=e['capture']['sha256']+':p4',packet=4,timestamp=str(float(ack['timestamp'])+.04))
        ack['tcp'].update(flags=0x18,payload_bytes=11);e['packets'].append(ack)
        r=analyse_tcp_exchanges(e)
        self.assertEqual(r['syns_with_sequence_matched_handshake'],1)
        self.assertEqual(r['ambiguous_syn_records'],0)
        self.assertEqual(r['exchanges'][0]['final_ack_reference'],e['packets'][2]['id'])
    def test_piggybacked_first_ack_can_complete_handshake(self):
        e=copy.deepcopy(self.evidence['Q03']);e['packets'][2]['tcp'].update(flags=0x18,payload_bytes=11)
        self.assertEqual(analyse_tcp_exchanges(e)['syns_with_sequence_matched_handshake'],1)
    def test_equal_time_final_ack_candidates_remain_ambiguous(self):
        e=copy.deepcopy(self.evidence['Q03']);ack=copy.deepcopy(e['packets'][2])
        ack.update(id=e['capture']['sha256']+':p4',packet=4);e['packets'].append(ack)
        r=analyse_tcp_exchanges(e);self.assertEqual(r['ambiguous_syn_records'],1)
        self.assertEqual(r['syns_with_sequence_matched_handshake'],0)
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
    def test_explicit_exchange_directions_and_interval_origins(self):
        e=self.evidence['Q03'];r=analyse_tcp_exchanges(e)['exchanges'][0]
        self.assertEqual(r['initiator']['address'],e['packets'][0]['ipv4']['src'])
        self.assertEqual(r['responder_service']['address'],e['packets'][0]['ipv4']['dst'])
        self.assertEqual(r['reply_direction']['source'],r['responder_service']['address'])
        self.assertEqual(r['final_ack_direction']['source'],r['initiator']['address'])
        self.assertAlmostEqual(r['handshake_elapsed_seconds'],r['reply_delay_seconds']+r['final_ack_delay_seconds'])
    def offset_answer(self,w):
        answer=stub_answer(w.context)|{'schema_version':'4.0','kind':'investigation'}
        answer['coverage']['status']='complete_supported'
        answer['observations']=[{'text':'Original log line l2 retains source provenance.','references':['l2']}]
        return answer
    def test_literal_byte_offset_prose_is_routed_to_checked_measurements(self):
        w=LogWorkspace(self.log,'Inspect provenance.');answer=self.offset_answer(w)
        for text in ('l2 has byte offset 999.','Lines l2 and l3 have byte offsets 121 and 191.',
                     'The offsets are 191 and 281.', 'At source offset 191.', 'file_offset: 191'):
            answer['observations'][0]['text']=text
            with self.assertRaisesRegex(ValueError,'Literal source byte offsets'):validate_final(json.dumps(answer),w)
    def test_original_byte_offset_measurement_is_checked_exactly(self):
        w=LogWorkspace(self.log,'Inspect provenance.');answer=self.offset_answer(w)
        offset=self.log['log_records'][0]['byte_offset']
        answer['measurements']=[{'reference':'l2','field':'byte_offset','value':offset}]
        accepted,_=validate_final(json.dumps(answer),w);self.assertEqual(accepted['measurements'][0]['value'],offset)
        answer['measurements'][0]['value']+=1
        with self.assertRaises(ValueError):validate_final(json.dumps(answer),w)

    def test_local_aggregate_selectors_preserve_canonical_identity_and_scope(self):
        w=EvidenceWorkspace(self.evidence['Q03'],'Inspect.')
        first=w.context['connections']['id'];self.assertEqual(first,'a1')
        result=w.inspect_tcp_exchanges()['records'][0];self.assertEqual(result['id'],'a2')
        self.assertEqual(w.inspect_tcp_exchanges()['records'][0]['id'],'a2')
        canonical=w.supplied['a2']['id'];self.assertTrue(canonical.startswith(w.digest+':a'))
        answer=stub_answer(w.context)|{'schema_version':'3.0'}
        answer['observations']=[{'text':'Supplied relationship.','references':['a2']}]
        accepted,_=validate_final(json.dumps(answer),w)
        self.assertEqual(accepted['observations'][0]['references'],[canonical])
        answer['observations'][0]['references']=['a999']
        with self.assertRaises(ValueError):validate_final(json.dumps(answer),w)
        answer['observations'][0]['references']=[canonical.split(':')[-1]]
        validate_final(json.dumps(answer),w)

    def test_coverage_disclosure_updates_after_retrieval_not_interpretation(self):
        w=EvidenceWorkspace(self.evidence['Q05'],'Inspect tail.')
        self.assertEqual(w.context['coverage_disclosure']['required_status'],'partial')
        missing=[n for n in w.packets if 'p'+str(n) not in w.supplied]
        while missing:
            result=w.get_packets(missing[:16]);self.assertTrue(result['ok']);missing=missing[16:]
        # Flow detail can still be omitted; disclosure must match validator,
        # not assume packet retrieval alone means every flow was supplied.
        from pp_context import required_coverage_status
        self.assertEqual(result['coverage_disclosure']['required_status'],required_coverage_status(w.evidence,w.validation_context()))
        self.assertEqual(result['coverage_disclosure']['context_selection'],w.context['context_selection'])

    def test_log_model_context_has_records_not_compatibility_packet_zeros(self):
        w=LogWorkspace(self.log,'Inspect.')
        self.assertNotIn('packet_count',w.context['capture'])
        self.assertNotIn('decoded_packets',w.context['coverage'])
        self.assertEqual(self.log['capture']['packet_count'],0)
        self.assertEqual(w.context['coverage_disclosure']['required_status'],'complete_supported')

    def test_tshark_advisory_field_lint_not_arbitrary_code_execution(self):
        from pp_investigation_contract import validate_advisory_fields
        for field in ('tcp.src_port','tcp.dst_port','udp.src_port','tcp.payload_bytes'):
            with self.assertRaisesRegex(ValueError,'TShark fields'):
                validate_advisory_fields({'code_suggestions':[{'language':'sh','code':'tshark -r x.pcap -T fields -e '+field}]})
        validate_advisory_fields({'code_suggestions':[{'language':'sh','code':'tshark -r x.pcap -T fields -e tcp.srcport -e tcp.len'}]})
    def test_historical_saved_prose_is_not_retroactively_rejected(self):
        w=LogWorkspace(self.log,'Inspect provenance.');answer=self.offset_answer(w)
        accepted,_=validate_final(json.dumps(answer),w)
        accepted['observations'][0]['text']='Original line l2 has byte offset 999.'
        self.assertEqual(validate_saved_assessment(accepted,self.log,w.validation_context()),accepted)
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
