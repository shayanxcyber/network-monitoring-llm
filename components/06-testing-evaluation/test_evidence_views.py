"""Presentation uses calculated original-source data, never model numbers."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import packetpilot
from pp_evidence import analyse_capture
from pp_evidence_views import build_views,record_page
from pp_logs import analyse_log
from pp_investigation_tools import EvidenceWorkspace
from pp_investigation_contract import WorkspaceAnswer, validate_final
from test_logs import log_bytes
from evidence_cases import case_bytes
from investigation_cases import contrasting_cases
from assessment_fixtures import stub_answer

class EvidenceViewsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'source.pcap';self.path.write_bytes(case_bytes()['normal'][0]);self.evidence=analyse_capture(self.path,'scapy')
    def tearDown(self):self.temp.cleanup()
    def source(self,name):self.path.write_bytes(case_bytes()[name][0]);return analyse_capture(self.path,'scapy')
    def test_counts_and_membership_follow_exact_original_records(self):
        e=self.source('mixed-udp');before=json.dumps(e,sort_keys=True);v=build_views(e)
        self.assertEqual(v['coverage']['decoded_records'],9);self.assertEqual(v['coverage']['excluded_records'],0)
        self.assertEqual(sum(r['count'] for r in v['map']['edges']),9);self.assertEqual(len(v['map']['nodes']),3)
        self.assertEqual(sum(r['count'] for r in v['comparison']),9);self.assertEqual(json.dumps(e,sort_keys=True),before)
    def test_partial_capture_retains_useful_observations_and_coverage(self):
        v=build_views(self.source('mixed-arp'));self.assertEqual(v['coverage']['decoded_records'],8);self.assertEqual(v['coverage']['excluded_records'],1);self.assertEqual(v['table']['total_matching'],9)
    def test_bar_counts_syn_headers_not_reply_ephemeral_services(self):
        v=build_views(self.evidence);self.assertEqual(sum(r['count'] for r in v['bar']['data']),3)
        self.assertEqual({r['label'].split(':')[-1] for r in v['bar']['data']},{'80','443'});self.assertIn('not unique',v['limits'][1])
    def test_short_capture_uses_no_artificial_time_series(self):
        v=build_views(self.evidence);self.assertEqual(v['series']['data'],[]);self.assertIsNone(v['series']['bin_seconds']);self.assertTrue(v['series']['reason'])
    def test_composition_keeps_partial_and_udp_original_members(self):
        v=build_views(self.source('mixed-udp'))
        self.assertEqual(sum(r['count'] for r in v['composition']),9)
        udp=next(r for r in v['composition'] if r['protocol']=='UDP')
        self.assertEqual(udp['count'],1);self.assertEqual(len(udp['references']),1)
        v=build_views(self.source('mixed-arp'))
        self.assertEqual(sum(r['count'] for r in v['composition']),v['coverage']['selected_records'])
    def test_filters_apply_before_pagination_with_honest_totals(self):
        e=self.source('mixed-udp');page=record_page(e,protocol='UDP',limit=1)
        self.assertEqual(page['total_matching'],1);self.assertEqual(page['rows'][0]['protocol'],'UDP')
        self.assertEqual(record_page(e,status='missing')['total_matching'],0)
        self.assertEqual(record_page(e,protocol='UDP',offset=1)['rows'],[])
        with self.assertRaises(ValueError):record_page(e,protocol='x'*25)
    def test_original_selection_rejects_cross_source_duplicates_and_fake_ids(self):
        for refs in [['other:p1'],[self.evidence['packets'][0]['id']]*2,[self.evidence['capture']['sha256']+':p9999']]:
            with self.assertRaises(ValueError):build_views(self.evidence,refs)
        ref=self.evidence['packets'][0]['id'];v=build_views(self.evidence,[ref]);self.assertEqual(v['coverage']['selected_records'],1);self.assertEqual(v['timeline'][0]['id'],ref)
    def test_flow_selection_does_not_invent_initiator_direction(self):
        flow=self.evidence['flows'][0];v=build_views(self.evidence,[flow['id']]);self.assertEqual(v['coverage']['selected_records'],flow['packet_count'])
        self.assertGreaterEqual(len(v['comparison']),2)
    def test_sort_search_and_pagination_over_original_rows(self):
        rows=record_page(self.evidence,sort='number',descending=True,limit=2)['rows'];self.assertEqual([r['number'] for r in rows],[9,8])
        self.assertEqual(record_page(self.evidence,query='nonsense')['total_matching'],0)
        with self.assertRaises(ValueError):record_page(self.evidence,limit=1000)
    def test_logs_keep_physical_lines_frame_numbers_units_and_direction(self):
        log=Path(self.temp.name)/'source.tsv';log.write_bytes(log_bytes(20));e=analyse_log(log);v=build_views(e)
        row=v['table']['rows'][0];self.assertEqual(row['number'],2);self.assertEqual(row['source_frame_number'],1)
        self.assertEqual(row['kind'],'log_line');self.assertEqual(row['byte_unit'],'reported frame bytes');self.assertIn(':l2',row['id'])
        self.assertEqual(sum(b['count'] for b in v['series']['data']),21)
        allowed={r['id'] for r in e['log_records']};self.assertTrue(all(set(b['references'])<=allowed for b in v['series']['data']))
    def test_long_series_membership_counts_window_and_protocols(self):
        log=Path(self.temp.name)/'source.tsv';log.write_bytes(log_bytes(40));v=build_views(analyse_log(log))
        self.assertTrue(4<=len(v['series']['data'])<=24);self.assertGreater(v['window']['duration_seconds'],0)
        for b in v['series']['data']:self.assertEqual(b['count'],sum(b['protocols'].values()));self.assertEqual(b['count'],len(b['references']))
    def test_old_answers_default_to_no_views_and_new_vocabulary_is_strict(self):
        w=EvidenceWorkspace(self.evidence,'Inspect.');a=stub_answer(w.context)|{'schema_version':'4.0','kind':'investigation','code_suggestions':[]}
        checked,_=validate_final(json.dumps(a),w);self.assertEqual(checked['views'],[])
        a['views']=[{'type':'timeline','references':['p1']}];checked,_=validate_final(json.dumps(a),w);self.assertEqual(checked['views'][0]['references'],[self.evidence['packets'][0]['id']])
        for view in [{'type':'html','references':[]},{'type':'bar','references':[],'values':[999]},{'type':'map','references':['p9999']}]:
            a['views']=[view]
            with self.assertRaises(ValueError):validate_final(json.dumps(a),w)

if __name__=='__main__':unittest.main()
