"""Depth upgrade calculations, persistence and endpoint boundaries; no paid calls."""
import copy,json,sys,tempfile,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));import packetpilot
from scapy.all import Ether,IP,TCP,UDP,Raw,DNS,DNSQR,wrpcap
from pp_evidence import analyse_capture
from pp_service_evidence import application_fields,service_facts,compare_service
from pp_sessions import ReviewStore
from pp_investigation_tools import EvidenceWorkspace,validate_tool_arguments
from pp_case_tools import CaseWorkspace
from pp_case_api import readable_report,case_export,same_case_scope
from pp_web import create_app
from fastapi.testclient import TestClient
from pp_llm import APIConfig
import shutil
from unittest.mock import patch,MagicMock
from pp_lab_capture import CaptureSessions
from pp_response_client import ResponseClient
from pp_linux_lab import LinuxLab

class CaptureLifecycleTests(unittest.TestCase):
    def test_transfer_outcome_checks_control_even_when_selected_client_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            lab=LinuxLab(folder);lab.check=MagicMock();lab.inside=MagicMock(side_effect=[RuntimeError('blocked'),MagicMock(stdout=json.dumps(dict(seconds=.1,bytes=131072,kbit_per_second=10485.76,body_sha256='d'*64,complete=True)))])
            result=lab.diagnose_transfer()
            self.assertFalse(result['clients']['source']['reachable']);self.assertTrue(result['clients']['control']['complete'])
            self.assertEqual(lab.inside.call_count,2);self.assertIsNone(result['clients']['control']['first_byte_seconds'])
    def test_file_only_mode_never_contacts_a_broker(self):
        with patch('pp_response_client.socket.socket') as socket:
            with self.assertRaises(ValueError):ResponseClient(enabled=False).call('diagnostic')
            socket.assert_not_called()
    def test_start_public_result_is_serializable_and_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as folder,patch('pp_lab_capture.threading.Thread'):
            lab=MagicMock();lab.directory=Path(folder)
            sessions=CaptureSessions(lab);result=sessions.start(6)
            self.assertEqual(json.loads(json.dumps(result))['status'],'starting')
            self.assertNotIn('thread',sessions.get(result['id']))
            with self.assertRaises(ValueError):sessions.start(6)
            self.assertEqual(sessions.stop(result['id'],True)['status'],'stopping')
            sessions.stop(result['id'],False)
            self.assertTrue(sessions.jobs[result['id']]['cancel'])
            with self.assertRaises(ValueError):sessions.get(result['id'],True)

def capture(folder,name,delay=.2):
    request=Ether()/IP(src='10.77.0.20',dst='10.77.0.10')/TCP(sport=45001,dport=8080,flags='PA')/Raw(b'GET / HTTP/1.0\r\n\r\n')
    reply=Ether()/IP(src='10.77.0.10',dst='10.77.0.20')/TCP(sport=8080,dport=45001,flags='PA')/Raw(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    request.time=100;reply.time=100+delay;p=Path(folder)/name;wrpcap(str(p),[request,reply]);return p,analyse_capture(p,'scapy')

class ServiceFactsTests(unittest.TestCase):
    def test_segment_startline_not_reassembly(self):
        self.assertEqual(application_fields(b'HTTP/1.0 503 No\r\n\r\n','TCP',8080,45000)['status_code'],503)
        self.assertIsNone(application_fields(b'NOT HTTP','TCP',8080,45000))
        self.assertIsNone(application_fields(b'GET / HTTP/1.0\r\n','UDP',8080,45000))
    def test_dns_datagram(self):
        row=application_fields(bytes(DNS(id=12,qr=1,rcode=3,qd=DNSQR(qname='service.lab.'))),'UDP',53,40000)
        self.assertEqual(row['response_code'],3);self.assertEqual(row['query'],'service.lab.')
    def test_exact_timing_and_unequal_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            _,a=capture(folder,'a.pcap',.2);_,b=capture(folder,'b.pcap',.6)
            result=compare_service(a,b,8080)
            self.assertEqual(result['delta']['record_count'],0)
            self.assertAlmostEqual(result['delta']['mean_candidate_reply_seconds'],.4)
            self.assertAlmostEqual(result['baseline']['records_per_second'],10)
            self.assertEqual(result['baseline']['visible_http_responses'],1)
            self.assertTrue(result['qualifications'])
    def test_zero_duration_and_duplicate(self):
        with tempfile.TemporaryDirectory() as folder:
            _,a=capture(folder,'a.pcap',0);_,b=capture(folder,'b.pcap',.4)
            self.assertIsNone(compare_service(a,b)['delta']['records_per_second'])
            with self.assertRaises(ValueError):compare_service(a,a)
    def test_log_has_no_application_visibility(self):
        with tempfile.TemporaryDirectory() as folder:
            _,a=capture(folder,'a.pcap');log=copy.deepcopy(a);log.update(input_kind='network_log',log_records=[])
            self.assertFalse(service_facts(log)['application_available'])
    def test_derived_log_precision_is_not_independent_confirmation(self):
        with tempfile.TemporaryDirectory() as folder:
            _,a=capture(folder,'a.pcap');b=copy.deepcopy(a)
            b['capture']['sha256']='b'*64;b['input_kind']='network_log';b['log_records']=b.pop('packets')
            for row in b['log_records']:
                row['timestamp']+='000';row['reported_frame_length']=row.pop('wire_bytes');row.pop('application',None)
            comparison=compare_service(a,b)
            self.assertTrue(any('derived' in reason for reason in comparison['qualifications']))
            self.assertIsNone(comparison['delta']['frame_bytes_per_second'])
    def test_ambiguous_http_requests_do_not_get_forced_pairs(self):
        with tempfile.TemporaryDirectory() as folder:
            _,a=capture(folder,'a.pcap');request=copy.deepcopy(a['packets'][0]);request['timestamp']='100.01';request['id']='r2'
            a['packets'].insert(1,request)
            self.assertEqual(service_facts(a)['candidate_pairs'],0)

class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.store=ReviewStore(self.folder/'data')
        p,a=capture(self.folder,'a.pcap');q,b=capture(self.folder,'b.pcap',.5)
        self.a=self.store.create('<script>alert(1)</script>',p,'api',a);self.b=self.store.create('second',q,'api',b)
        self.case=self.store.create_case(self.a['id'],'Service case')
        self.store.link_case(self.case['id'],self.b['id'],'baseline')
    def tearDown(self):self.temp.cleanup()
    def test_persistent_original_history_and_membership(self):
        restarted=ReviewStore(self.folder/'data')
        self.assertEqual(len(restarted.case_for(self.a['id'])['sources']),2)
        self.assertEqual(restarted.get(self.a['id'])['evidence'],self.a['evidence'])
        with self.assertRaises(ValueError):self.store.select_case(self.case['id'],[str(uuid.uuid4())])
        with self.assertRaises(ValueError):self.store.link_case(self.case['id'],self.b['id'],'after')
        with self.assertRaises(ValueError):self.store.create_case(self.b['id'],'   ')
    def test_tools_source_qualified_and_selection_isolation(self):
        workspace=CaseWorkspace(EvidenceWorkspace(self.a['evidence'],'Compare'),self.store.case_snapshot(self.a['id']))
        result=workspace.compare_sources(self.b['id'],self.a['id'])
        self.assertTrue(result['ok']);self.assertIn(result['records'][0]['id'],workspace.supplied)
        self.assertFalse(workspace.compare_sources(str(uuid.uuid4()),self.a['id'])['ok'])
        row=workspace.inspect_case_records(self.b['id'],[1])['records'][0]
        self.assertEqual(row['source_sha256'],self.b['evidence']['capture']['sha256'])
        self.assertFalse(workspace.inspect_case_records(self.b['id'],[True])['ok'])
    def test_unselected_current_source_cannot_question(self):
        self.store.select_case(self.case['id'],[self.b['id']])
        with self.assertRaises(ValueError):self.store.case_snapshot(self.a['id'])
    def test_prior_aggregate_scope_cannot_follow_deselected_sources(self):
        old=self.store.case_snapshot(self.a['id'])
        self.store.select_case(self.case['id'],[self.a['id']]);current=self.store.case_snapshot(self.a['id'])
        self.assertFalse(same_case_scope(old,current));self.assertFalse(same_case_scope(None,current))
        self.assertTrue(same_case_scope(None,None));self.assertTrue(same_case_scope(old,copy.deepcopy(old)))
    def test_export_escapes_content(self):
        value=case_export(self.store,self.store.case(self.case['id']),[]);self.assertEqual(len(value['comparisons']),1)
        report=readable_report(value)
        self.assertNotIn('<script>alert',report);self.assertIn('&lt;script&gt;',report)
        self.assertIn(self.a['evidence']['packets'][0]['id'],report)
    def test_mutated_original_cannot_be_exported_under_old_identity(self):
        with Path(self.a['capture']).open('ab') as stream:stream.write(b'changed')
        with self.assertRaises(ValueError):case_export(self.store,self.store.case(self.case['id']),[])
    def test_export_does_not_label_a_timed_out_check_as_a_complete_transfer(self):
        value=case_export(self.store,self.store.case(self.case['id']),[])
        failed=dict(reachable=False,complete=False,total_seconds=12,failure_type='TimeoutExpired',payload_kbit_per_second=999)
        value['sources'][0]['diagnostics']=[dict(phase='during',profile='transfer',recorded_at='unit-fixture',objective='Unit fixture',result=dict(clients=dict(source=failed,control=failed)))]
        report=readable_report(value)
        self.assertIn('check timed out after 12s',report)
        self.assertNotIn('complete transfer 12s',report);self.assertNotIn('999kbit/s',report)
    def test_export_missing_timing_has_no_invented_units(self):
        value=case_export(self.store,self.store.case(self.case['id']),[])
        missing=dict(reachable=False,first_byte_seconds=None)
        value['sources'][0]['diagnostics']=[dict(phase='after',profile='health',recorded_at='unit-fixture',objective='Unit fixture',result=dict(clients=dict(source=missing,control=missing)))]
        report=readable_report(value)
        self.assertIn('first-byte timing unavailable',report);self.assertNotIn('first byte Unavailables',report)
    def test_export_distinguishes_a_failed_model_attempt_from_its_offline_fallback(self):
        original=self.store.get
        def reviewed(identity):
            row=original(identity)
            if identity==self.a['id']:
                row['turns'].append(dict(run_id=str(uuid.uuid4()),question='Unit failed question',explanation=dict(source='rules',status='fallback_after_api_failure',api_error=dict(code='invalid_response',message='Unit validation failure'),answer=dict(summary='Unit fallback baseline'))))
            return row
        with patch.object(self.store,'get',side_effect=reviewed):
            value=case_export(self.store,self.store.case(self.case['id']),[])
        turn=next(s for s in value['sources'] if s['review_id']==self.a['id'])['turns'][-1]
        self.assertIsNone(turn['answer']);self.assertEqual(turn['api_error']['code'],'invalid_response')
        self.assertEqual(turn['fallback_baseline']['summary'],'Unit fallback baseline')
        report=readable_report(value)
        self.assertIn('Model assessment unavailable.',report);self.assertIn('not an accepted model answer',report)
        self.assertNotIn('<p>Unit fallback baseline</p>',report)
    def test_argument_coercion_rejected(self):
        for tool,raw in [('inspect_service','{"destination_port":true}'),('compare_sources','{"baseline_id":"x"}'),('probe_lab_service','{"command":"id"}')]:
            with self.assertRaises(ValueError):validate_tool_arguments(tool,raw)

class DepthWebTests(unittest.TestCase):
    def test_cases_and_csrf(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copytree(ROOT/'web',root/'web')
            app=create_app(root,test_mode=True,config_loader=lambda:APIConfig('https://example.invalid','test','test-only'))
            with TestClient(app) as c:
                h={'X-PacketPilot-Token':c.get('/api/config').json()['csrf']}
                a=c.post('/api/reviews',headers=h,json={'sample':'normal'}).json()
                b=c.post('/api/reviews',headers=h,json={'sample':'port-check'}).json()
                self.assertEqual(c.post('/api/reviews/'+a['id']+'/case',json={'title':'A'}).status_code,403)
                case=c.post('/api/reviews/'+a['id']+'/case',headers=h,json={'title':'A'}).json()
                linked=c.post('/api/cases/'+case['id']+'/sources',headers=h,json={'review_id':b['id'],'role':'baseline'})
                self.assertEqual(linked.status_code,200)
                self.assertEqual(c.get('/api/cases/'+case['id']+'/comparison',params={'baseline_id':b['id'],'comparison_id':a['id']}).status_code,200)
                self.assertEqual(c.get('/api/cases/'+case['id']+'/comparison',params={'baseline_id':str(uuid.uuid4()),'comparison_id':a['id']}).status_code,400)
                self.assertEqual(c.get('/api/cases/'+case['id']+'/export').status_code,200)
                exported=c.get('/api/cases/'+case['id']+'/export',params={'format':'json','baseline_id':b['id'],'comparison_id':a['id'],'port':8080})
                self.assertEqual(exported.status_code,200);self.assertEqual(exported.json()['comparisons'][0]['baseline']['service_port'],8080)
                self.assertEqual(c.get('/api/cases/'+case['id']+'/export',params={'baseline_id':b['id']}).status_code,400)
                self.assertEqual(c.post('/api/captures',headers=h,json={'duration_seconds':True,'provider':'rules'}).status_code,422)

if __name__=='__main__':unittest.main()
