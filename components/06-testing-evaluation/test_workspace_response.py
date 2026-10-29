"""v4 contract, scoped tool and selective response checks. Controlled doubles only."""
import copy
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_evidence import analyse_capture
from pp_investigation_tools import EvidenceWorkspace, validate_tool_arguments
from pp_workspace_tools import ResponseWorkspace
from pp_investigation_contract import validate_final, validate_saved_assessment
from pp_response_operations import validate_parameters, command_plan, proposal_script
from pp_response_engine import ResponseEngine
from assessment_fixtures import stub_answer
from evaluation_cases import cases
from test_response import FakeLab, WebResponseTests
from pp_linux_lab import LinuxLab
from types import SimpleNamespace
from unittest.mock import patch
import shutil
import threading
from fastapi.testclient import TestClient
from pp_web import create_app
from pp_llm import APIConfig, baseline_explanation


class PendingRequestTests(unittest.TestCase):
    def test_reload_observes_pending_request_and_completed_id_is_not_resent(self):
        started, release = threading.Event(), threading.Event()
        class SlowClient:
            def explain(self, evidence, question):
                started.set(); release.wait(5)
                return baseline_explanation(evidence, question)|{'model':'controlled-test','prompt_sha256':'0'*64}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); shutil.copytree(ROOT/'web',root/'web')
            app=create_app(root,config_loader=lambda:APIConfig('https://example.invalid','stub','test-only'),client_factory=lambda *args:SlowClient(),test_mode=True)
            with TestClient(app) as client:
                token=client.get('/api/config').json()['csrf']; headers={'X-PacketPilot-Token':token}
                saved=client.post('/api/reviews',json={'sample':'normal','provider':'api'},headers=headers).json()
                path=f"/api/reviews/{saved['id']}"; request={'question':'Controlled pending test','request_id':str(uuid.uuid4())}
                results=[]
                worker=threading.Thread(target=lambda:results.append(client.post(path+'/questions',json=request,headers=headers)))
                worker.start()
                try:
                    self.assertTrue(started.wait(3))
                    pending=client.get(path).json()['pending_request']
                    self.assertEqual(pending['request_id'],request['request_id']); self.assertEqual(pending['question'],request['question'])
                finally: release.set(); worker.join(5)
                self.assertEqual(results[0].status_code,200)
                self.assertIsNone(client.get(path).json()['pending_request'])
                again=client.post(path+'/questions',json=request,headers=headers)
                self.assertEqual(again.json()['run_id'],results[0].json()['run_id'])
                self.assertEqual(len(client.get(path).json()['turns']),1)


class LinuxRateStateTests(unittest.TestCase):
    def test_owned_htb_classes_are_retained_as_text_and_rollback_ignores_details(self):
        with tempfile.TemporaryDirectory() as directory:
            lab=LinuxLab(directory); action=str(uuid.uuid4()); lab.manifest={'generation':'g'}
            (Path(directory)/'rate-owner.json').write_text(json.dumps({'action_id':action,'generation':'g'}))
            qdisc='[{"kind":"htb","handle":"7a00:","root":true}]'
            with patch.object(lab,'check'),patch.object(lab,'inside',side_effect=[SimpleNamespace(stdout=qdisc),SimpleNamespace(stdout='class htb 7a00:10 root rate 512Kbit'),SimpleNamespace(stdout='[]')]):
                state=lab.rate_state(action)
            self.assertEqual(state['classes']['format'],'tc_text');self.assertTrue(state['present'])
            with patch.object(lab,'check'),patch.object(lab,'inside',side_effect=[SimpleNamespace(stdout=qdisc),SimpleNamespace(stdout='')]) as invoke:
                lab.unrate(action)
            self.assertEqual(invoke.call_count,2);self.assertFalse((Path(directory)/'rate-owner.json').exists())
    def test_noqueue_has_no_class_or_filter_json_and_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = LinuxLab(directory)
            lab.manifest = {'generation': 'fixed-test-generation'}
            with patch.object(lab, 'check'), patch.object(lab, 'inside', return_value=SimpleNamespace(stdout='[{"kind":"noqueue","handle":"0:","root":true}]')) as invoke:
                state = lab.rate_state(str(uuid.uuid4()))
            self.assertFalse(state['present']); self.assertEqual(state['classes'], [])
            self.assertEqual(state['filters'], []); self.assertEqual(invoke.call_count, 1)


def answer4(workspace):
    wire = stub_answer(workspace.context) | {'schema_version': '4.0', 'kind': 'investigation', 'code_suggestions': []}
    return wire


class Contract4Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        path = Path(self.temp.name)/'input.pcap'; path.write_bytes(cases()[0]['raw'])
        self.workspace = ResponseWorkspace(EvidenceWorkspace(analyse_capture(path, 'scapy'), 'Inspect.'))
    def tearDown(self): self.temp.cleanup()
    def test_conversation_needs_no_fake_evidence_or_recommendation(self):
        value = dict(schema_version='4.0', kind='conversation', capture_sha256=self.workspace.digest, summary='Hi! What would you like to investigate?')
        answer, _ = validate_final(json.dumps(value), self.workspace)
        self.assertEqual(answer['observations'], []); self.assertEqual(answer['recommendations'], [])
        validate_saved_assessment(answer, self.workspace.evidence, self.workspace.validation_context())
    def test_conversation_cannot_smuggle_a_report_or_action(self):
        wire = answer4(self.workspace); wire['kind'] = 'conversation'
        with self.assertRaises(ValueError): validate_final(json.dumps(wire), self.workspace)
    def test_saved_flow_hash_uses_original_short_alias_for_shape_validation(self):
        wire=answer4(self.workspace); wire['observations'][0]['references']=['f1']
        value,_=validate_final(json.dumps(wire),self.workspace)
        self.assertNotEqual(value['observations'][0]['references'],['f1'])
        validate_saved_assessment(value,self.workspace.evidence,self.workspace.validation_context())
    def test_code_is_permitted_but_fixed_as_unverified(self):
        wire = answer4(self.workspace)
        wire['code_suggestions'] = [dict(title='Inspect saved headers', language='sh', code='tshark -r "$CAPTURE" -Y tcp',
            target='Selected capture only', assumptions=['Set CAPTURE to the reviewed saved file.'],
            expected_effect='Displays TCP headers, not a network change.', reversal='No persistent change.',
            references=['overview'], status='unverified_example')]
        value, _ = validate_final(json.dumps(wire), self.workspace)
        self.assertIn('tshark', value['code_suggestions'][0]['code'])
        wire['code_suggestions'][0]['status'] = 'approved'
        with self.assertRaises(ValueError): validate_final(json.dumps(wire), self.workspace)
    def test_investigation_keeps_exact_coverage_and_references(self):
        wire = answer4(self.workspace); wire['observations'][0]['references'] = ['p99999']
        with self.assertRaises(ValueError): validate_final(json.dumps(wire), self.workspace)
        wire = answer4(self.workspace); wire['coverage']['status'] = 'partial'
        with self.assertRaises(ValueError): validate_final(json.dumps(wire), self.workspace)
    def test_saved_answer_does_not_accept_extra_command_authority(self):
        value, _ = validate_final(json.dumps(answer4(self.workspace)), self.workspace)
        value['execute'] = True
        with self.assertRaises(ValueError): validate_saved_assessment(value, self.workspace.evidence, self.workspace.validation_context())
    def test_unavailable_capability_has_no_execution_parameters(self):
        wire = answer4(self.workspace)
        wire['recommendations'] = [dict(action='change_external_network', rationale='Outside the implemented lab.', references=['overview'])]
        validate_final(json.dumps(wire), self.workspace)
        wire['recommendations'][0]['target'] = '10.77.0.20'
        with self.assertRaises(ValueError): validate_final(json.dumps(wire), self.workspace)
    def test_scoped_plan_has_no_network_or_proposal_side_effect(self):
        result = self.workspace.prepare_response_plan('rate_limit_service', '10.77.0.20', '10.77.0.10', 8080, 30, 512)
        self.assertTrue(result['ok']); self.assertFalse(result['network_changed']); self.assertFalse(result['proposal_created'])
        self.assertIn('template', result['records'][0]); self.assertEqual(len(self.workspace.trace), 1)
    def test_tools_reject_arbitrary_shell_path_and_boolean_rate(self):
        for name, raw in [('get_lab_status', '{"command":"id"}'), ('prepare_response_plan', '{"operation":"block_source"}'),
                          ('prepare_response_plan', '{"rate_kbit":true}')]:
            with self.assertRaises(ValueError): validate_tool_arguments(name, raw)
        self.assertFalse(self.workspace.prepare_response_plan('block_source', '192.168.37.128', '10.77.0.10',8080,30)['ok'])
    def test_current_state_has_distinct_timestamped_provenance(self):
        self.workspace.scope = {'review_id': str(uuid.uuid4()), 'binding': {'generation': 'g1'},
                                'inspect': lambda: dict(available=True, lab={'generation':'g1'})}
        result = self.workspace.get_lab_status(); row = result['records'][0]
        self.assertTrue(row['mapping_matches']); self.assertEqual(row['kind'], 'current_lab_state')
        self.assertIn('observed_at', row)
        self.assertIn(self.workspace.supplied[row['id']]['id'], self.workspace.aggregates)


class RateLab(FakeLab):
    def __init__(self):
        super().__init__(); self.rate_owner=None; self.shaping_works=True
    def rate_limit(self, identity, parameters):
        self.rate_owner=identity; return self.rate_state(identity)
    def rate_state(self, identity): return dict(present=self.rate_owner==identity, owned=self.rate_owner==identity)
    def unrate(self, identity):
        if not self.remove_works: raise RuntimeError('Synthetic removal failure')
        self.rate_owner=None
    def measure(self):
        slow=bool(self.rate_owner and self.shaping_works)
        return dict(source=dict(bytes=131072, seconds=2 if slow else .01, kbit_per_second=524 if slow else 104857,
                                complete=True),
                    control=dict(bytes=131072, seconds=.01, kbit_per_second=104857, complete=True))


class RateLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.lab=RateLab(); self.clock=1000;self.mono=100
        self.engine=ResponseEngine(self.lab,self.temp.name,lambda:self.clock,lambda:self.mono)
        self.data=dict(capture_id='capture',capture_sha256='digest',target='10.77.0.20',destination='10.77.0.10',port=8080,
                       operation='rate_limit_service',duration_seconds=30,rate_kbit=512,origin=None,reason='Controlled service shaping test')
    def tearDown(self): self.temp.cleanup()
    def approve(self,p): return self.engine.approve(dict(action_id=p['id'],approval_token=p['approval_token'],confirmation=p['confirmation']),'operator')
    def test_rate_plan_is_exact_and_preparation_does_not_shape(self):
        p=self.engine.propose(self.data,'operator');self.assertIsNone(self.lab.rate_owner)
        self.assertEqual(len(p['command_plan']['commands']),4);self.assertIn('512kbit',p['command_plan']['commands'][1])
        self.assertIn('10gbit',p['command_plan']['commands'][2])
        self.assertNotIn('approval_token',proposal_script(p))
    def test_actual_measurements_required_and_restoration_checked(self):
        p=self.engine.propose(self.data,'operator');a=self.approve(p)
        self.assertEqual(a['state'],'active');self.assertTrue(a['events'][-1]['evidence']['criteria']['control_unaffected'])
        restored=self.engine.rollback(p['id']);self.assertEqual(restored['state'],'rolled_back')
        self.assertLess(restored['events'][-1]['evidence']['measurement']['source']['seconds'],.2)
    def test_command_success_without_measured_effect_is_a_failure(self):
        p=self.engine.propose(self.data,'operator');self.lab.shaping_works=False
        a=self.approve(p);self.assertEqual(a['state'],'rolled_back')
        self.assertTrue(any(e['event']=='execution_or_verification_failed' for e in a['events']))
    def test_control_transfer_slowdown_fails_selective_effect(self):
        measure=self.lab.measure
        def slowed_control():
            result=measure()
            if self.lab.rate_owner: result['control']['seconds']=.1
            return result
        self.lab.measure=slowed_control
        p=self.engine.propose(self.data,'operator');a=self.approve(p)
        self.assertEqual(a['state'],'rolled_back');self.assertIsNone(self.lab.rate_owner)
        failed=next(e for e in a['events'] if e['event']=='execution_or_verification_failed')
        self.assertIn('control',failed['error'].lower())
    def test_rate_expiry_and_restart_recover_only_its_own_change(self):
        p=self.engine.propose(self.data,'operator');self.approve(p);self.clock+=31;self.engine.tick()
        self.assertEqual(self.engine.get(p['id'])['state'],'expired');self.assertIsNone(self.lab.rate_owner)
        p=self.engine.propose(self.data,'operator');self.approve(p)
        restarted=ResponseEngine(self.lab,self.temp.name,lambda:self.clock);restarted.recover()
        self.assertIsNone(self.lab.rate_owner);self.assertEqual(restarted.get(p['id'])['state'],'rolled_back')
    def test_cancel_revokes_approval_without_changing_network(self):
        p=self.engine.propose(self.data,'operator');self.engine.cancel(p['id'],'operator')
        with self.assertRaises(ValueError):self.approve(p)
        self.assertIsNone(self.lab.rate_owner)
    def test_bad_rate_scope_and_commands_rejected(self):
        for changes in ({'rate_kbit':True},{'rate_kbit':0},{'rate_kbit':2049},{'port':22},{'destination':'192.168.37.128'}, {'command':'id'}):
            with self.assertRaises(ValueError):self.engine.propose(self.data|changes,'operator')
    def test_model_origin_is_retained_and_duplicate_pending_is_rejected(self):
        origin=dict(review_id=str(uuid.uuid4()),turn_id=str(uuid.uuid4()),recommendation_index=0,references=['a'*64+':p1'])
        data=self.data|{'origin':origin}; p=self.engine.propose(data,'operator');self.assertEqual(p['origin'],origin)
        with self.assertRaises(ValueError):self.engine.propose(data,'operator')
    def test_rate_rollback_failure_disables_and_watchdog_retries(self):
        p=self.engine.propose(self.data,'operator');self.approve(p);self.lab.remove_works=False
        self.assertEqual(self.engine.rollback(p['id'])['state'],'rollback_failed')
        with self.assertRaises(ValueError):self.engine.propose(self.data,'operator')
        count=len(self.engine.actions[p['id']]['events']);self.engine.tick();self.assertEqual(len(self.engine.actions[p['id']]['events']),count)
        self.lab.remove_works=True;self.mono+=3;self.engine.tick();self.assertIsNone(self.lab.rate_owner);self.assertIsNone(self.engine.fault)


class LinkedRecommendationTests(WebResponseTests):
    def seed_answer(self, review):
        saved=self.app.state.store.get(review['id'])
        workspace=ResponseWorkspace(EvidenceWorkspace(saved['evidence'],'Controlled block test.'))
        wire=answer4(workspace)
        wire['recommendations']=[dict(action='block_source',target='10.77.0.20',destination='10.77.0.10',port=8080,
                                      duration_seconds=37,rate_kbit=None,rationale='Exact model rationale for a delegated lab test.',references=['overview'])]
        answer,_=validate_final(json.dumps(wire),workspace)
        result=dict(run_id=str(uuid.uuid4()),recorded_at='controlled-test-time',question='Controlled lab test',
                    explanation=dict(source='api',answer=answer,evidence_view=workspace.validation_context()))
        request=str(uuid.uuid4());self.app.state.store.begin_request(request,review['id'])
        self.app.state.store.finish_request(request,review['id'],result,ROOT/'runs'/'controlled-test.json')
        return result
    def test_linked_proposal_carries_exact_parameters_and_origin(self):
        review=self.post('/api/lab/capture',{'provider':'rules'}).json();turn=self.seed_answer(review)
        result=self.post(f"/api/reviews/{review['id']}/recommendations/0/propose",dict(turn_id=turn['run_id']))
        self.assertEqual(result.status_code,200,result.text)
        data=self.calls[-1][1];self.assertEqual(data['duration_seconds'],37)
        self.assertEqual(data['reason'],'Exact model rationale for a delegated lab test.')
        self.assertEqual(data['origin']['turn_id'],turn['run_id']);self.assertEqual(data['operation'],'block_source')
    def test_altered_parameters_and_cross_review_turn_are_rejected(self):
        review=self.post('/api/lab/capture',{'provider':'rules'}).json();turn=self.seed_answer(review)
        endpoint=f"/api/reviews/{review['id']}/recommendations/0/propose"
        self.assertEqual(self.post(endpoint,dict(turn_id=turn['run_id'],target='192.168.37.128')).status_code,422)
        other=self.post('/api/lab/capture',{'provider':'rules'}).json()
        self.assertEqual(self.post(f"/api/reviews/{other['id']}/recommendations/0/propose",dict(turn_id=turn['run_id'])).status_code,400)


if __name__=='__main__':unittest.main()
