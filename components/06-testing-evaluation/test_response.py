"""Portable lifecycle/authority tests; no root access or real network changes."""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_response_engine import ResponseEngine
from pp_linux_lab import LinuxLab
from pp_web import create_app
from pp_llm import APIConfig
from pp_samples import make_samples


class FakeLab:
    def __init__(self):
        self.rules = set(); self.control = True; self.works = True; self.remove_works = True
        self.generation = 'g1'; self.stale = False
    def status(self): return {'available': True, 'generation': self.generation}
    def validate_capture(self, identity, digest):
        if identity != 'capture' or digest != 'digest' or self.stale: raise ValueError('Stale/mismatched capture.')
        return {'generation': self.generation}
    def probe(self): return {'source_reachable': not self.rules or not self.works, 'control_reachable': self.control}
    def block(self, identity): self.rules.add(identity); return self.rule(identity)
    def unblock(self, identity):
        if not self.remove_works: raise RuntimeError('Removal failure')
        self.rules.discard(identity)
    def rule(self, identity): return {'present': identity in self.rules, 'rules': 'synthetic test state'}


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.lab = FakeLab(); self.clock = 1000; self.mono = 100
        self.engine = ResponseEngine(self.lab, self.temp.name, lambda:self.clock, lambda:self.mono)
        self.data = dict(capture_id='capture', capture_sha256='digest',target='10.77.0.20',duration_seconds=20,reason='Authorised lab response test')
    def tearDown(self): self.temp.cleanup()
    def proposal(self): return self.engine.propose(self.data, 'operator')
    def approve(self, proposal):
        return self.engine.approve(dict(action_id=proposal['id'],approval_token=proposal['approval_token'],confirmation=proposal['confirmation']), 'operator')
    def test_proposal_does_not_apply_a_rule(self):
        proposal = self.proposal(); self.assertFalse(self.lab.rules); self.assertEqual(proposal['state'],'proposed')
    def test_approval_applies_and_verifies_then_manual_rollback(self):
        proposal = self.proposal(); result = self.approve(proposal)
        self.assertEqual(result['state'],'active'); self.assertEqual(result['events'][-1]['event'],'effect_verified')
        self.assertTrue(self.engine.rollback(proposal['id'])['events'][-1]['restored']); self.assertFalse(self.lab.rules)
    def test_approval_cannot_be_replayed(self):
        proposal = self.proposal(); self.approve(proposal)
        with self.assertRaises(ValueError): self.approve(proposal)
    def test_approval_must_have_exact_token_actor_and_confirmation(self):
        proposal = self.proposal()
        values = dict(action_id=proposal['id'],approval_token=proposal['approval_token'],confirmation=proposal['confirmation'])
        for altered, actor in ((values|{'approval_token':'bad'}, 'operator'),(values|{'confirmation':'yes'},'operator'),(values,'other')):
            with self.assertRaises(ValueError): self.engine.approve(altered, actor)
        self.assertFalse(self.lab.rules)
    def test_expired_approval_does_not_apply(self):
        proposal = self.proposal(); self.clock += 61
        with self.assertRaises(ValueError): self.approve(proposal)
        self.assertFalse(self.lab.rules)
    def test_automatic_expiry_removes_rule_without_app(self):
        proposal = self.proposal(); self.approve(proposal); self.clock += 21; self.engine.tick()
        self.assertEqual(self.engine.get(proposal['id'])['state'],'expired'); self.assertFalse(self.lab.rules)
    def test_monotonic_expiry_survives_wall_clock_rollback(self):
        proposal=self.proposal(); self.approve(proposal); self.clock -= 100; self.mono += 21; self.engine.tick()
        self.assertFalse(self.lab.rules)
    def test_restart_recovers_active_rule_and_revokes_pending_approval(self):
        proposal=self.proposal(); self.approve(proposal)
        restarted=ResponseEngine(self.lab,self.temp.name,lambda:self.clock)
        restarted.recover(); self.assertFalse(self.lab.rules)
        self.assertEqual(restarted.get(proposal['id'])['events'][-1]['event'],'restart_recovery')
    def test_pending_approval_is_revoked_on_restart(self):
        proposal=self.proposal(); self.engine.recover()
        with self.assertRaises(ValueError): self.approve(proposal)
    def test_failed_effect_check_rolls_back(self):
        proposal=self.proposal(); self.lab.works=False
        self.assertEqual(self.approve(proposal)['state'],'rolled_back'); self.assertFalse(self.lab.rules)
    def test_failed_rollback_disables_new_actions_and_retries(self):
        proposal=self.proposal(); self.approve(proposal); self.lab.remove_works=False
        self.assertEqual(self.engine.rollback(proposal['id'])['state'],'rollback_failed')
        with self.assertRaises(ValueError): self.proposal()
        self.lab.remove_works=True; self.mono+=3; self.engine.tick(); self.assertFalse(self.lab.rules); self.assertIsNone(self.engine.fault)
    def test_target_duration_and_extra_commands_rejected(self):
        for data in (self.data|{'target':'192.168.37.128'}, self.data|{'target':'10.77.0.10'},self.data|{'duration_seconds':True},self.data|{'duration_seconds':121},self.data|{'command':'id'}):
            with self.assertRaises(ValueError): self.engine.propose(data,'operator')
    def test_stale_and_changed_lab_generation_rejected(self):
        proposal=self.proposal(); self.lab.generation='g2'
        with self.assertRaises(ValueError): self.approve(proposal)
        self.lab.stale=True
        with self.assertRaises(ValueError): self.proposal()
    def test_control_client_must_be_healthy(self):
        self.lab.control=False
        with self.assertRaises(ValueError): self.proposal()
    def test_tokens_not_in_public_state_or_audit(self):
        proposal=self.proposal()
        self.assertNotIn(proposal['approval_token'],json.dumps(self.engine.status()))
        self.assertNotIn('approval_hash',json.dumps(self.engine.status()))
        self.assertNotIn(proposal['approval_token'],Path(self.temp.name,'audit.jsonl').read_text())
    def test_rule_arguments_are_fixed_and_reject_command_injection(self):
        spec=LinuxLab.specification(str(uuid.uuid4()))
        self.assertIn('10.77.0.20/32',spec);self.assertIn('8080',spec)
        with self.assertRaises(ValueError): LinuxLab.specification('x; iptables -F')


class WebResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        (self.root/'web').mkdir()
        make_samples(self.root/'sample-data')
        self.calls=[]
        outer=self
        class FakeClient:
            def call(self, operation, data=None):
                outer.calls.append((operation,data))
                if operation=='status': return {'lab':{'available':True},'fault':None,'actions':[]}
                if operation=='capture':
                    from evidence_cases import case_bytes
                    raw=case_bytes()['mixed-udp'][0]
                    return {'capture_id':'capture','capture_sha256':hashlib.sha256(raw).hexdigest(),'generation':'test', 'pcap_base64':base64.b64encode(raw).decode()}
                if operation=='propose': return {'id':str(uuid.uuid4()),'state':'proposed','approval_token':'x'*32,'confirmation':'confirm'}
                return {'state':'active'}
        self.app=create_app(self.root,config_loader=lambda:APIConfig('https://api.example.test','test',''),test_mode=True,response_client=FakeClient())
        self.client=TestClient(self.app);self.token=self.client.get('/api/config').json()['csrf']
    def tearDown(self): self.client.close();self.temp.cleanup()
    def post(self,url,body=None): return self.client.post(url,json=body,headers={'X-PacketPilot-Token':self.token})
    def test_offline_review_cannot_bind_itself_to_execution(self):
        review=self.post('/api/reviews',{'sample':'port-check'}).json()
        result=self.post(f"/api/reviews/{review['id']}/actions/propose",{'reason':'test'})
        self.assertEqual(result.status_code,400);self.assertNotIn('propose',[c[0] for c in self.calls])
    def test_lab_capture_binding_and_proposal(self):
        review=self.post('/api/lab/capture',{'provider':'rules'}).json()
        self.assertEqual(review['lab_binding']['capture_id'],'capture')
        result=self.post(f"/api/reviews/{review['id']}/actions/propose",{'reason':'Controlled verification'})
        self.assertEqual(result.status_code,200,result.text)
        exported=self.client.get(f"/api/reviews/{review['id']}/export").json()
        self.assertNotIn('approval_token',json.dumps(exported))
        self.assertTrue(exported['response_action_ids'])
    def test_lab_post_requires_csrf_and_forbids_added_commands(self):
        self.assertEqual(self.client.post('/api/lab/capture',json={'provider':'rules'}).status_code,403)
        self.assertEqual(self.post('/api/lab/capture',{'provider':'rules','command':'id'}).status_code,422)
    def test_action_cannot_be_approved_from_another_review(self):
        a=self.post('/api/lab/capture',{'provider':'rules'}).json(); b=self.post('/api/lab/capture',{'provider':'rules'}).json()
        proposal=self.post(f"/api/reviews/{a['id']}/actions/propose",{'reason':'Test'}).json()
        result=self.post(f"/api/reviews/{b['id']}/actions/{proposal['id']}/approve",{'approval_token':'x'*32,'confirmation':'confirm'})
        self.assertEqual(result.status_code,400); self.assertNotIn('approve',[c[0] for c in self.calls])
    def test_modified_lab_capture_cannot_execute(self):
        review=self.post('/api/lab/capture',{'provider':'rules'}).json()
        stored=self.app.state.store.get(review['id']);Path(stored['capture']).write_bytes(b'bad')
        result=self.post(f"/api/reviews/{review['id']}/actions/propose",{'reason':'Test'})
        self.assertEqual(result.status_code,400)


if __name__=='__main__':unittest.main()
