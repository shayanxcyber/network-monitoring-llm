"""New durable job/event and SDK streaming checks. No hosted requests."""
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_runs import InvestigationRuns, TERMINAL
from pp_sessions import ReviewStore
from pp_investigator import provisional_summary, streamed_request
from pp_llm import APIConfig
from pp_web import create_app
from fastapi.testclient import TestClient
from openai.types.chat import ChatCompletionChunk


def await_terminal(jobs, review, identity):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        value=jobs.get(review,identity)
        if value['status'] in TERMINAL and not jobs.lock.locked(): return value
        time.sleep(.01)
    raise AssertionError('Controlled job did not finish.')


class DurableRunsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=ReviewStore(self.temp.name)
        self.review=self.store.create('test source','input.pcap','rules',{})['id']
        self.lock=threading.Lock();self.jobs=InvestigationRuns(self.store,self.lock)
        self.id=str(uuid.uuid4());self.release=threading.Event();self.entered=threading.Event();self.calls=0
    def tearDown(self):
        self.release.set()
        if self.lock.locked(): await_terminal(self.jobs,self.review,self.id)
        self.temp.cleanup()
    def runner(self, emit):
        self.calls+=1;emit('summary',{'text':'Controlled public summary','provisional':True})
        self.entered.set();self.release.wait(10)
        return {'run_id':str(uuid.uuid4()),'question':'exact question','explanation':{}},None,'test-run'
    def start(self): return self.jobs.start(self.review,self.id,'exact question',self.runner)
    def test_duplicate_same_id_while_busy_is_one_worker(self):
        self.start();self.start();self.release.set();run=await_terminal(self.jobs,self.review,self.id)
        self.assertEqual(self.calls,1);self.assertEqual(run['status'],'complete');self.assertEqual(len(self.store.get(self.review)['turns']),1)
    def test_conflicting_question_or_source_cannot_reuse_identity(self):
        self.start()
        with self.assertRaises(ValueError):self.jobs.start(self.review,self.id,'other question',self.runner)
        other=self.store.create('second','other','rules',{})['id']
        with self.assertRaises(ValueError):self.jobs.start(other,self.id,'exact question',self.runner)
    def test_public_journal_cursor_and_saved_turn_link(self):
        self.start();self.release.set();value=await_terminal(self.jobs,self.review,self.id)
        events=value['events'];self.assertEqual([e['sequence'] for e in events],list(range(1,len(events)+1)))
        self.assertTrue(all(e['sequence']>2 for e in self.jobs.get(self.review,self.id,2)['events']))
        self.assertEqual(events[-1]['type'],'complete');self.assertEqual(value['turn_id'],self.store.get(self.review)['turns'][0]['run_id'])
        self.assertEqual(self.jobs.list(self.review)[0]['events'],events)
    def test_unknown_event_and_run_rejected(self):
        with self.assertRaises(KeyError):self.jobs.get(self.review,self.id)
        with self.assertRaises(ValueError):self.jobs.emit(self.id,'reasoning',{'text':'private'})
    def test_restart_marks_interrupted_without_restarting_provider(self):
        self.store.begin_request(self.id,self.review)
        with self.store.connect() as db:db.execute('INSERT INTO investigation_runs (id,review_id,question,status,created_at,updated_at,turn_id,error) VALUES (?,?,?,?,?,?,?,?)',(self.id,self.review,'exact question','running','now','now',None,None))
        restarted=InvestigationRuns(self.store,threading.Lock());value=restarted.get(self.review,self.id)
        self.assertEqual(value['status'],'interrupted');self.assertEqual(self.calls,0)
        self.assertEqual(restarted.start(self.review,self.id,'exact question',self.runner)['status'],'interrupted')
    def test_exception_is_generic_and_does_not_leak_secret(self):
        def broken(emit):raise RuntimeError('private-secret-in-untrusted-exception')
        self.jobs.start(self.review,self.id,'exact question',broken);value=await_terminal(self.jobs,self.review,self.id)
        self.assertEqual(value['status'],'failed');self.assertNotIn('private-secret',json.dumps(value))
    def test_retained_api_failure_is_not_a_success(self):
        def fallback(emit):return {'run_id':str(uuid.uuid4()),'question':'exact question','explanation':{'api_error':{'code':'controlled','message':'Controlled failure'}}},None,'fallback'
        self.jobs.start(self.review,self.id,'exact question',fallback);value=await_terminal(self.jobs,self.review,self.id)
        self.assertEqual(value['status'],'failed');self.assertIsNotNone(value['turn_id'])
    def test_completed_legacy_request_is_not_repeated_or_relabelled(self):
        self.store.begin_request(self.id,self.review)
        saved={'run_id':str(uuid.uuid4()),'question':'exact question','explanation':{}}
        self.store.finish_request(self.id,self.review,saved,'old')
        with self.assertRaises(ValueError):self.jobs.start(self.review,self.id,'different question',self.runner)
        value=self.start();self.assertEqual(value['turn_id'],saved['run_id']);self.assertEqual(self.calls,0)
    def test_evidence_selection_is_part_of_durable_identity(self):
        self.jobs.start(self.review,self.id,'exact question',self.runner,'hash:p1')
        self.assertEqual(self.jobs.get(self.review,self.id)['selected_reference'],'hash:p1')
        with self.assertRaises(ValueError):self.jobs.start(self.review,self.id,'exact question',self.runner,'hash:p2')

    def test_stop_is_idempotent_and_waits_for_worker_without_saving_answer(self):
        self.start()
        self.assertTrue(self.entered.wait(3))
        stopped=self.jobs.cancel(self.review,self.id)
        self.assertEqual(stopped['status'],'stopping')
        self.assertEqual(self.jobs.cancel(self.review,self.id)['status'],'stopping')
        with self.assertRaises(ValueError):self.jobs.start(self.review,str(uuid.uuid4()),'new question',self.runner)
        self.release.set();value=await_terminal(self.jobs,self.review,self.id)
        self.assertEqual(value['status'],'cancelled');self.assertIsNone(value['turn_id'])
        self.assertEqual(self.store.get(self.review)['turns'],[])
        self.assertEqual([e['type'] for e in value['events']].count('stop_requested'),1)
        self.assertEqual(value['events'][-1]['type'],'cancelled')
        self.assertEqual(self.start()['status'],'cancelled');self.assertEqual(self.calls,1)

    def test_stop_of_completed_answer_or_wrong_source_cannot_change_history(self):
        self.start();self.release.set();before=await_terminal(self.jobs,self.review,self.id)
        self.assertEqual(self.jobs.cancel(self.review,self.id),before)
        with self.assertRaises(KeyError):self.jobs.cancel('other-source',self.id)


class StreamTests(unittest.TestCase):
    def chunks(self, deltas, finish='stop'):
        for delta in deltas:yield ChatCompletionChunk.model_validate({'id':'controlled','model':'stub','object':'chat.completion.chunk','created':0,'choices':[{'index':0,'delta':delta,'finish_reason':None}]})
        yield ChatCompletionChunk.model_validate({'id':'controlled','model':'stub','object':'chat.completion.chunk','created':0,'choices':[{'index':0,'delta':{},'finish_reason':finish}],'usage':{'prompt_tokens':20,'completion_tokens':4,'total_tokens':24}})
    def request(self,deltas,finish='stop',seconds=1):
        stream=Mock();stream.__iter__=Mock(return_value=self.chunks(deltas,finish));client=Mock();client.chat.completions.create.return_value=stream
        events=[];result=streamed_request(client,{'model':'stub'},seconds,lambda k,d:events.append((k,d)),'secret');return result,events,stream,client
    def test_real_content_snapshots_hide_private_reasoning_and_raw_json(self):
        result,events,stream,client=self.request([{'reasoning_content':'private thoughts'},{'content':'{"summary":"Useful '},{'content':'secret details","other":1}'}])
        self.assertEqual(result.usage.total_tokens,24);self.assertEqual(result.choices[0].message.reasoning_content,'private thoughts')
        self.assertEqual(events[-1][1]['text'],'Useful [redacted] details');self.assertNotIn('private thoughts',json.dumps(events));self.assertNotIn('"other"',json.dumps(events));stream.close.assert_called_once()
        self.assertTrue(client.chat.completions.create.call_args.kwargs['stream'])
    def test_tool_call_chunks_reassemble_exact_arguments(self):
        result,events,_,_=self.request([{'tool_calls':[{'index':0,'id':'call_1','type':'function','function':{'name':'get_packets','arguments':'{"numbers":'}}]},{'tool_calls':[{'index':0,'function':{'arguments':'[1,2]}'}}]}],'tool_calls')
        self.assertEqual(result.choices[0].message.tool_calls[0].function.arguments,'{"numbers":[1,2]}');self.assertEqual(events,[])
    def test_partial_escape_unicode_and_bound(self):
        self.assertEqual(provisional_summary('{"summary":"hi\\u'), 'hi')
        self.assertEqual(provisional_summary('{"summary":"hi\\"there"}'),'hi"there')
        self.assertEqual(len(provisional_summary('{"summary":"'+'x'*2000+'"}')),1400)
        self.assertEqual(provisional_summary('{"reasoning":"not public"}'),'')
    def test_timed_out_stream_never_emits_late_results(self):
        done=threading.Event();events=[]
        class Slow:
            def __iter__(self):
                done.wait(.2)
                yield next(StreamTests().chunks([{'content':'{"summary":"late"}'}]))
            def close(self):pass
        client=Mock();client.chat.completions.create.return_value=Slow()
        with self.assertRaises(TimeoutError):streamed_request(client,{'model':'stub'},.02,lambda k,d:events.append((k,d)),'')
        done.set();time.sleep(.04);self.assertEqual(events,[])

    def test_stop_signal_during_private_reasoning_closes_stream(self):
        from pp_runs import InvestigationCancelled
        flag=threading.Event();flag.set()
        events=[]
        def emit(kind,data):events.append((kind,data))
        emit.cancelled=flag
        stream=Mock();stream.__iter__=Mock(return_value=self.chunks([{'reasoning_content':'private'}]))
        client=Mock();client.chat.completions.create.return_value=stream
        with self.assertRaises(InvestigationCancelled):streamed_request(client,{'model':'stub'},1,emit,'')
        stream.close.assert_called_once();self.assertEqual(events,[])


class RunRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'web').mkdir();shutil.copy2(ROOT/'web/index.html',self.root/'web/index.html')
        self.app=create_app(self.root,config_loader=lambda:APIConfig('https://api.example.test','stub',''),test_mode=True)
        self.client=TestClient(self.app);self.token=self.client.get('/api/config').json()['csrf']
        self.review=self.post('/api/reviews',{'sample':'normal','provider':'rules'}).json();self.id=str(uuid.uuid4())
    def post(self,path,body):return self.client.post(path,json=body,headers={'X-PacketPilot-Token':self.token})
    def tearDown(self):self.client.close();self.temp.cleanup()
    def finished(self):return await_terminal(self.app.state.runs,self.review['id'],self.id)
    def test_route_accepts_fast_without_double_analysis_and_exports_final(self):
        path=f"/api/reviews/{self.review['id']}/runs";body={'request_id':self.id,'question':'What happened?'}
        self.assertEqual(self.post(path,body).status_code,202);self.finished();self.assertEqual(self.post(path,body).status_code,202)
        saved=self.client.get(f"/api/reviews/{self.review['id']}/export").json();self.assertEqual(len(saved['turns']),1)
    def test_csrf_origin_source_and_id_validation_unchanged(self):
        path=f"/api/reviews/{self.review['id']}/runs";body={'request_id':self.id,'question':'What happened?'}
        self.assertEqual(self.client.post(path,json=body).status_code,403)
        self.assertEqual(self.client.post(path,json=body,headers={'X-PacketPilot-Token':self.token,'Origin':'https://bad.test'}).status_code,403)
        self.assertEqual(self.post(path,body|{'request_id':'not-a-uuid'}).status_code,422)
        other=self.post('/api/reviews',{'sample':'normal','provider':'rules'}).json();self.post(path,body);self.finished()
        self.assertEqual(self.client.get(f"/api/reviews/{other['id']}/runs/{self.id}").status_code,404)
    def test_event_reconnection_cursor_and_terminal_stream(self):
        self.post(f"/api/reviews/{self.review['id']}/runs",{'request_id':self.id,'question':'What happened?'});self.finished()
        url=f"/api/reviews/{self.review['id']}/runs/{self.id}/events"
        stream=self.client.get(url,headers={'Last-Event-ID':'1'})
        self.assertEqual(stream.status_code,200);self.assertNotIn('id: 1\n',stream.text);self.assertIn('event: settled',stream.text)
        self.assertEqual(self.client.get(url,headers={'Last-Event-ID':'bad'}).status_code,400)
    def test_table_and_view_queries_are_read_only_and_source_bounded(self):
        url=f"/api/reviews/{self.review['id']}"
        self.assertEqual(self.client.get(url+'/records?sort=number&descending=true').status_code,200)
        self.assertEqual(self.client.get(url+'/records?sort=invalid').status_code,400)
        self.assertEqual(self.client.get(url+'/views?references=another:p1').status_code,400)
    def test_global_action_overview_only_returns_linked_sources(self):
        response=Mock();response.call.return_value={'actions':[{'id':'linked','state':'active'},{'id':'other','state':'active'}],'fault':None}
        with patch.object(self.app.state.store,'action_sources',return_value=[{'action_id':'linked','review_id':self.review['id'],'review_title':'test source'}]),patch('pp_response_client.ResponseClient.call',response.call):
            result=self.client.get('/api/actions').json()
        self.assertEqual([a['id'] for a in result['actions']],['linked']);self.assertEqual(result['actions'][0]['review_id'],self.review['id']);self.assertTrue(result['available']);response.call.assert_called_once_with('status')
    def test_global_action_unavailability_is_not_empty_success(self):
        with patch.object(self.app.state.store,'action_sources',return_value=[{'action_id':'linked','review_id':self.review['id'],'review_title':'test source'}]),patch('pp_response_client.ResponseClient.call',side_effect=ValueError('Controlled unavailable broker')):
            result=self.client.get('/api/actions').json()
        self.assertFalse(result['available']);self.assertEqual(result['unresolved_ids'],['linked']);self.assertIn('unavailable',result['reason'])
    def test_selected_context_retains_exact_question_and_original_reference(self):
        url=f"/api/reviews/{self.review['id']}";ref=self.review['evidence']['packets'][1]['id']
        body={'request_id':self.id,'question':'What does this show?','selected_reference':ref}
        accepted=self.post(url+'/runs',body);self.assertEqual(accepted.status_code,202);self.finished()
        self.assertEqual(accepted.json()['selected_reference'],ref)
        turn=self.client.get(url).json()['turns'][0]
        self.assertEqual(turn['question'],'What does this show?');self.assertEqual(turn['selected_reference'],ref)
        self.assertEqual(self.post(url+'/runs',body|{'selected_reference':ref+'wrong'}).status_code,400)

    def test_cancel_route_is_csrf_and_source_scoped(self):
        release=threading.Event();entered=threading.Event()
        def slow(*args,**kwargs):
            entered.set();release.wait(10)
            return {'run_id':str(uuid.uuid4()),'question':'What happened?','explanation':{}},None,'controlled'
        url=f"/api/reviews/{self.review['id']}/runs"
        try:
            with patch('pp_web.run_analysis',slow):
                self.post(url,{'request_id':self.id,'question':'What happened?'})
                self.assertTrue(entered.wait(3))
                cancel=url+'/'+self.id+'/cancel'
                self.assertEqual(self.client.post(cancel).status_code,403)
                self.assertEqual(self.post(cancel,{}).json()['status'],'stopping')
                self.assertEqual(self.client.get('/api/runs/active').json()[0]['status'],'stopping')
                release.set();self.assertEqual(self.finished()['status'],'cancelled')
        finally:release.set()

if __name__=='__main__':unittest.main()
