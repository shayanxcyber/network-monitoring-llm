"""Real Agno v4 dispatch against a loopback response stub, never hosted inference."""
import json
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import packetpilot
from pp_agent import AgnoClient
from pp_evidence import analyse_capture
from pp_llm import APIConfig
from evaluation_cases import cases
from assessment_fixtures import stub_answer


class WorkspaceProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); path=Path(self.temp.name)/'input.pcap';path.write_bytes(cases()[0]['raw'])
        self.evidence=analyse_capture(path,'scapy'); self.mode='conversation';self.received=[]
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])));outer.received.append(payload)
                contexts=[]
                for m in payload['messages']:
                    if m['role']=='user':
                        try:
                            c=json.loads(m['content'])
                            if isinstance(c,dict) and 'context_version' in c:contexts.append(c)
                        except (TypeError,ValueError):pass
                context=contexts[-1]
                repair=payload['messages'][-1]['content'].startswith('Correct the previous') if isinstance(payload['messages'][-1]['content'],str) else False
                review=payload['messages'][-1]['content'].startswith('Verify the previous draft') if isinstance(payload['messages'][-1]['content'],str) else False
                final=dict(schema_version='4.0',kind='conversation',capture_sha256=context['capture']['sha256'],summary='Hi! I can help inspect your selected evidence.')
                finish='stop'
                message=dict(role='assistant',content=json.dumps(final),reasoning_content='private stub reasoning must not be exported')
                if review:
                    final=json.loads(payload['messages'][-2]['content'])
                    if outer.mode in ('review_invalid','review_invalid_always'):final['observations'][0]['references']=['p99999']
                    message['content']=json.dumps(final)
                elif outer.mode=='tool' and payload['messages'][-1]['role']!='tool':
                    message=dict(role='assistant',content=None,reasoning_content='private stub reasoning must not be exported',
                                 tool_calls=[dict(id='current-lab-inspection',type='function',function=dict(name='get_lab_status',arguments='{}'))])
                    finish='tool_calls'
                elif outer.mode in ('tool','repair','investigation','review_invalid','review_invalid_always'):
                    final=stub_answer(context)|dict(schema_version='4.0',kind='investigation',code_suggestions=[])
                    final['observations']=[dict(text='The retained source contains packet records.',references=['capture'],support=[dict(reference='capture',field='packet_count',value=context['capture']['packet_count'])])]
                    if outer.mode=='tool':
                        aggregate=json.loads(payload['messages'][-1]['content'])['records'][0]
                        final['observations']=[dict(text='The fixed lab reports the shown generation.',references=[aggregate['id']],support=[dict(reference=aggregate['id'],field='state.lab.generation',value=aggregate['state']['lab']['generation'])])]
                    if outer.mode=='repair' and not repair: final['observations'][0]['references']=['p99999']
                    if outer.mode=='review_invalid_always' and repair:final['observations'][0]['references']=['p99999']
                    message['content']=json.dumps(final)
                raw=json.dumps(dict(id='loopback-test',object='chat.completion',created=0,model='test-only-model',
                                    choices=[dict(index=0,message=message,finish_reason=finish)],
                                    usage=dict(prompt_tokens=100,completion_tokens=10,total_tokens=110))).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        cfg=APIConfig(f'http://127.0.0.1:{self.server.server_port}','test-only-model','test-only-key',thinking='enabled',reasoning_effort='max',timeout=5,retries=0,allow_loopback_http=True)
        self.client=AgnoClient(cfg,Path(self.temp.name)/'history.sqlite3',str(uuid.uuid4()))
        self.client.configure_workspace(dict(review_id=str(uuid.uuid4()),binding={'generation':'g1'},inspect=lambda:dict(available=True,lab={'generation':'g1'})))
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def test_brief_v4_conversation_without_artificial_report(self):
        result=self.client.explain(self.evidence,'hello')
        self.assertEqual(result['answer']['kind'],'conversation');self.assertEqual(result['answer']['recommendations'],[])
        self.assertEqual(result['attempts'],1);self.assertEqual(result['final_review_attempts'],0)
        self.assertEqual(self.received[0]['thinking'],{'type':'enabled'});self.assertEqual(self.received[0]['reasoning_effort'],'max')
        self.assertNotIn('private stub reasoning',json.dumps(result))
    def test_native_scoped_tool_loop_returns_trace_and_current_state_reference(self):
        self.mode='tool';result=self.client.explain(self.evidence,'Inspect current lab mapping.')
        self.assertEqual(len(self.received),3);self.assertEqual(result['tool_trace'][0]['tool'],'get_lab_status')
        self.assertEqual(result['answer']['schema_version'],'4.0');self.assertIn(':a',result['answer']['observations'][0]['references'][0])
        self.assertEqual(result['final_review_attempts'],1);self.assertEqual(result['correction_attempts'],0)
        self.assertNotIn('tools',self.received[-1]);self.assertEqual(len(result['tool_trace']),1)
    def test_bounded_correction_preserves_rejected_attempt(self):
        self.mode='repair';result=self.client.explain(self.evidence,'Inspect normal traffic.')
        self.assertEqual(result['correction_attempts'],1);self.assertEqual(len(self.received),2)
        self.assertIn('validation_error',result['model_calls'][0]);self.assertEqual(result['answer']['kind'],'investigation')
        self.assertEqual(result['final_review_attempts'],1)

    def test_valid_investigation_is_reviewed_once_with_no_second_model_or_tools(self):
        self.mode='investigation'
        result=self.client.explain(self.evidence,'Inspect the retained source.')
        self.assertEqual(len(self.received),2);self.assertEqual(result['final_review_attempts'],1)
        self.assertTrue(result['model_calls'][0]['draft_validation_passed'])
        self.assertEqual(result['correction_attempts'],0)
        self.assertEqual({r['model'] for r in self.received},{'test-only-model'})
        self.assertEqual(self.received[-1]['reasoning_effort'],'max')
        self.assertNotIn('tools',self.received[-1]);self.assertNotIn('max_tokens',self.received[-1])
        instruction=self.received[-1]['messages'][-1]['content']
        self.assertIn('EVERY public section',instruction);self.assertIn('recommendation rationale',instruction)
        self.assertNotIn('private stub reasoning',json.dumps(result))

    def test_failed_review_and_correction_cannot_fall_back_or_get_a_fourth_attempt(self):
        from pp_llm import LLMError
        self.mode='review_invalid_always'
        with self.assertRaises(LLMError) as caught:self.client.explain(self.evidence,'Inspect the retained source.')
        record=caught.exception.record
        self.assertEqual(record['final_review_attempts'],1);self.assertEqual(len(self.received),3)
        self.assertEqual(record['correction_attempts'],1)
        self.assertTrue(record['model_calls'][0]['draft_validation_passed'])
        self.assertIn('validation_error',record['model_calls'][1]);self.assertNotIn('answer',record)

    def test_review_introduced_error_can_use_one_unspent_validation_correction(self):
        self.mode='review_invalid'
        result=self.client.explain(self.evidence,'Inspect the retained source.')
        self.assertEqual(len(self.received),3);self.assertEqual(result['correction_attempts'],1)
        self.assertEqual(result['final_review_attempts'],1)
        self.assertTrue(result['model_calls'][0]['draft_validation_passed'])
        self.assertIn('validation_error',result['model_calls'][1])
        self.assertNotIn('tools',self.received[-1]);self.assertEqual(result['answer']['kind'],'investigation')
        self.assertEqual(result['investigation_state']['completed_turns'],1)


if __name__=='__main__':unittest.main()
