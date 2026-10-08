import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {applyEvent,hydrateRun,messagesFor,defaultViews,label,referenceIndex,readLocal,writeLocal} from '../src/domain.js';
test('ordered snapshots deduplicate reconnect and clear provisional correction',()=>{
  const first={sequence:1,type:'summary',data:{text:'Observed detail'}};
  const a=applyEvent({id:'r',events:[]},first);assert.equal(applyEvent(a,first),a);
  const b=applyEvent(a,{sequence:2,type:'correction',data:{}});assert.equal(b.summary,'');
  assert.equal(hydrateRun({...b,events:[first,{sequence:2,type:'complete',data:{turn_id:'t'}}]}).turn_id,'t');
});
test('saved final and pending pair share identity without duplicates',()=>{
  const run={id:'request',question:'exact question ',status:'complete',turn_id:'turn'};
  const review={turns:[{run_id:'turn',question:run.question,explanation:{answer:{summary:'final'}}}]};
  const items=messagesFor(review,[run]);assert.equal(items.length,2);assert.equal(items[1].id,'request:assistant');assert.equal(items[0].text,run.question);
  assert.equal(messagesFor({turns:[]},[{...run,status:'running',turn_id:null}])[1].id,items[1].id);
});
test('legacy answers and failed attempts retain separate identity',()=>{
  const review={turns:[{run_id:'old',question:'past',explanation:{answer:{why:'legacy'}}}]};
  assert.equal(messagesFor(review,[{id:'new',question:'retry',status:'failed'}]).length,4);
});
test('older failed requests stay before later saved replies',()=>{
  const runs=[{id:'failed',created_at:'2026-10-04T10:00:00Z',question:'failed question',status:'failed'},
    {id:'later',created_at:'2026-10-04T10:01:00Z',question:'new question',status:'complete',turn_id:'saved'}];
  const review={turns:[{run_id:'saved',recorded_at:'2026-10-04T10:02:00Z',question:'new question',explanation:{answer:{summary:'new answer'}}}]};
  assert.deepEqual(messagesFor(review,runs).map(x=>x.id),['failed:user','failed:assistant','later:user','later:assistant']);
});
test('pending and completed replies retain chronological position and identity',()=>{
  const older={id:'failed',created_at:'2026-10-04T10:00:00Z',question:'failed',status:'failed'};
  const running={id:'new',created_at:'2026-10-04T10:01:00Z',question:'current',status:'running'};
  const before=messagesFor({turns:[]},[running,older]);
  const after=messagesFor({turns:[{run_id:'turn',question:'current',recorded_at:'2026-10-04T10:02:00Z',explanation:{answer:{summary:'answer'}}}]},[{...running,status:'complete',turn_id:'turn'},older]);
  assert.deepEqual(before.map(x=>x.id),after.map(x=>x.id));
  assert.equal(after.at(-1).id,'new:assistant');
});
test('views are adaptive bounded vocabulary, not inferred data or permissions',()=>{
  assert.deepEqual(defaultViews({kind:'conversation'},'hello',{}),[]);
  assert.deepEqual(defaultViews({views:[{type:'arbitrary_html'}]},'x',{}),[]);
  assert.equal(defaultViews({},'explain reply direction',{bar:{data:[]},series:{data:[]}})[0].type,'timeline');
  assert.deepEqual(defaultViews({},'activity over time',{bar:{data:[]},series:{data:[]}}),[]);
});
test('physical log references and packet identities stay distinct',()=>{
  const review={evidence:{capture:{sha256:'hash'},log_records:[{id:'hash:l2',line_number:2}],packets:[],flows:[]},turns:[]};
  assert.equal(label('hash:l2'),'L2');assert.equal(label('hash:p2'),'P2');assert.equal(referenceIndex(review).get('hash:l2').line_number,2);
  assert.equal(referenceIndex(review).has('hash:p2'),false);
});
test('browser preferences and drafts fail safely without storage',()=>{
  globalThis.localStorage={getItem:()=>{throw Error('disabled');},setItem:()=>{throw Error('disabled');}};
  assert.equal(readLocal('draft','fallback'),'fallback');assert.doesNotThrow(()=>writeLocal('draft','keep'));
});
test('reusable tabs and disclosures cannot implicitly submit the import form',()=>{
  const source=readFileSync(new URL('../src/components.jsx',import.meta.url),'utf8');
  for(const name of ['Modal','Disclosure','Segments']) {
    const section=source.split(`export function ${name}(`)[1].split('export function ')[0];
    for(const tag of section.matchAll(/<button\s[^>]*>/g))assert.match(tag[0],/type="button"/,name);
  }
});
