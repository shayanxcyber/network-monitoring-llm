import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {diagnosticPair,sourceOption,comparisonMatches,comparisonDefaults,sourceRelativeTime,currentSourceSelected,canDismissProposal} from '../src/depth-metrics.mjs';

const row=(id,phase,seconds,overrides={})=>({id,review_id:'review',phase,profile:'transfer',objective:'Restore service',
  recorded_at:`2026-10-23T10:00:${phase==='baseline'?'00':'10'}Z`,action_id:null,
  lab_context:{generation:'lab-generation',addresses:{source:'10.77.0.20',control:'10.77.0.30',service:'10.77.0.10'},service_port:8080},
  result:{service:'10.77.0.10:8080',path:'/payload',clients:{control:{reachable:true,complete:true,total_seconds:seconds}}},...overrides});
test('repeated cycles use the explicitly associated baseline, not the first matching row',()=>{
  const rows=[row('old','baseline',1,{action_id:'A'}),row('old-after','after',.8,{action_id:'A'}),row('new','baseline',10),row('new-after','after',9,{baseline_id:'new',action_id:'B'})];
  assert.equal(diagnosticPair(rows,'new','new-after').delta,-1);
  assert.equal(diagnosticPair(rows,'old','new-after').delta,null);
});
test('no pair is guessed from row ordering or missing choices',()=>{
  const rows=[row('after','after',.8),row('base','baseline',1)];
  assert.equal(diagnosticPair(rows,'','').delta,null);
  assert.ok(diagnosticPair(rows,'','after').reason.includes('No cycle is inferred'));
  assert.equal(diagnosticPair(rows,'base','after').delta,-.19999999999999996);
});
test('a legitimate null pre-action baseline can pair with its later response',()=>{
  assert.equal(diagnosticPair([row('b','baseline',10),row('a','after',9,{baseline_id:'b',action_id:'B'})],'b','a').delta,-1);
});
test('different action cycles, sources and chronology are rejected',()=>{
  for(const changed of [{action_id:'other'},{review_id:'other'},{recorded_at:'2026-10-23T09:00:00Z'},{recorded_at:'invalid'}]){
    const b=row('b','baseline',10,{action_id:'A'}),a=row('a','after',9,changed);
    assert.equal(diagnosticPair([b,a],'b','a').delta,null);
  }
});
test('repeated baselines stay distinct even with identical objectives and missing action IDs',()=>{
  const a=row('a','after',9,{baseline_id:'b2'}),b1=row('b1','baseline',1),b2=row('b2','baseline',10);
  assert.equal(diagnosticPair([b1,b2,a],'b1','a').delta,null);
  assert.equal(diagnosticPair([a,b2,b1],'b2','a').delta,-1);
});
test('mismatched profile, objective or target and incomplete results are not timings',()=>{
  for(const changed of [{profile:'health'},{objective:'Different'}, {result:{service:'other',path:'/payload',clients:{control:{reachable:true,complete:true,total_seconds:9}}}}, {result:{service:'10.77.0.10:8080',path:'/payload',clients:{control:{reachable:true,complete:false,total_seconds:12}}}}]){
    assert.equal(diagnosticPair([row('b','baseline',10),row('a','after',9,changed)],'b','a').delta,null);
  }
});
test('failed health checks do not produce a misleading control improvement',()=>{
  const b=row('b','baseline',1,{profile:'health'}),a=row('a','after',0,{profile:'health'});
  b.result.clients.control={reachable:true,first_byte_seconds:1};a.result.clients.control={reachable:false,first_byte_seconds:0};
  assert.equal(diagnosticPair([b,a],'b','a').delta,null);
});
test('missing values and reversed phases do not acquire timing units',()=>{
  assert.equal(diagnosticPair([row('b','during',1),row('a','after',0)],'b','a').delta,null);
  const b=row('b','baseline',1),a=row('a','after',0);delete a.result.clients.control.total_seconds;
  assert.equal(diagnosticPair([b,a],'b','a').delta,null);
});
test('comparison dirty state is based on the applied source pair and port',()=>{
  const result={baseline_review_id:'one',comparison_review_id:'two',baseline:{service_port:8080}};
  assert.equal(comparisonMatches(result,'one','two','8080'),true);
  for(const args of [['two','one','8080'],['one','two','80'],['one','two','']])assert.equal(comparisonMatches(result,...args),false);
});
test('opening the baseline or problem preserves the user-assigned comparison direction',()=>{
  const sources=[{review_id:'problem',role:'problem',selected:true},{review_id:'base',role:'baseline',selected:true}];
  for(const current of ['base','problem'])assert.deepEqual(comparisonDefaults(sources,current),{left:'base',right:'problem'});
});
test('comparison defaults exclude unselected sources and prefer relevant roles',()=>{
  const sources=[{review_id:'ref',role:'reference',selected:true},{review_id:'old',role:'baseline',selected:false},{review_id:'base',role:'baseline',selected:true},{review_id:'after',role:'after',selected:true}];
  assert.deepEqual(comparisonDefaults(sources,'ref'),{left:'base',right:'after'});
  assert.deepEqual(comparisonDefaults([], 'missing'),{left:'',right:''});
});
test('comparison defaults do not infer a duplicate self comparison from one source',()=>{
  assert.deepEqual(comparisonDefaults([{review_id:'only',role:'baseline',selected:true}],'only'),{left:'only',right:''});
});
test('duplicate names retain distinguishing identity and case eligibility',()=>{
  assert.equal(sourceOption({title:'same.pcap',id:'12345678-1',case_id:'case',case_title:'Service case'}),'same.pcap · 12345678 · in Service case');
});
test('lab generation and client identity changes are not comparable cycles',()=>{
  for(const lab_context of [undefined,{generation:'new'}, {generation:'lab-generation',addresses:{source:'10.77.0.30',control:'10.77.0.20',service:'10.77.0.10'},service_port:8080}]){
    assert.equal(diagnosticPair([row('b','baseline',1),row('a','after',.8,{lab_context})],'b','a').delta,null);
  }
});
test('relative display does not invent timestamps and exact originals remain separate',()=>{
  assert.equal(sourceRelativeTime('100.02','100'),'+0.0200 s from first retained record');
  assert.equal(sourceRelativeTime(undefined,'100'),'Not retained');
});
test('an unselected current source is recoverable without silently broadening question scope',()=>{
  const group={sources:[{review_id:'one',selected:1},{review_id:'two',selected:0}]};
  assert.equal(currentSourceSelected(group,'one'),true);
  assert.equal(currentSourceSelected(group,'two'),false);
  assert.equal(currentSourceSelected(null,'two'),true);
  group.sources[1].selected=1;assert.equal(currentSourceSelected(group,'two'),true);
});
test('failed cancellation may dismiss only a verified non-pending receipt',()=>{
  assert.equal(canDismissProposal([{id:'a',state:'approval_expired'}],'a'),true);
  assert.equal(canDismissProposal([{id:'a',state:'active'}],'a'),true);
  for(const rows of [[],[{id:'other',state:'expired'}],[{id:'a',state:'proposed'}],[{id:'a',state:'unknown'}]])assert.equal(canDismissProposal(rows,'a'),false);
});
test('composer derives its count without a per-keystroke state setter',()=>{
  const main=readFileSync(new URL('../src/main.jsx',import.meta.url),'utf8');
  const composer=main.slice(main.indexOf('function Composer('),main.indexOf('function EmptyConversation('));
  assert.ok(composer.includes('const characters=text.length;'));
  assert.ok(!composer.includes('setCharacters'));
  assert.ok(main.includes("defaultOpen={w.prefs.detail==='expanded'}"));
  assert.ok(main.includes('<WorkspacePanels key={review.id}'));
});
