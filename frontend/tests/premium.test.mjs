import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectionFor,uniqueNotes,endpoint,actionPresentation,shouldRevealAnswer,communicationLayout,activityOperations,timePlotRows} from '../src/domain.js';
const review={evidence:{capture:{sha256:'source'},packets:[{id:'source:p1'},{id:'source:p2'}],log_records:[{id:'source:l3'}],flows:[],facts:[]},turns:[]};
test('viewing and closing evidence cannot modify question context',()=>{
  const attached='source:p2';const viewed=inspectionFor('source:p1',review);
  assert.equal(viewed.id,'source:p1');assert.equal(attached,'source:p2');assert.equal(viewed.selected_reference,undefined);
  assert.equal(inspectionFor('other:p1',review),null);
});
test('aggregate selection retains members rather than selecting the first',()=>{
  const viewed=inspectionFor({title:'Direction',count:3,references:['source:p1','source:p2','other:p7']},review);
  assert.deepEqual(viewed.references,['source:p1','source:p2']);assert.equal(viewed.unavailable_references,1);assert.equal(viewed.id,undefined);assert.equal(viewed.aggregate,true);
});
test('physical logs remain original log references in aggregates',()=>assert.deepEqual(inspectionFor({references:['source:l3']},review).references,['source:l3']));
test('duplicate coverage paragraphs are removed without swallowing distinct limits',()=>assert.deepEqual(uniqueNotes(['Short window.'],['short window','Payload is missing.']),['Short window.','Payload is missing.']));
test('missing ports never become undefined or an invented service',()=>{assert.equal(endpoint('10.0.0.1',null),'10.0.0.1');assert.equal(endpoint('',80),'Not retained');});
test('answer positioning respects manual reading and waits for the saved turn',()=>{assert.equal(shouldRevealAnswer({following:false,completed:true,hasTurn:true}),false);assert.equal(shouldRevealAnswer({following:true,completed:true,hasTurn:false}),false);assert.equal(shouldRevealAnswer({following:true,completed:true,hasTurn:true}),true);});
test('proposal, applying and restoration states are distinct',()=>{assert.equal(actionPresentation('proposed').text,'Approval required');assert.equal(actionPresentation('applying').text,'Applying');assert.equal(actionPresentation('rollback_failed').tone,'failed');});
test('hub layout separates three hosts and retains compact two-host layout',()=>{const graph=communicationLayout(['a','b','c'],[{source:'a',destination:'b'},{source:'c',destination:'a'}]);assert.equal(graph.places.get('a').x,155);assert.notEqual(graph.places.get('b').y,graph.places.get('c').y);assert.equal(communicationLayout(['a','b'],[]).height,188);});
test('finished operations stop appearing as running, even with different event indexes',()=>{const operations=activityOperations([{sequence:1,type:'tool_started',data:{tool:'get_packets',index:0}},{sequence:2,type:'tool_finished',data:{tool:'get_packets',index:1,ok:true}},{sequence:3,type:'tool_started',data:{tool:'get_flows',index:1}}]);assert.equal(operations.length,2);assert.equal(operations[0].state,'done');assert.equal(operations[1].state,'working');});
test('large aggregate membership is bounded explicitly without inventing missing references',()=>{const packets=Array.from({length:300},(_,n)=>({id:`source:p${n}`}));const selection=inspectionFor({references:packets.map(p=>p.id)}, {...review,evidence:{...review.evidence,packets}});assert.equal(selection.references.length,256);assert.equal(selection.references_omitted,44);assert.equal(selection.unavailable_references,0);});
test('area steps use real bin boundaries and last endpoint does not invent a bin',()=>{const bins=[{start_seconds:0,end_seconds:1,count:2,protocols:{TCP:2}},{start_seconds:1,end_seconds:2,count:1,protocols:{UDP:1}}];const area=timePlotRows(bins,'area');assert.deepEqual(area.map(r=>r.time),[0,1,2]);assert.deepEqual(area.map(r=>r.index),[0,1,1]);assert.equal(area[1].TCP,0);assert.deepEqual(timePlotRows(bins).map(r=>r.time),[.5,1.5]);});
