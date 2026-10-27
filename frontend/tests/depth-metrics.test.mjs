import test from 'node:test';
import assert from 'node:assert/strict';
import {diagnosticMetric,controlTimingDelta} from '../src/depth-metrics.mjs';
test('a transfer timeout is elapsed checking, not a completed transfer or rate',()=>{
  assert.equal(diagnosticMetric({complete:false,total_seconds:12,failure_type:'TimeoutExpired',payload_kbit_per_second:500},'transfer'),'Check timed out after 12 s');
});
test('missing measurements do not acquire seconds or throughput units',()=>{
  assert.equal(diagnosticMetric({},'health'),'First-byte timing unavailable');
  assert.equal(diagnosticMetric({complete:false},'transfer'),'Transfer incomplete');
  assert.equal(diagnosticMetric({complete:true},'transfer'),'Complete transfer timing unavailable');
});
test('complete transfer measurements retain zero and the explicit rate',()=>{
  assert.equal(diagnosticMetric({complete:true,total_seconds:0,payload_kbit_per_second:256},'transfer'),'Complete transfer 0 s · 256 kbit/s');
});
const row=(seconds,complete=true,profile='transfer',objective='Same service')=>({profile,objective,result:{clients:{control:{complete,total_seconds:seconds,first_byte_seconds:seconds}}}});
test('control comparison rejects incomplete transfers and nonmatching conditions',()=>{
  assert.equal(controlTimingDelta(row(.2),row(12,false)),null);
  assert.equal(controlTimingDelta(row(12,false),row(.2)),null);
  assert.equal(controlTimingDelta(row(.2),row(.1,true,'health')),null);
  assert.equal(controlTimingDelta(row(.2),row(.1,true,'transfer','Different objective')),null);
  assert.equal(controlTimingDelta(null,row(.1)),null);
});
test('finite comparable outcomes calculate their genuine change',()=>{
  assert.equal(controlTimingDelta(row(.2),row(.1)),-.1);
  assert.equal(controlTimingDelta(row(0,true,'health'),row(.1,true,'health')),.1);
  assert.equal(controlTimingDelta(row(NaN),row(.1)),null);
});
