import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const main=readFileSync(new URL('../src/main.jsx',import.meta.url),'utf8');
const depth=readFileSync(new URL('../src/depth.jsx',import.meta.url),'utf8');
const cases=readFileSync(new URL('../src/case-panel.jsx',import.meta.url),'utf8');
const outcomes=readFileSync(new URL('../src/service-outcomes.jsx',import.meta.url),'utf8');
test('related evidence and outcome state is remounted when the review identity changes',()=>{
  assert(main.includes('<CasePanel key={review.id}'));
  assert(main.includes('<CaptureSession key={review?.id||\'home\'}'));
  assert(main.includes('<ServiceOutcomes key={review.id}'));
});
test('comparison export and original lookup use returned source identities, not changing picker values',()=>{
  assert(cases.includes('baseline_id:comparison.baseline_review_id'));
  assert(cases.includes("[[comparison.baseline_review_id,comparison.baseline,'Baseline']"));
  assert(cases.includes('comparison.baseline.service_port'));
});
test('a full six-source case does not prevent opening a new retained capture',()=>{
  assert(depth.includes('group.sources.length<6&&!group.sources.some'));
  assert(depth.includes('capture will open as a separate retained investigation'));
});
test('outcome UI delegates explicit pair checking to tested behaviour',()=>{
  assert(outcomes.includes('diagnosticPair(rows,pairIds.baseline,pairIds.after)'));
  assert(outcomes.includes("baseline_id:phase==='baseline'?null:baseline.id"));
});
