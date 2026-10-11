import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../src/main.jsx',import.meta.url),'utf8');
const css=readFileSync(new URL('../src/refinement.css',import.meta.url),'utf8');

test('composer reuses automatic sizing with one resting row and six-row cap',()=>{
  assert.match(source,/<ComposerPrimitive\.Input[^>]*minRows=\{1\}[^>]*maxRows=\{6\}/);
  assert.match(css,/\.composer textarea\{min-height:0;/);
  assert.match(source,/latestReply=\{unread\?jump:null\}/);
  assert.match(css,/\.composer-wrap>\.return-latest\{top:-40px;bottom:auto\}/);
});

test('conversation search has a stable frame and a centred empty placeholder',()=>{
  assert.match(css,/\.thread-search\{[^}]*border:1px solid #e0e6eb/);
  assert.match(css,/\.thread-search input\{width:100%;min-width:0/);
  assert.match(css,/\.thread-search input:placeholder-shown\{text-align:center\}/);
});
