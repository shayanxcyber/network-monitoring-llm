import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=name=>readFileSync(new URL('../src/'+name,import.meta.url),'utf8');
const css=read('landing.css'),source=read('main.jsx');

test('landing layout has one stylesheet owner, with no legacy narrow or nested-scroll rules',()=>{
  for(const file of ['style.css','premium.css','refinement.css'])assert(!/\.(welcome|home-recent)(?![\w-])/.test(read(file)),file+' must not compete with landing layout');
  assert.match(css,/\.welcome\s*\{[^}]*max-width:\s*none;/);
  assert.match(css,/\.welcome\s*\{[^}]*overflow:\s*visible;/);
  assert.match(css,/\.main\.is-home\s*\{[^}]*overflow-y:\s*auto;/);
});

test('full-width home layout does not change investigation scrolling or card actions',()=>{
  assert.match(source,/screen!=='actions'&&!review\?'is-home':''/);
  assert.match(source,/className="welcome-intro"/);
  assert.match(source,/<HomeRecent reviews=\{reviews\} select=\{select\}\/>/);
  assert.match(css,/@media \(max-width: 1000px\)/);
  assert.match(css,/\.welcome\s*\{[^}]*flex:\s*0 0 auto;/);
  assert(!/align-content:\s*center/.test(css));
});

test('home presents real recent records across the workspace, not four floating cards',()=>{
  const recent=read('refinement.jsx');
  assert.match(recent,/reviews\.slice\(0,8\)/);
  assert.match(recent,/className="recent-row"/);
  assert.match(recent,/onClick=\{\(\)=>select\(r.id\)\}/);
  assert.match(recent,/<time dateTime=\{valid\?r.updated_at:undefined\}/);
  assert.match(css,/\.recent-columns, \.recent-row\s*\{[^}]*minmax\(0, 1fr\)/);
});

test('quiet sidebar history remains scrollable and keyboard focusable',()=>{
  assert.match(source,/className="saved-list" role="region" aria-label="Saved investigations" tabIndex=\{0\}/);
  assert.match(css,/\.sidebar \.saved-list\s*\{[^}]*overflow-y:\s*auto;/);
  assert.match(css,/scrollbar-color:\s*transparent transparent;/);
  assert.match(css,/\.sidebar \.saved-list:hover, \.sidebar \.saved-list:focus-within/);
});
