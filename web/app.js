'use strict';
const $=id=>document.getElementById(id), UI=PacketPilotUI;
const views=UI.stateStore(), cache=new Map(), visuals=new Map(), actionRefreshes=new Set();
let config, current=null, index=new Map(), reviewList=[], selectionTicket=0;
let pending=null, pendingProposal=null, approvalSubmitting=false, captureBusy=false, actionRenderKey='', replayVersion=0;
const reduced=matchMedia('(prefers-reduced-motion: reduce)');
function node(tag,text,className){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;}
function button(text,className,callback){const el=node('button',text,className);el.type='button';el.onclick=callback;return el;}
function notice(message){$('notice').textContent=message;$('notice').hidden=!message;}
function date(value){const d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString([],{dateStyle:'medium',timeStyle:'short'});}
function short(id){return UI.shortReference(id);}
function brand(){return document.querySelector('.brand-symbol').cloneNode(true);}
async function api(path,options={}){
 const headers={...options.headers};if(options.method&&options.method!=='GET')headers['X-PacketPilot-Token']=config.csrf;
 if(options.body&&!(options.body instanceof FormData))headers['Content-Type']='application/json';
 let response;try{response=await fetch(path,{...options,headers});}catch(_){throw new Error('The backend could not be reached. Your previous answers and draft are still here.');}
 let data;try{data=await response.json();}catch(_){throw new Error('The backend returned an unreadable response. Your saved investigation is unchanged.');}
 if(!response.ok){const e=new Error(typeof data.detail==='string'?data.detail:'Check the supplied details and try again.');e.status=response.status;throw e;}return data;
}
async function loadConfig(){config=await api('/api/config');$('connection-label').textContent=config.api_ready?'Backend available · Ready':'Backend available · Offline';}
function setExpanded(expanded){$('shell').classList.toggle('expanded',expanded);$('toggle-sidebar').setAttribute('aria-expanded',String(expanded));$('toggle-sidebar').setAttribute('aria-label',expanded?'Collapse sidebar':'Expand sidebar');}
function renderList(){
 const q=$('review-search').value.toLowerCase().trim(), list=$('review-list');list.replaceChildren();$('review-count').textContent=reviewList.length;
 const shown=reviewList.filter(r=>r.title.toLowerCase().includes(q));
 for(const r of shown){const b=button(undefined,'review-item'+(current?.id===r.id?' selected':''),()=>selectReview(r.id).catch(e=>notice(e.message)));b.dataset.reviewId=r.id;b.append(node('strong',r.title),node('small',`${r.provider==='api'?'Conversation':'Offline inspection'} · ${date(r.updated_at)}`));list.append(b);}
 if(!shown.length)list.append(node('p',q?'No matching investigations.':'Saved investigations will appear here.','sidebar-empty'));
}
async function refreshList(){reviewList=await api('/api/reviews');renderList();}
function saveView(){if(!current)return;const state=views.get(current.id);state.draft=$('question').value;state.scrollTop=$('turns').scrollTop;state.evidenceTop=$('evidence-scroll').scrollTop;}
function setView(view){if(!current)return;cancelReplay();views.get(current.id).view=view;for(const b of document.querySelectorAll('[data-view]'))b.setAttribute('aria-selected',String(b.dataset.view===view));for(const name of ['connections','records','coverage','actions'])$(name+'-view').hidden=name!==view;}
function renderComposer(){
 if(!current)return;const s=views.get(current.id),own=pending?.reviewId===current.id,other=pending&&!own;
 $('question-form').classList.toggle('is-busy',!!own);$('question-form').classList.toggle('has-error',!!s.failed);
 $('working').hidden=!own;$('retry-question').hidden=!s.failed||!!pending;$('pending-source').hidden=!other;
 $('send-question').disabled=!!pending||captureBusy||!$('question').value.trim()||(current.provider==='api'&&!config?.api_ready);
 $('send-question').setAttribute('aria-label',current.provider==='api'?'Send question':'Show offline summary');
 $('composer-note').textContent=own?'Investigating this evidence. The request is running.':other?'A question is running in another investigation.':s.failed?s.failed.message:current.provider==='api'?'Saved evidence. Questions use the configured hosted model.':'Offline inspection. No model request will be sent.';
}
function renderReview(review){
 const same=current?.id===review.id;if(same)saveView();else{$('turns').replaceChildren();actionRenderKey='';}
 current=review;cache.set(review.id,review);index=UI.referenceIndex(review);const ev=review.evidence,s=views.get(review.id),log=ev.input_kind==='network_log',counts=UI.counts(ev);
 if(review.pending_request&&!pending){pending={reviewId:review.id,question:review.pending_request.question,request_id:review.pending_request.request_id,resumed:true};if(!s.draft)s.draft=pending.question;}
 if(!s.view)s.view=counts.partial?'coverage':'connections';
 $('welcome').hidden=true;$('workspace').hidden=false;$('review-title').textContent=review.title;$('breadcrumb-current').textContent=review.title;
 $('input-label').textContent=log?'SAVED NETWORK LOG':'NETWORK INVESTIGATION';$('evidence-title').textContent=log?'Log evidence':'Capture evidence';
 const rows=UI.records(ev),times=rows.map(UI.time).filter(Number.isFinite),duration=times.length?Math.max(...times)-Math.min(...times):null;
 $('review-meta').textContent=`${counts.total} ${log?'original log rows':'packets'} · ${UI.decoderLabel(ev.decoder)}${duration===null?'':` · ${duration.toFixed(3)} s recorded window`}`;
 $('fact-count').textContent=ev.schema_version==='2'?`${rows.length} ${log?'original lines':'records'}`:`${(ev.facts||[]).length} facts`;
 const latest=[...(review.turns||[])].reverse().find(t=>['2.0','3.0','4.0'].includes(t.explanation.answer?.schema_version)&&t.explanation.answer.assessment);
 $('finding-badge').textContent=latest?latest.explanation.answer.assessment.replaceAll('_',' '):review.provider==='api'?'Not yet assessed':'Offline inspection';
 $('mode-label').textContent=review.provider==='api'?'Saved conversation':'Legacy comparator · no model';
 $('export-review').href=`/api/reviews/${review.id}/export`;$('lab-response').hidden=!review.lab_binding;
 $('capture-hash').textContent='SHA-256 '+ev.capture.sha256;$('question').value=s.draft;$('record-filter').value=s.filter;$('record-sort').value=s.sort;
 renderConnections();renderRecords();renderCoverage();setView(s.view);renderTurns(review);renderComposer();renderList();
 $('turns').scrollTop=s.scrollTop;$('evidence-scroll').scrollTop=s.evidenceTop;$('jump-latest').hidden=!s.unread;
 refreshActions().catch(e=>{$('response-actions').replaceChildren(node('p',e.message,'inline-error'));});
}
async function selectReview(id,replace=false){
 saveView();cancelReplay();await dismissProposal();
 const ticket=++selectionTicket;
 const saved=await api(`/api/reviews/${encodeURIComponent(id)}`);if(ticket!==selectionTicket)return;
 renderReview(saved);const hash=`#review=${saved.id}`;if(location.hash!==hash)history[replace?'replaceState':'pushState']({},'',hash);notice('');
 try{const data=await api(`/api/reviews/${saved.id}/visual`);if(data.supported&&data.capture_sha256===saved.evidence.capture.sha256)visuals.set(saved.id,data.relationships);else visuals.set(saved.id,{unavailable:data.reason});if(ticket===selectionTicket&&current?.id===saved.id){const top=$('evidence-scroll').scrollTop;renderConnections();$('evidence-scroll').scrollTop=top;}}
 catch(e){if(ticket===selectionTicket&&current?.id===saved.id){visuals.set(saved.id,{unavailable:e.message});renderConnections();}}
}
function referenceLinks(references,reviewId=current?.id){const wrap=node('div',undefined,'answer-links');for(const id of references||[]){const b=button(short(id)+' ↗','evidence-link',()=>{if(current?.id!==reviewId)return;inspectReference(id,b);});b.title=id;b.dataset.reference=id;wrap.append(b);}return wrap;}
function fields(items){const dl=node('dl',undefined,'identity-details');for(const [key,value]of items){dl.append(node('dt',key),node('dd',value===null||value===undefined?'Not available':String(value)));}return dl;}
function showInspector(title,content,kind='ORIGINAL EVIDENCE'){cancelReplay();$('inspector-title').textContent=title;$('inspector-kind').textContent=kind;$('inspector-content').replaceChildren(content);if(!$('inspector').open)$('inspector').showModal();}
function inspectReference(id){
 const record=index.get(id);if(!record){notice('This reference is unavailable in the saved evidence. No substitute record has been selected.');return;}
 const s=views.get(current.id);s.selectedRef=id;document.querySelectorAll('[data-record-id]').forEach(el=>el.classList.toggle('selected',el.dataset.recordId===id));
 const content=node('div'),value=record.value;content.append(node('p',id,'mono reference-id'));
 if(value?.packet!==undefined||value?.line_number!==undefined){const ep=UI.endpoints(value),meta=UI.recordFields(value,UI.timeOrigin(current.evidence)),stamp=UI.time(value),timestamp=Number.isFinite(stamp)&&Number.isFinite(new Date(stamp*1000).getTime())?new Date(stamp*1000).toISOString():value.timestamp;
  const visible=[['Original identity',short(id)],['Recorded timestamp',timestamp],['Relative to source start',meta.elapsed],['Source',ep.source+(ep.sourcePort!==''?':'+ep.sourcePort:'')],['Destination',ep.destination+(ep.destinationPort!==''?':'+ep.destinationPort:'')],['Protocol',value.protocol],['Header status',value.status],[meta.lengthLabel,meta.length===null?null:meta.length+' bytes']];
  if(value.tcp)visible.push(['TCP flags',meta.flags||null]);if(meta.payload!==null)visible.push(['Payload length',meta.payload+' bytes']);if(value.tcp?.sequence!==undefined)visible.push(['TCP sequence',value.tcp.sequence]);if(value.tcp?.acknowledgement!==undefined)visible.push(['TCP acknowledgement',value.tcp.acknowledgement]);if(value.ipv4?.ttl!==undefined)visible.push(['IPv4 TTL',value.ipv4.ttl]);content.append(fields(visible));
  if(value.line_number!==undefined)content.append(fields([['Exported frame number',value.source_frame_number],['Original line offset',value.byte_offset],['Original line length',value.byte_length],['Original line SHA-256',value.line_sha256]]),node('p','Original log-line identity is preserved. Exported fields do not establish captured packet bytes.','quiet'));else content.append(fields([['Capture file offset',value.file_offset],['Wire length',value.wire_bytes],['Captured frame SHA-256',value.frame_sha256]]));}
 if(value?.endpoint_a){const endpoint=e=>`${e?.address||'Unknown'}${e?.port!==undefined?':'+e.port:''}`,row=UI.connectionRows(current.evidence,visuals.get(current.id)).find(r=>r.id===id);content.append(fields([['Endpoint A',endpoint(value.endpoint_a)],['Endpoint B',endpoint(value.endpoint_b)],['Protocol',value.protocol],['Retained records',value.packet_count??value.record_count],['Duration',value.duration_seconds===undefined?null:value.duration_seconds+' seconds'],['A → B records',value.directions?.a_to_b],['B → A records',value.directions?.b_to_a]]),node('p','Endpoint ordering is a bidirectional aggregate, not an assignment of client or server roles.','quiet'));if(row?.references.length)content.append(node('h3','Original records'),referenceLinks(row.references.slice(0,20)));}
 const refs=value?.supporting_references;if(refs)content.append(referenceLinks(refs));
 const raw=node('details',undefined,'fact raw-record');raw.append(node('summary','Full retained fields · JSON'),node('pre',JSON.stringify(value,null,2),'record-detail'));content.append(raw);
 if(id===current.evidence.capture.sha256+':capture'){const decoder=node('details',undefined,'fact');decoder.append(node('summary','Decoder metadata'),node('pre',JSON.stringify(current.evidence.decoder,null,2),'record-detail'));content.append(decoder);}
 const label=Number.isInteger(value?.selected_tcp_record_count)?`TCP exchange analysis · ${value.selected_tcp_record_count} header records`:record.label;
 showInspector(label,content);
}
function renderRecords(){
 if(!current)return;const ev=current.evidence,s=views.get(current.id),log=ev.input_kind==='network_log';
 const rows=UI.filteredRecords(ev,s.filter,s.sort),table=$('record-table');table.replaceChildren();$('record-count').textContent=`${rows.length} matching ${log?'log lines':'packets'} · original identities preserved`;
 const grid=node('table',undefined,'evidence-grid packet-grid'),head=node('thead'),header=node('tr'),body=node('tbody'),origin=UI.timeOrigin(ev);grid.setAttribute('aria-label',log?'Original exported log fields':'Original packet fields');
 for(const label of [log?'Line':'Packet','Time +','Type','Source →','Destination','Flags',log?'Reported B':'Captured B','Status']){const cell=node('th',label);cell.scope='col';header.append(cell);}head.append(header);grid.append(head,body);table.append(grid);
 for(const r of rows.slice(0,s.limit)){const ep=UI.endpoints(r),meta=UI.recordFields(r,origin),row=node('tr',undefined,'evidence-data-row'+(s.selectedRef===r.id?' selected':''));row.dataset.recordId=r.id;
  const first=node('td'),open=button(short(r.id)+' ↗','record-open',()=>inspectReference(r.id));open.setAttribute('aria-label',`Inspect ${log?'original line':'packet'} ${UI.recordNumber(r)}`);first.append(open);row.append(first);
  for(const [text,cls]of [[meta.elapsed,'mono'],[r.protocol||'Unknown','mono'],[ep.source?`${ep.source}${ep.sourcePort!==''?':'+ep.sourcePort:''}`:'Not retained','mono endpoint-cell'],[ep.destination?`${ep.destination}${ep.destinationPort!==''?':'+ep.destinationPort:''}`:'Not retained','mono endpoint-cell'],[meta.flags||'Not applicable','mono'],[meta.length===null?'Not retained':meta.length,'mono'],[r.status,'status'+(r.status==='decoded'?'':' partial')]])row.append(node('td',text,cls));
  row.onclick=e=>{if(!e.target.closest('button'))inspectReference(r.id);};row.title=UI.issues(r)||r.id;body.append(row);
 }
 if(rows.length>s.limit)table.append(button('Show 100 more records','records-more',()=>{s.limit+=100;renderRecords();}));
 if(!rows.length)table.append(node('p','No matching records. Change or clear the filter.','surface quiet'));
 if(ev.schema_version!=='2'){for(const fact of ev.facts||[])table.append(button(fact.text,'flow-card',()=>inspectReference(fact.id)));}
}
function renderCoverage(){
 const ev=current.evidence,c=UI.counts(ev),target=$('coverage-view');target.replaceChildren();
 const box=node('section',undefined,'surface');box.append(node('h3',c.partial?'Some evidence is incomplete.':'Retained header coverage'),node('p',ev.coverage?.scope||'Coverage is bounded by the decoder and the saved input.'));
 const grid=node('div',undefined,'coverage-grid');for(const [label,num]of [['Total records',c.total],['Decoded records',c.decoded],['Malformed / invalid',c.malformed],['Other / unsupported',c.other]]){const tile=node('div',undefined,'coverage-tile');tile.append(node('strong',num),node('span',label));grid.append(tile);}box.append(grid);
 const limits=node('ul',undefined,'coverage-list');for(const text of ev.limitations||[])limits.append(node('li',text));box.append(limits,referenceLinks([ev.capture.sha256+':coverage',ev.capture.sha256+':overview']));
 if(ev.input_kind==='network_log')box.append(node('p','Only exported fields can be inspected. Original log-line hashes and byte ranges are retained separately from source-frame identifiers.','quiet'));
 target.append(box);const issues=UI.records(ev).filter(r=>r.status!=='decoded');for(const row of issues)target.append(button(`${short(row.id)} · ${row.status} · ${UI.issues(row)}`,'flow-card',()=>inspectReference(row.id)));
}
function svg(tag,attributes={},text){const el=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [k,v]of Object.entries(attributes))el.setAttribute(k,v);if(text!==undefined)el.textContent=text;return el;}
function hostGroup(x,label,address,port,reference){const g=svg('g',{class:'host-control',role:'button',tabindex:'0','aria-label':`Inspect ${label.toLowerCase()} record ${short(reference)}`});g.append(svg('rect',{x,y:48,width:150,height:98,rx:12,class:'host'}),svg('text',{x:x+14,y:70,class:'caption'},label),svg('text',{x:x+14,y:94,class:'address'},address),svg('text',{x:x+14,y:120,class:'caption'},port));g.onclick=()=>inspectReference(reference);g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inspectReference(reference);}};return g;}
function selectedExchange(){const xs=visuals.get(current?.id)?.exchanges||[],s=views.get(current?.id);return xs.find(x=>x.syn_reference===s.exchangeRef)||null;}
function renderConnections(){
 const target=$('connections-view');target.replaceChildren();if(!current)return;const ev=current.evidence,s=views.get(current.id),relationships=visuals.get(current.id),xs=relationships?.exchanges||[];
 const hosts=new Set(UI.records(ev).flatMap(r=>{const ep=UI.endpoints(r);return [ep.source,ep.destination].filter(Boolean);}));
 const log=ev.input_kind==='network_log',counts=UI.counts(ev),origin=UI.timeOrigin(ev),rows=UI.connectionRows(ev,relationships),selectedRow=rows.find(r=>r.id===s.connectionRef);
 const overview=node('div',undefined,'evidence-overview');overview.append(node('span',`${hosts.size} addresses`));for(const [protocol,count]of Object.entries(UI.protocolCounts(ev)))overview.append(node('span',`${protocol} ${count}`));overview.append(button(counts.partial?'Partial coverage ↗':'Header coverage ↗','overview-coverage'+(counts.partial?' partial':''),()=>setView('coverage')));target.append(overview);
 const heading=node('div',undefined,'exchange-heading');heading.append(node('h3',`${rows.length} ${log?'observed endpoint pairs':'retained flow groups'}`),button('View records','text-button',()=>setView('records')));target.append(heading);
 if(log)target.append(node('p','Grouped exported lines, not reconstructed packet sessions. TCP and UDP are included.','table-caption'));
 const wrap=node('div',undefined,'connection-table'),grid=node('table',undefined,'evidence-grid connection-grid'),head=node('thead'),header=node('tr'),body=node('tbody');grid.setAttribute('aria-label',log?'Observed log endpoint pairs':'Retained bidirectional flows');
 for(const label of ['Type','Recorded endpoint pair','Records','First +']){const cell=node('th',label);cell.scope='col';header.append(cell);}head.append(header);grid.append(head,body);wrap.append(grid);target.append(wrap);
 for(const row of rows.slice(0,100)){const tr=node('tr',undefined,'evidence-data-row'+(s.connectionRef===row.id?' selected':'')),pair=node('td'),select=()=>{cancelReplay();s.connectionRef=row.id;s.exchangeRef=row.exchanges[0]?.syn_reference||null;renderConnections();};
  const a=`${row.a.address||'Unknown'}${row.a.port!==''&&row.a.port!==undefined?':'+row.a.port:''}`,b=`${row.b.address||'Unknown'}${row.b.port!==''&&row.b.port!==undefined?':'+row.b.port:''}`,open=button(undefined,'connection-open',select);open.append(node('span',a+' ↔','mono'),node('span',b,'mono'));open.setAttribute('aria-label',`Select ${row.protocol} pair ${a} and ${b}`);pair.append(open);tr.append(node('td',row.protocol||'Unknown','mono'),pair,node('td',row.count,'mono'),node('td',UI.relativeTime(row.firstTime,origin),'mono'));tr.dataset.connectionId=row.id;tr.onclick=e=>{if(!e.target.closest('button'))select();};body.append(tr);
 }
 if(rows.length>100)target.append(node('p',`${rows.length-100} additional groups remain in the source export. All records are available in Records.`,'table-caption'));
 if(!rows.length)target.append(node('p','No endpoint pairs can be displayed from these retained fields. Inspect Records and Coverage for omitted or unreadable information.','table-caption'));
 if(!relationships)target.append(node('p','Loading the neutral TCP pairing details…','table-caption'));else if(relationships.unavailable)target.append(node('p',relationships.unavailable,'table-caption'));
 if(selectedRow&&!s.exchangeRef&&selectedRow.exchanges.length)s.exchangeRef=selectedRow.exchanges[0].syn_reference;
 const selected=selectedExchange();
 if(selectedRow){const selection=node('div',undefined,'selection-heading');selection.append(node('span',`${selectedRow.protocol} selection · ${selectedRow.count} retained ${log?'lines':'records'}`),button('Inspect selection ↗','small-button',()=>inspectReference(selectedRow.reference)));target.append(selection);}
 if(selected){
  const box=node('section',undefined,'surface map-surface'),toolbar=node('div',undefined,'map-toolbar');toolbar.append(node('h3','Selected TCP exchange'),button('Explain visually','small-button',()=>startReplay()));toolbar.lastChild.id='explain-visually';box.append(toolbar);
  const stats=node('div',undefined,'map-stats');stats.append(node('span',`Service port ${selected.destination_port}`,'tag neutral'),node('span',selected.candidate_reply_reference?'Reply candidate retained':'No paired reply retained','tag neutral'));box.append(stats);
  const diagram=svg('svg',{viewBox:'0 0 540 200',class:'map-diagram',role:'group','aria-label':'Recorded request and reply directions'}),defs=svg('defs');
  const arrow=svg('marker',{id:'request-arrow',viewBox:'0 0 10 10',refX:8,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});arrow.append(svg('path',{d:'M1 1L8 5L1 9',fill:'none',stroke:'#3459ad','stroke-width':1.5}));defs.append(arrow);diagram.append(defs);
  diagram.append(svg('path',{id:'request-path',d:'M164 77 Q270 20 376 77',class:'request-line','marker-end':'url(#request-arrow)'}));
  if(selected.candidate_reply_reference)diagram.append(svg('path',{id:'reply-path',d:'M376 124 Q270 181 164 124',class:'reply-line','marker-end':'url(#request-arrow)'}));
  diagram.append(hostGroup(14,'SOURCE',selected.source,`TCP / ${selected.source_port}`,selected.syn_reference),hostGroup(376,'SERVICE',selected.destination,`TCP / ${selected.destination_port}`,selected.candidate_reply_reference||selected.syn_reference));
  diagram.append(svg('text',{x:180,y:44,class:'caption'},'SYN →'),svg('text',{x:195,y:177,class:'caption'},UI.flags(selected.candidate_reply_flags)||'No paired reply'),svg('circle',{id:'travel-marker',r:6,class:'marker',visibility:'hidden'}));box.append(diagram);
  const caption=node('p',undefined,'map-caption');caption.id='replay-caption';caption.textContent=selected.reply_acknowledgement_matches_syn===true?'Sequence-matched reply. Select the original records below.':'Candidate matching only; missing sequence fields or ambiguity may limit pairing.';box.append(caption,referenceLinks(selected.supporting_references));
  if(selected.reply_delay_seconds!==null)box.append(node('p',`Recorded reply delay: ${selected.reply_delay_seconds} s. Animation timing is illustrative, not live traffic.`,'quiet'));
  if(selected.ambiguous)box.append(node('p','Multiple possible replies are present. This drawing is not proof of a completed connection.','inline-error'));
  target.append(box);
 }else if(selectedRow){const detail=node('section',undefined,'surface compact-selection');detail.append(node('h3',log?'Selected exported records':'Selected flow records'),node('p',selectedRow.flagNames?`Retained TCP flags: ${selectedRow.flagNames}`:'No TCP SYN/reply diagram applies to this selection. The original records remain available.'),referenceLinks(selectedRow.references.slice(0,20)));if(selectedRow.references.length>20)detail.append(node('p','First 20 references shown. View Records for the full retained source.','quiet'));target.append(detail);}
 else target.append(node('p','Select an endpoint pair to inspect its records and any available TCP request/reply diagram.','table-caption selection-prompt'));
 if(selectedRow?.exchanges.length>1){const detail=node('details',undefined,'fact');detail.append(node('summary',`${selectedRow.exchanges.length} SYN attempts in this selection`));for(const x of selectedRow.exchanges)detail.append(button(`${short(x.syn_reference)} · ${x.candidate_reply_reference?UI.flags(x.candidate_reply_flags):'No paired reply'}`,'attempt-row'+(s.exchangeRef===x.syn_reference?' selected':''),()=>{cancelReplay();s.exchangeRef=x.syn_reference;renderConnections();}));target.append(detail);}
 if(relationships?.exchange_details_omitted)target.append(node('p',`${relationships.exchange_details_omitted} TCP pairing details omitted from the bounded projection. All retained records remain available.`,'table-caption'));
}
function cancelReplay(){replayVersion++;const marker=$('travel-marker');if(marker)marker.setAttribute('visibility','hidden');}
async function startReplay(){
 cancelReplay();const x=selectedExchange(),caption=$('replay-caption'),marker=$('travel-marker');if(!x||!caption||!marker)return;
 const version=replayVersion;caption.textContent='Illustrative exchange. Recorded packet timing is unchanged.';
 if(reduced.matches){caption.textContent='Static explanation: SYN travels source → service; any paired reply travels service → source. Original records remain selectable.';return;}
 const leg=(pathId,text)=>new Promise(resolve=>{const path=$(pathId);if(!path){resolve(false);return;}const length=path.getTotalLength();let start=null;caption.textContent=text;marker.setAttribute('visibility','visible');
  function step(now){if(version!==replayVersion||document.hidden){resolve(false);return;}if(start===null)start=now;const t=Math.min(1,(now-start)/2000),point=path.getPointAtLength(length*t);marker.setAttribute('cx',point.x);marker.setAttribute('cy',point.y);if(t<1)requestAnimationFrame(step);else resolve(true);}requestAnimationFrame(step);
 });
 const hold=ms=>new Promise(resolve=>setTimeout(()=>resolve(version===replayVersion),ms));
 if(!await leg('request-path',`${short(x.syn_reference)} · SYN from ${x.source}:${x.source_port} to service ${x.destination_port}. Illustrative, not live.`))return;
 if(!await hold(650))return;
 if(x.candidate_reply_reference&&!await leg('reply-path',`${short(x.candidate_reply_reference)} · ${UI.flags(x.candidate_reply_flags)} reply reverses those endpoints. Illustrative, not live.`))return;
 if(!await hold(650))return;
 marker.setAttribute('visibility','hidden');caption.textContent='Exchange explanation complete. The static diagram and original evidence remain available.';
}
function section(parent,label,texts,references){if(!texts?.length)return;const box=node('section',undefined,'answer-section');box.append(node('h3',label));for(const text of texts)if(text)box.append(node('p',text,'answer-paragraph'));if(references)box.append(referenceLinks(references));parent.append(box);}
function trace(explanation){
 const operations=node('details',undefined,'fact'),steps=explanation.tool_trace||[];operations.append(node('summary',`Investigation trace · ${steps.length} tool operations · ${explanation.attempts||0} model calls`));
 if(!steps.length)operations.append(node('p','No additional tool inspection was requested.'));
 for(const step of steps){const detail=node('details',undefined,'fact');detail.append(node('summary',`${step.tool} · ${step.ok?'completed':'rejected'}`),node('p',JSON.stringify(step.arguments)),node('pre',JSON.stringify(step.result,null,2),'record-detail'));operations.append(detail);}
 operations.append(node('p',`Harness ${explanation.harness_version} · ${explanation.corrections||0} correction attempts.`));
 if(explanation.investigation_state){const state=node('details',undefined,'fact');state.append(node('summary','Saved investigation state'),node('pre',JSON.stringify(explanation.investigation_state,null,2),'record-detail'));operations.append(state);}return operations;
}
function renderTurn(turn,review){
 const el=node('article',undefined,'turn');el.dataset.runId=turn.run_id;el.append(node('div','YOUR QUESTION','question-label'),node('p',turn.question,'question-message'));
 const explanation=turn.explanation,answer=explanation.answer,modern=['2.0','3.0','4.0'].includes(answer.schema_version),conversation=answer.kind==='conversation',surface=node('section',undefined,'answer-surface'),heading=node('div',undefined,'answer-heading');heading.append(brand(),node('span','PacketPilot'),node('small',conversation?'Conversation':modern?'Evidence-led assessment':explanation.source==='api'?'Legacy rule-conditioned answer':'Offline summary'));surface.append(heading);
 if(explanation.status==='fallback_after_api_failure'){surface.append(node('p','Model answer unavailable. The following is a fixed-rule fallback, not an accepted model assessment.','inline-error'),node('p',explanation.api_error?.message||'Request failed.','api-error'));if(explanation.failed_attempt?.harness_version)surface.append(trace(explanation.failed_attempt));}
 surface.append(node('p',answer.summary,'answer-summary'));
 if(modern&&!conversation){
  for(const o of answer.observations||[])section(surface,'Observation',[o.text],o.references);
  section(surface,'Interpretation',[answer.interpretation]);section(surface,'Alternative explanations',answer.alternatives);section(surface,'Uncertainty',answer.uncertainty);section(surface,'Coverage · '+answer.coverage.status,answer.coverage.limitations);section(surface,'Questions for you',answer.questions);
  for(const m of answer.measurements||[])section(surface,'Measurement',[`${m.field}: ${m.value}`],[m.reference]);
  (answer.recommendations||[]).forEach((item,i)=>{
   const capability=(config.capabilities||[]).find(c=>c.action===item.action);
   section(surface,capability?.title||item.action.replaceAll('_',' '),[item.rationale],item.references);
   if(['block_source','rate_limit_service'].includes(item.action))surface.append(button('Review proposed action','small-button',()=>inspectRecommendation(review.id,turn.run_id,i).catch(e=>notice(e.message))));
   else if(capability?.unavailable)surface.append(node('p',capability.description,'quiet'));
  });
  (answer.code_suggestions||[]).forEach((example,i)=>{
   const box=node('section',undefined,'answer-section code-suggestion');box.append(node('h3',example.title),node('span','Unverified example · not executed','tag neutral'),node('pre',example.code,'suggested-code'));
   box.append(fields([['Intended target',example.target],['Expected effect',example.expected_effect],['Reversal',example.reversal]]));section(box,'Assumptions',example.assumptions);box.append(referenceLinks(example.references));
   const controls=node('div',undefined,'code-controls');controls.append(copyButton(example.code));const download=node('a','Download example','small-button');download.href=`/api/reviews/${review.id}/code/${i}?turn_id=${turn.run_id}`;controls.append(download);box.append(controls);surface.append(box);
  });
  if(explanation.harness_version)surface.append(trace(explanation));
  const selection=explanation.final_context_selection||explanation.context_selection;if(selection&&!selection.all_detail_included)surface.append(node('p',selection.records_omitted!==undefined?`Context subset: ${selection.records_omitted} log rows were not supplied after inspection. The full source is retained.`:`Context subset: ${selection.packets_omitted} packet records and ${selection.flows_omitted} flows were not supplied after inspection. The full source is retained.`,'api-error'));
 }else if(!conversation){section(surface,'Why',[answer.why]);section(surface,'What to check next',[answer.next_step]);surface.append(referenceLinks(answer.fact_ids,review.id));}
 if(explanation.review_note&&!conversation)surface.append(node('p',explanation.review_note,'turn-meta'));surface.append(node('p',`${date(turn.recorded_at)}${conversation?'':' · No network action executed by this answer.'}`,'turn-meta'));el.append(surface);return el;
}
function copyButton(text){return button('Copy code','small-button',async e=>{try{await navigator.clipboard.writeText(text);e.currentTarget.textContent='Copied';}catch(_){notice('Clipboard unavailable. Select the visible code to copy it.');}});}
async function inspectRecommendation(reviewId,turnId,index){
 const result=await api(`/api/reviews/${reviewId}/recommendations/${index}?turn_id=${turnId}`);if(current?.id!==reviewId)return;
 const content=node('div');content.append(node('p',result.rationale),referenceLinks(result.references),node('p',result.next_step,'quiet'));
 const rec=result.recommendation;content.append(fields([['Source',rec.target],['Service',rec.destination&&`${rec.destination}:${rec.port}`],['Duration',rec.duration_seconds&&`${rec.duration_seconds} seconds`],['Rate',rec.rate_kbit&&`${rec.rate_kbit} kbit/s`]]));
 const proposalError=node('p',undefined,'inline-error');proposalError.setAttribute('role','alert');proposalError.hidden=true;
 if(result.can_propose)content.append(button('Prepare exact proposal','primary-button',async e=>{const b=e.currentTarget;b.disabled=true;proposalError.hidden=true;try{const proposal=await api(`/api/reviews/${reviewId}/recommendations/${index}/propose`,{method:'POST',body:JSON.stringify({turn_id:turnId})});if(current?.id!==reviewId)return;$('inspector').close();showProposal(proposal,reviewId);await refreshActions();}catch(error){proposalError.textContent=error.message;proposalError.hidden=false;notice(error.message);b.disabled=false;}}));
 else if(result.status==='offline_mapping_required')content.append(button('Open current lab capture','primary-button',()=>{$('inspector').close();$('lab-capture').click();}));
 content.append(proposalError);showInspector(result.title,content,result.can_propose?'ACTION · NOT YET APPROVED':'RECOMMENDATION');
}
function showProposal(proposal,reviewId){
 pendingProposal={...proposal,reviewId};$('approval-error').hidden=true;$('approval-error').textContent='';$('approval-scope').textContent=proposal.confirmation;$('approval-confirmation').value='';const content=$('approval-plan');content.replaceChildren();
 const plan=proposal.command_plan;if(plan){content.append(node('p',proposal.reason),node('p',plan.expected_effect),fields([['Source',proposal.target],['Service',`${proposal.destination}:${proposal.port}`],['Duration',`${proposal.duration_seconds} seconds`],['Rate',proposal.parameters.rate_kbit?`${proposal.parameters.rate_kbit} kbit/s`:'Not applicable']]));
  if(proposal.origin)content.append(referenceLinks(proposal.origin.references));
  const code=plan.commands.join('\n');content.append(node('h3','Exact validated change'),node('pre',code,'suggested-code'),copyButton(code),node('h3','Exact reversal'),node('pre',plan.reversal.join('\n'),'suggested-code'),node('p',plan.expiry,'quiet'));
  const download=node('a','Download proposal plan','small-button');download.href=`/api/reviews/${reviewId}/actions/${proposal.id}/plan`;content.append(download);
 }
 $('approval-dialog').showModal();$('approval-confirmation').focus();
}
function renderTurns(review){
 const target=$('turns'),existing=new Map([...target.querySelectorAll(':scope > .turn')].map(el=>[el.dataset.runId,el]));
 if(!review.turns.length){if(!target.querySelector('.empty-conversation')){const empty=node('div',undefined,'empty-conversation');empty.append(node('strong','The evidence is ready.'),node('p',review.provider==='api'?'Ask a question to begin. PacketPilot uses retained observations and bounded read-only tools. Hosted requests send structured fields and bounded payload previews, not the raw capture.':'Inspect records and coverage, or ask for the legacy comparator summary. Offline mode does not call a model.'));target.replaceChildren(empty);}return;}
 target.querySelector('.empty-conversation')?.remove();for(const turn of review.turns)if(!existing.has(turn.run_id))target.append(renderTurn(turn,review));
}
async function submitQuestion(retry=null){
 if(pending||captureBusy||!current)return;const reviewId=current.id,s=views.get(reviewId),question=retry?.question||$('question').value.trim();if(!question)return;
 const request=retry||{reviewId,question,request_id:crypto.randomUUID()};s.failed=null;pending=request;saveView();renderComposer();
 try{
  const result=await api(`/api/reviews/${reviewId}/questions`,{method:'POST',body:JSON.stringify({question:request.question,request_id:request.request_id})});
  const modelFailed=result.explanation?.status==='fallback_after_api_failure';
  if(modelFailed){s.failed={...request,request_id:crypto.randomUUID(),message:'The model could not finish. The failed attempt is saved. Retry sends a new request, not a duplicate.'};s.draft=question;}
  const saved=await api(`/api/reviews/${reviewId}`);cache.set(reviewId,saved);s.unread=true;
  if(!modelFailed&&s.draft.trim()===question)s.draft='';
  if(UI.requestOutcome(current?.id,reviewId,saved)){const scroll=$('turns').scrollTop,evidenceTop=$('evidence-scroll').scrollTop;const nextDraft=modelFailed?question:$('question').value.trim()===question?'':$('question').value;$('question').value=nextDraft;s.draft=nextDraft;renderReview(saved);$('turns').scrollTop=scroll;$('evidence-scroll').scrollTop=evidenceTop;$('jump-latest').hidden=false;}
  await refreshList();
 }catch(e){s.failed={...request,message:e.message};}
 finally{pending=null;if(current?.id===reviewId&&s.failed)$('question').value=s.draft;renderComposer();}
}
function renderPreview(result){const content=node('div');content.append(node('h3',result.allowed_preview?'Preview permitted · NOT EXECUTED':'Preview rejected · NOT EXECUTED'),node('p',result.operator_note));for(const r of result.reasons||[])content.append(node('p',r));if(result.target)content.append(node('p',`Target ${result.target} · ${result.duration_seconds} seconds`,'mono'));showInspector('Recommendation preview',content,'ADVICE · NO EXECUTION');}
async function refreshLabStatus(){try{const status=await api('/api/lab/status');$('lab-capture').disabled=!status.available||!!status.fault;$('lab-status').textContent=status.available?(status.fault||'Isolated Linux lab available. Explicit approval required.'):'Response execution is unavailable on this backend.';}catch(e){$('lab-capture').disabled=true;$('lab-status').textContent=e.message;}}
async function refreshActions(){
 if(!current)return;const id=current.id;if(actionRefreshes.has(id))return;actionRefreshes.add(id);
 try{await renderActions();}finally{actionRefreshes.delete(id);}
}
async function renderActions(){
 if(!current)return;const id=current.id,actions=await api(`/api/reviews/${id}/actions`);if(current?.id!==id)return;const key=id+JSON.stringify(actions);if(key===actionRenderKey)return;actionRenderKey=key;const target=$('response-actions');target.replaceChildren();
 if(!actions.length)target.append(node('p','No executed or proposed lab actions are linked to this investigation.','surface quiet'));
 for(const action of actions){const box=node('section',undefined,'preview-result');box.append(node('strong',action.state.replaceAll('_',' ').toUpperCase()),node('p',action.confirmation));const effect=action.events.find(e=>e.event==='effect_verified')?.evidence,restored=[...action.events].reverse().find(e=>e.restored===true)?.evidence;
  if(effect?.source_reachable===false&&effect?.control_reachable===true)box.append(node('p','Effect verified: selected client blocked, control client remained reachable.'));
  if(effect?.measurement){const m=effect.measurement;box.append(node('p',`Measured rate effect: source ${m.source.kbit_per_second.toFixed(1)} kbit/s, control ${m.control.kbit_per_second.toFixed(1)} kbit/s.`, 'verified-effect'));box.append(node('p',`Each measured transfer received ${m.source.bytes} verified bytes. Source slowed: ${effect.criteria.source_slower}; control transfer within baseline tolerance: ${effect.criteria.control_unaffected}.`));}
  if(restored?.source_reachable===true&&restored?.control_reachable===true&&restored?.rule?.present===false)box.append(node('p','Restoration verified: both clients reachable and temporary rule removed.'));
  if(restored?.measurement)box.append(node('p',`Restored transfer: source ${restored.measurement.source.kbit_per_second.toFixed(1)} kbit/s, control ${restored.measurement.control.kbit_per_second.toFixed(1)} kbit/s.`));
  if(action.command_plan){const plan=node('details');plan.append(node('summary','Validated commands and reversal'),node('pre',action.command_plan.commands.join('\n')+'\n\n# Reversal\n'+action.command_plan.reversal.join('\n'),'suggested-code'));box.append(plan);const download=node('a','Download proposal plan','small-button');download.href=`/api/reviews/${id}/actions/${action.id}/plan`;box.append(download);}
  const detail=node('details');detail.append(node('summary','Approval, rule and verification evidence'),node('pre',JSON.stringify(action.events,null,2),'record-detail'));box.append(detail);
  if(['active','applying','rollback_failed'].includes(action.state))box.append(button('Roll back now','small-button',async e=>{e.currentTarget.disabled=true;try{await api(`/api/reviews/${id}/actions/${action.id}/rollback`,{method:'POST'});await refreshActions();}catch(error){notice(error.message);e.currentTarget.disabled=false;}}));target.append(box);
  if(action.state==='proposed'&&pendingProposal?.id!==action.id)box.append(button('Cancel pending proposal','small-button',async e=>{e.currentTarget.disabled=true;try{await api(`/api/reviews/${id}/actions/${action.id}/cancel`,{method:'POST'});await refreshActions();}catch(error){notice(error.message);e.currentTarget.disabled=false;}}));
 }
}
async function openNew(sample='port-check',upload=false,log=false){await loadConfig();$('sample').value=sample;$('capture-file').value='';$('capture-file').accept=log?'.tsv':'.pcap,.tsv';$('provider').querySelector('[value="api"]').disabled=!config.api_ready;$('provider').value=config.api_ready?'api':'rules';$('provider-help').textContent=config.api_ready?'Opening evidence is offline. Sending a question uses the configured hosted model and may incur API charges.':'Offline evidence inspection is available. Configure the API key on the backend host to enable conversations.';$('dialog-error').hidden=true;$('new-dialog').showModal();if(upload)$('capture-file').focus();}
$('toggle-sidebar').onclick=()=>setExpanded(!$('shell').classList.contains('expanded'));
$('nav-investigations').onclick=()=>{setExpanded(true);$('review-search').focus();};$('review-search').oninput=renderList;
$('new-review').onclick=()=>openNew().catch(e=>notice(e.message));$('upload-start').onclick=()=>openNew('port-check',true).catch(e=>notice(e.message));$('upload-log').onclick=()=>openNew('port-check',true,true).catch(e=>notice(e.message));$('close-dialog').onclick=()=>$('new-dialog').close();
$('nav-actions').onclick=()=>{if(current)setView('actions');else{const content=node('div');content.append(node('p','Open an investigation to inspect linked response actions. Current execution requires a separate isolated lab capture.'));showInspector('Lab action boundary',content,'WORKSPACE');}};
$('settings').onclick=()=>{const content=node('div');content.append(fields([['Backend','Available at the last configuration check'],['Conversation',config?.api_ready?'Configured, not a continuous model connection':'Not configured'],['Execution','Separate explicit approval in the fixed isolated lab'],['History',config?.history||'Saved with the selected source']]),node('p','Credentials remain on the backend host and are never included in these exports.','quiet'));showInspector('Workspace status',content,'LOCAL WORKSPACE');};
for(const b of document.querySelectorAll('[data-sample]'))b.onclick=()=>openNew(b.dataset.sample).catch(e=>notice(e.message));
for(const b of document.querySelectorAll('[data-view]'))b.onclick=()=>setView(b.dataset.view);
$('record-filter').oninput=()=>{if(!current)return;const s=views.get(current.id);s.filter=$('record-filter').value;s.limit=100;renderRecords();};$('record-sort').onchange=()=>{views.get(current.id).sort=$('record-sort').value;renderRecords();};
$('capture-identity').onclick=()=>{if(current)inspectReference(current.evidence.capture.sha256+':capture');};$('close-inspector').onclick=()=>$('inspector').close();
$('question').oninput=()=>{if(current)views.get(current.id).draft=$('question').value;renderComposer();};$('question').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();$('question-form').requestSubmit();}};
$('question-form').onsubmit=e=>{e.preventDefault();submitQuestion();};$('retry-question').onclick=()=>{const s=views.get(current.id);if(s.failed)submitQuestion(s.failed);};$('pending-source').onclick=()=>{if(pending)selectReview(pending.reviewId).catch(e=>notice(e.message));};
$('jump-latest').onclick=()=>{if(!current)return;const last=$('turns').lastElementChild;if(last)$('turns').scrollTop=Math.max(0,last.offsetTop-$('turns').offsetTop-8);views.get(current.id).unread=false;$('jump-latest').hidden=true;};
$('turns').onscroll=()=>{if(current)views.get(current.id).scrollTop=$('turns').scrollTop;};$('evidence-scroll').onscroll=()=>{if(current)views.get(current.id).evidenceTop=$('evidence-scroll').scrollTop;};
$('new-form').onsubmit=async e=>{e.preventDefault();$('create-review').disabled=true;$('dialog-error').hidden=true;try{const file=$('capture-file').files[0];let saved;if(file){if(!file.size||file.size>config.max_upload_bytes)throw new Error('Choose a non-empty file no larger than 8 MiB.');const data=new FormData();data.append('file',file);data.append('provider',$('provider').value);saved=await api('/api/reviews/upload',{method:'POST',body:data});}else saved=await api('/api/reviews',{method:'POST',body:JSON.stringify({sample:$('sample').value,provider:$('provider').value})});$('new-dialog').close();await refreshList();await selectReview(saved.id);$('question').focus();}catch(error){$('dialog-error').textContent=error.message;$('dialog-error').hidden=false;}finally{$('create-review').disabled=false;}};
$('sample').onchange=()=>{$('capture-file').value='';};
$('lab-capture').onclick=async()=>{captureBusy=true;renderComposer();$('lab-capture').disabled=true;try{const saved=await api('/api/lab/capture',{method:'POST',body:JSON.stringify({provider:config.api_ready?'api':'rules'})});await refreshList();await selectReview(saved.id);setView('actions');$('question').focus();}catch(e){notice(e.message);}finally{captureBusy=false;renderComposer();refreshLabStatus();}};
async function dismissProposal(){const proposal=pendingProposal;pendingProposal=null;if($('approval-dialog').open)$('approval-dialog').close();if(proposal&&!approvalSubmitting){try{await api(`/api/reviews/${proposal.reviewId}/actions/${proposal.id}/cancel`,{method:'POST'});await refreshActions();}catch(e){notice(e.message);}}}
$('cancel-approval').onclick=()=>dismissProposal();$('approval-dialog').onclose=()=>dismissProposal();
$('approval-form').onsubmit=async e=>{e.preventDefault();const proposal=pendingProposal;if(!proposal||approvalSubmitting)return;const b=e.submitter;b.disabled=true;approvalSubmitting=true;$('approval-error').hidden=true;try{await api(`/api/reviews/${proposal.reviewId}/actions/${proposal.id}/approve`,{method:'POST',body:JSON.stringify({approval_token:proposal.approval_token,confirmation:$('approval-confirmation').value})});pendingProposal=null;$('approval-dialog').close();await refreshActions();}catch(error){$('approval-error').textContent=error.message;$('approval-error').hidden=false;notice(error.message);}finally{approvalSubmitting=false;b.disabled=false;}};
for(const operation of ['block','rate'])$('ask-'+operation).onclick=()=>{if(!current)return;$('question').value=`For an authorised demonstration in this disconnected lab, inspect the current mapping and recommend a temporary ${operation==='block'?'block':'512 kbit/s service rate limit'} for source 10.77.0.20 to service 10.77.0.10 TCP/8080 for 30 seconds. Explain the effect and reversal. Do not execute anything.`;views.get(current.id).draft=$('question').value;renderComposer();$('question').focus();};
function resize(value){const share=Math.max(32,Math.min(62,value));$('panels').style.setProperty('--evidence-share',share+'%');$('panel-divider').setAttribute('aria-valuenow',String(Math.round(share)));}
$('panel-divider').onkeydown=e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();const value=Number($('panel-divider').getAttribute('aria-valuenow'));resize(e.key==='Home'?32:e.key==='End'?62:value+(e.key==='ArrowLeft'?-2:2));}};
$('panel-divider').onpointerdown=e=>{e.preventDefault();$('panel-divider').setPointerCapture(e.pointerId);$('panel-divider').onpointermove=move=>{const r=$('panels').getBoundingClientRect(),pad=parseFloat(getComputedStyle($('panels')).paddingLeft);resize((move.clientX-r.left-pad)/(r.width-pad*2)*100);};};$('panel-divider').onpointerup=()=>$('panel-divider').onpointermove=null;
document.addEventListener('visibilitychange',()=>{if(document.hidden)cancelReplay();});reduced.addEventListener('change',()=>cancelReplay());
setInterval(()=>{if(current?.lab_binding&&!document.hidden)refreshActions().catch(()=>{});},2500);
let resumedPollBusy=false;
setInterval(async()=>{if(!pending?.resumed||resumedPollBusy)return;resumedPollBusy=true;const request=pending;try{const saved=await api(`/api/reviews/${request.reviewId}`);if(!saved.pending_request&&pending===request){pending=null;const s=views.get(request.reviewId);s.unread=true;if(s.draft===request.question)s.draft='';cache.set(saved.id,saved);if(current?.id===saved.id){$('question').value=s.draft;renderReview(saved);$('jump-latest').hidden=false;}else renderComposer();await refreshList();}}catch(e){notice(e.message);}finally{resumedPollBusy=false;}},1500);
window.onpopstate=()=>{const id=new URLSearchParams(location.hash.slice(1)).get('review');if(id)selectReview(id,true).catch(e=>notice(e.message));};
(async()=>{try{await loadConfig();await refreshList();await refreshLabStatus();const id=new URLSearchParams(location.hash.slice(1)).get('review');if(id)await selectReview(id,true);}catch(e){notice(e.message);}})();
