export const terminal = status => ['complete', 'failed', 'interrupted', 'cancelled'].includes(status);
export function evidenceFileError(file,maxBytes=8388608) {
  return file&&(/\.(pcap|tsv)$/i.test(file.name)&&file.size>0&&file.size<=maxBytes)?'':'Choose a non-empty PCAP or supported TSV log, up to 8 MiB. Your previous selection is unchanged.';
}
export const label = ref => {
  const suffix = String(ref || '').split(':').at(-1);
  return /^p\d+$/.test(suffix) ? `P${suffix.slice(1)}` : /^l\d+$/.test(suffix) ? `L${suffix.slice(1)}`
    : suffix?.startsWith('f') ? `Flow ${suffix.slice(1, 7)}` : suffix?.startsWith('a') ? `Result ${suffix.slice(1, 7)}` : suffix;
};
export function referenceIndex(review) {
  const index = new Map(), e = review.evidence, hash = e.capture.sha256;
  for (const key of ['capture', 'overview', 'coverage']) index.set(`${hash}:${key}`, e[key]);
  for (const row of [...(e.packets || []), ...(e.log_records || []), ...(e.flows || []), ...(e.facts || [])]) index.set(row.id, row);
  for (const turn of review.turns || []) for (const row of turn.explanation.aggregate_provenance || []) index.set(row.id, row);
  return index;
}
export function applyEvent(run, event) {
  if (event.sequence <= (run.cursor || 0)) return run;
  const result = {...run, cursor: event.sequence, events: [...(run.events || []), event]};
  if (event.type === 'summary') result.summary = event.data.text;
  if (event.type === 'correction') result.summary = '';
  if (['started', 'provider_started'].includes(event.type)) result.status = 'running';
  if (event.type === 'stop_requested') result.status = 'stopping';
  if (terminal(event.type)) { result.status = event.type; result.turn_id = event.data.turn_id; result.error = event.type === 'complete' ? null : event.data.message; }
  return result;
}
export function hydrateRun(run) {
  return (run.events || []).reduce(applyEvent, {...run, events: [], cursor: 0});
}
export function messagesFor(review, runs = []) {
  const pairs = [], linked = new Set();
  const stamp = value => { const n=Date.parse(value); return Number.isFinite(n)?n:null; };
  for (const turn of review.turns || []) {
    const run = runs.find(r => r.turn_id === turn.run_id);
    const identity = run?.id || turn.run_id;
    if (run) linked.add(run.id);
    pairs.push({time:stamp(run?.created_at || turn.recorded_at), order:pairs.length, messages:[
      {id: `${identity}:user`, role: 'user', text: run?.question || turn.question, reference: run?.selected_reference || turn.selected_reference},
      {id: `${identity}:assistant`, role: 'assistant', text: turn.explanation.answer?.summary || '', turn, run}
    ]});
  }
  for (const run of runs.filter(r => !linked.has(r.id))) {
    pairs.push({time:stamp(run.created_at), order:pairs.length, messages:[
      {id: `${run.id}:user`, role: 'user', text: run.question, reference: run.selected_reference},
      {id: `${run.id}:assistant`, role: 'assistant', text: run.summary || '', run}
    ]});
  }
  // Interleave failed attempts and saved replies using their real request time.
  // Undated legacy pairs retain their order before newer dated requests.
  return pairs.sort((a,b)=>(a.time??-Infinity)-(b.time??-Infinity)||a.order-b.order).flatMap(pair=>pair.messages);
}
export function defaultViews(answer, question, data) {
  if (!answer || answer.kind === 'conversation') return [];
  if (answer.views?.length) return answer.views.filter(v => ['table','timeline','map','comparison','bar','line','area'].includes(v.type));
  if (/when|over time|increase|rate of/.test(question.toLowerCase()) && data?.series.data.length) return [{type: 'line', references: []}];
  if (/compar|retry|scann|one service|ports/.test(question.toLowerCase()) && data?.bar.data.length) return [{type: 'bar', references: []}];
  if (/reply|direction|handshake|exchange/.test(question.toLowerCase())) return [{type: 'timeline', references: []}];
  if (/connect|communicat|hosts|address/.test(question.toLowerCase())) return [{type: 'map', references: []}];
  return [];
}
export function readLocal(key, fallback) { try { return JSON.parse(localStorage.getItem(`packetpilot:${key}`)) ?? fallback; } catch { return fallback; } }
export function writeLocal(key, value) { try { localStorage.setItem(`packetpilot:${key}`, JSON.stringify(value)); } catch { /* The live workspace remains usable without storage. */ } }

// An inspection is a view selection, never a question attachment. Aggregate
// selections retain all bounded members, rather than substituting packet one.
export function inspectionFor(target, review) {
  const index=referenceIndex(review);
  if(typeof target==='string') return index.has(target)?{id:target,value:index.get(target)}:null;
  if(!target||!Array.isArray(target.references))return null;
  const unique=[...new Set(target.references)], valid=unique.filter(id=>index.has(id)), ids=valid.slice(0,256);
  return {...target,references:ids,aggregate:true,references_omitted:(target.references_omitted||0)+Math.max(0,valid.length-256),unavailable_references:unique.length-valid.length};
}
export function uniqueNotes(...groups) {
  const seen=new Set();return groups.flat().filter(Boolean).filter(text=>{const key=String(text).toLowerCase().replace(/[\s.,;:]+/g,' ').trim();if(seen.has(key))return false;seen.add(key);return true;});
}
export function endpoint(address,port) {return address?`${address}${port==null?'':':'+port}`:'Not retained';}
export function actionPresentation(state) {
  const labels={proposed:['Approval required','waiting'],applying:['Applying','working'],active:['Effect verified','verified'],rolled_back:['Restoration verified','restored'],expired:['Restoration verified','restored'],cancelled:['Cancelled','muted'],stale:['Stale proposal','muted'],rollback_failed:['Restoration needs attention','failed'],failed:['Failed','failed']};
  const [text,tone]=labels[state]||[String(state||'Unknown').replaceAll('_',' '),'muted'];return {text,tone};
}
export function actionStages(action) {
  const events=action.events||[],names=new Set(events.map(e=>e.event));
  return [
    {label:'Proposed',done:names.has('proposal_created')},
    {label:'Approved',done:names.has('explicit_operator_approval')},
    {label:'Applied',done:names.has('rule_applied')},
    {label:'Effect checked',done:names.has('effect_verified')},
    {label:'Restored',done:events.some(e=>e.restored===true)}
  ];
}
export function shouldRevealAnswer({following,completed,hasTurn}) {return Boolean(following&&completed&&hasTurn);}

export function timePlotRows(series,type='line') {
  const protocols=[...new Set(series.flatMap(bin=>Object.keys(bin.protocols)))];
  const rows=series.map((bin,index)=>({...bin,index,time:type==='area'?bin.start_seconds:(bin.start_seconds+bin.end_seconds)/2,...Object.fromEntries(protocols.map(protocol=>[protocol,bin.protocols[protocol]||0]))}));
  // Area steps cover the true bin boundaries. The final endpoint is a drawing
  // boundary for the last bin, not an additional measured bin or record.
  return type==='area'&&rows.length?[...rows,{...rows.at(-1),time:rows.at(-1).end_seconds}]:rows;
}

export function communicationLayout(nodes,edges) {
  const degree=node=>edges.filter(e=>e.source===node||e.destination===node).length;
  const ordered=[...nodes].sort((a,b)=>degree(b)-degree(a)||a.localeCompare(b));
  if(nodes.length<=2)return {width:640,height:188,places:new Map(nodes.map((node,i)=>[node,{x:155+i*330,y:92}]))};
  const hub=ordered[0], neighbours=new Set(edges.filter(e=>e.source===hub||e.destination===hub).flatMap(e=>[e.source,e.destination]));
  if(neighbours.size===nodes.length){const height=Math.max(244,(nodes.length-1)*88+44);return {width:640,height,places:new Map(ordered.map((node,i)=>[node,i===0?{x:155,y:height/2}:{x:490,y:66+(i-1)*88}]))};}
  const height=Math.max(300,Math.ceil(nodes.length/2)*100+60),places=new Map(ordered.map((node,i)=>{const angle=-Math.PI/2+i*2*Math.PI/nodes.length;return [node,{x:320+Math.cos(angle)*220,y:height/2+Math.sin(angle)*(height/2-42)}];}));
  return {width:640,height,places};
}
export function activityOperations(activity) {
  const operations=[];
  for(const event of activity){if(event.type==='tool_started')operations.push({...event,state:'working'});else if(event.type==='tool_finished'){const candidates=[...operations].reverse().filter(o=>o.state==='working'&&o.data.tool===event.data.tool),operation=candidates.find(o=>event.data.index!=null&&o.data.index===event.data.index)||candidates[0];if(operation){operation.state=event.data.ok===false?'failed':'done';operation.finished=event.sequence;operation.data={...operation.data,...event.data};}else operations.push({...event,state:event.data.ok===false?'failed':'done'});}}
  return operations;
}

export function inspectionReferences(item) {
  if(!item)return [];
  if(item.aggregate)return item.references||[];
  const value=item.value||{},hash=item.id?.split(':')[0];
  if(value.packet_refs)return value.packet_refs.map(n=>`${hash}:p${n}`);
  return item.id?[item.id]:[];
}
export function selectionOverlaps(item, references=[]) {
  const selected=new Set(inspectionReferences(item));return references.some(id=>selected.has(id));
}
export function drillInspection(state,item,scroll=0) {
  if(!item)return {item:null,parents:[],scroll:0};
  const nested=state.item&&state.item!==item&&inspectionReferences(state.item).includes(item.id);
  return {item,parents:nested?[...state.parents,{item:state.item,scroll}]:[],scroll:0};
}
export function backInspection(state) {
  const parent=state.parents.at(-1);return parent?{...parent,parents:state.parents.slice(0,-1)}:state;
}
export function technicalSegments(text='') {
  const value=String(text),pattern=/`[^`\n]{1,180}`|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|\b(?:SYN(?:-ACK)?|ACK|FIN|RST|PSH|TCP|UDP|ICMP|ARP|HTTP\/[\d.]+)\b|\b\d+(?:\.\d+)?\s*(?:ms|seconds?|s|packets?|records?|bytes|ports?)\b/g;
  const pieces=[];let start=0;
  for(const match of value.matchAll(pattern)){if(match.index>start)pieces.push({text:value.slice(start,match.index),technical:false});pieces.push({text:match[0],technical:true});start=match.index+match[0].length;}
  if(start<value.length)pieces.push({text:value.slice(start),technical:false});return pieces;
}
