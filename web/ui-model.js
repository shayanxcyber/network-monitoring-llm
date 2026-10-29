/* Pure source-scoped UI helpers; no threat verdicts or execution authority. */
(function(root) {
 'use strict';
 function stateStore(){const states=new Map();return {get(id){if(!states.has(id))states.set(id,{draft:'',scrollTop:0,evidenceTop:0,view:null,filter:'',sort:'number',limit:100,connectionRef:null,selectedRef:null,exchangeRef:null,unread:false,failed:null});return states.get(id);}};}
 function shortReference(id){const s=String(id).split(':').at(-1);if(/^p\d+$/.test(s))return 'P'+s.slice(1);if(/^l\d+$/.test(s))return 'L'+s.slice(1);if(s.startsWith('f')&&s.length>6)return 'Flow '+s.slice(1,7);if(s.startsWith('a')&&s.length>6)return 'Aggregate '+s.slice(1,7);return s;}
 function referenceIndex(review){const ev=review.evidence,hash=ev.capture.sha256,index=new Map();for(const [key,label]of[['capture','Source identity'],['overview','Whole-source overview'],['coverage','Coverage']])index.set(hash+':'+key,{id:hash+':'+key,label,value:ev[key]});for(const p of ev.packets||[])index.set(p.id,{id:p.id,label:`Packet ${p.packet} · ${p.protocol||'unknown'} · ${p.status}`,value:p});for(const r of ev.log_records||[])index.set(r.id,{id:r.id,label:`Original log line ${r.line_number} · ${r.protocol||'unknown'} · ${r.status}`,value:r});for(const f of ev.flows||[])index.set(f.id,{id:f.id,label:`Flow · ${f.protocol} · ${f.packet_count??f.record_count} records`,value:f});(ev.facts||[]).forEach((f,i)=>index.set(f.id,{id:f.id,label:`Legacy fact ${i+1}`,value:f}));for(const t of review.turns||[])for(const r of t.explanation.aggregate_provenance||[])index.set(r.id,{id:r.id,label:Number.isInteger(r.selected_tcp_record_count)?'TCP exchange analysis':'Retained aggregate',value:r});return index;}
 function records(ev){return ev.input_kind==='network_log'?ev.log_records||[]:ev.packets||[];}
 function recordNumber(r){return r.line_number??r.packet??0;}
 function endpoints(r){const ip=r.ipv4||r.ip||{},tr=r.tcp||r.udp||{};return {source:ip.src||r.source||'',destination:ip.dst||r.destination||'',sourcePort:tr.src_port??'',destinationPort:tr.dst_port??'',flags:(r.tcp?.flag_names||[]).join(', ')};}
 function time(r){if(Number.isFinite(r.time))return r.time;if(typeof r.timestamp==='string'&&r.timestamp.trim()&&Number.isFinite(Number(r.timestamp)))return Number(r.timestamp);return null;}
 function decoderLabel(decoder){const version=decoder?.version||'saved evidence';return /^TShark \(Wireshark\) [\d.]+/.exec(version)?.[0]||version;}
 function issues(r){return (r.issues||[]).join(', ')||r.reason||'';}
 function searchable(value){if(value===null||value===undefined)return '';if(typeof value==='object')return Object.values(value).map(searchable).join(' ');return String(value);}
 function filteredRecords(ev,filter='',sort='number'){const q=filter.trim().toLowerCase(),rows=records(ev).filter(r=>!q||searchable(r).toLowerCase().includes(q)).slice();rows.sort(sort==='newest'?(a,b)=>(time(b)??-Infinity)-(time(a)??-Infinity)||recordNumber(a)-recordNumber(b):sort==='protocol'?(a,b)=>String(a.protocol).localeCompare(String(b.protocol))||recordNumber(a)-recordNumber(b):(a,b)=>recordNumber(a)-recordNumber(b));return rows;}
 function counts(ev){const rows=records(ev),c=ev.coverage||{},log=ev.input_kind==='network_log';return {total:log?(ev.capture.record_count??rows.length):(ev.capture.packet_count??rows.length),decoded:rows.filter(r=>r.status==='decoded').length,malformed:rows.filter(r=>['malformed','invalid'].includes(r.status)).length,other:rows.filter(r=>!['decoded','malformed','invalid'].includes(r.status)).length,partial:c.complete_for_supported_headers===false||rows.some(r=>r.status!=='decoded')};}
 function requestOutcome(activeId,requestId,review){return activeId===requestId&&review.id===requestId;}
 function flags(value){if(Array.isArray(value))return value.join(' / ');if(Number.isInteger(value))return [[1,'FIN'],[2,'SYN'],[4,'RST'],[8,'PSH'],[16,'ACK'],[32,'URG'],[64,'ECE'],[128,'CWR']].filter(([bit])=>(value&bit)!==0).map(([,name])=>name).join(' / ')||'No flags';return value==null?'':String(value);}
 function timeOrigin(ev){const times=records(ev).map(time).filter(Number.isFinite);return times.length?Math.min(...times):null;}
 function relativeTime(value,origin){return Number.isFinite(value)&&Number.isFinite(origin)?'+'+(value-origin).toFixed(4)+' s':'Not retained';}
 function recordFields(r,origin){const tcp=r.tcp,log=r.line_number!==undefined;return {elapsed:relativeTime(time(r),origin),flags:tcp?flags(tcp.flag_names?.length?tcp.flag_names:tcp.flags):'',length:log?r.reported_frame_length??null:r.captured_bytes??null,lengthLabel:log?'Reported frame length':'Captured frame length',payload:r.payload?.length??r.tcp?.payload_bytes??r.udp?.payload_bytes??null};}
 function protocolCounts(ev){const result={};for(const r of records(ev)){const key=r.protocol||'Unknown';result[key]=(result[key]||0)+1;}return result;}
 // Display grouping is neutral and local. It creates no evidence IDs or verdicts.
 function connectionRows(ev,relationships={}){
  const all=records(ev),byFlow=new Map();for(const r of all){if(r.flow_id){if(!byFlow.has(r.flow_id))byFlow.set(r.flow_id,[]);byFlow.get(r.flow_id).push(r);}}
  const exchanges=relationships?.exchanges||[];
  const describe=(id,a,b,protocol,rows,flow=null)=>{
   const times=rows.map(time).filter(Number.isFinite),references=rows.map(r=>r.id),owned=new Set(references);
   return {id,a,b,protocol,count:flow?.packet_count??flow?.record_count??rows.length,firstTime:Number.isFinite(flow?.first_time)?flow.first_time:times.length?Math.min(...times):null,
    references,reference:flow?.id||references[0],flow,exchanges:exchanges.filter(x=>owned.has(x.syn_reference)),
    flagNames:[...new Set(rows.flatMap(r=>r.tcp?.flag_names||[]))].join(' / ')};
  };
  if((ev.flows||[]).length)return ev.flows.map(f=>describe(f.id,f.endpoint_a||{},f.endpoint_b||{},f.protocol,byFlow.get(f.id)||[],f));
  const groups=new Map();for(const r of all){const ep=endpoints(r);if(r.status!=='decoded'||!ep.source||!ep.destination)continue;
   const pair=[{address:ep.source,port:ep.sourcePort},{address:ep.destination,port:ep.destinationPort}].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
   const key=JSON.stringify([r.protocol,pair]);if(!groups.has(key))groups.set(key,{pair,protocol:r.protocol,rows:[]});groups.get(key).rows.push(r);
  }
  return [...groups.values()].map(g=>describe('display:'+g.rows[0].id,g.pair[0],g.pair[1],g.protocol,g.rows));
 }
 const api={stateStore,shortReference,referenceIndex,records,recordNumber,endpoints,filteredRecords,counts,requestOutcome,flags,time,decoderLabel,issues,timeOrigin,relativeTime,recordFields,protocolCounts,connectionRows};if(typeof module==='object'&&module.exports)module.exports=api;else root.PacketPilotUI=Object.freeze(api);
})(typeof globalThis==='object'?globalThis:this);
