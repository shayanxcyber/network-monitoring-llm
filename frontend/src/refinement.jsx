import React,{useId,useState,useEffect,useRef} from 'react';
import * as Select from '@radix-ui/react-select';
import * as Popover from '@radix-ui/react-popover';
import {Check,ChevronDown,Search,ArrowUpRight,Database,FileText,MessageSquare,ArrowRight} from 'lucide-react';
import {motion,useReducedMotion} from 'motion/react';
import {label,technicalSegments,referenceIndex,endpoint,selectionOverlaps} from './domain';

export function Choice({label: name,value,onChange,items}) {
  const choices=items.map(x=>typeof x==='string'?{value:x,label:x}:x);
  return <Select.Root value={value||'__all__'} onValueChange={v=>onChange(v==='__all__'?'':v)}><Select.Trigger className="choice-trigger" aria-label={name}><Select.Value/><Select.Icon><ChevronDown size={14}/></Select.Icon></Select.Trigger><Select.Portal><Select.Content className="choice-menu" position="popper" sideOffset={6} collisionPadding={12}><Select.ScrollUpButton className="choice-scroll">↑</Select.ScrollUpButton><Select.Viewport>{choices.map(x=><Select.Item className="choice-option" key={x.value||'__all__'} value={x.value||'__all__'} textValue={x.label}><Select.ItemText>{x.label}</Select.ItemText><Select.ItemIndicator><Check size={13}/></Select.ItemIndicator></Select.Item>)}</Select.Viewport><Select.ScrollDownButton className="choice-scroll">↓</Select.ScrollDownButton></Select.Content></Select.Portal></Select.Root>;
}

// Controlled search on the existing Radix focus/portal foundation. No global
// key listeners or fixed IDs from an upstream demonstration component.
export function FlowPicker({flows=[],selected,onChange}) {
  const [open,setOpen]=useState(false),[query,setQuery]=useState(''),[active,setActive]=useState(0),uid=useId(),input=useRef(),list=useRef();
  const title=f=>`${f.protocol} · ${endpoint(f.endpoint_a.address,f.endpoint_a.port)} ↔ ${endpoint(f.endpoint_b.address,f.endpoint_b.port)}`;
  const rows=flows.filter(f=>title(f).toLowerCase().includes(query.toLowerCase())),current=flows.find(f=>f.id===selected?.id);
  useEffect(()=>{setActive(0);},[query]);
  useEffect(()=>{list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({block:'nearest'});},[active]);
  const choose=f=>{onChange(f.id);setOpen(false);};
  return <Popover.Root open={open} onOpenChange={v=>{setOpen(v);if(v){setQuery('');setActive(0);}}}><Popover.Trigger asChild><button className="flow-picker-trigger" aria-label="Inspect a flow"><span>{current?title(current):'Choose a flow to inspect'}</span><ChevronDown size={14}/></button></Popover.Trigger><Popover.Portal><Popover.Content className="flow-picker-menu" sideOffset={7} align="start" collisionPadding={14} onOpenAutoFocus={e=>{e.preventDefault();input.current?.focus();}}><label className="search"><Search size={15}/><input ref={input} role="combobox" aria-label="Find a flow" aria-controls={uid} aria-expanded={open} aria-autocomplete="list" aria-activedescendant={rows[active]?`${uid}-${active}`:undefined} placeholder="Filter an address, port or protocol" value={query} onChange={e=>setQuery(e.target.value)} onKeyDown={e=>{if(['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();setActive(i=>rows.length?(i+(e.key==='ArrowDown'?1:-1)+rows.length)%rows.length:0);}if(e.key==='Enter'){e.preventDefault();if(rows[active])choose(rows[active]);}}}/></label><div className="flow-picker-list" id={uid} ref={list} role="listbox" aria-label="Matching flows">{rows.map((f,i)=><button key={f.id} id={`${uid}-${i}`} data-index={i} className={active===i?'active':''} role="option" tabIndex={-1} aria-selected={f.id===current?.id} onMouseMove={()=>setActive(i)} onClick={()=>choose(f)}><span>{title(f)}<small>{f.packet_count??f.record_count} retained records</small></span>{f.id===current?.id?<Check size={14}/>:<ArrowUpRight size={14}/>}</button>)}{!rows.length&&<p className="picker-empty" role="status">No flows match. Change or clear the search.</p>}</div><small className="picker-hint">↑ ↓ to browse · Enter to inspect · Esc to close</small></Popover.Content></Popover.Portal></Popover.Root>;
}

export function TechnicalText({text=''}) {
  return technicalSegments(text).map((part,i)=>part.technical?<code className="technical-run" key={i}>{part.text.startsWith('`')?part.text.slice(1,-1):part.text}</code>:<React.Fragment key={i}>{part.text}</React.Fragment>);
}

export function EvidenceExtracts({answer,review,inspect,selected}) {
  const index=referenceIndex(review),rank=id=>{const row=index.get(id);return row.packet!=null||row.line_number!=null?0:row.endpoint_a?1:row.member_count!=null?2:3;},all=[...new Set((answer.observations||[]).flatMap(r=>r.references||[]))].filter(id=>index.has(id)).sort((a,b)=>rank(a)-rank(b)),[expanded,setExpanded]=useState(false),shown=all.slice(0,expanded?12:3);
  if(!shown.length)return null;
  return <section className="evidence-extracts"><div className="view-heading"><strong>Referenced evidence</strong><span>Open the original</span></div><div className="extract-grid">{shown.map(id=>{const row=index.get(id),tr=row.tcp||row.udp||{},log=row.line_number!=null,detail=row.ipv4?`${endpoint(row.ipv4.src,tr.src_port)} → ${endpoint(row.ipv4.dst,tr.dst_port)}`:row.endpoint_a?`${endpoint(row.endpoint_a.address,row.endpoint_a.port)} ↔ ${endpoint(row.endpoint_b.address,row.endpoint_b.port)}`:row.member_count!=null?`${row.member_count} member records`:label(id);return <button key={id} className={`evidence-extract ${selectionOverlaps(selected,[id])?'selected':''}`} onClick={()=>inspect(id)}><span className="extract-label">{log?<FileText size={13}/>:<Database size={13}/>}<b>{label(id)}</b><small>{log?'Original log line':row.packet!=null?'Original packet':row.endpoint_a?'Retained flow':'Calculated selection'}</small><ArrowUpRight size={13}/></span><span className="extract-detail">{detail}</span>{row.protocol&&<span className="extract-meta">{row.protocol}{row.tcp?.flag_names?.length?` · ${row.tcp.flag_names.join(' / ')}`:''} · {row.status||'retained'}</span>}</button>;})}</div>{all.length>3&&<button className="view-more" onClick={()=>setExpanded(!expanded)}>{expanded?'Show fewer extracts':`Show ${Math.min(12,all.length)} of ${all.length} references`}</button>}{expanded&&all.length>12&&<p className="view-note">All original citations remain with the observations below.</p>}</section>;
}

export function WorkspacePanels({composition,children,...props}) {
  const parts=React.Children.toArray(children);
  return <div {...props} data-composition={composition}>{composition==='report'?[parts[2],parts[1],parts[0]]:parts}</div>;
}
export function HomeRecent({reviews,select}) {
  return !!reviews.length&&<section className="home-recent" aria-labelledby="recent-heading"><div className="recent-heading"><div><h2 id="recent-heading">Recent investigations</h2><p>Continue where you left off.</p></div><span>{reviews.length} saved locally</span></div><div className="recent-list"><div className="recent-columns" aria-hidden="true"><span>Investigation</span><span>Conversation</span><span>Updated</span><span/></div><div role="list" aria-label="Recent investigations">{reviews.slice(0,8).map(r=>{const date=new Date(r.updated_at),valid=!Number.isNaN(date.getTime()),replies=r.turn_count??0;return <div role="listitem" key={r.id}><button className="recent-row" title={`${r.title} · ${r.id}`} onClick={()=>select(r.id)}><span className="recent-source"><span className="recent-icon">{r.provider==='api'?<MessageSquare size={18}/>:<Database size={18}/>}</span><span><strong>{r.title}</strong><small><code>{r.id.slice(0,8)}</code> · {r.provider==='api'?'Evidence and conversation':'Evidence only'}</small></span></span><span className={`recent-state ${r.provider==='api'?'has-conversation':''}`}>{r.provider==='api'?`${replies} saved ${replies===1?'reply':'replies'}`:'Offline evidence'}</span><time dateTime={valid?r.updated_at:undefined}>{valid?date.toLocaleDateString([],{month:'short',day:'numeric'}):'Not recorded'}{valid&&<small>{date.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</small>}</time><ArrowRight className="recent-open" size={16}/></button></div>;})}</div></div></section>;
}

export function SectionEntrance({children,className=''}) {
  const reduced=useReducedMotion();return <motion.section className={className} initial={{opacity:reduced?1:.5,y:reduced?0:5}} animate={{opacity:1,y:0}} transition={{duration:reduced?0:.25,ease:[.2,0,0,1]}}>{children}</motion.section>;
}
