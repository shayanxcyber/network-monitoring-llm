import React, {useId, useRef, useState, useEffect, useLayoutEffect} from 'react';
import {activityOperations,evidenceFileError,label} from './domain';
import * as Dialog from '@radix-ui/react-dialog';
import * as Tooltip from '@radix-ui/react-tooltip';
import {AnimatePresence, motion, useReducedMotion} from 'motion/react';
import {X, ChevronDown, Check, FileUp, FileText, CircleAlert, ArrowUpRight} from 'lucide-react';

// Registry adaptations and their original MIT notices are retained in
// COPIED_COMPONENT_NOTICES.txt. No Tailwind or secondary motion engine is needed.
export function Hint({label, children}) {
  return <Tooltip.Root><Tooltip.Trigger asChild>{children}</Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="hint" sideOffset={7}>{label}<Tooltip.Arrow/></Tooltip.Content></Tooltip.Portal></Tooltip.Root>;
}
export function Tooltips({children}) {return <Tooltip.Provider delayDuration={450} skipDelayDuration={180}>{children}</Tooltip.Provider>;}
export function Modal({title, children, close, wide=false,className=''}) {
  return <Dialog.Root open onOpenChange={open=>!open&&close()}><Dialog.Portal><Dialog.Overlay className="dialog-scrim"/><Dialog.Content className={`modal premium-dialog ${wide?'wide':''} ${className}`} aria-describedby={undefined}>
    <div className="modal-heading"><Dialog.Title asChild><h2>{title}</h2></Dialog.Title><button type="button" className="icon-button" aria-label="Close dialog" onClick={close}><X size={18}/></button></div>{children}
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}
export function Disclosure({title, count, children, defaultOpen=false, className=''}) {
  const [open,setOpen]=useState(defaultOpen), id=useId(), reduced=useReducedMotion();
  useEffect(()=>setOpen(defaultOpen),[defaultOpen]);
  return <section className={`disclosure ${open?'open':''} ${className}`}><button type="button" className="disclosure-heading" aria-expanded={open} aria-controls={id} onClick={()=>setOpen(!open)}><span>{title}{count!=null&&<small>{count}</small>}</span><motion.span animate={{rotate:open?180:0}} transition={{duration:reduced?0:.18}}><ChevronDown size={16}/></motion.span></button>
    <AnimatePresence initial={false}>{open&&<motion.div id={id} initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:reduced?0:.23,ease:[.2,0,0,1]}} className="disclosure-content"><div>{children}</div></motion.div>}</AnimatePresence></section>;
}
export function Segments({items,value,onChange,label,className='', role='tab'}) {
  const group=useId(), reduced=useReducedMotion();
  return <div className={`segments ${className}`} role={role==='tab'?'tablist':'group'} aria-label={label}>{items.map((item,i)=>{const name=typeof item==='string'?item:item.value, text=typeof item==='string'?item[0].toUpperCase()+item.slice(1):item.label; return <button type="button" key={name} role={role==='tab'?'tab':undefined} aria-selected={role==='tab'?value===name:undefined} aria-pressed={role==='tab'?undefined:value===name} tabIndex={role==='tab'&&value!==name?-1:0} className={value===name?'active':''} onClick={()=>onChange(name)} onKeyDown={e=>{if(role!=='tab'||!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const next=e.key==='Home'?0:e.key==='End'?items.length-1:(i+(e.key==='ArrowLeft'?-1:1)+items.length)%items.length;onChange(typeof items[next]==='string'?items[next]:items[next].value);e.currentTarget.parentElement.children[next].focus();}}>{value===name&&<motion.span className="segment-active" layoutId={group} transition={reduced?{duration:0}:{type:'spring',bounce:.06,duration:.32}}/>}<span>{text}</span></button>;})}</div>;
}
export function BorderBeam() {
  const reduced=useReducedMotion();
  return <div aria-hidden="true" className={`border-beam ${reduced?'static':''}`}><motion.div className="beam-light" initial={{offsetDistance:'0%'}} animate={reduced?undefined:{offsetDistance:'100%'}} transition={{repeat:Infinity,duration:7,ease:'linear'}}/></div>;
}
export function ActivitySignal({phase, reconnecting=false, variant='orbit'}) {
  const reduced=useReducedMotion();
  return <div className="activity-signal" role="status"><div className={`signal-mark ${variant}`} aria-hidden="true">{variant==='bars'?Array.from({length:4},(_,i)=><motion.i key={i} animate={reduced?undefined:{scaleY:[.45,1,.45]}} transition={{repeat:Infinity,duration:1.6,delay:i*.18}}/>):<><motion.span animate={reduced?undefined:{rotate:360}} transition={{repeat:Infinity,duration:12,ease:'linear'}}>✳</motion.span><i/></>}</div><div><strong>{phase}</strong><small>{reconnecting?'Rejoining the same request. Your draft is safe.':'Following the evidence'}</small></div></div>;
}
const toolLabels={get_packets:'Inspecting packet details',get_flow:'Reading a flow',summarize_connections:'Comparing connection directions',inspect_protocol:'Reading protocol fields',inspect_packets:'Inspecting packet details', inspect_flow:'Reading a flow', inspect_flows:'Reading flow directions', connection_statistics:'Comparing connections', inspect_statistics:'Comparing connections', inspect_protocol_fields:'Reading protocol fields'};
export function activityLabel(event) {
  if(event?.data?.tool) return toolLabels[event.data.tool] || event.data.tool.replaceAll('_',' ').replace(/^./,x=>x.toUpperCase());
  return event?.data?.message || event?.type?.replaceAll('_',' ').replace(/^./,x=>x.toUpperCase()) || 'Preparing the investigation';
}
export function ActivitySteps({activity=[],inspect}) {
  const tools=activityOperations(activity);
  const visible=tools.length?tools:activity.filter(e=>!['started','complete','summary'].includes(e.type));
  return visible.length>0&&<Disclosure title="Investigation activity" count={visible.length} className="run-activity"><ol>{visible.map(e=><li key={e.sequence}><span className={`event-state ${e.state||'done'}`} aria-hidden="true">{e.state==='working'?<i/>:e.state==='failed'?<CircleAlert size={13}/>:<Check size={13}/>}</span><div className="operation-detail"><span>{activityLabel(e)}</span>{e.state==='done'&&<small>Completed{e.data.returned_records!=null?` · ${e.data.returned_records} evidence record${e.data.returned_records===1?'':'s'} returned`:''}</small>}{e.state==='failed'&&<small>Unable to complete this inspection</small>}{inspect&&e.data.references?.length>0&&<div className="operation-references">{e.data.references.map(id=><button key={id} onClick={()=>inspect(id)}>{label(id)}<ArrowUpRight size={11}/></button>)}</div>}</div>{e.data.elapsed_seconds!=null&&<small>{e.data.elapsed_seconds.toFixed(e.data.elapsed_seconds<1?3:2)} s</small>}</li>)}</ol></Disclosure>;
}
export function PublicStream({text}) {
  const [pieces,setPieces]=useState(()=>text?[{start:0,text}]:[]), previous=useRef(text),reduced=useReducedMotion();
  useLayoutEffect(()=>{if(text===previous.current)return;const before=previous.current;previous.current=text;setPieces(old=>text.startsWith(before)?[...old,{start:before.length,text:text.slice(before.length)}]:text?[{start:0,text}]:[]);},[text]);
  return <p className="answer-text">{pieces.map(piece=><motion.span className="stream-piece" key={`${piece.start}:${piece.text}`} initial={{opacity:reduced?1:.45}} animate={{opacity:1}} transition={{duration:reduced?0:.16}}>{piece.text}</motion.span>)}<span className="stream-cursor" aria-hidden="true"/></p>;
}
export function UploadZone({file,setFile,maxBytes=8388608,disabled=false}) {
  const input=useRef(), [drag,setDrag]=useState(false), [error,setError]=useState(''), depth=useRef(0);
  const choose=f=>{if(disabled)return;setError('');if(!f)return;const message=evidenceFileError(f,maxBytes);if(message){setError(message);return;}setFile(f);};
  return <><button type="button" disabled={disabled} aria-busy={disabled} className={`upload-zone ${drag?'dragging':''} ${file?'has-file':''}`} aria-label={file?`Replace evidence file ${file.name}`:'Choose or drop an evidence file'} onClick={()=>input.current.click()} onDragEnter={e=>{if(disabled||!e.dataTransfer.types.includes('Files'))return;e.preventDefault();depth.current++;setDrag(true);}} onDragOver={e=>{if(e.dataTransfer.types.includes('Files'))e.preventDefault();}} onDragLeave={()=>{depth.current=Math.max(0,depth.current-1);if(!depth.current)setDrag(false);}} onDrop={e=>{e.preventDefault();depth.current=0;setDrag(false);choose(e.dataTransfer.files[0]);}}><motion.span animate={{scale:drag?1.07:1,y:drag?-3:0}} transition={{duration:.18}}>{file?<FileText size={25}/>:<FileUp size={25}/>}</motion.span><strong>{file?file.name:'Drop your evidence here'}</strong><span>{disabled?'Reading this evidence…':file?`${(file.size/1024).toFixed(1)} KiB · click to replace`:'or choose a file · PCAP / TShark TSV · 8 MiB'}</span></button><input ref={input} className="visually-hidden" disabled={disabled} tabIndex={-1} type="file" accept=".pcap,.tsv" aria-label="Choose evidence file" onChange={e=>{choose(e.target.files[0]);e.target.value='';}}/>{file&&<button type="button" disabled={disabled} className="subtle-button" onClick={()=>{setFile(null);setError('');input.current.value='';}}>Remove file<X size={12}/></button>}{error&&<p className="error" role="alert">{error}</p>}</>;
}
export function EmptyState({title,children,icon:Icon=FileText}) {return <div className="empty-state"><Icon size={24} strokeWidth={1.3}/><h3>{title}</h3><p>{children}</p></div>;}
