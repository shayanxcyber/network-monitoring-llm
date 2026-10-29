import React,{useEffect,useState} from 'react';
import {api,post} from './api';
import {ArrowRight,Check,Database,Download,Layers,Network,Square,X} from 'lucide-react';
import './depth.css';

const number=value=>value==null?'Unavailable':typeof value==='number'?new Intl.NumberFormat(undefined,{maximumFractionDigits:4}).format(value):String(value);
const rememberedCapture=()=>{try{return localStorage.getItem('packetpilot:capture-session');}catch{return null;}};
const rememberCapture=id=>{try{if(id)localStorage.setItem('packetpilot:capture-session',id);else localStorage.removeItem('packetpilot:capture-session');}catch{/* Collection still works without browser persistence. */}};

export {CasePanel} from './case-panel';
export {ServiceOutcomes} from './service-outcomes';

export function CaptureSession({config,onOpen,reviewId,notice}){
  const [duration,setDuration]=useState(6),[job,setJob]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const [provider,setProvider]=useState(config?.api_ready?'api':'rules'),[group,setGroup]=useState(null),[role,setRole]=useState('after');
  useEffect(()=>{let alive=true;const id=rememberedCapture();if(id)api(`/api/captures/${id}`).then(v=>{if(alive)setJob(v);}).catch(()=>{});if(reviewId)api(`/api/reviews/${reviewId}/case`).then(v=>{if(alive)setGroup(v);}).catch(()=>{});return()=>{alive=false;};},[reviewId]);
  useEffect(()=>{if(!job||!['starting','collecting','stopping'].includes(job.status))return;let alive=true;const timer=setInterval(()=>api(`/api/captures/${job.id}`).then(value=>{if(alive)setJob(value);}).catch(e=>{if(alive)setError(e.message);}),800);return()=>{alive=false;clearInterval(timer);};},[job?.id,job?.status]);
  const run=async action=>{setBusy(true);setError('');try{await action();}catch(e){setError(e.message);}finally{setBusy(false);}};
  const active=job&&['starting','collecting','stopping'].includes(job.status);
  return <div className="capture-session"><p className="view-note">Collect real traffic at the isolated service interface. This profile generates authorised HTTP health requests from both lab clients. It cannot capture the wider network.</p>{error&&<p className="notice" role="alert">{error}</p>}
    {!active&&<form className="depth-form" onSubmit={e=>{e.preventDefault();run(async()=>{const value=await post('/api/captures',{duration_seconds:Number(duration),provider});setJob(value);rememberCapture(value.id);});}}><label>Duration · seconds<input type="number" min="2" max="20" required value={duration} onChange={e=>setDuration(e.target.value)}/></label><label>Investigation mode<select value={provider} onChange={e=>setProvider(e.target.value)}><option value="api" disabled={!config?.api_ready}>Hosted investigation</option><option value="rules">Offline evidence inspection</option></select></label><button className="primary-button" disabled={busy}><Network size={16}/>Start collection</button></form>}
    {job&&<section className="capture-state" aria-live="polite"><div className="depth-heading"><strong><i className={`capture-dot ${active?'active':''}`}/>{job.status}</strong><small>{job.id?.slice(0,8)}</small></div><p>{job.observation_point||'Fixed lab service'} · {number(job.bytes||0)} saved bytes</p>{active&&<><p className="view-note">Collection is running in the broker and remains bounded if this window closes.</p><div className="depth-actions"><button disabled={busy||job.status==='stopping'} onClick={()=>run(async()=>setJob(await post(`/api/captures/${job.id}/stop`,{})))}><Square size={14}/>Stop and keep evidence</button><button disabled={busy} onClick={()=>run(async()=>setJob(await post(`/api/captures/${job.id}/cancel`,{})))}>Cancel collection</button></div></>}{job.error&&<p>{job.error}</p>}
    {job.status==='completed'&&<>{group&&group.sources.length<6&&<label>Attach to {group.title}<select value={role} onChange={e=>setRole(e.target.value)}>{['after','baseline','problem','reference'].map(v=><option key={v}>{v}</option>)}</select></label>}{group?.sources.length>=6&&<p className="view-note">This case has six sources. The capture will open as a separate retained investigation.</p>}<button className="primary-button" disabled={busy} onClick={()=>run(async()=>{const saved=await post(`/api/captures/${job.id}/import`,{});if(group&&group.sources.length<6&&!group.sources.some(s=>s.review_id===saved.id))await post(`/api/cases/${group.id}/sources`,{review_id:saved.id,role});rememberCapture(null);await onOpen(saved.id);})}><Database size={16}/>Open retained evidence</button></>}{job.status==='cancelled'&&<p>No investigation was imported. The bounded collection is stopped.</p>}</section>}
  </div>;
}

