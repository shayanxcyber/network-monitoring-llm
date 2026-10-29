import React,{useEffect,useState} from 'react';
import {api,post} from './api';
import {readLocal,writeLocal} from './domain';
import {diagnosticMetric,diagnosticPair} from './depth-metrics.mjs';

const number=v=>new Intl.NumberFormat(undefined,{maximumFractionDigits:4}).format(v);
const identity=r=>`${r.id.slice(0,8)} · ${new Date(r.recorded_at).toLocaleTimeString()} · ${r.profile||'health'}`;
export function ServiceOutcomes({review}){
  const [rows,setRows]=useState([]),[lab,setLab]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const [profile,setProfile]=useState('health'),[objective,setObjective]=useState('Observe service reachability and recovery for both clients.');
  const [pairIds,setPairIds]=useState(()=>readLocal(`outcome-pair:${review.id}`,{baseline:'',after:''}));
  useEffect(()=>{writeLocal(`outcome-pair:${review.id}`,pairIds);},[review.id,pairIds]);
  useEffect(()=>{
    let alive=true;
    api(`/api/reviews/${review.id}/diagnostics`).then(v=>{if(alive)setRows(v);}).catch(e=>{if(alive)setError(e.message);});
    api('/api/lab/status').then(v=>{if(alive)setLab(v.available&&v.lab?.available?v.lab:null);}).catch(()=>{});
    return()=>{alive=false;};
  },[review.id]);
  const baseline=rows.find(r=>r.id===pairIds.baseline);
  const canFollow=baseline&&(baseline.profile||'health')===profile&&baseline.objective===objective&&baseline.lab_context?.generation===lab?.generation;
  const pair=diagnosticPair(rows,pairIds.baseline,pairIds.after);
  const record=async phase=>{
    setBusy(true);setError('');
    try{
      const value=await post(`/api/reviews/${review.id}/diagnostics`,{
        phase,profile,objective,action_id:null,baseline_id:phase==='baseline'?null:baseline.id
      });
      setRows(old=>[...old,value]);
      if(phase==='baseline')setPairIds({baseline:value.id,after:''});
      if(phase==='after')setPairIds(old=>({...old,after:value.id}));
    }catch(e){setError(e.message);}finally{setBusy(false);}
  };
  return <section className="depth-section service-outcomes"><h3>Did the service outcome change?</h3>
    <p className="view-note">These checks send fresh requests in the current lab. They do not measure the historical ports or service in an uploaded file.</p>
    {lab?<dl className="diagnostic-scope"><div><dt>Current service</dt><dd>{lab.addresses.service}:{lab.service_port}</dd></div><div><dt>Selected client</dt><dd>{lab.addresses.source}</dd></div><div><dt>Control client</dt><dd>{lab.addresses.control}</dd></div><div><dt>Check</dt><dd>{profile==='transfer'?'Complete 128 KiB transfer':'HTTP health and first byte'}</dd></div></dl>:<p className="depth-caution">Current lab details are unavailable. Saved observations remain readable; new checks are disabled.</p>}
    <div className="depth-form"><label>Service objective<input value={objective} maxLength={240} onChange={e=>setObjective(e.target.value)} disabled={busy}/></label><label>Check<select value={profile} onChange={e=>setProfile(e.target.value)} disabled={busy}><option value="health">HTTP health and first byte</option><option value="transfer">Complete 128 KiB transfer</option></select></label></div>
    <div className="depth-actions">{['baseline','during','after'].map(phase=><button disabled={busy||!lab||!objective.trim()||(phase!=='baseline'&&!canFollow)} key={phase} onClick={()=>record(phase)}>{busy?'Checking…':`Record ${phase}`}</button>)}</div>
    <p className="view-note">Start a new baseline for each measurement cycle. During/after use the selected baseline below and the same check and objective. Phase labels are yours; they do not prove that an action is active or approved.</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {!!rows.length&&<>
      <div className="depth-table-wrap"><table className="depth-table"><thead><tr><th>Observation</th><th>Selected client</th><th>Control client</th></tr></thead><tbody>{rows.map(r=><tr key={r.id}><th>{r.phase}<small>{identity(r)}{r.baseline_id?` · baseline ${r.baseline_id.slice(0,8)}`:''}</small></th>{['source','control'].map(role=><td key={role}>{r.result.clients[role].reachable?'HTTP reachable':'No successful response'}<small>{diagnosticMetric(r.result.clients[role],r.profile,number)}</small></td>)}</tr>)}</tbody></table></div>
      <div className="depth-form"><label>Baseline observation<select aria-label="Baseline observation" value={pairIds.baseline} disabled={busy} onChange={e=>setPairIds({baseline:e.target.value,after:''})}><option value="">Choose a baseline</option>{rows.filter(r=>r.phase==='baseline').map(r=><option key={r.id} value={r.id}>{identity(r)}</option>)}</select></label>
        <label>After observation<select aria-label="After observation" value={pairIds.after} disabled={busy} onChange={e=>setPairIds(old=>({...old,after:e.target.value}))}><option value="">Choose an after observation</option>{rows.filter(r=>r.phase==='after').map(r=><option key={r.id} value={r.id}>{identity(r)}</option>)}</select></label></div>
      {pair.delta==null?<p className="view-note">{pair.reason}</p>:<p className="depth-caution">Baseline {pair.first.id.slice(0,8)} → after {pair.last.id.slice(0,8)} · {pair.last.result.service} · {pair.last.objective}<br/>Control-client {pair.last.profile==='transfer'?'complete-transfer':'first-byte'} change: {number(pair.delta)} s. One request per client per observation. This pair alone does not establish causation or representative performance.</p>}
      <details><summary>Original diagnostic results and objectives</summary><pre>{JSON.stringify(rows,null,2)}</pre></details>
    </>}
  </section>;
}
