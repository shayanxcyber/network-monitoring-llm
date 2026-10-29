import React,{useEffect,useRef,useState} from 'react';
import {api,post} from './api';
import {sourceOption,comparisonMatches,comparisonDefaults} from './depth-metrics.mjs';
import {ArrowRight,Download,Layers,X} from 'lucide-react';

const number=v=>v==null?'Unavailable':typeof v==='number'?new Intl.NumberFormat(undefined,{maximumFractionDigits:4}).format(v):String(v);
const metrics=[['record_count','Decoded records'],['duration_seconds','Observed span · s'],['records_per_second','Records / observed s'],['frame_bytes_per_second','Frame bytes / observed s'],['syn_records','SYN without ACK records'],['reset_records','Reset records'],['visible_http_responses','Visible HTTP responses'],['mean_candidate_reply_seconds','Candidate reply delay · s']];
const roles=['baseline','problem','after','reference'];

export function CasePanel({review,reviews,onOpen,onChange}){
  const [group,setGroup]=useState(null),[ready,setReady]=useState(false),[title,setTitle]=useState('Service investigation');
  const [source,setSource]=useState(''),[role,setRole]=useState('baseline');
  const [left,setLeft]=useState(''),[right,setRight]=useState(review.id),[port,setPort]=useState('0');
  const [comparison,setComparison]=useState(null),[original,setOriginal]=useState(null),[removed,setRemoved]=useState(null);
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  const alive=useRef(true),revision=useRef(0);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;revision.current++;};},[]);
  const commit=value=>{onChange?.(value);if(!alive.current)return;setGroup(value);setComparison(null);setOriginal(null);};
  useEffect(()=>{
    let active=true;
    api(`/api/reviews/${review.id}/case`).then(value=>{
      if(!active)return;
      setGroup(value);setReady(true);
      if(value){const initial=comparisonDefaults(value.sources,review.id);setLeft(initial.left);setRight(initial.right);}
    }).catch(e=>{if(active){setError(e.message);setReady(true);}});
    return()=>{active=false;};
  },[review.id]);
  useEffect(()=>{
    if(!group)return;
    const selected=group.sources.filter(s=>s.selected);
    if(!selected.some(s=>s.review_id===left))setLeft(selected.find(s=>s.review_id!==right)?.review_id||'');
    if(!selected.some(s=>s.review_id===right))setRight(selected.find(s=>s.review_id===review.id)?.review_id||selected[0]?.review_id||'');
  },[group,left,right,review.id]);
  const run=async operation=>{
    setBusy(true);setError('');
    try{await operation();}catch(e){if(alive.current)setError(e.message);}
    finally{if(alive.current)setBusy(false);}
  };
  const edit=(set,value)=>{revision.current++;set(value);setOriginal(null);};
  const compare=()=>run(async()=>{
    const token=++revision.current;
    const value=await api(`/api/cases/${group.id}/comparison?${new URLSearchParams({baseline_id:left,comparison_id:right,port})}`);
    if(alive.current&&token===revision.current)setComparison(value);
  });
  const showOriginal=(sourceId,reference)=>run(async()=>{
    const saved=await api(`/api/reviews/${sourceId}`);
    const record=[...(saved.evidence.packets||[]),...(saved.evidence.log_records||[])].find(r=>r.id===reference);
    if(!record)throw new Error('This exact original is unavailable.');
    if(alive.current)setOriginal({sourceId,title:saved.title,record});
  });
  const comparisonQuery=comparison?new URLSearchParams({baseline_id:comparison.baseline_review_id,comparison_id:comparison.comparison_review_id,port:comparison.baseline.service_port}).toString():'';
  const dirty=comparison&&!comparisonMatches(comparison,left,right,port);
  const name=id=>{const s=group?.sources.find(s=>s.review_id===id);return s?`${s.title} · ${id.slice(0,8)}`:id.slice(0,8);};
  if(!ready)return <p role="status">Opening related evidence…</p>;
  return <div className="case-workspace">
    <p className="view-note">Keep baseline, problem and follow-up evidence together. Each source retains its own originals. Grouping does not authorise a network change.</p>
    {error&&<p className="notice" role="alert">{error}</p>}
    {!group?<form className="depth-form" onSubmit={e=>{e.preventDefault();run(async()=>commit(await post(`/api/reviews/${review.id}/case`,{title})));}}>
      <label>Investigation name<input value={title} maxLength={160} onChange={e=>setTitle(e.target.value)} required/></label>
      <button className="primary-button" disabled={busy}><Layers size={16}/>Group this source</button>
    </form>:<>
      <div className="depth-heading"><div><small>RELATED EVIDENCE</small><h2>{group.title}</h2></div><div className="depth-actions">
        <a className="subtle-button" href={`/api/cases/${group.id}/export?${comparisonQuery}`} download><Download size={15}/>Readable report</a>
        <a className="subtle-button" href={`/api/cases/${group.id}/export?format=json&${comparisonQuery}`} download>JSON</a>
      </div></div>
      <div className="case-sources">{group.sources.map(s=><div className="case-source" key={s.review_id}>
        <label><input type="checkbox" aria-label={`Include ${s.title} ${s.review_id.slice(0,8)}`} checked={!!s.selected} disabled={busy||(s.review_id===review.id&&!!s.selected)} onChange={e=>{
          const ids=group.sources.filter(x=>x.selected&&x.review_id!==s.review_id).map(x=>x.review_id);
          if(e.target.checked)ids.push(s.review_id);
          run(async()=>commit(await post(`/api/cases/${group.id}/selection`,{review_ids:ids})));
        }}/><span><strong>{s.title}</strong><small>{s.review_id.slice(0,8)} · {s.input_kind} · {s.sha256.slice(0,12)}{s.review_id===review.id?' · current source':''}</small></span></label>
        <div className="case-source-controls"><select aria-label={`Role for ${s.title} ${s.review_id.slice(0,8)}`} value={s.role} disabled={busy} onChange={e=>run(async()=>commit(await post(`/api/cases/${group.id}/sources/${s.review_id}/role`,{role:e.target.value})))}>{roles.map(v=><option key={v}>{v}</option>)}</select>
          <button className="subtle-button" disabled={busy} onClick={()=>onOpen(s.review_id)}>Open<ArrowRight size={14}/></button>
          {s.review_id!==review.id&&<button className="subtle-button" disabled={busy} onClick={()=>run(async()=>{
            const previous={source:s,selection:group.sources.filter(v=>v.selected).map(v=>v.review_id)};
            commit(await post(`/api/cases/${group.id}/sources/${s.review_id}/unlink`,{}));setRemoved(previous);
          })}>Unlink</button>}
        </div>
      </div>)}</div>
      {removed&&<p className="depth-caution" role="status">Unlinked {removed.source.title}. Its original and earlier answers are unchanged. <button className="subtle-button" disabled={busy} onClick={()=>run(async()=>{
        await post(`/api/cases/${group.id}/sources`,{review_id:removed.source.review_id,role:removed.source.role});
        commit(await post(`/api/cases/${group.id}/selection`,{review_ids:removed.selection}));setRemoved(null);
      })}>Undo unlink</button></p>}
      <form className="depth-form" onSubmit={e=>{e.preventDefault();run(async()=>{
        commit(await post(`/api/cases/${group.id}/sources`,{review_id:source,role}));
        if(role==='baseline')setLeft(source);else if(['problem','after'].includes(role))setRight(source);
        setSource('');
      });}}>
        <label>Link an existing source<select value={source} required disabled={busy} onChange={e=>setSource(e.target.value)}><option value="">Choose saved evidence</option>{reviews.filter(r=>!group.sources.some(s=>s.review_id===r.id)).map(r=><option value={r.id} key={r.id} disabled={!!r.case_id||group.sources.some(s=>s.sha256===r.sha256)}>{sourceOption(r)}{group.sources.some(s=>s.sha256===r.sha256)?' · same original already linked':''}</option>)}</select></label>
        <label>Role<select value={role} disabled={busy} onChange={e=>setRole(e.target.value)}>{roles.map(v=><option key={v}>{v}</option>)}</select></label>
        <button disabled={busy||!source||group.sources.length>=6}>Link source</button>
      </form>
      <section className="depth-section"><h3>What changed?</h3>
        <form className="depth-form" onSubmit={e=>{e.preventDefault();compare();}}>
          <label>Baseline<select aria-label="Baseline" required disabled={busy} value={left} onChange={e=>edit(setLeft,e.target.value)}><option value="">Choose baseline</option>{group.sources.filter(s=>s.selected).map(s=><option value={s.review_id} key={s.review_id}>{name(s.review_id)}</option>)}</select></label>
          <label>Compare with<select aria-label="Compare with" value={right} disabled={busy} onChange={e=>edit(setRight,e.target.value)}>{group.sources.filter(s=>s.selected).map(s=><option value={s.review_id} key={s.review_id}>{name(s.review_id)}</option>)}</select></label>
          <label className="port-filter">Service port<input type="number" min="0" max="65535" required disabled={busy} value={port} onChange={e=>edit(setPort,e.target.value)} title="0 means all ports"/></label>
          <button className="primary-button" disabled={busy||!left||left===right}>Compare</button>
        </form>
        {comparison&&<><p className="comparison-applied">Showing {name(comparison.baseline_review_id)} → {name(comparison.comparison_review_id)} · {comparison.baseline.service_port?`TCP/UDP port ${comparison.baseline.service_port}`:'all supported ports'}</p>
          {dirty&&<p className="depth-caution" role="status">Selection changed. Choose Compare to apply it. The results and report still use the pair shown above.</p>}
          <div className="depth-table-wrap"><table className="depth-table"><thead><tr><th>Measurement</th><th>Baseline</th><th>Comparison</th><th>Change</th></tr></thead><tbody>{metrics.map(([key,text])=><tr key={key}><th>{text}</th><td>{number(comparison.baseline[key])}</td><td>{number(comparison.comparison[key])}</td><td>{number(comparison.delta[key])}</td></tr>)}</tbody></table></div>
          <p className="view-note">{comparison.policy}</p>{comparison.qualifications.map((text,i)=><p className="depth-caution" key={i}>{text}</p>)}
          <div className="depth-original-links">{[[comparison.baseline_review_id,comparison.baseline,'Baseline'],[comparison.comparison_review_id,comparison.comparison,'Comparison']].map(([id,facts,title])=><div key={id}><strong>{title} originals · {id.slice(0,8)}</strong><p className="view-note">{facts.byte_unit} · {facts.excluded_records} excluded records</p>{facts.references.slice(0,8).map(ref=><button className="reference-chip" key={ref} onClick={()=>showOriginal(id,ref)}>{ref.split(':').pop()}</button>)}</div>)}</div>
        </>}
        {original&&<aside className="case-original"><div className="depth-heading"><h3>Original evidence · {original.title}</h3><button aria-label="Close original record" onClick={()=>setOriginal(null)}><X size={16}/></button></div><pre>{JSON.stringify(original.record,null,2)}</pre><button className="subtle-button" onClick={()=>onOpen(original.sourceId)}>Open this source workspace<ArrowRight size={14}/></button></aside>}
      </section>
      <p className="view-note">New questions use the selected sources above. Earlier answers keep their original evidence scope. Unlinking never deletes an original. Up to six sources per case.</p>
    </>}
  </div>;
}
