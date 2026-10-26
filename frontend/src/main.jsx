import React, {createContext, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, useCallback} from 'react';
import {createRoot} from 'react-dom/client';
import {AssistantRuntimeProvider, useExternalStoreRuntime, useAui, useAuiState,
  ThreadPrimitive, MessagePrimitive, ComposerPrimitive} from '@assistant-ui/react';
import {motion, MotionConfig, AnimatePresence, useReducedMotion} from 'motion/react';
import {PanelLeft, Plus, Search, FileUp, Network, SlidersHorizontal, Download, ArrowUp,
  X, ChevronRight, Database, MessageSquare, ShieldCheck, Copy, Check, ArrowRight, ArrowLeft, CircleAlert, Maximize2, Command, LockKeyhole, FileText} from 'lucide-react';
import {api, post} from './api';
import {label, referenceIndex, applyEvent, hydrateRun, messagesFor, defaultViews, terminal, readLocal, writeLocal, inspectionFor, uniqueNotes, endpoint, shouldRevealAnswer, drillInspection, backInspection} from './domain';
import {DataTable, References, EvidenceVisual, AnswerView, ProtocolComposition} from './views';
import {Modal, Tooltips, Hint, Segments, Disclosure, BorderBeam, ActivitySignal, ActivitySteps, activityLabel, UploadZone, EmptyState, PublicStream} from './components';
import {ActionReceipts, ActionOverview} from './actions';
import {FlowPicker, TechnicalText, EvidenceExtracts, WorkspacePanels, HomeRecent, SectionEntrance} from './refinement';
import {CasePanel,CaptureSession,ServiceOutcomes} from './depth';
import {sourceRelativeTime,currentSourceSelected,canDismissProposal} from './depth-metrics.mjs';
import './style.css';
import './premium.css';
import './refinement.css';
import './landing.css';

const Workspace = createContext(null);
const TSV_HEADER=['frame.number','frame.time_epoch','frame.len','ip.src','ip.dst','ip.proto','tcp.srcport','tcp.dstport','tcp.flags','udp.srcport','udp.dstport'].join('\t');
const draftKey = id => `draft:${id}`;
function Mark() {return <span className="brand-mark" aria-hidden="true">✳</span>;}
function IconButton({title, icon: Icon, ...props}) {return <Hint label={title}><button className="icon-button" aria-label={title} {...props}><Icon size={18} strokeWidth={1.5}/></button></Hint>;}
function CopyButton({text}) {const [state,setState]=useState('idle'),timer=useRef();useEffect(()=>()=>clearTimeout(timer.current),[]);return <span className="copy-feedback"><button className="subtle-button" onClick={async()=>{clearTimeout(timer.current);try{await navigator.clipboard.writeText(text);setState('copied');timer.current=setTimeout(()=>setState('idle'),2500);}catch{setState('failed');}}}>{state==='copied'?<Check size={14}/>:<Copy size={14}/>} {state==='copied'?'Copied':'Copy'}</button>{state==='failed'&&<small role="status">Copy unavailable. Select the text or download it.</small>}</span>;}

function App() {
  const [config,setConfig]=useState(null), [reviews,setReviews]=useState([]), [review,setReview]=useState(null);
  const [caseInfo,setCaseInfo]=useState(null);
  const [data,setData]=useState(null), [runsBySource,setRuns]=useState(()=>readLocal('unresolved-runs',{})), [expanded,setExpanded]=useState(readLocal('sidebar',true));
  const [listQuery,setListQuery]=useState(''), [threadQuery,setThreadQuery]=useState(''), [tab,setTabValue]=useState('records');
  const [modal,setModal]=useState(null), [notice,setNotice]=useState(''), [loading,setLoading]=useState(false);
  const [selected,setSelected]=useState(null), [inspectionState,setInspectionState]=useState({item:null,parents:[],scroll:0}), [screen,setScreen]=useState('investigation'), [prefs,setPrefs]=useState(readLocal('preferences',{density:'comfortable',detail:'focused'}));
  const inspection=inspectionState.item, setInspection=useCallback(item=>setInspectionState({item,parents:[],scroll:0}),[]);
  const [share,setShare]=useState(readLocal('evidence-share',42));
  const ticket=useRef(0), selectedId=useRef(null), subscriptions=useRef(new Map());
  const caseRevision=useRef(0);
  const evidenceBody=useRef(),inspectionOrigin=useRef();
  const closeInspection=useCallback(()=>{setInspection(null);requestAnimationFrame(()=>{if(inspectionOrigin.current?.isConnected)inspectionOrigin.current.focus({preventScroll:true});});},[setInspection]);
  const setTab=useCallback(value=>{setTabValue(value);if(selectedId.current)writeLocal(`view:${selectedId.current}`,value);},[]);
  const showHome=useCallback((push=true)=>{++ticket.current;selectedId.current=null;setReview(null);setData(null);setSelected(null);setInspection(null);setScreen('home');setLoading(false);if(push&&location.hash!=='#view=home')history.pushState({},'','#view=home');},[setInspection]);
  useLayoutEffect(()=>{if(review&&evidenceBody.current)evidenceBody.current.scrollTop=readLocal(`evidence-scroll:${review.id}:${tab}`,0);},[review?.id,tab]);
  useLayoutEffect(()=>{if(!inspection)return;for(const el of document.querySelectorAll('.inspector-scroll,.reference-content'))el.scrollTop=inspectionState.scroll||0;},[inspection,inspectionState.scroll]);
  useEffect(()=>{document.title=review&&screen==='investigation'?`${review.title} · PacketPilot`:screen==='actions'?'Lab actions · PacketPilot':'Workspace · PacketPilot';},[review?.title,screen]);
  const refreshList=useCallback(async()=>setReviews(await api('/api/reviews')),[]);
  const updatePrefs=value=>{setPrefs(value);writeLocal('preferences',value);};
  const updateShare=value=>{const v=Math.max(30,Math.min(62,value));setShare(v);writeLocal('evidence-share',v);};
  const select=useCallback(async(id)=>{
    const n=++ticket.current,scopeVersion=caseRevision.current; setLoading(true); setNotice(''); setThreadQuery('');
    try {
      const [saved, jobs, views, initialGroup] = await Promise.all([api(`/api/reviews/${id}`),api(`/api/reviews/${id}/runs`),api(`/api/reviews/${id}/views`),api(`/api/reviews/${id}/case`)]);
      const group=scopeVersion===caseRevision.current?initialGroup:await api(`/api/reviews/${id}/case`);
      if(ticket.current!==n)return;
      selectedId.current=id;setReview(saved);setData(views);setCaseInfo(group);setSelected(null);setInspection(null);setScreen('investigation');
      setRuns(previous=>({...previous,[id]:[...jobs.map(hydrateRun),...(previous[id]||[]).filter(r=>!jobs.some(j=>j.id===r.id))]}));
      const savedView=readLocal(`view:${id}`,saved.evidence.schema_version==='2'?'records':'coverage');setTabValue(['records','timeline','map','charts','coverage','actions'].includes(savedView)?savedView:'records');
      if(location.hash!==`#review=${id}`)history.pushState({},'',`#review=${id}`);
    } catch(e) {if(ticket.current===n)setNotice(e.message);} finally {if(ticket.current===n)setLoading(false);}
  },[]);
  const caseChanged=useCallback(value=>{
    caseRevision.current++;
    const current=selectedId.current;
    if(value.sources.some(s=>s.review_id===current))setCaseInfo(value);
    else if(current)api(`/api/reviews/${current}/case`).then(v=>{if(selectedId.current===current)setCaseInfo(v);}).catch(e=>setNotice(e.message));
    refreshList().catch(e=>setNotice(e.message));
  },[refreshList]);
  useEffect(()=>{
    (async()=>{try{setConfig(await api('/api/config')); const saved=await api('/api/reviews');setReviews(saved);
      const active=await api('/api/runs/active');setRuns(previous=>{const groups={...previous};for(const r of active)groups[r.review_id]=[...(groups[r.review_id]||[]).filter(j=>j.id!==r.id),r];return groups;});
      const params=new URLSearchParams(location.hash.slice(1)),id=params.get('review');if(params.get('view')==='actions')setScreen('actions');else if(id)await select(id);
    }catch(e){setNotice(e.message);}})();
    const historyChange=()=>{const p=new URLSearchParams(location.hash.slice(1));if(p.get('view')==='actions')setScreen('actions');else if(p.get('review'))select(p.get('review'));else showHome(false);};
    window.addEventListener('popstate',historyChange);return()=>window.removeEventListener('popstate',historyChange);
  },[select,showHome]);
  useEffect(()=>{const unresolved={};for(const [id,runs]of Object.entries(runsBySource)){const pending=runs.filter(r=>!terminal(r.status)||r.local_failure);if(pending.length)unresolved[id]=pending.map(r=>({...r,status:r.status==='sending'?'uncertain':r.status}));}writeLocal('unresolved-runs',unresolved);},[runsBySource]);
  const busy = Object.values(runsBySource).flat().find(run=>!terminal(run.status));
  const pendingIds=Object.values(runsBySource).flat().filter(run=>!terminal(run.status)&&run.status!=='sending').map(r=>r.id).sort().join(',');
  useEffect(()=>{
    const jobs=Object.values(runsBySource).flat().filter(run=>!terminal(run.status)&&run.status!=='sending');
    for(const job of jobs) {
      if(subscriptions.current.has(job.id))continue;
      const stream=new EventSource(`/api/reviews/${job.review_id}/runs/${job.id}/events?after=${job.cursor||0}`);
      subscriptions.current.set(job.id,stream);
      let settled=false, checking=false;
      const finish=async()=>{
        if(settled)return;settled=true;stream.close();clearInterval(poll);subscriptions.current.delete(job.id);
        try {const [result,saved]=await Promise.all([api(`/api/reviews/${job.review_id}/runs/${job.id}`),api(`/api/reviews/${job.review_id}`)]);
          setRuns(previous=>({...previous,[job.review_id]:(previous[job.review_id]||[]).map(run=>run.id===job.id?hydrateRun(result):run)}));
          if(selectedId.current===job.review_id)setReview(saved);await refreshList();
        }catch(e){setNotice(e.message);}
      };
      stream.onmessage=event=>{let item;try{item=JSON.parse(event.data);}catch{return;}
        setRuns(previous=>({...previous,[job.review_id]:(previous[job.review_id]||[]).map(run=>run.id===job.id?applyEvent({...run,reconnecting:false},item):run)}));
        if(terminal(item.type))finish();};
      const recover=async()=>{if(settled||checking)return;checking=true;try{const snapshot=await api(`/api/reviews/${job.review_id}/runs/${job.id}?after=${job.cursor||0}`);
        setRuns(previous=>({...previous,[job.review_id]:(previous[job.review_id]||[]).map(run=>run.id===job.id?hydrateRun({...snapshot,events:[...(run.events||[]),...snapshot.events].filter((e,i,all)=>all.findIndex(x=>x.sequence===e.sequence)===i)}):run)}));
        if(terminal(snapshot.status))await finish();
      }catch(e){if(e.status===404){settled=true;stream.close();clearInterval(poll);subscriptions.current.delete(job.id);setRuns(previous=>({...previous,[job.review_id]:(previous[job.review_id]||[]).map(run=>run.id===job.id?{...run,status:'failed',local_failure:true,error:'This request was not accepted by the backend. It was not sent again.'}:run)}));}}finally{checking=false;}};
      const poll=setInterval(recover,4000);
      stream._cleanup=()=>clearInterval(poll);
      stream.onerror=()=>{setRuns(previous=>({...previous,[job.review_id]:(previous[job.review_id]||[]).map(run=>run.id===job.id?{...run,reconnecting:true}:run)}));recover();};
      stream.addEventListener('settled',finish);
    }
    for(const [id,stream]of subscriptions.current)if(!jobs.some(job=>job.id===id)){stream.close();stream._cleanup?.();subscriptions.current.delete(id);}
  },[pendingIds,refreshList]);
  useEffect(()=>()=>{for(const stream of subscriptions.current.values()){stream.close();stream._cleanup?.();}},[]);
  const submit=useCallback(async(question, id=crypto.randomUUID(), selectedReference=selected)=>{
    const source=selectedId.current;if(!source)return;
    const optimistic={id,review_id:source,question,selected_reference:selectedReference,status:'sending',events:[],cursor:0,created_at:new Date().toISOString()};
    setRuns(previous=>({...previous,[source]:[...(previous[source]||[]),optimistic]}));
    try {const accepted=hydrateRun(await post(`/api/reviews/${source}/runs`,{question,request_id:id,selected_reference:selectedReference}));
      setRuns(previous=>({...previous,[source]:previous[source].map(run=>run.id===id?accepted:run)}));
      if(terminal(accepted.status)){const saved=await api(`/api/reviews/${source}`);if(selectedId.current===source)setReview(saved);await refreshList();}
    }catch(e){
      // Lost acknowledgement is not proof the provider job failed. Query the
      // same identity before offering a fresh paid retry.
      try {const recovered=hydrateRun(await api(`/api/reviews/${source}/runs/${id}`));setRuns(previous=>({...previous,[source]:previous[source].map(run=>run.id===id?recovered:run)}));}
      catch(check){setRuns(previous=>({...previous,[source]:previous[source].map(run=>run.id===id?{...run,status:e.status||check.status===404?'failed':'uncertain',local_failure:!!(e.status||check.status===404),error:e.message}:run)}));}
    }
  },[refreshList,selected]);
  const inspect=useCallback(target=>{
    if(!review)return;const item=inspectionFor(target,review);
    if(!item){setNotice('That original reference is unavailable. No substitute was selected.');return;}
    if(!inspection)inspectionOrigin.current=document.activeElement?.closest('.flow-picker-menu')?document.querySelector('.flow-picker-trigger'):document.activeElement;
    const scroll=document.querySelector('.reference-content')?.scrollTop??document.querySelector('.inspector-scroll')?.scrollTop??0;
    setInspectionState(previous=>drillInspection(previous,item,scroll));setModal(previous=>previous?.kind==='reference'?{...item,kind:'reference'}:previous?.kind==='recommendation'?null:previous);
  },[review,inspection]);
  const goBack=()=>{const state=backInspection(inspectionState);setInspectionState(state);setModal(previous=>previous?.kind==='reference'?{...state.item,kind:'reference'}:previous);requestAnimationFrame(()=>document.querySelector('.inspector-content')?.focus({preventScroll:true}));};
  const create=async(value, file)=>{
    let saved;
    if(file){if(!file.size||file.size>config.max_upload_bytes)throw new Error('Choose a non-empty PCAP or supported TSV log no larger than 8 MiB.');const form=new FormData();form.append('file',file);form.append('provider',value.provider);saved=await api('/api/reviews/upload',{method:'POST',body:form});}
    else saved=await post('/api/reviews',value);
    setModal(null);await refreshList();await select(saved.id);
  };
  const capture=()=>setModal({kind:'capture'});
  const inspectRecommendation=async(turnId,index)=>{try{const value=await api(`/api/reviews/${review.id}/recommendations/${index}?turn_id=${turnId}`);setModal({kind:'recommendation',value,turnId,index});}catch(e){setNotice(e.message);}};
  const composition='report';
  const context={review,data,inspect,inspection,inspectionState,goBack,composition,selected,setSelected,submit,prefs,threadQuery,clearSearch:()=>setThreadQuery(''),caseInfo,openCase:()=>setModal({kind:'case'}),runs:runsBySource[review?.id]||[],busy,config,inspectRecommendation,notice:setNotice};
  const showActions=()=>{setScreen('actions');setInspection(null);history.pushState({},'','#view=actions');};
  useEffect(()=>{const shortcut=e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();setModal({kind:'command'});}if(e.key==='Escape'&&!modal&&!e.defaultPrevented&&!document.querySelector('[data-radix-popper-content-wrapper]'))closeInspection();};window.addEventListener('keydown',shortcut);return()=>window.removeEventListener('keydown',shortcut);},[modal,closeInspection]);
  const count=data?.coverage, log=review?.evidence.input_kind==='network_log';
  const variants=['quiet','editorial','compact'];const selectedVariant=new URLSearchParams(location.search).get('variant');
  const variant=variants.includes(selectedVariant)?selectedVariant:'quiet';
  return <MotionConfig reducedMotion="user"><Tooltips><Workspace.Provider value={context}>
  <div className={`shell ${expanded?'expanded':''} density-${prefs.density} variant-${variant}`}>
    <aside className="sidebar"><a className="brand" href="#view=home" aria-label="PacketPilot home" title="Return to workspace" onClick={e=>{e.preventDefault();showHome();}}><Mark/><span>PacketPilot</span></a>
      <nav className="workspace-navigation" aria-label="Workspace"><button onClick={()=>{setExpanded(!expanded);writeLocal('sidebar',!expanded);}} title="Toggle sidebar" aria-label="Toggle sidebar" aria-expanded={expanded}><PanelLeft size={18}/><span>Workspace</span></button>
      <button onClick={()=>setModal({kind:'import'})} title="Import evidence"><FileUp size={18}/><span>Import evidence</span></button><button onClick={capture} disabled={loading||!!busy||!config} title="Current lab capture"><Network size={18}/><span>Current lab capture</span></button>
      <button className={screen==='actions'?'selected':''} onClick={showActions} title="Lab actions"><ShieldCheck size={18}/><span>Lab actions</span></button><button onClick={()=>setModal({kind:'command'})} title="Quick switch · Ctrl K"><Command size={18}/><span>Quick switch<kbd>Ctrl K</kbd></span></button></nav>
      <section className="saved-section"><div className="section-heading"><span>Investigations</span><IconButton icon={Plus} title="New investigation" onClick={()=>setModal({kind:'import'})}/></div>
        <label className="search"><Search size={14}/><input aria-label="Search saved investigations" placeholder="Find an investigation" value={listQuery} onChange={e=>setListQuery(e.target.value)}/></label>
        <HistoryList reviews={reviews} query={listQuery} current={screen==='investigation'?review?.id:null} select={select}/>
      </section>
      <footer><button title="Reading preferences" onClick={()=>setModal({kind:'settings'})}><SlidersHorizontal size={18}/><span>Preferences</span></button><p><LockKeyhole size={12}/><span>Local workspace</span></p></footer>
    </aside>
    <main className={`main ${screen!=='actions'&&!review?'is-home':''}`}><header className="topbar"><div><a className="home-link" href="#view=home" onClick={e=>{e.preventDefault();showHome();}}>Workspace</a><ChevronRight size={13}/><strong>{screen==='actions'?'Lab actions':review?.title||'Investigations'}</strong></div><div><Hint label={config?.api_ready?'Model configuration is available. A submitted question verifies the connection.':'No model configuration. Original evidence is still available.'}><span className="ready"><i className="status-dot"/>{config?.api_ready?'Model ready':'Offline'}</span></Hint><button className="subtle-button" onClick={()=>setModal({kind:'import'})} disabled={!config}><Plus size={16}/>New investigation</button></div></header>
      {notice&&<div className="notice" role="alert"><CircleAlert size={16}/>{notice}<IconButton title="Dismiss notice" icon={X} onClick={()=>setNotice('')}/></div>}
      {screen==='actions'?<ActionOverview select={select} capture={capture} notice={setNotice}/>:!review ? <section className={`welcome ${reviews.length?'has-recent':''}`}><div className="welcome-intro"><div className="welcome-copy"><p className="eyebrow">EVIDENCE, WITH UNDERSTANDING</p><h1>Make sense of your network.</h1><p>Bring a capture or saved network log. Investigate the details, follow the evidence and review the next step.</p></div><div className="welcome-start"><div className="welcome-actions"><button className="primary-button" onClick={()=>setModal({kind:'import'})} disabled={!config}><FileUp size={17}/>Open evidence</button><button onClick={capture} disabled={!config||loading||!!busy}><Network size={17}/>Current lab capture</button></div><span className="muted">PCAP · supported TShark TSV</span></div></div><HomeRecent reviews={reviews} select={select}/></section>
      : <><section className="investigation-header"><div><p className="eyebrow">{log?'SAVED NETWORK LOG':'NETWORK INVESTIGATION'}</p><h1>{review.title}</h1><p>{count?.selected_records} {log?'original lines':'packets'} · {data?.window.duration_seconds.toFixed(3)} s decoded window · {review.provider==='api'?'Saved conversation':'Offline inspection'}</p></div><div className="depth-actions"><button className="subtle-button" onClick={()=>setModal({kind:'case'})}><Database size={16}/>Related evidence & compare</button><a className="subtle-button" href={`/api/reviews/${review.id}/export`} download><Download size={16}/>Export source</a></div></section>
      <WorkspacePanels key={review.id} composition={composition} className={`panels ${loading?'is-loading':''}`} style={{'--evidence-share':`${share}%`}}>
        <section className={`evidence-panel ${inspection?'has-inspector':''}`}><div className="panel-heading"><div><Database size={17}/><h2>{log?'Log evidence':'Capture evidence'}</h2></div><Hint label="Source identity and full checksum"><button className="source-identity" onClick={()=>inspect(`${review.evidence.capture.sha256}:capture`)}>{review.evidence.capture.sha256.slice(0,8)}<ArrowRight size={13}/></button></Hint></div>
        <Segments className="evidence-tabs" label="Evidence views" value={tab} onChange={setTab} items={['records','timeline','map','charts','coverage','actions']}/>
        <div className="evidence-body" ref={evidenceBody} onScroll={e=>writeLocal(`evidence-scroll:${review.id}:${tab}`,e.currentTarget.scrollTop)}>
          {tab==='records'&&<>{!!review.evidence.flows?.length&&<div className="flow-selector"><span>Flow details</span><FlowPicker flows={review.evidence.flows} selected={inspection} onChange={inspect}/></div>}<DataTable key={review.id} reviewId={review.id} inspect={inspect} selected={inspection}/></>}
          {tab==='timeline'&&<EvidenceVisual type="timeline" data={data} inspect={inspect} selected={inspection}/>}
          {tab==='map'&&<EvidenceVisual type="map" data={data} inspect={inspect} selected={inspection}/>}
          {tab==='charts'&&<><ProtocolComposition data={data} inspect={inspect} selected={inspection}/><EvidenceVisual type="bar" data={data} inspect={inspect} selected={inspection}/>{data?.series.data.length ? <ChartChoice data={data} inspect={inspect} selected={inspection}/> : <p className="view-note">{data?.series.reason} Open Timeline to inspect the recorded exchanges.</p>}<EvidenceVisual type="comparison" data={data} inspect={inspect} selected={inspection}/></>}
          {tab==='coverage'&&<section className="coverage"><h3>What this source can show</h3><dl><dt>Retained records</dt><dd>{count?.selected_records}</dd><dt>Decoded TCP/UDP</dt><dd>{count?.decoded_records}</dd><dt>Excluded or unreadable</dt><dd>{count?.excluded_records}</dd></dl><p>{log?'Original physical lines and exported header fields. No raw packet, payload or sequence reconstruction.':'Retained supported packet headers, original references and bounded payload previews.'}</p><ul>{(review.evidence.limitations||[]).map((t,i)=><li key={i}>{t}</li>)}</ul><References ids={[`${review.evidence.capture.sha256}:coverage`]} inspect={inspect}/></section>}
          {tab==='actions'&&<><ActionReceipts review={review} notice={setNotice}/><ServiceOutcomes key={review.id} review={review} notice={setNotice}/></>}
        </div><AnimatePresence initial={false}>{inspection&&<motion.aside className="inline-inspector" key={review.id} initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:.24,ease:[.2,0,0,1]}} aria-label="Evidence inspector"><div className="inspector-heading"><span><small>INSPECTING</small><strong>{inspection.aggregate?inspection.title:label(inspection.id)}</strong></span><div><IconButton title="Expand evidence details" icon={Maximize2} onClick={()=>setModal({...inspection,kind:'reference'})}/><IconButton title="Close evidence inspector" icon={X} onClick={closeInspection}/></div></div><div className="inspector-scroll"><InspectorContent item={inspection} add={()=>{setSelected(inspection.id);closeInspection();}}/></div></motion.aside>}</AnimatePresence><div className="evidence-footer"><span>{count?.decoded_records} decoded · {count?.excluded_records ? `${count.excluded_records} excluded` : 'supported headers retained'}</span><button onClick={()=>setTab('coverage')}>Coverage<ArrowRight size={12}/></button></div></section>
        <div className="divider" role="separator" tabIndex="0" aria-label="Resize evidence panel" aria-orientation="vertical" aria-valuemin="30" aria-valuemax="62" aria-valuenow={Math.round(share)} onKeyDown={e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();updateShare(e.key==='Home'?30:e.key==='End'?62:share+(e.key==='ArrowLeft'?-2:2)*(composition==='report'?-1:1));}}} onPointerDown={e=>{const element=e.currentTarget,panel=element.parentElement; element.setPointerCapture(e.pointerId); const move=ev=>{const r=panel.getBoundingClientRect(),ratio=(ev.clientX-r.left)/r.width*100;updateShare(composition==='report'?100-ratio:ratio);}; const end=()=>{element.removeEventListener('pointermove',move);element.removeEventListener('pointerup',end);element.removeEventListener('pointercancel',end);};element.addEventListener('pointermove',move);element.addEventListener('pointerup',end);element.addEventListener('pointercancel',end);}}/>
        <section className="conversation-panel"><div className="panel-heading"><div><MessageSquare size={17}/><h2>Investigation</h2></div><label className="thread-search"><Search size={15}/><input aria-label="Find in conversation" placeholder="Find text or reference" value={threadQuery} onChange={e=>setThreadQuery(e.target.value)}/></label></div><Conversation key={review.id}/></section>
      </WorkspacePanels></>}
    </main>
  </div>
  {modal?.kind==='import'&&<ImportModal close={()=>setModal(null)} config={config} create={create}/>}
  {modal?.kind==='case'&&review&&<Modal title="Related evidence and comparisons" className="case-dialog" wide close={()=>setModal(null)}><CasePanel key={review.id} review={review} reviews={reviews} notice={setNotice} onChange={caseChanged} onOpen={async id=>{setModal(null);await select(id);}}/></Modal>}
  {modal?.kind==='capture'&&<Modal title="Collect service evidence" close={()=>setModal(null)}><CaptureSession key={review?.id||'home'} config={config} reviewId={review?.id} notice={setNotice} onOpen={async id=>{setModal(null);await refreshList();await select(id);}}/></Modal>}
  {modal?.kind==='settings'&&<Modal title="Reading preferences" close={()=>setModal(null)}><Preferences prefs={prefs} set={updatePrefs}/></Modal>}
  {modal?.kind==='reference'&&<Modal title={modal.aggregate?modal.title:`Original evidence · ${label(modal.id)}`} wide close={()=>{setModal(null);closeInspection();}}><div className="reference-content"><InspectorContent item={modal} add={()=>{setSelected(modal.id);setModal(null);closeInspection();}}/></div></Modal>}
  {modal?.kind==='command'&&<QuickSwitch reviews={reviews} close={()=>setModal(null)} select={async id=>{setModal(null);await select(id);}} actions={()=>{setModal(null);showActions();}} importEvidence={()=>setModal({kind:'import'})}/>}
  {modal?.kind==='recommendation'&&<RecommendationModal modal={modal} review={review} inspect={inspect} close={()=>setModal(null)} capture={capture} proposal={value=>setModal({kind:'proposal',value,reviewId:review.id})}/>}
  {modal?.kind==='proposal'&&<ApprovalModal modal={modal} close={()=>setModal(null)} refresh={()=>setTab('actions')}/>}
  {selectedVariant&&<nav className="variant-picker" aria-label="Visual variants">{variants.map(name=><button key={name} aria-current={name===variant} onClick={()=>{const url=new URL(location.href);url.searchParams.set('variant',name);location.assign(url.href);}}>{name}</button>)}</nav>}
  </Workspace.Provider></Tooltips></MotionConfig>;
}

function ChartChoice({data,inspect,selected}) {const [type,setType]=useState('line');return <section className="chart-choice"><Segments label="Activity chart style" role="group" value={type} onChange={setType} items={[{value:'line',label:'Record count'},{value:'area',label:'Protocol layers'}]}/><EvidenceVisual type={type} data={data} inspect={inspect} selected={selected}/></section>;}
function HistoryList({reviews,query,current,select}) {
  const matches=reviews.filter(r=>`${r.title} ${r.id} ${r.provider}`.toLowerCase().includes(query.toLowerCase())),groups=new Map();
  for(const r of matches){const date=new Date(r.updated_at),title=date.toDateString()===new Date().toDateString()?'Today':date.toLocaleDateString([],{day:'numeric',month:'short'});if(!groups.has(title))groups.set(title,[]);groups.get(title).push(r);}
  return <div className="saved-list" role="region" aria-label="Saved investigations" tabIndex={0}>{query&&<small className="history-search-count">{matches.length} matching investigations</small>}{[...groups].map(([title,rows])=><section className="history-group" key={title}><h3>{title}</h3>{rows.map(r=><button key={r.id} className={`saved-item ${current===r.id?'selected':''}`} title={`${r.title} · ${r.id}`} onClick={()=>select(r.id)}>{r.provider==='api'?<MessageSquare size={15}/>:<Database size={15}/>}<span><strong>{r.title}</strong><small>{r.provider==='api'?`${r.turn_count??0} ${(r.turn_count??0)===1?'reply':'replies'}`:'Offline'}<i/> {new Date(r.updated_at).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} · {r.id.slice(0,4)}</small></span></button>)}</section>)}{!matches.length&&<p className="muted">{query?'No saved investigation matches.':'Your investigations appear here.'}</p>}</div>;
}
function QuickSwitch({reviews,close,select,actions,importEvidence}) {
  const [query,setQuery]=useState('');const list=reviews.filter(r=>`${r.title} ${r.id}`.toLowerCase().includes(query.toLowerCase())).slice(0,12);
  return <Modal title="Go to…" close={close}><label className="search command-search"><Search size={18}/><input autoFocus aria-label="Quick switch search" placeholder="Search investigations" value={query} onChange={e=>setQuery(e.target.value)}/><kbd>esc</kbd></label><div className="command-results"><button onClick={importEvidence}><FileUp size={17}/>Import evidence<small>New</small></button><button onClick={actions}><ShieldCheck size={17}/>Lab actions<small>Overview</small></button>{list.map(r=><button key={r.id} onClick={()=>select(r.id)}><Database size={16}/><span>{r.title}<small>{r.id.slice(0,8)} · {new Date(r.updated_at).toLocaleDateString()}</small></span><ArrowRight size={14}/></button>)}</div></Modal>;
}

function Conversation() {
  const workspace=useContext(Workspace), {review,runs,busy,config,submit,selected,prefs,threadQuery}=workspace;
  const messages=useMemo(()=>messagesFor(review,runs),[review,runs]);
  const currentRun=runs.find(r=>!terminal(r.status));
  const onNew=useCallback(async message=>{const question=message.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'); if(question.trim()){writeLocal(draftKey(review.id),'');await submit(question);}},[submit,review.id]);
  const convertMessage=useCallback(message=>({id:message.id,role:message.role,content:[{type:'text',text:message.text}],
    status:message.role==='assistant'?message.run&&!terminal(message.run.status)?{type:'running'}:{type:'complete',reason:'stop'}:undefined,
    metadata:{custom:{item:message}}}),[]);
  const runtime=useExternalStoreRuntime({messages,convertMessage,onNew,isRunning:!!currentRun,
    isSendDisabled:!!busy||!currentSourceSelected(workspace.caseInfo,review.id)||(review.provider==='api'&&!config?.api_ready)});
  const viewport=useRef(), content=useRef(), following=useRef(true), initial=useRef(false), previous=useRef(null), [unread,setUnread]=useState(false), reduced=useReducedMotion();
  const positionFrame=useRef();
  const reveal=useCallback((identity,behavior='smooth')=>{cancelAnimationFrame(positionFrame.current);positionFrame.current=requestAnimationFrame(()=>{if(!following.current)return;const el=viewport.current, target=content.current?.querySelector(`[data-message-id="${identity}"]`);if(el&&target){const top=el.scrollTop+target.getBoundingClientRect().top-el.getBoundingClientRect().top-18;el.scrollTo({top:Math.max(0,top),behavior:reduced?'instant':behavior});}});},[reduced]);
  useEffect(()=>()=>cancelAnimationFrame(positionFrame.current),[]);
  useLayoutEffect(()=>{
    const latest=messages.at(-1),el=viewport.current;if(!el)return;
    if(!initial.current){initial.current=true;const saved=readLocal(`scroll:${review.id}`,null);el.scrollTop=!messages.length?0:saved===null?el.scrollHeight:saved;following.current=saved===null||el.scrollHeight-el.scrollTop-el.clientHeight<80;previous.current={id:latest?.id,done:!!latest?.turn};return;}
    const newTurn=latest?.id!==previous.current?.id,completed=!!latest?.turn&&!previous.current?.done;
    if(newTurn){following.current=true;setUnread(false);reveal(messages.at(-2)?.id);}
    else if(shouldRevealAnswer({following:following.current,completed,hasTurn:latest?.turn}))reveal(latest.id);
    else if(completed)setUnread(true);
    previous.current={id:latest?.id,done:!!latest?.turn};
  },[messages,review.id,reveal]);
  const jump=()=>{following.current=true;setUnread(false);reveal(messages.at(-1)?.id);};
  return <AssistantRuntimeProvider runtime={runtime}><ThreadPrimitive.Root className="thread-root">
    <ThreadPrimitive.Viewport ref={viewport} className="thread-viewport" autoScroll={false} scrollToBottomOnRunStart={false} scrollToBottomOnInitialize={false} scrollToBottomOnThreadSwitch={false} onWheel={()=>{following.current=false;if(currentRun)setUnread(true);}} onTouchMove={()=>{following.current=false;if(currentRun)setUnread(true);}} onKeyDown={e=>{if(['PageUp','PageDown','Home','End','ArrowUp','ArrowDown'].includes(e.key)&&e.target===e.currentTarget)following.current=false;}} onPointerDown={e=>{if(e.clientX>=e.currentTarget.getBoundingClientRect().right-18)following.current=false;}} onScroll={e=>writeLocal(`scroll:${review.id}`,e.currentTarget.scrollTop)}><div ref={content} className="thread-content">
      {!messages.length&&<EmptyConversation/>}
      {threadQuery&&<p className="search-feedback" role="status">{messages.filter(m=>m.role==='user'?m.text.toLowerCase().includes(threadQuery.toLowerCase()):JSON.stringify(m.turn||m).toLowerCase().includes(threadQuery.toLowerCase())).length} matching messages.{currentRun?' The active reply remains visible.':''} <button className="subtle-button" onClick={workspace.clearSearch}>Clear search</button></p>}
      <ThreadPrimitive.Messages components={{UserMessage,AssistantMessage}}/>
    </div></ThreadPrimitive.Viewport>
    <Composer key={review.id} selected={selected} latestReply={unread?jump:null}/>
  </ThreadPrimitive.Root></AssistantRuntimeProvider>;
}
function UserMessage() {
  const item=useAuiState(s=>s.message.metadata.custom?.item), {threadQuery,inspect}=useContext(Workspace);
  const hidden=threadQuery&&!item?.text.toLowerCase().includes(threadQuery.toLowerCase());
  return <MessagePrimitive.Root className="user-message" data-message-id={item?.id} hidden={hidden}><motion.div initial={{opacity:0,y:7}} animate={{opacity:1,y:0}} transition={{duration:.22,ease:[.2,0,0,1]}}><span className="speaker">You</span><p>{item?.text}</p>{item?.reference&&<References ids={[item.reference]} inspect={inspect}/>}</motion.div></MessagePrimitive.Root>;
}
function AssistantMessage() {
  const item=useAuiState(s=>s.message.metadata.custom?.item), w=useContext(Workspace);
  if(!item)return null;
  const {run,turn}=item, pending=run&&(!terminal(run.status)||(run.status==='complete'&&!turn)), failed=run&&['failed','interrupted'].includes(run.status), cancelled=run?.status==='cancelled', answer=turn?.explanation.answer;
  const searchable=JSON.stringify(turn||item).toLowerCase();
  const hidden=w.threadQuery&&!pending&&!searchable.includes(w.threadQuery.toLowerCase());
  const activity=run?.events?.filter(e=>e.type!=='summary')||[], last=activity.at(-1);
  const phase=run?.reconnecting?'Reconnecting to this investigation':run?.status==='complete'&&!turn?'Opening the saved answer':last?.type==='tool_started'?activityLabel(last):last?.data.message||'Investigating this evidence';
  const loader=new URLSearchParams(location.search).get('loader')==='bars'?'bars':'orbit';
  return <MessagePrimitive.Root className={`assistant-message ${pending?'pending':''}`} data-message-id={item.id} hidden={hidden}><motion.div className="reply-surface" initial={{opacity:0,y:7}} animate={{opacity:1,y:0}} transition={{duration:.25,ease:[.2,0,0,1]}}>
    <div className="reply-heading"><Mark busy={pending}/><strong>PacketPilot</strong><span>{pending?(run.status==='stopping'?'Stopping':'Investigating'):cancelled?'Stopped':failed?'Needs attention':answer?.kind==='conversation'?'':'Evidence-led assessment'}</span></div>
    {pending&&<><BorderBeam/><div className="pending-content"><ActivitySignal phase={phase} reconnecting={run.reconnecting} variant={loader}/>{run.summary&&<div className="streamed-explanation"><span className="provisional-label">Explanation in progress</span><PublicStream text={run.summary}/></div>}<ActivitySteps activity={activity} inspect={w.inspect}/><button className="stop-investigation" disabled={run.status==='stopping'||run.status==='sending'} onClick={async()=>{try{await post(`/api/reviews/${w.review.id}/runs/${run.id}/cancel`);}catch(e){w.notice(e.message);}}}>{run.status==='stopping'?'Stopping…':'Stop investigation'}</button>{run.status==='stopping'&&<p className="view-note">Waiting for the current operation to settle. Already-sent provider work may still incur cost.</p>}</div></>}
    {cancelled&&<div className="stopped-turn"><p>{run.error}</p><button className="subtle-button" disabled={!!w.busy} onClick={()=>w.submit(run.question,undefined,run.selected_reference||null)}>Ask again</button></div>}
    {failed&&<div className="error-turn" role="alert"><CircleAlert size={16}/><div><p>{run.error||'This investigation did not finish.'}</p><button disabled={!!w.busy} onClick={()=>w.submit(run.question,undefined,run.selected_reference||null)}>Retry question</button><p className="muted">Retry is a new explicit request. Earlier attempts stay in the record.</p></div></div>}
    {!pending&&turn&&!failed&&<AnswerBody turn={turn}/>} 
    {!pending&&failed&&turn&&<details><summary>Retained fallback and failed attempt</summary><p>{turn.explanation.answer?.summary||turn.explanation.answer?.why}</p><pre>{JSON.stringify(turn.explanation.api_error,null,2)}</pre></details>}
  </motion.div></MessagePrimitive.Root>;
}
function AnswerBody({turn}) {
  const w=useContext(Workspace), answer=turn.explanation.answer||{}, conversation=answer.kind==='conversation';
  const views=defaultViews(answer,turn.question,w.data);
  const fallback=turn.explanation.status==='fallback_after_api_failure';
  const activity=w.runs.find(r=>r.turn_id===turn.run_id)?.events||[];
  const visuals=views.map((view,i)=><AnswerView key={JSON.stringify(view)+i} descriptor={view} reviewId={w.review.id} data={w.data} inspect={w.inspect} selected={w.inspection}/>);
  return <div className={`answer-body composition-${w.composition}`}>
    {fallback&&<p className="error">Model answer unavailable. This is an explicitly labelled offline comparator fallback.</p>}
    {!conversation&&w.composition==='report'&&<span className="answer-section-label">What the evidence shows</span>}
    <p className="answer-text summary"><TechnicalText text={answer.summary||answer.why||'See the saved evidence and result details.'}/></p>
    {!conversation&&<>
      {w.composition==='fieldnotes'&&visuals}
      {answer.interpretation&&<SectionEntrance className="interpretation-section"><h3>Interpretation</h3><p className="answer-text interpretation"><TechnicalText text={answer.interpretation}/></p></SectionEntrance>}
      <EvidenceExtracts answer={answer} review={w.review} inspect={w.inspect} selected={w.inspection}/>
      {answer.observations?.length>0&&<Disclosure title="Supporting observations" count={answer.observations.length} defaultOpen={w.prefs.detail==='expanded'} className="supporting-evidence">{answer.observations.map((r,i)=><div className="observation" key={i}><span className="observation-number">{i+1}</span><div><p><TechnicalText text={r.text}/></p><References ids={r.references} inspect={w.inspect}/></div></div>)}</Disclosure>}
      {w.composition==='report'&&visuals}
      {answer.alternatives?.length>0&&<SectionEntrance className="hypotheses"><h3>Other explanations</h3>{answer.alternatives.map((t,i)=><p key={i}><TechnicalText text={t}/></p>)}</SectionEntrance>}
      {uniqueNotes(answer.uncertainty||[],answer.coverage?.limitations||[]).length>0&&<Disclosure title="Uncertainty and coverage" className="uncertainty">{uniqueNotes(answer.uncertainty||[],answer.coverage?.limitations||[]).map((t,i)=><p key={i}>{t}</p>)}</Disclosure>}
      {answer.recommendations?.map((r,i)=><SectionEntrance key={i} className="recommendation"><span className="eyebrow">{['block_source','rate_limit_service'].includes(r.action)?'PROPOSED NEXT STEP · APPROVAL SEPARATE':'GUIDANCE · NO NETWORK CHANGE'}</span><p><TechnicalText text={r.rationale}/></p><References ids={r.references} inspect={w.inspect}/><button onClick={()=>w.inspectRecommendation(turn.run_id,i)}>{['block_source','rate_limit_service'].includes(r.action)?'Review action':'View guidance'}<ArrowRight size={14}/></button></SectionEntrance>)}
      {answer.code_suggestions?.map((code,i)=><section className="code-suggestion" key={i}><h3>{code.title}</h3><span className="tag">Unverified example · not executed</span><pre>{code.code}</pre><dl><dt>Target</dt><dd>{code.target||'See assumptions'}</dd><dt>Expected effect</dt><dd>{code.expected_effect}</dd><dt>Reversal</dt><dd>{code.reversal}</dd></dl>{code.assumptions.map((t,i)=><p className="muted" key={i}>{t}</p>)}<References ids={code.references} inspect={w.inspect}/><div className="button-row"><CopyButton text={code.code}/><a href={`/api/reviews/${w.review.id}/code/${i}?turn_id=${turn.run_id}`} download>Download example</a></div></section>)}
      {answer.questions?.length>0&&<Disclosure title="Context to clarify">{answer.questions.map((t,i)=><p key={i}>{t}</p>)}</Disclosure>}
      {!answer.schema_version&&answer.fact_ids&&<References ids={answer.fact_ids} inspect={w.inspect}/>}
      <ActivitySteps activity={activity} inspect={w.inspect}/>
      <Disclosure title="Trace and saved result" className="technical-details"><p>{turn.explanation.review_note}</p><p>{turn.explanation.tool_trace?.length||0} tool operations · {turn.explanation.attempts||0} provider calls · {turn.explanation.correction_attempts||0} corrections</p><pre>{JSON.stringify({tool_trace:turn.explanation.tool_trace,measurements:answer.measurements,coverage:answer.coverage},null,2)}</pre></Disclosure>
    </>}
    <div className="reply-actions"><CopyButton text={[answer.summary,answer.interpretation].filter(Boolean).join('\n\n')}/><span>{turn.recorded_at&&!Number.isNaN(Date.parse(turn.recorded_at))?new Date(turn.recorded_at).toLocaleString([],{dateStyle:'medium',timeStyle:'short'}):'Saved response'}</span></div>
  </div>;
}
function Composer({selected,latestReply}) {
  const w=useContext(Workspace), runtime=useAui(), [initialDraft]=useState(()=>readLocal(draftKey(w.review.id),'')), initialized=useRef(false), restored=useRef(false);
  useLayoutEffect(()=>{if(initialized.current)return;initialized.current=true;runtime.composer.setText(initialDraft);},[runtime,initialDraft]);
  const text=useAuiState(s=>s.composer.text);
  useEffect(()=>{if(!restored.current){if(text!==initialDraft)return;restored.current=true;}writeLocal(draftKey(w.review.id),text);},[text,initialDraft,w.review.id]);
  // Character count is derived, not another state write inside the runtime's
  // per-keystroke update cycle. Rapid typing must not recursively reschedule it.
  const characters=text.length;
  const starter=value=>runtime.composer.setText(value);
  return <div className="composer-wrap">{latestReply&&<button className="return-latest" onClick={latestReply}><ArrowUp size={14} className="reverse"/>Latest reply</button>}<div className="source-context"><span><Database size={13}/>{w.review.title}</span>{selected&&<button title="Remove selected evidence context" aria-label={`Remove ${label(selected)} from question context`} onClick={()=>w.setSelected(null)}>{label(selected)}<X size={12}/></button>}</div>
    <button className="case-context" onClick={w.openCase}><Database size={12}/><span>{w.caseInfo?`${w.caseInfo.title} · ${currentSourceSelected(w.caseInfo,w.review.id)?'Using':'Current source not selected · choose from'} ${w.caseInfo.sources.filter(s=>s.selected).length} selected source${w.caseInfo.sources.filter(s=>s.selected).length===1?'':'s'}`:'Single source · add related evidence or compare'}</span><ChevronRight size={12}/></button>
    {selected&&<button className="selected-followup" onClick={()=>starter(`Explain ${label(selected)} and what it shows in this source. Reference: ${selected}`)}>Ask about {label(selected)}<ArrowRight size={13}/></button>}
    <ComposerPrimitive.Root className="composer"><ComposerPrimitive.Input aria-label="Ask about this evidence" placeholder="Ask about this evidence…" maxLength={600} minRows={1} maxRows={6} autoFocus cancelOnEscape={false} unstable_focusOnRunStart={false} unstable_focusOnScrollToBottom={false} unstable_focusOnThreadSwitched={false}/><div className="composer-footer"><span>{w.busy ? w.busy.review_id===w.review.id?'You can write your next question while this runs.':'An investigation is running in another source.' : 'Enter to send · Shift + Enter for a new line'}<small>{characters}/600</small></span><ComposerPrimitive.Send className="send-button" aria-label="Send question"><ArrowUp size={19}/></ComposerPrimitive.Send></div></ComposerPrimitive.Root>
  </div>;
}
function EmptyConversation() {const w=useContext(Workspace), runtime=useAui();return <section className="empty-conversation"><Mark/><p className="eyebrow">START AN INVESTIGATION</p><h3>The evidence is ready.</h3><p>Ask a question, inspect the details and follow what they support.</p><div className="starter-questions">{['What happened in this source?',w.review.evidence.input_kind==='network_log'?'Explain the exported lines and their limitations.':'Is this activity retrying one service or probing several?','Explain the request and reply directions.'].map(q=><button key={q} onClick={()=>runtime.composer.setText(q)}>{q}<ArrowRight size={14}/></button>)}</div><span className="source-mode"><LockKeyhole size={12}/>{w.review.provider==='api'?'Model-enabled conversation':'Offline evidence inspection'}</span></section>;}

function ImportModal({close,config,create}) {
  const [file,setFile]=useState(null),[mode,setMode]=useState('file'),[sample,setSample]=useState('port-check'),[provider,setProvider]=useState(config?.api_ready?'api':'rules'),[busy,setBusy]=useState(false),[error,setError]=useState('');
  return <Modal title="Open evidence" close={()=>!busy&&close()}><form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{if(mode==='file'&&!file)throw new Error('Choose a capture or saved log first.');await create({sample,provider},mode==='file'?file:null);}catch(error){setError(error.message);}finally{setBusy(false);}}}>
    <fieldset disabled={busy} className="import-controls"><p className="modal-intro">Open evidence, then ask a question. Use Related evidence & compare to group baseline and follow-up sources. Actions contains separate current-lab checks. Nothing is sent to the model until you ask.</p><Segments label="Evidence source" value={mode} onChange={v=>!busy&&setMode(v)} items={[{value:'file',label:'Your file'},{value:'sample',label:'Try a sample'}]}/>
    {mode==='file'?<><p className="input-limits">Up to 8 MiB / 10,000 records. Classic Ethernet PCAP or the exact TShark TSV below. Interpreted traffic is outer, unfragmented IPv4 TCP/UDP in 10.77.0.0/24. PCAPNG and arbitrary text logs are not supported.</p><UploadZone file={file} setFile={setFile} disabled={busy} maxBytes={config?.max_upload_bytes}/><Disclosure title="TShark TSV schema and help"><p>UTF-8 text with this exact tab-separated header, then one row per exported record. Keep all eleven fields in order; fields for the other transport are empty. These are saved log lines, not original packet bytes.</p><pre className="tsv-schema">{TSV_HEADER}</pre><CopyButton text={TSV_HEADER}/></Disclosure></>:<div className="sample-choices">{[['normal','Normal TCP exchange','Follow request and reply directions.'],['port-check','Multiple-service activity','Compare destinations and service ports.']].map(([value,title,text])=><button type="button" className={sample===value?'selected':''} onClick={()=>setSample(value)} key={value}><Network size={21}/><span><strong>{title}</strong><small>{text}</small></span>{sample===value&&<Check size={17}/>}</button>)}</div>}
    <div className="conversation-mode"><span>Investigation mode<small>Original evidence always stays available.</small></span><Segments label="Investigation mode" role="group" value={provider} onChange={v=>{if(!busy&&(v!=='api'||config?.api_ready))setProvider(v);}} items={[{value:'api',label:'Conversation'},{value:'rules',label:'Offline'}]}/></div>{!config?.api_ready&&<p className="view-note">Conversation requires model configuration.</p>}</fieldset>{error&&<p role="alert" className="error">{error}</p>}<button className="primary-button modal-submit" disabled={busy} aria-busy={busy}>{busy?'Reading evidence…':'Open investigation'}<ArrowRight size={16}/></button>
  </form></Modal>;
}
function Preferences({prefs,set}) {return <div className="preferences">{[['density','Reading density',[['comfortable','Comfortable'],['compact','Compact']]],['detail','Answer detail',[['focused','Focused'],['expanded','Expanded']]]].map(([key,title,options])=><section key={key}><h3>{title}</h3><p>{key==='density'?'Choose the spacing that suits your screen.':'Keep supporting observations closed, or open them with each answer.'}</p><Segments label={title} role="group" value={prefs[key]} onChange={value=>set({...prefs,[key]:value})} items={options.map(([value,label])=>({value,label}))}/></section>)}<p className="view-note">Saved for this browser.</p></div>;}
function InspectorContent({item,add}) {
  const w=useContext(Workspace),reduced=useReducedMotion(),identity=item.id||`${item.title}:${item.references?.[0]}`;
  const parent=w.inspectionState.parents.at(-1);
  return <><div className="inspector-navigation">{parent&&<button className="inspector-back" onClick={w.goBack}><ArrowLeft size={14}/><span>Back to {parent.item.title||label(parent.item.id)}</span></button>}</div><motion.div key={identity} className="inspector-content" tabIndex={-1} initial={{opacity:reduced?1:.55,x:reduced?0:6}} animate={{opacity:1,x:0}} transition={{duration:reduced?0:.2,ease:[.2,0,0,1]}}><ReferenceDetails item={item} add={add}/></motion.div></>;
}
function ReferenceDetails({item,add}) {
  const {inspect,review}=useContext(Workspace);
  if(item.aggregate)return <AggregateDetails item={item}/>;
  const r=item.value, ip=r.ipv4||{}, tr=r.tcp||r.udp||{};
  const packetRefs=(r.packet_refs||[]).slice(0,96).map(n=>`${review.evidence.capture.sha256}:p${n}`);
  return <><details className="reference-identity"><summary>Original identity · {label(item.id)}</summary><p className="reference-id mono">{item.id}</p></details>
    {(r.packet!==undefined||r.line_number!==undefined)&&<dl className="spec-sheet">{[
      ['Original identity',r.line_number!==undefined?`Physical log line ${r.line_number}`:`Packet ${r.packet}`],
      ['Exported frame number',r.source_frame_number??'Not a separate log frame'],
      ['Source',endpoint(ip.src,tr.src_port)],['Destination',endpoint(ip.dst,tr.dst_port)],
      ['Protocol',r.protocol],['Status',r.status],['Source-relative time',sourceRelativeTime(r.timestamp,[...(review.evidence.packets||[]),...(review.evidence.log_records||[])][0]?.timestamp)],
      ['Flags',r.tcp?.flag_names?.join(' / ')||'Not applicable'],['Sequence',r.tcp?.sequence??'Not retained'],
      ['Acknowledgement',r.tcp?.acknowledgement??'Not retained'],
      [r.line_number!==undefined?'Reported frame bytes':'Captured frame bytes',r.captured_bytes??r.reported_frame_length??'Not retained']
    ].map(([key,value])=><React.Fragment key={key}><dt>{key}</dt><dd>{value}</dd></React.Fragment>)}</dl>}
    {r.endpoint_a&&<><dl className="spec-sheet"><dt>Endpoint A</dt><dd>{r.endpoint_a.address}:{r.endpoint_a.port}</dd>
      <dt>Endpoint B</dt><dd>{r.endpoint_b.address}:{r.endpoint_b.port}</dd><dt>Direction</dt><dd>Endpoint ordering is not automatically initiator direction.</dd>
      <dt>Retained records</dt><dd>{r.packet_count??r.record_count}</dd><dt>Recorded duration</dt><dd>{r.duration_seconds} s</dd>
      <dt>Header-record directions</dt><dd>A → B: {r.directions?.a_to_b} · B → A: {r.directions?.b_to_a}</dd>
      <dt>Captured frame bytes</dt><dd>{r.captured_bytes??'Not retained'}</dd></dl><References ids={packetRefs} inspect={inspect}/>
      {(r.packet_refs?.length||0)>96&&<p className="view-note">First 96 member references shown. The full record retains membership.</p>}</>}
    <Disclosure title="Full retained record"><pre>{JSON.stringify(r,null,2)}</pre></Disclosure>
    <button className="primary-button" onClick={add}>Use as question context</button></>;
}
function AggregateDetails({item}) {const {review,inspect}=useContext(Workspace),key=`inspect-all:${review.id}:${item.title}:${item.references[0]}`,[all,setAll]=useState(()=>readLocal(key,false)),index=referenceIndex(review),members=all?item.references:item.references.slice(0,12);return <div className="aggregate-details"><dl className="spec-sheet"><dt>Selected group</dt><dd>{item.count??item.references.length} {item.unit||'records'}</dd><dt>Retained membership</dt><dd>{item.references.length} original references{item.references_omitted?` · ${item.references_omitted} more outside this bounded list`:''}</dd></dl><p className="view-note">Inspect a member below. Only its explicit context button attaches it to your question.</p><div className="member-records">{members.map(id=>{const r=index.get(id),t=r?.tcp||r?.udp||{};return <button key={id} onClick={()=>inspect(id)}><span>{label(id)}</span><strong>{r?.protocol||'Result'}</strong><small>{endpoint(r?.ipv4?.src,t.src_port)}<ArrowRight size={12}/>{endpoint(r?.ipv4?.dst,t.dst_port)}</small><ArrowRight size={14}/></button>;})}</div>{item.references.length>12&&<button className="view-more" onClick={()=>{setAll(!all);writeLocal(key,!all);}}>{all?'Show less':`Show ${item.references.length} members`}</button>}{!item.references.length&&<p className="view-note">No records in this time bin.</p>}{item.unavailable_references>0&&<p className="error">{item.unavailable_references} references are not available in this source.</p>}<Disclosure title="Full calculated selection"><pre>{JSON.stringify(item,null,2)}</pre></Disclosure></div>;}
function RecommendationModal({modal,review,close,inspect,capture,proposal}) {const d=modal.value,[busy,setBusy]=useState(false),[error,setError]=useState('');return <Modal title={d.title} close={close}><p>{d.rationale}</p><p className="muted">{d.next_step}</p><References ids={d.references} inspect={inspect}/><dl><dt>Source</dt><dd>{d.recommendation.target||'Not an execution target'}</dd><dt>Service</dt><dd>{d.recommendation.destination?`${d.recommendation.destination}:${d.recommendation.port}`:'Not specified'}</dd><dt>Duration</dt><dd>{d.recommendation.duration_seconds?`${d.recommendation.duration_seconds} s`:'Not applicable'}</dd><dt>Rate</dt><dd>{d.recommendation.rate_kbit?`${d.recommendation.rate_kbit} kbit/s`:'Not applicable'}</dd></dl>{error&&<p className="error" role="alert">{error}</p>}{d.can_propose&&<button disabled={busy} className="primary-button" onClick={async()=>{setBusy(true);try{proposal(await post(`/api/reviews/${review.id}/recommendations/${modal.index}/propose`,{turn_id:modal.turnId}));}catch(e){setError(e.message);}finally{setBusy(false);}}}>Prepare exact proposal</button>}{d.status==='offline_mapping_required'&&<button onClick={capture}>Open current lab capture</button>}<p className="view-note">Viewing guidance or preparing a proposal executes nothing.</p></Modal>;}
function ApprovalModal({modal,close,refresh}) {
  const p=modal.value,[text,setText]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const cancel=async()=>{
    if(busy)return;
    setBusy(true);
    try{
      try{await post(`/api/reviews/${modal.reviewId}/actions/${p.id}/cancel`);}
      catch(cancelError){
        // Expiry or a lost approval acknowledgement can make cancellation
        // inapplicable. Read the real receipt; never invent a cancelled state.
        const actions=await api(`/api/reviews/${modal.reviewId}/actions`);
        if(!canDismissProposal(actions,p.id))throw cancelError;
      }
      close();refresh();
    }catch(e){setError(e.message);}finally{setBusy(false);}
  };
  return <Modal title="Review and approve the exact change" close={cancel} wide>
    <p>{p.reason}</p><p>{p.command_plan?.expected_effect}</p>
    {Number.isFinite(p.approval_deadline)&&<p className="view-note">One-time approval expires at {new Date(p.approval_deadline*1000).toLocaleTimeString()}. After that, close this dialog and prepare a fresh proposal.</p>}
    <dl><dt>Source</dt><dd>{p.target}</dd><dt>Service</dt><dd>{p.destination}:{p.port}</dd><dt>Duration</dt><dd>{p.duration_seconds} s</dd></dl>
    <h3>Validated commands</h3><pre>{p.command_plan?.commands.join('\n')}</pre>
    <h3>Reversal</h3><pre>{p.command_plan?.reversal.join('\n')}</pre>
    <a href={`/api/reviews/${modal.reviewId}/actions/${p.id}/plan`} download>Download proposal plan</a>
    <p className="approval-phrase">{p.confirmation}</p>
    <label className="field">Type the exact confirmation above<input autoFocus value={text} onChange={e=>setText(e.target.value)} autoComplete="off"/></label>
    {error&&<p className="error" role="alert">{error} Close this dialog to check the current response; an expired approval needs a new proposal.</p>}
    <div className="button-row"><button onClick={cancel} disabled={busy}>{error?'Close and check response':'Cancel proposal'}</button>
      <button className="primary-button" disabled={busy||text!==p.confirmation} onClick={async()=>{
        setBusy(true);setError('');
        try{await post(`/api/reviews/${modal.reviewId}/actions/${p.id}/approve`,{approval_token:p.approval_token,confirmation:text});close();refresh();}
        catch(e){setError(e.message);}finally{setBusy(false);}
      }}>{busy?'Applying and checking…':'Approve this change'}</button>
    </div>
  </Modal>;
}

createRoot(document.getElementById('root')).render(<App/>);
