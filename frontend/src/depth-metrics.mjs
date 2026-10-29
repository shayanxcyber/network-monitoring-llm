// Presentation of measured outcomes must preserve failure and missing-data states.
export function diagnosticMetric(client,profile,format=String){
  if(profile==='transfer'){
    if(client.complete!==true){
      const prefix=client.failure_type==='TimeoutExpired'?'Check timed out':'Transfer incomplete';
      return Number.isFinite(client.total_seconds)?`${prefix} after ${format(client.total_seconds)} s`:prefix;
    }
    const elapsed=Number.isFinite(client.total_seconds)?`${format(client.total_seconds)} s`:'timing unavailable';
    const rate=Number.isFinite(client.payload_kbit_per_second)?` · ${format(client.payload_kbit_per_second)} kbit/s`:'';
    return `Complete transfer ${elapsed}${rate}`;
  }
  return Number.isFinite(client.first_byte_seconds)?`First byte ${format(client.first_byte_seconds)} s`:'First-byte timing unavailable';
}

export function controlTimingDelta(first,last){
  if(!first||!last||(first.profile||'health')!==(last.profile||'health')||first.objective!==last.objective)return null;
  const a=first.result?.clients?.control,b=last.result?.clients?.control;
  if(!a||!b)return null;
  if(last.profile==='transfer'&&(a.complete!==true||b.complete!==true))return null;
  const field=last.profile==='transfer'?'total_seconds':'first_byte_seconds';
  return Number.isFinite(a[field])&&Number.isFinite(b[field])?b[field]-a[field]:null;
}

// Pair explicit identities, never the earliest baseline and latest after row.
export function diagnosticPair(rows, baselineId, afterId){
  const first=rows.find(r=>r.id===baselineId),last=rows.find(r=>r.id===afterId);
  const invalid=reason=>({first,last,delta:null,reason});
  if(!first||!last)return invalid('Choose a baseline and an after observation. No cycle is inferred.');
  if(first.phase!=='baseline'||last.phase!=='after')return invalid('Choose baseline and after phases.');
  if(!Number.isFinite(Date.parse(first.recorded_at))||!Number.isFinite(Date.parse(last.recorded_at))||Date.parse(first.recorded_at)>=Date.parse(last.recorded_at))return invalid('The after observation must follow the baseline.');
  if(last.baseline_id&&last.baseline_id!==first.id)return invalid('This after observation is linked to another baseline.');
  if(first.action_id&&first.action_id!==last.action_id)return invalid('These observations refer to different response actions.');
  if((first.profile||'health')!==(last.profile||'health')||first.objective!==last.objective)return invalid('Check profiles and objectives must match.');
  if(first.review_id!==last.review_id)return invalid('Choose observations from the same retained source.');
  if(!first.lab_context?.generation||!last.lab_context?.generation||
    first.lab_context.generation!==last.lab_context.generation||
    first.lab_context.service_port!==last.lab_context.service_port||
    ['source','control','service'].some(k=>!first.lab_context.addresses?.[k]||first.lab_context.addresses[k]!==last.lab_context.addresses?.[k]))return invalid('Lab identity is missing or changed. Use a new identified baseline and after check.');
  if(!first.result?.service||first.result.service!==last.result?.service||first.result.path!==last.result.path)return invalid('The recorded service target and path must match.');
  const a=first.result?.clients?.control,b=last.result?.clients?.control;
  if(!a?.reachable||!b?.reachable)return invalid('Both control checks must have a successful response.');
  const delta=controlTimingDelta(first,last);
  return {first,last,delta,reason:delta==null?'These observations have no comparable completed timing.':null};
}

export function sourceOption(source){
  return `${source.title} · ${source.id.slice(0,8)}${source.input_kind==='network_log'?' · TSV':''}${source.case_id?' · in '+(source.case_title||'another case'):''}`;
}

export function comparisonMatches(value,left,right,port){
  return !!value&&value.baseline_review_id===left&&value.comparison_review_id===right&&value.baseline.service_port===Number(port);
}

// User-assigned roles guide initial choices, not analytical verdicts. In
// particular, opening the baseline itself must not reverse the pair.
export function comparisonDefaults(sources,reviewId){
  const selected=sources.filter(s=>s.selected);
  const baseline=selected.find(s=>s.role==='baseline')||selected.find(s=>s.review_id!==reviewId);
  const others=selected.filter(s=>s.review_id!==baseline?.review_id);
  const comparison=others.find(s=>s.review_id===reviewId&&['problem','after'].includes(s.role))||
    others.find(s=>s.role==='problem')||others.find(s=>s.role==='after')||
    others.find(s=>s.review_id===reviewId)||others[0];
  return {left:baseline?.review_id||'',right:comparison?.review_id||''};
}

export function sourceRelativeTime(value,origin){
  const point=Number(value),start=Number(origin);
  if(value==null||origin==null||!Number.isFinite(point)||!Number.isFinite(start))return value??'Not retained';
  const delta=point-start;
  return `${delta>=0?'+':''}${delta.toFixed(4)} s from first retained record`;
}

export function currentSourceSelected(group,reviewId){
  return !group||group.sources.some(s=>s.review_id===reviewId&&!!s.selected);
}

export function canDismissProposal(actions,identity){
  const current=actions.find(a=>a.id===identity);
  return !!current&&['approval_expired','cancelled','stale','failed','rolled_back','expired','active','applying','rollback_failed'].includes(current.state);
}
