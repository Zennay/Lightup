/* LightUp Scope Permission Brief. Untrusted local proposal data is NEVER authority. */
(() => {
'use strict';
const MAX_BYTES=65536;
const $=id=>document.getElementById(id);
const statuses=['unanswered','question_sent','answered_unverified'];
const flags=()=>({authenticated:false,client_consent:false,operator_consent:false,scope_approved:false,risk_approved:false,authorization:false,grant:false,revocation_checked:false,execution:false,scan:false,deploy:false,release:false});
let current=null, questions=[], epoch=0;
const questionCatalog={
 client_identity:['client','Independent client identity','Confirm that the requester has separately authenticated through the protected client workflow.'],
 asset_ownership:['client','Assets and ownership','What independently verifiable evidence connects the requester to every proposed asset?'],
 purpose_limits:['client','Intent, prohibited activity and handling','Confirm the proposed purpose, forbidden actions, evidence retention and secure delivery channel.'],
 client_consent:['client','Actual client authorization','Client consent must occur in a protected authenticated request; a reply or this brief is not consent.'],
 operator_independence:['operator','Separate operator review','A qualified operator must independently decide without relying on self-reported draft or handoff statuses.'],
 enforceable_scope:['operator','Enforceable precise scope','Verify exact host, IP/CIDR and exclusions in the protected policy; no target is contacted here.'],
 risk_approval:['operator','Recorded risk approval','Risk tier, activity restrictions, environment and escalation must be approved independently.'],
 stop_revocation:['operator','Emergency STOP and revocation at use','Confirm emergency contacts, stop criteria and a fresh at-use revocation decision.'],
 mandatory_gates:['operator','Release and security gates','Existing CI, security/privacy review, correct tenant lineage and explicit human GO still apply.'],
 high_risk:['operator','Elevated-risk escalation','Risk 4 requires separate escalation, restrictions and explicit signoff.'],
 lab_provenance:['operator','Private laboratory provenance','Any proposed network check needs independently proven lab ownership and approved lab boundaries.'],
 no_exclusions:['operator','Explicit exclusions','No exclusions were listed. Ask whether exclusions or forbidden hosts are needed.'],
 open_window:['operator','Unresolved time window','Unscheduled or incomplete/ambiguous windows require separately approved UTC bounds.'],
 safety_context:['client','Safety and stop instructions','No safety-purpose notes are present in the proposal; request clear, privately handled instructions.'],
 network_activity:['client','Network interaction expectations','Clarify that proposed lab checks cannot be performed against public or unapproved targets.']
};
function hold(message){
 epoch++;current=null;questions=[];
 document.dispatchEvent(new CustomEvent('lightup:brief-source-change'));
 $('workspace').hidden=true;$('export').disabled=true;$('textExport').disabled=true;$('print').disabled=true;
 $('handoff').textContent='';$('replyState').textContent='No review note imported.';
 $('sourceState').textContent=message+' · HOLD';
}
function assert(condition,message){if(!condition)throw Error(message);}
function object(v){return v!==null&&typeof v==='object'&&!Array.isArray(v);}
function text(v,max){return typeof v==='string'&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v);}
function noteText(v,max){return typeof v==='string'&&v.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);}
function exactKeys(v,keys){return object(v)&&Object.keys(v).every(k=>keys.includes(k));}
/* Lexically parse the entire JSON, rejecting duplicate keys anywhere (including nested).
   JSON.parse alone would silently accept contradictory authority fields. */
function assertUnambiguousJSON(source){
 let at=0,tokens=0;
 function whitespace(){while(/[\x20\x09\x0a\x0d]/.test(source[at]||''))at++;}
 function str(){
  assert(source[at]==='"','Invalid JSON string');
  let start=at++;let escaped=false;
  while(at<source.length){
   const ch=source[at++];
   if(escaped){escaped=false;continue;}
   if(ch==='\\'){escaped=true;continue;}
   if(ch==='"')return JSON.parse(source.slice(start,at));
  }
  throw Error('Unterminated string');
 }
 function value(depth){
  assert(depth<24&&++tokens<1800,'JSON too deep or complex');whitespace();
  if(source[at]==='{'){
   at++;whitespace();const keys=new Set();
   if(source[at]==='}') {at++;return;}
   while(true){
    whitespace();const key=str();
    assert(!keys.has(key),'Duplicate JSON key');
    assert(!['__proto__','constructor','prototype'].includes(key),'Unsafe JSON key');
    keys.add(key);whitespace();assert(source[at++]===':','Expected colon');
    value(depth+1);whitespace();
    const delimiter=source[at++];
    if(delimiter==='}')return;
    assert(delimiter===',','Expected object comma');
   }
  }
  if(source[at]==='['){
   at++;whitespace();if(source[at]===']'){at++;return;}
   while(true){
    value(depth+1);whitespace();const delimiter=source[at++];
    if(delimiter===']')return;
    assert(delimiter===',','Expected array comma');
   }
  }
  if(source[at]==='"'){str();return;}
  const tail=source.slice(at),token=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(tail);
  assert(token,'Invalid JSON value');at+=token[0].length;
  assert(!/[a-zA-Z0-9.+-]/.test(source[at]||''),'Ambiguous JSON token');
 }
 value(0);whitespace();assert(at===source.length,'Trailing JSON data');
}
function validateWindow(d){
 assert(exactKeys(d.proposed_window_local,['start','end']),'Invalid local window');
 const local=d.proposed_window_local,utc=d.proposed_window_utc;
 const localShape=x=>x===null||(text(x,32)&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(x));
 assert(localShape(local.start)&&localShape(local.end),'Noncanonical local window');
 if(utc===undefined){
  assert(local.start===null&&local.end===null,'Scheduled source lacks UTC evidence');
  return 'Unscheduled';
 }
 assert(exactKeys(utc,['status','timezone','start','end','start_offset_minutes','end_offset_minutes']),'Invalid UTC record');
 assert(text(utc.timezone,100),'Invalid timezone label');
 if(utc.status==='incomplete'||utc.status==='unscheduled'){
  assert(utc.start===null&&utc.end===null,'Unresolved UTC has instants');
  assert(utc.status==='unscheduled'?(local.start===null&&local.end===null):((local.start===null)!==(local.end===null)),'Unresolved window mismatch');
  return utc.status==='unscheduled'?'Unscheduled':'Incomplete';
 }
 assert(utc.status==='resolved','Unknown UTC status');
 const pattern=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/;
 assert(typeof utc.start==='string'&&typeof utc.end==='string'&&pattern.test(utc.start)&&pattern.test(utc.end)&&utc.start<utc.end,'Unresolved UTC instant');
 function normalize(wall,offset){
  assert(typeof wall==='string'&&Number.isInteger(offset)&&Math.abs(offset)<=840,'Invalid offset');
  const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(wall);
  assert(m,'Invalid date syntax');
  const [y,mo,d,h,mi]=m.slice(1).map(Number);
  assert(y>=2020&&y<=2100&&mo>=1&&mo<=12&&h<=23&&mi<=59,'Out-of-range local window');
  const day=new Date(Date.UTC(y,mo-1,d));
  assert(day.getUTCFullYear()===y&&day.getUTCMonth()===mo-1&&day.getUTCDate()===d,'Impossible local date');
  return new Date(Date.UTC(y,mo-1,d,h,mi)+offset*60000).toISOString();
 }
 assert(normalize(local.start,utc.start_offset_minutes)===utc.start&&normalize(local.end,utc.end_offset_minutes)===utc.end,'UTC source contradiction');
 return 'Resolved (still unapproved)';
}
function validateDraft(d){
 const accepted=['schema_version','kind','state','authorization','client_consent','operator_consent','grant','execution','revocation_checked','proposal_name','client_label','requested_assets','excluded_assets','requested_mode','requested_risk','notes','proposed_activities','proposed_window_local','proposed_window_utc','exported_at_utc','scope_fingerprint_sha256'];
 assert(exactKeys(d,accepted),'Unknown/invalid source fields');
 assert(d.schema_version===1&&d.kind==='lightup.scope_proposal_draft'&&d.state==='DRAFT_ONLY','Unsupported Studio v1 draft');
 for(const f of ['authorization','client_consent','operator_consent','grant','execution'])assert(d[f]===false,'Unsafe authority assertion');
 assert(d.revocation_checked===undefined||d.revocation_checked===false,'Unsafe revocation assertion');
 assert(text(d.proposal_name,120)&&text(d.client_label,100)&&noteText(d.notes,3000),'Invalid private proposal text');
 assert(d.requested_mode==='analysis_only'||d.requested_mode==='authorized_assessment','Invalid mode');
 assert([1,2,3,4].includes(d.requested_risk),'Invalid risk');
 for(const f of ['requested_assets','excluded_assets']){
  assert(Array.isArray(d[f])&&d[f].length<=80,'Invalid asset counts');
  assert(d[f].every(s=>text(s,253)&&s.length&&s.trim()===s),'Invalid asset labels');
  assert(new Set(d[f].map(s=>s.toLowerCase())).size===d[f].length,'Duplicate assets');
 }
 assert(d.requested_assets.length>0,'No proposed assets');
 const activities=['passive_analysis','configuration_review','private_lab_network_checks'];
 assert(exactKeys(d.proposed_activities,activities)&&activities.every(k=>typeof d.proposed_activities[k]==='boolean'),'Malformed activities');
 if(d.scope_fingerprint_sha256!==undefined)assert(typeof d.scope_fingerprint_sha256==='string'&&/^[0-9a-f]{64}$/.test(d.scope_fingerprint_sha256),'Invalid draft fingerprint');
 if(d.exported_at_utc!==undefined)assert(text(d.exported_at_utc,80),'Invalid export metadata');
 return validateWindow(d);
}
function questionIds(d,window){
 const codes=['client_identity','asset_ownership','purpose_limits','client_consent','operator_independence','enforceable_scope','risk_approval','stop_revocation','mandatory_gates'];
 if(d.requested_risk===4)codes.push('high_risk');
 if(d.proposed_activities.private_lab_network_checks)codes.push('lab_provenance','network_activity');
 if(!d.excluded_assets.length)codes.push('no_exclusions');
 if(window!=='Resolved (still unapproved)')codes.push('open_window');
 if(!d.notes.trim())codes.push('safety_context');
 return codes;
}
function exportModel(){
 if(!current)return null;
 return {
  kind:'lightup.scope_permission_brief',schema_version:1,state:'REVIEW_ONLY_HOLD',
  source_kind:'lightup.scope_proposal_draft',source_sha256:current.sha256,
  audience:document.querySelector('[name="audience"]:checked').value,
  requested_mode:current.draft.requested_mode,requested_risk:current.draft.requested_risk,
  proposed_assets_count:current.draft.requested_assets.length,excluded_assets_count:current.draft.excluded_assets.length,
  window_status:current.window==='Resolved (still unapproved)'?'resolved_unapproved':current.window.toLowerCase(),
  // A role-labelled export may report ONLY that role's own preparation questions.
  // Other-role local annotations stay private and cannot impersonate another reply.
  question_states:questions.map(q=>({code:q.code,role:q.role,
   status:q.role===document.querySelector('[name="audience"]:checked').value?q.status:'unanswered'})),
  outstanding_questions:questions.filter(q=>q.role!==document.querySelector('[name="audience"]:checked').value||q.status!=='answered_unverified').length,
  flags:flags(),
  notice:'No approval, consent, permission, grant, scan, deployment, release or authority. Answers are unverified.'
 };
}
function render(){
 if(!current)return;
 const d=current.draft;
 $('assets').textContent=String(d.requested_assets.length);
 $('excluded').textContent=String(d.excluded_assets.length);
 $('risk').textContent=String(d.requested_risk)+' / 4';
 $('window').textContent=current.window;
 const activities=Object.entries(d.proposed_activities).filter(([,value])=>value).map(([key])=>key.replaceAll('_',' '));
 $('clientSummary').textContent='Proposed '+d.requested_mode.replaceAll('_',' ')+' covering '+d.requested_assets.length+' declared asset(s), with '+d.excluded_assets.length+' exclusion(s) and risk '+d.requested_risk+'. Proposed activity categories: '+(activities.join(', ')||'none')+'. Dates, if present, remain tentative.';
 $('operatorSummary').textContent='Review every individual asset and exclusion against a verified tenant and owned scope, then assess requested risk '+d.requested_risk+', activity constraints and '+current.window.toLowerCase()+' planning. Draft data never crosses the execution boundary.';
 const parent=$('questions');parent.replaceChildren();
 questions.forEach(q=>{
  const [role,title,body]=questionCatalog[q.code];
  const row=document.createElement('div');row.className='question';
  const desc=document.createElement('div');
  const heading=document.createElement('h3');heading.textContent=title;
  const tag=document.createElement('span');tag.className='tag';tag.textContent=role.toUpperCase()+' PREPARATION';
  const explanation=document.createElement('p');explanation.textContent=body;
  desc.append(heading,tag,explanation);
  const label=document.createElement('label');label.textContent='Human note status (unverified)';
  const select=document.createElement('select');select.setAttribute('aria-label',title+' status');
  [['unanswered','Unanswered'],['question_sent','Question sent'],['answered_unverified','Answered, unverified']].forEach(([code,name])=>{
   const opt=document.createElement('option');opt.value=code;opt.textContent=name;select.append(opt);
  });
  select.value=q.status;
  select.addEventListener('change',()=>{
   if(!statuses.includes(select.value))return;
   q.status=select.value;refreshExport();
  });
  label.append(select);row.append(desc,label);parent.append(row);
 });
 refreshExport();
}
function refreshExport(){
 const model=exportModel();if(!model)return;
 $('openCount').textContent=String(model.outstanding_questions);
 $('preview').textContent=JSON.stringify(model,null,2);
 $('handoff').textContent=handoffText(model);
 $('receipt').textContent='Unsigned SHA-256 of original local bytes: '+current.sha256+' · REFERENCE ONLY, NOT A SIGNATURE';
}
function handoffText(model){
 const role=model.audience==='client'?'Client':'Operator';
 const unresolved=questions.filter(q=>q.status!=='answered_unverified' && q.role===model.audience);
 return [
  'LIGHTUP / '+role.toUpperCase()+' PREPARATION / REVIEW_ONLY_HOLD',
  'This note is not consent, approval, a grant, execution or release.',
  'Original source SHA-256: '+model.source_sha256,
  'Requested mode: '+model.requested_mode+' · Risk: '+model.requested_risk+' / 4',
  'Proposed asset counts: '+model.proposed_assets_count+' · Exclusions: '+model.excluded_assets_count,
  'Planning window: '+model.window_status+' (not approved)',
  '',
  'Open '+role.toLowerCase()+' clarification questions ('+unresolved.length+'):',
  ...unresolved.map((q,i)=>(i+1)+'. '+questionCatalog[q.code][1]+' ['+q.status+']'),
  '',
  'Every identity, consent, grant, risk approval, revocation, scan, deploy and release flag is FALSE.',
  'Please use independent authenticated channels for any actual decision.'
 ].join('\\n').replaceAll('\\n','\n');
}
function downloadText(){
 const model=exportModel();if(!model)return;
 const blob=new Blob([handoffText(model)+'\n'],{type:'text/plain;charset=utf-8'});
 const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download='lightup-human-permission-note-HOLD.txt';document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function importReview(file){
 if(!current){$('replyState').textContent='Load the original draft first · HOLD';return;}
 const oldEpoch=epoch,originalSha=current.sha256;
 try{
  assert(file&&file.size>0&&file.size<=MAX_BYTES,'Review file size is unsafe');
  const bytes=await file.arrayBuffer();
  assert(bytes.byteLength<=MAX_BYTES,'Review too large');
  const source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  assert(!source.startsWith('\ufeff'),'BOM refused');
  assertUnambiguousJSON(source);
  const incoming=JSON.parse(source),reference=exportModel();
  assert(oldEpoch===epoch&&current?.sha256===originalSha,'Original source changed');
  assert(exactKeys(incoming,Object.keys(reference))&&Object.keys(incoming).length===Object.keys(reference).length,'Unexpected review fields');
  for(const key of Object.keys(reference)){
   if(['audience','question_states','outstanding_questions'].includes(key))continue;
   assert(JSON.stringify(incoming[key])===JSON.stringify(reference[key]),'Review source or flags mismatch');
  }
  assert(['client','operator'].includes(incoming.audience),'Unknown audience');
  assert(Array.isArray(incoming.question_states)&&incoming.question_states.length===questions.length,'Review question mismatch');
  const restored=[];
  for(let i=0;i<questions.length;i++){
   const q=incoming.question_states[i],expected=questions[i];
   assert(exactKeys(q,['code','role','status'])&&Object.keys(q).length===3,'Unknown question fields');
   assert(q.code===expected.code&&q.role===expected.role&&statuses.includes(q.status),'Review question changed');
   assert(q.role===incoming.audience||q.status==='unanswered','Foreign-role reply claims are forbidden');
   restored.push(q.status);
  }
  assert(incoming.outstanding_questions===restored.filter(x=>x!=='answered_unverified').length,'Review summary mismatch');
  // All imported labels remain explicitly unverified. Commit the whole restore only after preflight.
  // Preserve other-role local work; importing this role never overwrites it.
  questions.forEach((q,i)=>{if(q.role===incoming.audience)q.status=restored[i];});
  document.querySelector('[name="audience"][value="'+incoming.audience+'"]').checked=true;
  render();$('replyState').textContent='Review note matches exact original bytes · imported as unverified preparation only · HOLD';
 }catch(_){
  $('replyState').textContent='Review note rejected: ambiguous, altered or not source-bound · HOLD';
 }
}
function download(){
 const model=exportModel();if(!model)return;
 const bytes=new Blob([JSON.stringify(model,null,2)+'\n'],{type:'application/json'});
 const url=URL.createObjectURL(bytes),link=document.createElement('a');
 link.href=url;link.download='lightup-permission-brief-review-only.json';
 document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function loadFile(file){
 // Capture only privacy-minimal, unverified previous review context before clearing it.
 const priorRevision=exportModel();
 hold('Reading draft');
 if(!file||file.size===0||file.size>MAX_BYTES){hold('Missing or oversized file');return;}
 const token=epoch;
 try{
  const bytes=await file.arrayBuffer();
  assert(bytes.byteLength>0&&bytes.byteLength<=MAX_BYTES,'Oversized source');
  const source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  assert(!source.startsWith('\ufeff'),'BOM not accepted');
  assertUnambiguousJSON(source);
  const draft=JSON.parse(source);
  const window=validateDraft(draft);
  assert(globalThis.crypto?.subtle,'Secure local WebCrypto unavailable');
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  const sha256=Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
  if(token!==epoch)return;
  current={draft,window,sha256};
  questions=questionIds(draft,window).map(code=>({code,role:questionCatalog[code][0],status:'unanswered'}));
  document.dispatchEvent(new CustomEvent('lightup:brief-source-change'));

  $('workspace').hidden=false;$('export').disabled=false;$('textExport').disabled=false;$('print').disabled=false;
  $('sourceState').textContent='Source loaded · '+draft.requested_assets.length+' proposed assets · REVIEW_ONLY/HOLD';
  render();
  document.dispatchEvent(new CustomEvent('lightup:brief-revision',{
   detail:{before:priorRevision,after:exportModel()}
  }));
 }catch(_){if(token===epoch)hold('Invalid, ambiguous or unsafe Studio draft');}
}
/* Only privacy-minimal snapshot/strict parser are exposed to the adjacent offline reconciliation view. */
window.LightUpBriefRuntime=Object.freeze({
 snapshot:()=>{const m=exportModel();return m?JSON.parse(JSON.stringify(m)):null;},
 assertUnambiguousJSON
});
$('source').addEventListener('change',event=>loadFile(event.target.files?.[0]));
$('clear').addEventListener('click',()=>{hold('Source forgotten');$('source').value='';$('reply').value='';$('preview').textContent='';$('receipt').textContent='';});
$('export').addEventListener('click',download);
$('textExport').addEventListener('click',downloadText);
$('reply').addEventListener('change',event=>importReview(event.target.files?.[0]));
$('print').addEventListener('click',()=>{if(current)window.print();});
document.querySelectorAll('[name="audience"]').forEach(el=>el.addEventListener('change',refreshExport));
})();