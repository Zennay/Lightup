/* LightUp: local, non-authorizing coordination board. Never wire to grants or execution. */
(() => {
'use strict';
const MAX_FILE=65536, MAX_WORKSPACE=262144, MAX_RECORDS=20;
const STAGES=[
  ['client_evidence','Client identity and asset ownership evidence','Client-side preparation; evidence must be verified in the real authenticated system.'],
  ['scope_boundary','Exact assets, exclusions and activities','Operator must independently validate enforceable effective scope; this is not a policy check.'],
  ['client_consent','Client review and consent coordination','Track preparation only; cannot record actual authenticated client consent.'],
  ['operator_review','Independent operator review','Track review actions only; cannot record operator approval or a risk clearance.'],
  ['window_stop','UTC window, risk escalation and stop route','Agree a separately approved window, revocation route and emergency STOP contact.'],
  ['privacy_handoff','Evidence minimization and incident handoff','Clarify retention, redaction, incident handling and authorized delivery.']
];
const STATUSES=['todo','waiting','prepared'];
const $=id=>document.getElementById(id);
let entries=[], active=null, dirty=false;
const flags=()=>({authenticated:false,client_consent:false,operator_consent:false,authorization:false,risk_approved:false,grant:false,revocation_checked:false,execution:false,scan:false,release:false});
const fresh=()=>Object.fromEntries(STAGES.map(([id])=>[id,{status:'todo',owner:'',due:'',next_action:''}]));
function notice(msg){$('message').textContent=msg;}
function validText(v,max){return typeof v==='string' && v.length<=max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v);}
function plain(v){return v && typeof v==='object'&&!Array.isArray(v);}
function allowedFlags(o){
  const keys=Object.keys(flags());
  return plain(o)&&keys.every(k=>o[k]===false);
}
function parseJSON(text){
 const obj=JSON.parse(text,(k,v)=>(k==='__proto__'||k==='constructor'||k==='prototype')?undefined:v);
 if(!plain(obj))throw Error('Expected a JSON object.');
 return obj;
}
function validDraft(d){
 if(!plain(d)||d.kind!=='lightup.scope_proposal_draft'||d.schema_version!==1||d.state!=='DRAFT_ONLY')return false;
 if(!['authorization','client_consent','operator_consent','grant','execution','revocation_checked'].every(k=>d[k]===false))return false;
 if(!validText(d.proposal_name,120)||!validText(d.client_label,100)||!validText(d.notes,3000))return false;
 if(!['analysis_only','authorized_assessment'].includes(d.requested_mode)||![1,2,3,4].includes(d.requested_risk))return false;
 if(!Array.isArray(d.requested_assets)||!Array.isArray(d.excluded_assets)||d.requested_assets.length>80||d.excluded_assets.length>80)return false;
 if(![...d.requested_assets,...d.excluded_assets].every(x=>validText(x,253)&&x.length>0&&x.trim()===x))return false;
 if(!plain(d.proposed_activities)||!['passive_analysis','configuration_review','private_lab_network_checks'].every(k=>typeof d.proposed_activities[k]==='boolean'))return false;
 if(!plain(d.proposed_window_local)||!plain(d.proposed_window_utc))return false;
 if(!['start','end'].every(k=>d.proposed_window_local[k]===null||validText(d.proposed_window_local[k],80)))return false;
 // Any stored source digest is only a continuity hint. Never treat it as trusted identity.
 if(d.scope_fingerprint_sha256!==undefined && !/^[0-9a-f]{64}$/.test(d.scope_fingerprint_sha256))return false;
 // Refuse unexpected asserted authority even when not among the original Studio keys.
 for(const k of Object.keys(d))if(/(?:approved|authorized|permission|consent|grant|execution|scan|release|verified)/i.test(k)&&d[k]===true)return false;
 return true;
}
function sha(text){
 if(!globalThis.crypto||!crypto.subtle)throw Error('Browser WebCrypto SHA-256 is unavailable; source binding must not be weakened.');
 const bytes=new TextEncoder().encode(text);
 return crypto.subtle.digest('SHA-256',bytes).then(buffer=>Array.from(new Uint8Array(buffer),x=>x.toString(16).padStart(2,'0')).join(''));
}
function sourceRecord(d,digest){
 return {
  source_sha256:digest,name:d.proposal_name||'Untitled scope draft',client_label:d.client_label,
  requested_mode:d.requested_mode,requested_risk:d.requested_risk,asset_count:d.requested_assets.length,
  excluded_count:d.excluded_assets.length,planned_utc:d.proposed_window_utc.status==='resolved'?
   {start:d.proposed_window_utc.start,end:d.proposed_window_utc.end}:null,
  source_attached:true,tasks:fresh()
 };
}
function cleanRecord(r){
 if(!plain(r)||!(/^[0-9a-f]{64}$/).test(r.source_sha256)||!validText(r.name,120)||!validText(r.client_label,100)||
 !['analysis_only','authorized_assessment'].includes(r.requested_mode)||![1,2,3,4].includes(r.requested_risk)||
 !Number.isInteger(r.asset_count)||r.asset_count<0||r.asset_count>80||
 !Number.isInteger(r.excluded_count)||r.excluded_count<0||r.excluded_count>80)return null;
 if(r.planned_utc!==null && (!plain(r.planned_utc)||!['start','end'].every(k=>validText(r.planned_utc[k],50))))return null;
 if(!plain(r.tasks)||Object.keys(r.tasks).length!==STAGES.length)return null;
 const tasks={};
 for(const [key] of STAGES){
  const t=r.tasks[key];
  if(!plain(t)||!STATUSES.includes(t.status)||!validText(t.owner,80)||!validText(t.next_action,350)||
  !validText(t.due,10)||(t.due!==''&&!/^\d{4}-\d{2}-\d{2}$/.test(t.due)))return null;
  if(t.due!==''&&new Date(t.due+'T00:00:00Z').toISOString().slice(0,10)!==t.due)return null;
  tasks[key]={status:t.status,owner:t.owner,due:t.due,next_action:t.next_action};
 }
 return {source_sha256:r.source_sha256,name:r.name,client_label:r.client_label,
  requested_mode:r.requested_mode,requested_risk:r.requested_risk,asset_count:r.asset_count,
  excluded_count:r.excluded_count,planned_utc:r.planned_utc,
  source_attached:false,tasks};
}
const unresolved=r=>STAGES.filter(([k])=>r.tasks[k].status!=='prepared').length;
const overdue=r=>STAGES.filter(([k])=>r.tasks[k].status!=='prepared'&&r.tasks[k].due&&r.tasks[k].due<new Date().toISOString().slice(0,10)).length;
function setDirty(){dirty=true;$('save').disabled=!entries.length;$('csv').disabled=!entries.length;$('print').disabled=!entries.length;}
function make(tag,txt,cls){const el=document.createElement(tag);if(txt!==undefined)el.textContent=txt;if(cls)el.className=cls;return el;}
function brief(){
 const lines=['LIGHTUP / HUMAN SCOPE COORDINATION — NON-AUTHORIZING','State: REVIEW_ONLY · DRAFT-HOLD',
 'No authenticated consent, operator approval, grant, verified ownership or execution.',
 'Entries: '+entries.length,''];
 for(let i=0;i<entries.length;i++){
  const r=entries[i];lines.push((i+1)+'. '+r.name+' · '+r.requested_mode+' · risk '+r.requested_risk);
  lines.push('Source SHA-256 (unsigned): '+r.source_sha256);
  lines.push('Original file: '+(r.source_attached?'locally loaded':'NOT RE-ATTACHED · HOLD'));
  lines.push('Assets declared (not proved): '+r.asset_count+' · exclusions: '+r.excluded_count);
  lines.push('UTC request (not booked): '+(r.planned_utc?r.planned_utc.start+' → '+r.planned_utc.end:'unresolved · HOLD'));
  for(const [id,title] of STAGES){
   const t=r.tasks[id];lines.push('  - '+title+': '+t.status.toUpperCase()+'; follow-up: '+(t.next_action||'not assigned')+
   '; owner label: '+(t.owner||'unassigned')+'; target: '+(t.due||'unset'));
  }
  lines.push('ALL AUTHORIZATION / GRANT / SCAN FLAGS: FALSE','');
 }
 return lines.join('\n');
}
function renderStats(){
 $('count').textContent=String(entries.length);
 $('unbound').textContent=String(entries.filter(r=>!r.source_attached).length);
 $('blockers').textContent=String(entries.reduce((s,r)=>s+unresolved(r),0));
 $('overdue').textContent=String(entries.reduce((s,r)=>s+overdue(r),0));
 $('brief').textContent=brief();
 $('save').disabled=!entries.length;$('csv').disabled=!entries.length;$('print').disabled=!entries.length;
}
function renderList(){
 const list=$('drafts'), filter=$('filter').value;list.replaceChildren();
 const selected=entries.filter(r=>filter==='all'||filter==='hold'&&unresolved(r)>0||
  filter==='missing'&&!r.source_attached||filter==='risk'&&r.requested_risk===4);
 if(!selected.length){list.append(make('p','No matching drafts.'));return;}
 for(const r of selected){
  const b=make('button',undefined,'item'+(active===r.source_sha256?' active':''));
  b.type='button';b.append(make('strong',r.name||'Untitled proposal'));
  b.append(make('small',(r.client_label||'No client label')+' · risk '+r.requested_risk+' · '+r.requested_mode));
  b.append(make('small',(r.source_attached?'Source loaded':'SOURCE MISSING · HOLD')+
    ' · '+unresolved(r)+' unresolved prep tasks'+(overdue(r)?' · '+overdue(r)+' overdue':'')));
  b.addEventListener('click',()=>{active=r.source_sha256;renderList();renderDetail();});
  list.append(b);
 }
}
function renderDetail(){
 const box=$('detail');box.replaceChildren();const r=entries.find(x=>x.source_sha256===active);
 if(!r){box.append(make('p','Select a Studio draft to track separate client and operator preparation.'));return;}
 box.append(make('h3',r.name));
 box.append(make('p','Source SHA-256: '+r.source_sha256,'small truncate'));
 const summary=make('p',(r.source_attached?'Source file bound to this exact local session.':'Original source file must be re-attached before relying on continuity.')+
  ' · '+r.asset_count+' proposed assets / '+r.excluded_count+' exclusions · risk '+r.requested_risk,'hint');
 box.append(summary);
 const message=make('p','Each “prepared” state means paperwork prepared only. No authenticated client/operator consent can be set here.','small');box.append(message);
 const scroll=make('div',undefined,'scroll'),table=make('table'),thead=make('thead'),tr=make('tr');
 for(const name of ['Preparation workstream','Paperwork state','Follow-up owner label','Target date','Next action / blocker'])tr.append(make('th',name));
 thead.append(tr);table.append(thead);
 const tbody=make('tbody');
 for(const [id,title,help] of STAGES){
  const task=r.tasks[id], row=make('tr'), titleCell=make('td');
  titleCell.append(make('strong',title),make('span',help,'small'));row.append(titleCell);
  const status=make('select');status.setAttribute('aria-label',title+' paperwork state');
  for(const [val,label] of [['todo','Not started'],['waiting','Waiting / blocked'],['prepared','Prepared — unverified']]){
   const option=make('option',label);option.value=val;option.selected=task.status===val;status.append(option);
  }
  status.addEventListener('change',()=>{task.status=status.value;setDirty();renderStats();renderList();});
  const stateCell=make('td');stateCell.append(status);row.append(stateCell);
  const owner=make('input');owner.type='text';owner.maxLength=80;owner.value=task.owner;owner.placeholder='Unverified coordinator';
  owner.setAttribute('aria-label',title+' owner label');
  owner.addEventListener('input',()=>{task.owner=owner.value;setDirty();renderStats();});
  const ownerCell=make('td');ownerCell.append(owner);row.append(ownerCell);
  const due=make('input');due.type='date';due.value=task.due;due.setAttribute('aria-label',title+' target date');
  due.addEventListener('change',()=>{task.due=due.value;setDirty();renderStats();renderList();});
  const dueCell=make('td');dueCell.append(due);row.append(dueCell);
  const next=make('textarea');next.maxLength=350;next.rows=2;next.value=task.next_action;next.placeholder='Concrete missing document or follow-up…';
  next.setAttribute('aria-label',title+' next action');
  next.addEventListener('input',()=>{task.next_action=next.value;setDirty();renderStats();});
  const nextCell=make('td');nextCell.append(next);row.append(nextCell);tbody.append(row);
 }
 table.append(tbody);scroll.append(table);box.append(scroll);
 const tools=make('div',undefined,'toolbar');
 const remove=make('button','Remove draft from local board');remove.type='button';
 remove.addEventListener('click',()=>{if(!confirm('Remove this local coordination draft? Source files are never changed.'))return;
 entries=entries.filter(x=>x!==r);active=entries[0]?.source_sha256||null;setDirty();render();});
 tools.append(remove);box.append(tools);
}
function render(){renderStats();renderList();renderDetail();}
function download(name,data,type){
 const url=URL.createObjectURL(new Blob([data],{type}));
 const a=make('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1200);
}
async function addSource(file){
 if(!file||file.size>MAX_FILE||!file.size)throw Error('Source file must be 1–65536 bytes.');
 const text=await file.text(), obj=parseJSON(text);
 if(!validDraft(obj))throw Error('Not a safe Studio v1 DRAFT_ONLY source.');
 const digest=await sha(text);
 let existing=entries.find(r=>r.source_sha256===digest);
 if(existing){
  if(existing.name!==obj.proposal_name||existing.requested_risk!==obj.requested_risk||
   existing.asset_count!==obj.requested_assets.length||existing.excluded_count!==obj.excluded_assets.length)
   throw Error('Same source digest but inconsistent imported source metadata.');
  existing.source_attached=true;return 're-attached';
 }
 if(entries.length>=MAX_RECORDS)throw Error('20-item board limit reached.');
 entries.push(sourceRecord(obj,digest));return 'added';
}
$('sourceUpload').addEventListener('change',async event=>{
 const files=Array.from(event.target.files);event.target.value='';
 if(!files.length)return;if(files.length>MAX_RECORDS){notice('Rejected: too many files in one batch.');return;}
 // Parse and SHA all files first; no partial import if any file is malformed.
 try{
  const incoming=[];
  for(const file of files){
   if(!file.size||file.size>MAX_FILE)throw Error('One source file is too large.');
   const text=await file.text(),d=parseJSON(text);
   if(!validDraft(d))throw Error('One source is not a safe Studio v1 DRAFT_ONLY.');
   incoming.push({d,digest:await sha(text)});
  }
  const newShas=new Set(incoming.filter(x=>!entries.some(r=>r.source_sha256===x.digest)).map(x=>x.digest));
  if(entries.length+newShas.size>MAX_RECORDS)throw Error('Board is limited to 20 different revisions.');
  for(const x of incoming){
   const existing=entries.find(r=>r.source_sha256===x.digest);
   if(existing){
    if(existing.name!==x.d.proposal_name||existing.requested_risk!==x.d.requested_risk||
       existing.asset_count!==x.d.requested_assets.length||existing.excluded_count!==x.d.excluded_assets.length)throw Error('Source metadata mismatch; no changes applied.');
   }
  }
  for(const x of incoming){
   const r=entries.find(e=>e.source_sha256===x.digest);
   if(r)r.source_attached=true;else entries.push(sourceRecord(x.d,x.digest));
  }
  active=incoming[0].digest;setDirty();render();notice('Loaded '+incoming.length+' local source file(s). Every task remains non-authorizing.');
 }catch(e){notice('Import HOLD: '+e.message+' Existing board preserved.');}
});
$('restoreInput').addEventListener('change',async event=>{
 const file=event.target.files[0];event.target.value='';if(!file)return;
 try {
  if(!file.size||file.size>MAX_WORKSPACE)throw Error('Workspace file must be 1–262144 bytes.');
  const parsed=parseJSON(await file.text());
  if(parsed.kind!=='lightup.scope_readiness_workspace'||parsed.schema_version!==1||parsed.disposition!=='REVIEW_ONLY'||
     !allowedFlags(parsed.security)||!Array.isArray(parsed.records)||parsed.records.length>MAX_RECORDS)throw Error('Unsupported or unsafe workspace schema.');
  const next=parsed.records.map(cleanRecord);
  if(next.some(r=>!r)||new Set(next.map(r=>r.source_sha256)).size!==next.length)throw Error('Invalid, duplicated or malformed source-bound record.');
  if(entries.length&&!confirm('Replace your current in-memory board? Save it first if needed.'))return;
  entries=next;active=entries[0]?.source_sha256||null;dirty=false;render();
  notice('Restored tracking only. Studio source files deliberately remain UNBOUND until exact SHA-256 re-attachment. ALL authorization flags false.');
 }catch(e){notice('Restore HOLD: '+e.message+' Existing board unchanged.');}
});
$('filter').addEventListener('change',renderList);
$('save').addEventListener('click',()=>{
 if(!entries.length)return;
 const records=entries.map(r=>{const clean=cleanRecord(r);if(!clean)throw Error('Invalid local task record.');delete clean.source_attached;return clean;});
 const payload={kind:'lightup.scope_readiness_workspace',schema_version:1,disposition:'REVIEW_ONLY',
  security:flags(),exported_at_utc:new Date().toISOString(),records,
  notice:'Not authoritative. Source hashes are unsigned. Re-attach originals and complete separate authenticated two-party consent, grant and at-use revocation controls.'};
 download('lightup-scope-readiness-private.json',JSON.stringify(payload,null,2)+'\n','application/json');
 dirty=false;notice('Saved local private review-only snapshot. Keep it within approved private storage.');
});
function csvCell(s){
 const value=String(s??'');
 const safe=/^[\s\uFEFF]*[=+@\-]/.test(value)?"'"+value:value;
 return '"'+safe.replaceAll('"','""')+'"';
}
$('csv').addEventListener('click',()=>{
 const rows=[['Source SHA-256 (unsigned)','Draft','Requested risk','Stage','Paperwork status','Owner label','Target date','Next action','Source attached at export','Authorization']];
 for(const r of entries)for(const [id,title] of STAGES){
  const t=r.tasks[id];rows.push([r.source_sha256,r.name,r.requested_risk,title,t.status,t.owner,t.due,t.next_action,r.source_attached?'yes':'no','NO']);
 }
 download('lightup-scope-readiness-actions.csv',rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
 notice('Private action register exported. It is not evidence of permission.');
});
$('print').addEventListener('click',()=>{if(entries.length)window.print();});
$('reset').addEventListener('click',()=>{
 if(entries.length&&!confirm('Clear all in-memory coordination work? Save it first if needed.'))return;
 entries=[];active=null;dirty=false;$('sourceUpload').value='';$('restoreInput').value='';render();notice('Memory cleared. No source records changed.');
});
window.addEventListener('beforeunload',event=>{if(dirty&&entries.length){event.preventDefault();event.returnValue='';}});
render();
})();
