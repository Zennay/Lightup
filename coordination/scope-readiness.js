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
let entries=[], active=null, dirty=false, editEpoch=0, bulkPlan=null, packetDraft=null, bulkUndo=null, mergePlan=null;
// Full original Studio drafts exist only in volatile browser memory; never serialized into casework exports.
const sourceCopies=new Map();
let revisionPreview=null;
const flags=()=>({authenticated:false,client_consent:false,operator_consent:false,authorization:false,risk_approved:false,grant:false,revocation_checked:false,execution:false,scan:false,release:false});
const fresh=()=>Object.fromEntries(STAGES.map(([id])=>[id,{status:'todo',owner:'',due:'',next_action:''}]));
function notice(msg){$('message').textContent=msg;}
function validText(v,max){return typeof v==='string' && v.length<=max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v);}
function plain(v){return v && typeof v==='object'&&!Array.isArray(v);}
function allowedFlags(o){
  const keys=Object.keys(flags());
  return plain(o)&&Object.keys(o).length===keys.length&&
  Object.keys(o).every(k=>keys.includes(k))&&keys.every(k=>o[k]===false);
}
function parseJSON(text){
 const obj=JSON.parse(text,(k,v)=>{
  if(k==='__proto__'||k==='constructor'||k==='prototype')throw Error('Unsafe reserved JSON key.');
  return v;
 });
 if(!plain(obj))throw Error('Expected a JSON object.');
 return obj;
}
function validUtcWindow(d){
 const w=d.proposed_window_utc,l=d.proposed_window_local;
 if(!plain(w)||!plain(l))return false;
 if(Object.keys(w).some(k=>!['status','timezone','start','end','start_offset_minutes','end_offset_minutes'].includes(k)))return false;
 if(!validText(w.timezone,100))return false;
 if(w.status==='unscheduled'||w.status==='incomplete'){
  const emptyStart=l.start===null,emptyEnd=l.end===null;
  return (w.status==='unscheduled'?(emptyStart&&emptyEnd):(emptyStart!==emptyEnd))&&w.start===null&&w.end===null;
 }
 if(w.status!=='resolved')return false;
 const iso=/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:00\\.000Z$/;
 const local=/^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2})$/;
 if(typeof w.start!=='string'||typeof w.end!=='string'||!iso.test(w.start)||!iso.test(w.end)||w.start>=w.end)return false;
 if(!Number.isInteger(w.start_offset_minutes)||!Number.isInteger(w.end_offset_minutes)||
  Math.abs(w.start_offset_minutes)>840||Math.abs(w.end_offset_minutes)>840)return false;
 const make=(wall,offset)=>{
  if(typeof wall!=='string')return null;
  const match=local.exec(wall);if(!match)return null;
  const [y,m,day,h,min]=match.slice(1).map(Number);
  if(y<2020||y>2100||m<1||m>12||day<1||day>31||h>23||min>59)return null;
  const utc=new Date(Date.UTC(y,m-1,day,h,min)+offset*60000);
  // Refuse impossible day/month normalization rather than guessing a timezone.
  const calendar=new Date(Date.UTC(y,m-1,day));
  if(calendar.getUTCFullYear()!==y||calendar.getUTCMonth()!==m-1||calendar.getUTCDate()!==day)return null;
  return utc.toISOString();
 };
 try{return make(l.start,w.start_offset_minutes)===w.start && make(l.end,w.end_offset_minutes)===w.end;}
 catch(_){return false;}
}
function validDraft(d){
 if(!plain(d)||d.kind!=='lightup.scope_proposal_draft'||d.schema_version!==1||d.state!=='DRAFT_ONLY')return false;
 const allowedSourceFields=[
  'schema_version','kind','state','authorization','client_consent','operator_consent','grant',
  'execution','revocation_checked','proposal_name','client_label','requested_assets',
  'excluded_assets','requested_mode','requested_risk','notes','proposed_activities',
  'proposed_window_local','proposed_window_utc','exported_at_utc','scope_fingerprint_sha256'
 ];
 if(Object.keys(d).some(k=>!allowedSourceFields.includes(k)))return false;
 if(!['authorization','client_consent','operator_consent','grant','execution','revocation_checked'].every(k=>d[k]===false))return false;
 if(!validText(d.proposal_name,120)||!validText(d.client_label,100)||!validText(d.notes,3000))return false;
 if(!['analysis_only','authorized_assessment'].includes(d.requested_mode)||![1,2,3,4].includes(d.requested_risk))return false;
 if(!Array.isArray(d.requested_assets)||!Array.isArray(d.excluded_assets)||d.requested_assets.length>80||d.excluded_assets.length>80)return false;
 if(!d.requested_assets.length||![...d.requested_assets,...d.excluded_assets].every(x=>validText(x,253)&&x.length>0&&x.trim()===x))return false;
 const noDuplicates=list=>new Set(list.map(x=>x.toLowerCase())).size===list.length;
 if(!noDuplicates(d.requested_assets)||!noDuplicates(d.excluded_assets))return false;
 if(!plain(d.proposed_activities)||Object.keys(d.proposed_activities).some(k=>!['passive_analysis','configuration_review','private_lab_network_checks'].includes(k))||
  !['passive_analysis','configuration_review','private_lab_network_checks'].every(k=>typeof d.proposed_activities[k]==='boolean'))return false;
 if(!plain(d.proposed_window_local)||!validUtcWindow(d))return false;
 if(!['start','end'].every(k=>d.proposed_window_local[k]===null||validText(d.proposed_window_local[k],80)))return false;
 // Any stored source digest is only a continuity hint. Never treat it as trusted identity.
 if(d.scope_fingerprint_sha256!==undefined && !/^[0-9a-f]{64}$/.test(d.scope_fingerprint_sha256))return false;
 // Refuse unexpected asserted authority even when not among the original Studio keys.
 for(const k of Object.keys(d))if(/(?:approved|authorized|permission|consent|grant|execution|scan|release|verified)/i.test(k)&&d[k]===true)return false;
 return true;
}
function sha(bytes){
 if(!globalThis.crypto||!crypto.subtle)throw Error('Browser WebCrypto SHA-256 is unavailable; source binding must not be weakened.');
 // Hash the actual imported bytes, never a lossy decoded-and-reencoded approximation.
 return crypto.subtle.digest('SHA-256',bytes).then(buffer=>Array.from(new Uint8Array(buffer),x=>x.toString(16).padStart(2,'0')).join(''));
}
async function readSourceBytes(file){
 const bytes=await file.arrayBuffer();
 // Malformed UTF-8 is a HOLD. File.text() would silently replace invalid bytes.
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 return {bytes,text};
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
function cleanRecord(r,{restored=false}={}){
 // Imported casework is never allowed to smuggle a claimed authority field.
 if(!plain(r)||(restored&&Object.prototype.hasOwnProperty.call(r,'source_attached'))||Object.keys(r).some(k=>![
  'source_sha256','name','client_label','requested_mode','requested_risk',
  'asset_count','excluded_count','planned_utc','source_attached','tasks'
 ].includes(k)))return null;
 if(!plain(r)||!(/^[0-9a-f]{64}$/).test(r.source_sha256)||!validText(r.name,120)||!validText(r.client_label,100)||
 !['analysis_only','authorized_assessment'].includes(r.requested_mode)||![1,2,3,4].includes(r.requested_risk)||
 !Number.isInteger(r.asset_count)||r.asset_count<0||r.asset_count>80||
 !Number.isInteger(r.excluded_count)||r.excluded_count<0||r.excluded_count>80)return null;
 if(r.planned_utc!==null && (!plain(r.planned_utc)||
   Object.keys(r.planned_utc).some(k=>!['start','end'].includes(k))||
   !['start','end'].every(k=>validText(r.planned_utc[k],50)&&
   /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:00\\.000Z$/.test(r.planned_utc[k]))||
   r.planned_utc.start>=r.planned_utc.end))return null;
 if(!plain(r.tasks)||Object.keys(r.tasks).length!==STAGES.length)return null;
 const tasks={};
 for(const [key] of STAGES){
  const t=r.tasks[key];
  if(!plain(t)||Object.keys(t).some(k=>!['status','owner','due','next_action'].includes(k))||!STATUSES.includes(t.status)||!validText(t.owner,80)||!validText(t.next_action,350)||
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
const roleOverlap=r=>{
 const client=r.tasks.client_consent.owner.trim().toLocaleLowerCase();
 const operator=r.tasks.operator_review.owner.trim().toLocaleLowerCase();
 return Boolean(client&&operator&&client===operator);
};
const firstDue=r=>STAGES.map(([k])=>r.tasks[k]).filter(t=>t.status!=='prepared'&&t.due).map(t=>t.due).sort()[0]||'9999-12-31';
function attention(r){
 // Local operational sorting only. Does not judge scope authority or operator identity.
 return (r.source_attached?0:100)+(overdue(r)?60:0)+(roleOverlap(r)?40:0)+
  (r.requested_risk===4?30:0)+unresolved(r);
}
function clearBulkPreview(message='Preview expired after a change; recompute before applying.'){
 bulkPlan=null;$('bulkApply').disabled=true;$('bulkResult').textContent=message;
}
function clearPacketPreview(message='Source or coordination data changed. Create a new preview before download.'){
 packetDraft=null;$('packetDownload').disabled=true;$('packetStatus').textContent=message;
 $('packetText').textContent='No prepared packet.';
}
function clearMergePreview(message='Merge preview is stale; select the workspace file again.'){
 mergePlan=null;$('mergeApply').disabled=true;$('mergeStatus').textContent=message;$('mergeConflicts').replaceChildren();
}
function setDirty(){dirty=true;editEpoch++;clearRevisionPreview();clearMergePreview();bulkUndo=null;$('bulkUndo').disabled=true;clearPacketPreview();clearBulkPreview();$('save').disabled=!entries.length;$('csv').disabled=!entries.length;$('print').disabled=!entries.length;$('todoExport').disabled=!entries.length;}
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
  if(roleOverlap(r))lines.push('HUMAN REVIEW: client and operator coordination use the SAME SELF-REPORTED LABEL. Check independent roles in authenticated systems.');
  lines.push('UTC request (not booked): '+(r.planned_utc?r.planned_utc.start+' → '+r.planned_utc.end:'unresolved · HOLD'));
  for(const [id,title] of STAGES){
   const t=r.tasks[id];lines.push('  - '+title+': '+t.status.toUpperCase()+'; follow-up: '+(t.next_action||'not assigned')+
   '; owner label: '+(t.owner||'unassigned')+'; target: '+(t.due||'unset'));
  }
  lines.push('ALL AUTHORIZATION / GRANT / SCAN FLAGS: FALSE','');
 }
 return lines.join('\n');
}
function renderActionBoard(){
 const root=$('actionBoard');root.replaceChildren();
 const view=$('boardView').value,today=new Date().toISOString().slice(0,10);
 for(const [id,title] of STAGES){
  const items=entries.filter(r=>{
   const t=r.tasks[id];
   if(t.status==='prepared')return false;
   if(view==='overdue')return Boolean(t.due&&t.due<today);
   if(view==='unassigned')return !t.owner.trim();
   if(view==='waiting')return t.status==='waiting';
   return true;
  }).sort((a,b)=>{
   const da=a.tasks[id].due||'9999-12-31',db=b.tasks[id].due||'9999-12-31';
   return da.localeCompare(db)||attention(b)-attention(a)||a.name.localeCompare(b.name);
  });
  const lane=make('section',undefined,'actionLane');
  lane.append(make('h3',title+' ('+items.length+')'));
  if(!items.length){lane.append(make('p','No matching actions.','small'));root.append(lane);continue;}
  for(const r of items.slice(0,8)){
   const t=r.tasks[id],button=make('button');button.type='button';
   button.append(make('strong',r.name||'Untitled proposal'));
   button.append(make('span',(t.due?'Target '+t.due:'No target date')+
    ' · '+(t.owner||'No coordinator')+
    ' · '+(r.source_attached?'source attached':'source HOLD')));
   button.addEventListener('click',()=>{
    active=r.source_sha256;$('filter').value='all';clearBulkPreview();clearPacketPreview();
    renderList();renderDetail();
    const row=Array.from($('detail').querySelectorAll('[data-stage-id]')).find(el=>el.dataset.stageId===id);
    if(row)row.scrollIntoView({behavior:'smooth',block:'center'});
   });
   lane.append(button);
  }
  if(items.length>8)lane.append(make('p','+'+(items.length-8)+' more in this workstream. Use the draft register to see the rest.','small'));
  root.append(lane);
 }
}
$('boardView').addEventListener('change',renderActionBoard);
function clearRevisionPreview(message='Source or paperwork changed; compare the exact originals again.'){
 revisionPreview=null;$('revisionReopen').disabled=true;$('revisionCarry').disabled=true;$('revisionExport').disabled=true;
 $('revisionStatus').textContent=message;$('revisionChanges').replaceChildren();
}
function renderRevisionSources(){
 for(const id of ['revisionFrom','revisionTo']){
  const select=$(id),before=select.value;
  select.replaceChildren();const blank=make('option','Select original Studio draft');blank.value='';select.append(blank);
  for(const r of entries){
   if(!sourceCopies.has(r.source_sha256)||!r.source_attached)continue;
   const option=make('option',(r.name||'Untitled')+' · '+r.source_sha256.slice(0,12));
   option.value=r.source_sha256;select.append(option);
  }
  select.value=[...select.options].some(o=>o.value===before)?before:'';
 }
}
function currentRevisionSelection(){
 const from=$('revisionFrom').value,to=$('revisionTo').value;
 if(!from||!to||from===to)throw Error('Select two DISTINCT source-bound Studio revisions.');
 const first=entries.find(r=>r.source_sha256===from),second=entries.find(r=>r.source_sha256===to);
 if(!first||!second||!first.source_attached||!second.source_attached||
    !sourceCopies.has(from)||!sourceCopies.has(to))throw Error('Both exact originals must be reattached locally.');
 return {from,to,first,second};
}
for(const id of ['revisionFrom','revisionTo'])$(id).addEventListener('change',()=>clearRevisionPreview('Revision selection changed. Compare before taking action.'));
$('revisionDiscard').addEventListener('click',()=>clearRevisionPreview('Comparison cleared. Sources and paperwork unchanged.'));
$('revisionCompare').addEventListener('click',()=>{
 clearRevisionPreview();
 try{
  const {from,to}=currentRevisionSelection();
  const result=LightUpRevisionReview.compare(sourceCopies.get(from),sourceCopies.get(to));
  const root=$('revisionChanges');
  root.append(make('p',result.message,'hint'));
  if(!result.summary.length)root.append(make('p','No listed proposal changes; no action applied.','small'));
  for(const changed of result.summary){
   const box=make('div',undefined,'item');
   box.append(make('strong',changed.label));
   box.append(make('small',changed.detail));
   if(changed.stages.length)box.append(make('small','Re-review: '+changed.stages.join(', ')));
   root.append(box);
  }
  root.append(make('p',result.affectedStages.length+' preparation stage(s) require review. Source SHA-256 only proves local byte continuity; nothing authenticates scope rights.','small'));
  revisionPreview={epoch:editEpoch,from,to,result};
  $('revisionReopen').disabled=!result.affectedStages.length;
  $('revisionCarry').disabled=sourceCopies.get(from).client_label!==sourceCopies.get(to).client_label;
  $('revisionExport').disabled=false;
  $('revisionStatus').textContent='PRIVATE PREVIEW: '+result.summary.length+
   ' proposal difference category/categories; '+result.affectedStages.length+
   ' paperwork stage(s) flagged. No status changed. Literal CIDR/hostname labels are not effective coverage.';
 }catch(e){$('revisionStatus').textContent='Comparison HOLD: '+e.message;}
});
function checkedRevisionPreview(){
 if(!revisionPreview||revisionPreview.epoch!==editEpoch)throw Error('Comparison is stale.');
 const {from,to}=currentRevisionSelection();
 if(from!==revisionPreview.from||to!==revisionPreview.to)throw Error('Revision selection changed.');
 const current=LightUpRevisionReview.compare(sourceCopies.get(from),sourceCopies.get(to));
 if(JSON.stringify(current)!==JSON.stringify(revisionPreview.result))throw Error('Original proposal evidence changed.');
 return {current,target:entries.find(r=>r.source_sha256===to),from,to};
}
$('revisionCarry').addEventListener('click',()=>{
 try{
  const {current,target,from}=checkedRevisionPreview();
  const source=entries.find(r=>r.source_sha256===from);
  if(!source||source===target||source.client_label!==target.client_label)
   throw Error('Unverified client labels differ. Cross-label logistics carryover is HOLD.');
  const changes=[];
  for(const [stage] of STAGES){
   const original=source.tasks[stage],destination=target.tasks[stage];
   // Never transfer an old preparedness verdict or replace user-written assignments.
   if(destination.status==='prepared')continue;
   const fill={};
   for(const key of ['owner','due','next_action']){
    // A changed request can invalidate the meaning of an earlier instruction.
    // Carry owner/date logistics, but NEVER copy an older action note into an impacted stage.
    if(key==='next_action'&&current.affectedStages.includes(stage))continue;
    if(original[key]&&!destination[key])fill[key]=original[key];
   }
   if(Object.keys(fill).length)changes.push({stage,fill});
  }
  if(!changes.length){
   $('revisionStatus').textContent='No safe missing assignments to carry over. Prepared/newer paperwork is untouched.';
   return;
  }
  if(!confirm('Copy '+changes.reduce((n,c)=>n+Object.keys(c.fill).length,0)+
   ' missing coordinator, due-date or action fields across '+changes.length+
   ' preparation streams to the UPDATED draft? Matching self-reported client labels DO NOT verify tenancy. Earlier action notes for changed preparation streams, prepared/blocked statuses, consent, operator decisions, grants and source files never transfer.'))return;
  for(const change of changes)Object.assign(target.tasks[change.stage],change.fill);
  const count=changes.length;
  setDirty();render();
  $('revisionStatus').textContent='Filled missing follow-up logistics on '+count+
   ' newer draft streams. All approval/consent/authorization remain unverified; re-compare originals before re-opening stages.';
 }catch(e){clearRevisionPreview('Successor carryover HOLD: '+e.message);}
});
$('revisionReopen').addEventListener('click',()=>{
 try{
  const {current,target}=checkedRevisionPreview(),ids=current.affectedStages;
  if(!ids.length)throw Error('No material re-review stages identified.');
  const affected=ids.filter(id=>target.tasks[id].status!=='todo');
  if(!affected.length){$('revisionStatus').textContent='All impacted paperwork is already NOT STARTED. No state changes needed.';return;}
  if(!confirm('Reopen '+affected.length+' preparation workstream(s) on the UPDATED draft? Prepared/blocked paperwork states become NOT STARTED. Owner, due date and notes remain, but NO authenticated consent/approval/grants are implied. Original draft unchanged.'))return;
  for(const id of affected)target.tasks[id].status='todo';
  setDirty();render();
  $('revisionStatus').textContent='Reopened '+affected.length+' changed-scope preparation workstream(s) on the updated local record. All actual authorizations remain external and unverified.';
 }catch(e){clearRevisionPreview('Reopen HOLD: '+e.message);}
});
$('revisionExport').addEventListener('click',()=>{
 try{
  const {current,from,to}=checkedRevisionPreview();
  if(!confirm('Export an UNSIGNED, non-authorizing JSON of human review categories and source hashes? It contains no asset names or approval.'))return;
  const packet={
   kind:'lightup.scope_revision_impact_review',schema_version:1,disposition:'REVIEW_ONLY',
   original_source_sha256:from,updated_source_sha256:to,security:flags(),
   changed_categories:current.summary.map(c=>({key:c.key,review_stages:c.stages,scope_membership_unverified:c.scopeConcern})),
   affected_workstreams:current.affectedStages,
   warning:'Human review only. Not effective CIDR analysis, identity, ownership, consent, authority, grant or a valid release gate.'
  };
  download('lightup-revision-impact-review-private.json',JSON.stringify(packet,null,2)+'\\n','application/json');
  $('revisionStatus').textContent='Private review note downloaded. This is not an authenticated approval record.';
 }catch(e){clearRevisionPreview('Export HOLD: '+e.message);}
});
function renderStats(){
 $('count').textContent=String(entries.length);
 $('unbound').textContent=String(entries.filter(r=>!r.source_attached).length);
 $('blockers').textContent=String(entries.reduce((s,r)=>s+unresolved(r),0));
 $('overdue').textContent=String(entries.reduce((s,r)=>s+overdue(r),0));
 $('roleOverlap').textContent=String(entries.filter(roleOverlap).length);
 renderActionBoard();
 $('brief').textContent=brief();
 $('save').disabled=!entries.length;$('csv').disabled=!entries.length;$('print').disabled=!entries.length;
 $('todoExport').disabled=!entries.length;
}
function visibleQueue(){
 const filter=$('filter').value;
 return entries.filter(r=>filter==='all'||filter==='hold'&&unresolved(r)>0||
  filter==='missing'&&!r.source_attached||filter==='risk'&&r.requested_risk===4||
  filter==='overdue'&&overdue(r)>0||filter==='collision'&&roleOverlap(r));
}
function renderList(){
 const list=$('drafts');list.replaceChildren();
 const selected=visibleQueue();
 const sort=$('sort').value;
 selected.sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):
  sort==='due'?firstDue(a).localeCompare(firstDue(b)):
  attention(b)-attention(a)||a.name.localeCompare(b.name));
 if(!selected.length){list.append(make('p','No matching drafts.'));return;}
 for(const r of selected){
  const b=make('button',undefined,'item'+(active===r.source_sha256?' active':''));
  b.type='button';b.append(make('strong',r.name||'Untitled proposal'));
  b.append(make('small',(r.client_label||'No client label')+' · risk '+r.requested_risk+' · '+r.requested_mode));
  b.append(make('small',(r.source_attached?'Source loaded':'SOURCE MISSING · HOLD')+
    ' · '+unresolved(r)+' unresolved prep tasks'+(overdue(r)?' · '+overdue(r)+' overdue':'')+
    (roleOverlap(r)?' · SAME ROLE LABEL REVIEW':'')));
  b.addEventListener('click',()=>{active=r.source_sha256;clearPacketPreview();renderList();renderDetail();});
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
 const roleMsg=make('p',roleOverlap(r)?'Client and operator use the same UNVERIFIED coordinator label. Verify independent roles in authenticated systems.':'','hint');roleMsg.id='roleWarning';box.append(roleMsg);
 const message=make('p','Each “prepared” state means paperwork prepared only. No authenticated client/operator consent can be set here.','small');box.append(message);
 const scroll=make('div',undefined,'scroll'),table=make('table'),thead=make('thead'),tr=make('tr');
 for(const name of ['Preparation workstream','Paperwork state','Follow-up owner label','Target date','Next action / blocker'])tr.append(make('th',name));
 thead.append(tr);table.append(thead);
 const tbody=make('tbody');
 for(const [id,title,help] of STAGES){
  const task=r.tasks[id], row=make('tr'), titleCell=make('td');row.dataset.stageId=id;
  titleCell.append(make('strong',title),make('span',help,'small'));row.append(titleCell);
  const status=make('select');status.setAttribute('aria-label',title+' paperwork state');
  for(const [val,label] of [['todo','Not started'],['waiting','Waiting / blocked'],['prepared','Prepared — unverified']]){
   const option=make('option',label);option.value=val;option.selected=task.status===val;status.append(option);
  }
  status.addEventListener('change',()=>{task.status=status.value;setDirty();renderStats();renderList();});
  const stateCell=make('td');stateCell.append(status);row.append(stateCell);
  const owner=make('input');owner.type='text';owner.maxLength=80;owner.value=task.owner;owner.placeholder='Unverified coordinator';
  owner.setAttribute('aria-label',title+' owner label');
  owner.addEventListener('input',()=>{task.owner=owner.value;setDirty();renderStats();renderList();const msg=$('roleWarning');if(msg)msg.textContent=roleOverlap(r)?'Client and operator use the same UNVERIFIED coordinator label. Verify independent roles in authenticated systems.':'';});
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
 // Reuse only assignment logistics for a separately reviewed revision.
 // Never propagate prepared evidence, user identity, consent, or approval state.
 if(entries.length>1){
  const copyLabel=make('label','Carry only follow-up assignments from another draft');
  copyLabel.htmlFor='copyFrom';box.append(copyLabel);
  const choose=make('select');choose.id='copyFrom';
  const empty=make('option','Choose another untrusted draft');empty.value='';choose.append(empty);
  for(const other of entries){
   if(other===r)continue;
   const opt=make('option',other.name+' · '+other.source_sha256.slice(0,12));
   opt.value=other.source_sha256;choose.append(opt);
  }
  const transfer=make('button','Copy coordination fields only');
  transfer.type='button';
  transfer.addEventListener('click',()=>{
   const source=entries.find(item=>item.source_sha256===choose.value);
   if(!source||source===r)return;
   if(STAGES.some(([id])=>{
    const t=r.tasks[id];return t.status!=='todo'||t.owner||t.due||t.next_action;
   })){notice('Transfer HOLD: target already has coordination data. Preserve existing work; no overwrite.');return;}
   const changes=[];
   if(r.client_label!==source.client_label)changes.push('client label differs');
   if(r.requested_risk!==source.requested_risk)changes.push('risk changed');
   if(r.requested_mode!==source.requested_mode)changes.push('mode changed');
   if(r.asset_count!==source.asset_count||r.excluded_count!==source.excluded_count)changes.push('asset totals changed');
   const warning=changes.length?changes.join(', '):'source metadata totals appear similar (not a scope equality proof)';
   if(!confirm('Copy coordinator labels, planned target dates and next actions ONLY? All six target states remain NOT STARTED; no approvals or prepared evidence copied. '+warning+'.'))return;
   for(const [id] of STAGES){
    const t=source.tasks[id];
    r.tasks[id]={status:'todo',owner:t.owner,due:t.due,next_action:t.next_action};
   }
   setDirty();render();
   notice('Copied only follow-up logistics. All preparation states reset to NOT STARTED and require new human review.');
  });
  choose.setAttribute('aria-label','Source draft to copy coordination fields from');
  tools.append(choose,transfer);
 }
 const remove=make('button','Remove draft from local board');remove.type='button';
 remove.addEventListener('click',()=>{if(!confirm('Remove this local coordination draft? Source files are never changed.'))return;
 entries=entries.filter(x=>x!==r);sourceCopies.delete(r.source_sha256);active=entries[0]?.source_sha256||null;setDirty();render();});
 tools.append(remove);box.append(tools);
}
function render(){renderStats();renderList();renderDetail();renderRevisionSources();}
// Batch planner only fills missing paperwork logistics. Never updates states or authority.
const bulkInputs=['bulkStage','bulkAudience','bulkOwner','bulkDue','bulkNext'];
for(const name of bulkInputs)$(name).addEventListener('input',()=>clearBulkPreview('Inputs changed. Preview before applying.'));
$('bulkDiscard').addEventListener('click',()=>clearBulkPreview('Preview discarded; no work items changed.'));
function bulkSpec(){
 const stage=$('bulkStage').value,audience=$('bulkAudience').value;
 const owner=$('bulkOwner').value.trim(),due=$('bulkDue').value,next=$('bulkNext').value.trim();
 if(!STAGES.some(([id])=>id===stage)||!['visible','attached','all'].includes(audience))throw Error('Unknown batch scope.');
 if(!validText(owner,80)||!validText(next,350))throw Error('Invalid coordinator or next action.');
 if(!owner&&!due&&!next)throw Error('Enter a coordinator, date or next action first.');
 if(due){
  if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(due)||
     !Number.isFinite(Date.parse(due+'T00:00:00Z'))||
     new Date(due+'T00:00:00Z').toISOString().slice(0,10)!==due)throw Error('Invalid target date.');
 }
 return {stage,audience,owner,due,next};
}
function bulkCandidates(spec){
 const selected=spec.audience==='visible'?visibleQueue():
  spec.audience==='attached'?entries.filter(r=>r.source_attached):entries.slice();
 const planned=[];
 for(const r of selected){
  const task=r.tasks[spec.stage];if(task.status==='prepared')continue;
  const fills={};
  if(spec.owner&&!task.owner)fills.owner=spec.owner;
  if(spec.due&&!task.due)fills.due=spec.due;
  if(spec.next&&!task.next_action)fills.next_action=spec.next;
  if(Object.keys(fills).length)planned.push({r,fills});
 }
 return {selected,planned};
}
$('bulkPreview').addEventListener('click',()=>{
 clearBulkPreview();
 try{
  const spec=bulkSpec(),{selected,planned}=bulkCandidates(spec);
  if(!selected.length){$('bulkResult').textContent='No matching drafts; no assignments created.';return;}
  if(!planned.length){$('bulkResult').textContent='No empty eligible fields. Existing assignments and prepared states are preserved.';return;}
  bulkPlan={epoch:editEpoch,spec,planned};
  const fields=planned.reduce((sum,x)=>sum+Object.keys(x.fills).length,0);
  const held=planned.filter(x=>!x.r.source_attached).length;
  $('bulkResult').textContent='PREVIEW ONLY: '+planned.length+' draft(s), '+fields+
    ' empty field(s), '+held+' source-unbound HOLD(s). Prepared tasks and all existing values stay unchanged. Explicit confirmation required.';
  $('bulkApply').disabled=false;
 }catch(e){$('bulkResult').textContent='Batch HOLD: '+e.message;}
});
$('bulkApply').addEventListener('click',()=>{
 if(!bulkPlan||bulkPlan.epoch!==editEpoch){clearBulkPreview();return;}
 const {spec,planned}=bulkPlan;
 // Full all-or-nothing revalidation before any in-memory mutation.
 try{
  const now=bulkSpec(),current=bulkCandidates(now);
  if(JSON.stringify(now)!==JSON.stringify(spec)||current.planned.length!==planned.length||
   current.planned.some((x,i)=>x.r!==planned[i].r||JSON.stringify(x.fills)!==JSON.stringify(planned[i].fills)))throw Error('Queue or field selection changed.');
  if(!confirm('Apply '+planned.length+' coordination-only assignments? This fills EMPTY fields and does not change any paperwork status, authenticated consent, decision or grant.'))return;
  const snapshots=planned.map(({r,fills})=>({
   r,original:{...r.tasks[spec.stage]},applied:{...r.tasks[spec.stage],...fills}
  }));
  for(const {r,fills} of planned)Object.assign(r.tasks[spec.stage],fills);
  const count=planned.length;
  setDirty();
  bulkUndo={epoch:editEpoch,stage:spec.stage,snapshots};$('bulkUndo').disabled=false;
  render();$('bulkResult').textContent='Applied to '+count+' preparation entries. Undo remains available until the next edit. No approval, consent or authorization changed.';
 }catch(e){clearBulkPreview('Batch HOLD: '+e.message+' No changes made.');}
});

$('bulkUndo').addEventListener('click',()=>{
 if(!bulkUndo||bulkUndo.epoch!==editEpoch){$('bulkUndo').disabled=true;return;}
 const {stage,snapshots}=bulkUndo;
 if(!snapshots.every(({r,applied})=>entries.includes(r)&&
  JSON.stringify(r.tasks[stage])===JSON.stringify(applied))){
  bulkUndo=null;$('bulkUndo').disabled=true;
  $('bulkResult').textContent='Undo HOLD: data has changed; do not overwrite newer coordination work.';
  return;
 }
 if(!confirm('Undo the last '+snapshots.length+' coordination-only batch? This restores previous paperwork fields but never changes approval/consent/grant state.'))return;
 for(const {r,original} of snapshots)r.tasks[stage]={...original};
 const count=snapshots.length;
 setDirty();render();
 $('bulkResult').textContent='Reverted '+count+' batch assignments to their original local paperwork fields. Review and save the workspace.';
});
const PACKET_STAGES={
 client:['client_evidence','client_consent'],
 operator:['scope_boundary','operator_review','window_stop','privacy_handoff']
};
function packetSelection(scope){
 if(scope==='current')return entries.filter(r=>r.source_sha256===active);
 if(scope==='visible')return visibleQueue();
 if(scope==='all')return entries.slice();
 throw Error('Unsupported packet selection.');
}
function mdText(value){
 // Treat untrusted user labels/notes as text, never as a trusted Markdown instruction.
 return String(value??'').replace(/[\\r\\n\\t]+/g,' ').replace(/[\\u0000-\\u001f\\u007f]/g,' ')
  .replace(/([\\\\`*_{}\\[\\]<>#!|])/g,'\\$1').slice(0,450);
}
function makePacket(audience,selected){
 const labels=audience==='client'?['Ownership evidence','Client coordination — not consent']:
  ['Exact scope and exclusions','Independent operator preparation — not approval','Risk/window/STOP','Privacy and incident handoff'];
 const keys=PACKET_STAGES[audience];
 const lines=[
  '# LightUp · Private '+(audience==='client'?'client':'operator')+' preparation request',
  '',
  '**DRAFT/HOLD · REVIEW_ONLY · NON-AUTHORIZING.**',
  'This offline note is for requesting missing paperwork only. It is neither a signed request nor verified permission.',
  'Authenticated client consent: FALSE. Authenticated operator approval: FALSE. Risk approval: FALSE.',
  'Grant: FALSE. Action-time revocation checked: FALSE. Scan: FALSE. Execution: FALSE. Release: FALSE.',
  '',
  'Source drafts: '+selected.length+' · Source hashes are unsigned local file-continuity hints.',
  ''
 ];
 let unresolvedCount=0, unbound=0;
 for(let i=0;i<selected.length;i++){
  const r=selected[i];if(!r.source_attached)unbound++;
  lines.push('## '+(i+1)+'. '+mdText(r.name||'Untitled source draft'));
  lines.push('Original source SHA-256 (unsigned): '+r.source_sha256);
  lines.push('Local source custody: '+(r.source_attached?'ATTACHED IN CURRENT SESSION':'UNBOUND · RE-ATTACH SOURCE · HOLD'));
  lines.push('Risk requested (unapproved): '+r.requested_risk);
  if(audience==='operator')lines.push('Proposed UTC window (not booked): '+(r.planned_utc?
    r.planned_utc.start+' to '+r.planned_utc.end:'unresolved / not supplied'));
  lines.push('');
  for(let k=0;k<keys.length;k++){
   const task=r.tasks[keys[k]];
   if(task.status==='prepared'){
    lines.push('- '+labels[k]+': preparatory paperwork marked prepared but **UNVERIFIED**. No actual approval implied.');
    continue;
   }
   unresolvedCount++;
   lines.push('- **'+labels[k]+'** — '+(task.status==='waiting'?'blocked / waiting':'not started'));
   lines.push('  - Requested next action: '+mdText(task.next_action||'Please coordinate the relevant human review.'));
   if(task.due)lines.push('  - Suggested paperwork target: '+task.due+' (not a scheduled assessment).');
  }
  lines.push('');
 }
 lines.push('---','This document never creates or records consent, verified ownership, authenticated identity, grant, release or permission for real target contact.');
 lines.push('Send only through independently approved channels, after manually checking recipients and private content.','');
 return {text:lines.join('\\n'),unresolvedCount,unbound};
}
for(const id of ['packetAudience','packetScope'])$(id).addEventListener('change',()=>clearPacketPreview('Recipient or selection changed; preview again.'));
$('packetDiscard').addEventListener('click',()=>clearPacketPreview('Packet discarded. No records changed.'));
$('packetPreview').addEventListener('click',()=>{
 clearPacketPreview();
 try{
  const audience=$('packetAudience').value,scope=$('packetScope').value;
  if(!Object.prototype.hasOwnProperty.call(PACKET_STAGES,audience))throw Error('Unknown recipient.');
  const selected=packetSelection(scope);
  if(!selected.length)throw Error('Select or import source drafts first.');
  const built=makePacket(audience,selected);
  packetDraft={epoch:editEpoch,audience,scope,digests:selected.map(r=>r.source_sha256),text:built.text};
  $('packetText').textContent=built.text;
  $('packetStatus').textContent='LOCAL PREVIEW: '+selected.length+' draft(s), '+built.unresolvedCount+
   ' open preparation requests, '+built.unbound+' source-unbound HOLD(s). Check text and recipient before exporting.';
  $('packetDownload').disabled=false;
 }catch(e){$('packetStatus').textContent='Packet HOLD: '+e.message;}
});
$('packetDownload').addEventListener('click',()=>{
 if(!packetDraft||packetDraft.epoch!==editEpoch){clearPacketPreview();return;}
 const {audience,scope,digests,text}=packetDraft;
 if(audience!==$('packetAudience').value||scope!==$('packetScope').value||
  JSON.stringify(packetSelection(scope).map(r=>r.source_sha256))!==JSON.stringify(digests)){
  clearPacketPreview('Selection changed; recompute packet.');return;
 }
 if(!confirm('Download this PRIVATE, UNSIGNED '+audience+' follow-up note? Review recipient and any user-entered action text manually. This is NOT authenticated consent, approval or authority.'))return;
 download('lightup-'+audience+'-paperwork-request-private.md',text+'\\n','text/markdown;charset=utf-8');
 $('packetStatus').textContent='Private local Markdown saved. No message sent and no authentication/grant state changed.';
});
// Privacy-minimal local calendar TASKS, not assessment events or bookings.
$('todoExport').addEventListener('click',()=>{
 try{
  const selected=packetSelection($('todoScope').value);
  if(!selected.length)throw Error('Choose at least one local draft.');
  if(!globalThis.crypto||!crypto.getRandomValues)throw Error('Secure random identifiers unavailable in this browser.');
  const dueTasks=[];
  for(let i=0;i<selected.length;i++)for(const [id] of STAGES){
   const t=selected[i].tasks[id];
   if(t.status==='prepared'||!t.due)continue;
   if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(t.due)||
      new Date(t.due+'T00:00:00Z').toISOString().slice(0,10)!==t.due)throw Error('Invalid target date.');
   dueTasks.push({draftOrdinal:i+1,id,due:t.due,unbound:!selected[i].source_attached});
  }
  if(!dueTasks.length)throw Error('No incomplete paperwork tasks with target dates in this selection.');
  if(dueTasks.length>120)throw Error('Workload exceeds 120 calendar task limit.');
  const missing=dueTasks.filter(t=>t.unbound).length;
  if(!confirm('Export '+dueTasks.length+' PRIVATE task deadlines, including '+missing+
   ' source-unbound HOLD(s)? Only anonymous paperwork labels and due dates are included. Do not mistake these tasks for scheduled assessments or import into an unapproved shared calendar.'))return;
  const stages={
   client_evidence:'Client ownership paperwork',
   scope_boundary:'Scope boundary paperwork',
   client_consent:'Client coordination paperwork',
   operator_review:'Operator review paperwork',
   window_stop:'Risk and STOP paperwork',
   privacy_handoff:'Evidence privacy paperwork'
  };
  const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\\.\\d{3}Z$/,'Z');
  const rows=['BEGIN:VCALENDAR','VERSION:2.0','CALSCALE:GREGORIAN',
   'PRODID:-//LightUp//Private Paperwork VTODO//EN','X-WR-CALNAME:LightUp Paperwork NOT Assessment Booking'];
  for(const task of dueTasks){
   const entropy=crypto.getRandomValues(new Uint8Array(16));
   const uid=Array.from(entropy,x=>x.toString(16).padStart(2,'0')).join('')+'@lightup-paperwork.invalid';
   rows.push('BEGIN:VTODO','UID:'+uid,'DTSTAMP:'+stamp,
    'DUE;VALUE=DATE:'+task.due.replaceAll('-',''),'STATUS:NEEDS-ACTION','CLASS:PRIVATE',
    'SUMMARY:LightUp paperwork '+task.draftOrdinal+' - '+stages[task.id],
    'DESCRIPTION:PREPARATION ONLY. DRAFT HOLD. NO CONSENT APPROVAL GRANT OR SCAN.',
    'X-LIGHTUP-AUTHORIZATION:FALSE','X-LIGHTUP-CONSENT:FALSE','END:VTODO');
  }
  rows.push('END:VCALENDAR');
  download('lightup-private-paperwork-tasks.ics',rows.join('\\r\\n')+'\\r\\n','text/calendar;charset=utf-8');
  $('todoStatus').textContent='Downloaded '+dueTasks.length+' anonymous, PRIVATE VTODO tasks ('+missing+
   ' source-unbound). No client/asset data, assessment bookings or online sync.';
 }catch(e){$('todoStatus').textContent='VTODO HOLD: '+e.message;}
});
function download(name,data,type){
 const url=URL.createObjectURL(new Blob([data],{type}));
 const a=make('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1200);
}
async function addSource(file){
 if(!file||file.size>MAX_FILE||!file.size)throw Error('Source file must be 1–65536 bytes.');
 const {bytes,text}=await readSourceBytes(file), obj=parseJSON(text);
 if(!validDraft(obj))throw Error('Not a safe Studio v1 DRAFT_ONLY source.');
 const digest=await sha(bytes);
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
   const {bytes,text}=await readSourceBytes(file),d=parseJSON(text);
   if(!validDraft(d))throw Error('One source is not a safe Studio v1 DRAFT_ONLY.');
   incoming.push({d,digest:await sha(bytes)});
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
   sourceCopies.set(x.digest,x.d);
  }
  active=incoming[0].digest;setDirty();render();notice('Loaded '+incoming.length+' local source file(s). Every task remains non-authorizing.');
 }catch(e){notice('Import HOLD: '+e.message+' Existing board preserved.');}
});
async function readPrivateWorkspace(file){
 if(!file||!file.size||file.size>MAX_WORKSPACE)throw Error('Workspace file must be 1–262144 bytes.');
 const {text}=await readSourceBytes(file);
 const parsed=parseJSON(text);
 if(Object.keys(parsed).some(k=>!['kind','schema_version','disposition','security','exported_at_utc','records','notice'].includes(k)))throw Error('Unknown or authority-like workspace fields.');
 if(parsed.kind!=='lightup.scope_readiness_workspace'||parsed.schema_version!==1||parsed.disposition!=='REVIEW_ONLY'||
    !allowedFlags(parsed.security)||!Array.isArray(parsed.records)||parsed.records.length>MAX_RECORDS)throw Error('Unsupported or unsafe workspace schema.');
 const next=parsed.records.map(r=>cleanRecord(r,{restored:true}));
 if(next.some(r=>!r)||new Set(next.map(r=>r.source_sha256)).size!==next.length)throw Error('Invalid, duplicated or malformed source-bound record.');
 return next;
}
function mergeAnalysis(incoming){
 const original=new Map(entries.map(r=>[r.source_sha256,r]));
 const newRecords=[],conflicts=[];let identical=0;
 for(const row of incoming){
  const existing=original.get(row.source_sha256);
  if(!existing){newRecords.push(row);continue;}
  const current=cleanRecord(existing);
  if(!current||JSON.stringify(current)!==JSON.stringify(row)){
   const metadata=['name','client_label','requested_mode','requested_risk','asset_count','excluded_count','planned_utc']
    .filter(k=>!current||JSON.stringify(current[k])!==JSON.stringify(row[k]));
   const workstreams=STAGES.filter(([id])=>!current||JSON.stringify(current.tasks[id])!==JSON.stringify(row.tasks[id]))
    .map(([,title])=>title);
   conflicts.push({digest:row.source_sha256.slice(0,16),metadata,workstreams});
  }
  else identical++;
 }
 if(entries.length+newRecords.length>MAX_RECORDS)throw Error('Merged register exceeds 20 distinct source revisions.');
 return {newRecords,conflicts,identical};
}
$('mergeDiscard').addEventListener('click',()=>clearMergePreview('Merge preview discarded. Current workspace unchanged.'));
$('mergeInput').addEventListener('change',async event=>{
 const file=event.target.files[0];event.target.value='';clearMergePreview();
 if(!file)return;
 try{
  const incoming=await readPrivateWorkspace(file);
  const summary=mergeAnalysis(incoming);
  if(summary.conflicts.length){
   $('mergeStatus').textContent='Merge HOLD: '+summary.conflicts.length+
    ' same-source records differ. Differences are categorized below without showing private field values. No records changed.';
   const list=$('mergeConflicts');
   for(const issue of summary.conflicts){
    const parts=['Source '+issue.digest+'…'];
    if(issue.metadata.length)parts.push('Changed proposal metadata fields: '+issue.metadata.join(', '));
    if(issue.workstreams.length)parts.push('Changed paperwork stages: '+issue.workstreams.join('; '));
    list.append(make('li',parts.join(' — ')));
   }
   return;
  }
  if(!summary.newRecords.length){$('mergeStatus').textContent='Nothing new to merge. '+summary.identical+' source record(s) already identical.';return;}
  mergePlan={epoch:editEpoch,incoming};
  $('mergeApply').disabled=false;
  $('mergeStatus').textContent='PREVIEW ONLY: add '+summary.newRecords.length+' new source-unbound draft(s), '+
   summary.identical+' already identical, no conflicts. Existing assignments will never be overwritten.';
 }catch(e){$('mergeStatus').textContent='Merge HOLD: '+e.message+' Current workspace unchanged.';}
});
$('mergeApply').addEventListener('click',()=>{
 if(!mergePlan||mergePlan.epoch!==editEpoch){clearMergePreview();return;}
 try{
  const summary=mergeAnalysis(mergePlan.incoming);
  if(summary.conflicts.length||!summary.newRecords.length)throw Error('Merge changed; preview again.');
  if(!confirm('Add '+summary.newRecords.length+' private draft register(s) as SOURCE-UNBOUND? '+
   'Existing records, source attachments, coordinator notes, paperwork status and all authority flags remain unchanged.'))return;
  entries=[...entries,...summary.newRecords];
  if(!active)active=summary.newRecords[0].source_sha256;
  const count=summary.newRecords.length;
  setDirty();render();
  $('mergeStatus').textContent='Merged '+count+' review-only records. New sources remain UNBOUND pending exact original-file reattachment.';
 }catch(e){clearMergePreview('Merge HOLD: '+e.message);}
});
$('restoreInput').addEventListener('change',async event=>{
 const file=event.target.files[0];event.target.value='';if(!file)return;
 try {
  const next=await readPrivateWorkspace(file);
  if(entries.length&&!confirm('Replace your current in-memory board? Save it first if needed.'))return;
  entries=next;sourceCopies.clear();active=entries[0]?.source_sha256||null;dirty=false;editEpoch++;clearMergePreview();bulkUndo=null;$('bulkUndo').disabled=true;clearBulkPreview();clearPacketPreview();render();
  notice('Restored tracking only. Studio source files deliberately remain UNBOUND until exact SHA-256 re-attachment. ALL authorization flags false.');
 }catch(e){notice('Restore HOLD: '+e.message+' Existing board unchanged.');}
});
$('filter').addEventListener('change',()=>{clearBulkPreview();clearPacketPreview();renderList();});
$('sort').addEventListener('change',renderList);
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
 entries=[];sourceCopies.clear();active=null;dirty=false;editEpoch++;clearMergePreview();bulkUndo=null;$('bulkUndo').disabled=true;clearBulkPreview();clearPacketPreview();$('sourceUpload').value='';$('restoreInput').value='';render();notice('Memory cleared. No source records changed.');
});
window.addEventListener('beforeunload',event=>{if(dirty&&entries.length){event.preventDefault();event.returnValue='';}});
render();
})();
