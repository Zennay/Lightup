/* LightUp PRIVATE Evidence Follow-up Desk.
 * HUMAN planning only. This module can read but never write source-owner Casework,
 * Evidence Review, target/network APIs, scans, retests or authorization. */
(function(){
'use strict';
const B=window.LightUpArtifactLedgerBridge;
if(!B)throw Error('Original source-bound Artifact Ledger bridge required.');
const $=id=>document.getElementById(id);
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const KINDS=['missing_evidence','patch_change','deployment_record','rollback_plan','retest_request','followup_question','other'];
const STAGES=['draft','requested_human','submitted_unverified','needs_changes','closed_human'];
const MAX_ROWS=200,MAX_BATCH=40,MAX_FILE=1048576;
const FIELDS=['request_id','finding_id','request_kind','assignee','due_date','instructions','linked_sha256','human_stage','human_response','created_utc','updated_utc'];
const state={binding:null,requests:[],preview:null,ownerReplyPending:null,filter:'open'};
function problem(t){throw Error(t);}
function alert(t,error=false){$('requestMessage').textContent=t;$('requestMessage').dataset.error=String(error);}
function exactKeys(o,keys){
 return o&&Object.getPrototypeOf(o)===Object.prototype&&
 Object.keys(o).length===keys.length&&Object.keys(o).every(x=>keys.includes(x));
}
function str(s,max,name,required=false){
 if(typeof s!=='string'||s.length>max||s.includes('\0')||
   /[\u202a-\u202e\u2066-\u2069]/.test(s)||(required&&!s.trim()))problem('Invalid PRIVATE '+name+'.');
 return s;
}
function date(d){
 if(d==='')return '';
 if(typeof d!=='string'||!/^\d{4}-\d\d-\d\d$/.test(d)||!Number.isFinite(Date.parse(d+'T00:00:00Z'))||
   new Date(d+'T00:00:00Z').toISOString().slice(0,10)!==d)problem('Invalid HUMAN follow-up date.');
 return d;
}
function stamp(d){
 if(typeof d!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(d)||Number.isNaN(Date.parse(d)))
  problem('Invalid local HUMAN timestamp.');
 return d;
}
function bindingFor(c){return {source_sha256:c.sha,client_reference:c.client,engagement_reference:c.engagement};}
function same(c){
 return Boolean(c.sha&&state.binding&&c.sha===state.binding.source_sha256&&
   c.client===state.binding.client_reference&&c.engagement===state.binding.engagement_reference);
}
function current(require=true){
 const c=B.context();
 if(require&&!same(c))problem('PRIVATE human requests are bound to a different original source or context. Export OLD notes and start a new workspace.');
 return c;
}
function fingerprintsFor(c,id){return new Set(c.artifacts.filter(a=>a.finding_id===id).map(a=>a.sha256));}
function validate(row,c){
 if(!exactKeys(row,FIELDS))problem('Invalid HUMAN evidence request fields.');
 const ids=new Set(c.findings.map(x=>x.finding_id));
 if(!ids.has(row.finding_id))problem('HUMAN request references an absent original finding.');
 if(!/^[0-9a-f]{32}$/.test(row.request_id))problem('Invalid local request ID.');
 if(!KINDS.includes(row.request_kind)||!STAGES.includes(row.human_stage))problem('Invalid HUMAN request type/stage.');
 str(row.assignee,120,'assignee');
 str(row.instructions,1400,'instructions',true);str(row.human_response,1800,'response');
 date(row.due_date);stamp(row.created_utc);stamp(row.updated_utc);
 if(row.linked_sha256!==''&&!/^[0-9a-f]{64}$/.test(row.linked_sha256))
   problem('Invalid local file fingerprint reference.');
 return {...row};
}
function nonce(){
 if(!crypto||!crypto.getRandomValues)problem('Secure local ID generator is unavailable.');
 const b=crypto.getRandomValues(new Uint8Array(16));
 return [...b].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function packet(){
 if(!state.binding)problem('No private request source loaded.');
 return {kind:'lightup.private_human_evidence_requests',schema_version:1,
  disposition:'UNVERIFIED_HUMAN_FOLLOW_UP_ONLY',
  source_contract:'lightup.finding_export._COLUMNS_v1',...state.binding,
  ...Object.fromEntries(FLAGS.map(k=>[k,false])),
  requests:state.requests.map(r=>({...r})),
  warning:'Unverified local human follow-up planning. This does NOT grant testing consent, execution authority, verified retest or evidence authenticity.'};
}
function exportPrivate(){
 if(!state.binding)problem('Load original source before creating a private request draft.');
 if(!confirm('Download PRIVATE source-bound HUMAN request IDs, assignee aliases, context references, notes and file SHA hashes? Confirm private recipient and storage independently.'))return;
 B.download('LightUp-PRIVATE-human-evidence-requests.json',JSON.stringify(packet(),null,2)+'\n','application/json');
}
function fileText(file){
 if(!file||file.size>MAX_FILE)problem('Private human request packet exceeds 1 MiB.');
 return file.text();
}
async function importPrivate(){
 const c=current();
 const source=JSON.stringify(bindingFor(c)),before=JSON.stringify(state.requests);
 const raw=B.strictJSON(await fileText($('requestImport').files[0]),MAX_FILE);
 const expected=['kind','schema_version','disposition','source_contract','source_sha256',
  'client_reference','engagement_reference',...FLAGS,'requests','warning'];
 if(!exactKeys(raw,expected)||raw.kind!=='lightup.private_human_evidence_requests'||
 raw.schema_version!==1||raw.disposition!=='UNVERIFIED_HUMAN_FOLLOW_UP_ONLY'||
 raw.source_contract!=='lightup.finding_export._COLUMNS_v1'||FLAGS.some(k=>raw[k]!==false)||
 raw.source_sha256!==c.sha||raw.client_reference!==c.client||
 raw.engagement_reference!==c.engagement||!Array.isArray(raw.requests)||
 raw.requests.length>MAX_ROWS||typeof raw.warning!=='string'||raw.warning.length>600)
  problem('Original PRIVATE request source, context, format or non-authority flags disagree.');
 const ids=new Set(),rows=raw.requests.map(x=>{const y=validate(x,c);
  if(ids.has(y.request_id))problem('Repeated original HUMAN request identity.');
  ids.add(y.request_id);return y;
 });
 if(!same(B.context())||JSON.stringify(bindingFor(B.context()))!==source||
    JSON.stringify(state.requests)!==before)problem('Source or local HUMAN requests changed during private import.');
 if(!confirm('Replace ALL '+state.requests.length+' current PRIVATE human requests with '+rows.length+' original source-bound request records? Keep your old PRIVATE export separately.'))return;
 state.requests=rows;state.preview=null;state.ownerReplyPending=null;$('requestImport').value='';render();
 alert('Imported '+rows.length+' PRIVATE HUMAN requests for identical original source. No retest or authorization inferred.');
}
function make(id,kind,assignee,due,instructions,linked=''){
 const c=current();
 const now=new Date().toISOString();
 return validate({request_id:nonce(),finding_id:id,request_kind:kind,assignee,
  due_date:due,instructions,linked_sha256:linked,human_stage:'draft',
  human_response:'',created_utc:now,updated_utc:now},c);
}
function createOne(){
 const c=current();
 if(state.requests.length>=MAX_ROWS)problem('PRIVATE human request desk limit is 200.');
 const id=$('requestFinding').value,kind=$('requestKind').value;
 const assignee=str($('requestAssignee').value.trim(),120,'assignee');
 const due=date($('requestDue').value);
 const instructions=str($('requestInstructions').value.trim(),1400,'instructions',true);
 const linked=$('requestLinkFile').value;
 if(linked&&!fingerprintsFor(c,id).has(linked))problem('Selected file fingerprint is not registered under this original finding.');
 state.requests.push(make(id,kind,assignee,due,instructions,linked));
 state.preview=null;render();alert('Drafted PRIVATE HUMAN evidence request for original finding '+id+'. No network or retest.');
}
function selectableBatch(c,mode){
 const artifactIds=new Set(c.artifacts.map(a=>a.finding_id));
 const cases=new Map((c.casework||[]).map(x=>[x.finding_id,x]));
 const reviews=new Map((c.evidence||[]).map(x=>[x.finding_id,x]));
 const active=new Set(state.requests.filter(x=>x.human_stage!=='closed_human').map(x=>x.finding_id));
 return c.findings.filter(f=>{
  if(active.has(f.finding_id))return false;
  if(mode==='critical_unlinked')return (f.severity==='critical'||f.severity==='high')&&!artifactIds.has(f.finding_id);
  if(mode==='all_unlinked')return !artifactIds.has(f.finding_id);
  if(mode==='review_followup')return reviews.has(f.finding_id)&&
    ['missing','needs_changes'].includes(reviews.get(f.finding_id).stage);
  if(mode==='casework_blocked')return cases.has(f.finding_id)&&
    (cases.get(f.finding_id).status==='blocked'||Boolean(cases.get(f.finding_id).blocker));
  return false;
 }).slice(0,MAX_BATCH);
}
function makeBatchPreview(){
 const c=current(),mode=$('requestBatchMode').value;
 const cases=new Map((c.casework||[]).map(x=>[x.finding_id,x]));
 const found=selectableBatch(c,mode);
 if(!found.length)problem('No eligible original findings for that local HUMAN follow-up batch.');
 if(state.requests.length+found.length>MAX_ROWS)problem('Adding this human batch would exceed 200 records.');
 const kind=$('requestBatchKind').value;
 if(!KINDS.includes(kind))problem('Invalid human follow-up request type.');
 const text=str($('requestBatchInstructions').value.trim(),1400,'batch instructions',true);
 const due=date($('requestBatchDue').value);
 state.preview={source:JSON.stringify(bindingFor(c)),baseline:JSON.stringify(state.requests),
  keys:found.map(f=>f.finding_id),kind,text,due,
  rows:found.map(f=>({id:f.finding_id,severity:f.severity,assignee:cases.get(f.finding_id)?.owner||''}))};
 $('requestBatchPreview').textContent=['PRIVATE HUMAN batch review · '+found.length+' original source-bound requests',
  'Original SHA-256: '+c.sha,'Type: '+kind,'HUMAN suggested date: '+(due||'none'),
  'Assignees are unverified original Casework human owners.',
  ...state.preview.rows.map(x=>x.id+' / '+x.severity+' / '+(x.assignee||'unassigned')),
  'All external follow-up still requires a separately verified and approved human channel. No requests were sent.'].join('\n');
 $('requestBatchPreview').hidden=false;$('requestBatchApply').disabled=false;
 alert('Review '+found.length+' original finding IDs before creating PRIVATE HUMAN follow-up drafts.');
}
function applyBatch(){
 const c=current(),p=state.preview;
 if(!p)problem('No current HUMAN request batch proposal.');
 if(p.source!==JSON.stringify(bindingFor(c))||p.baseline!==JSON.stringify(state.requests)||
  p.keys.join('\n')!==selectableBatch(c,$('requestBatchMode').value).map(f=>f.finding_id).join('\n')||
  p.kind!==$('requestBatchKind').value||
  p.text!==$('requestBatchInstructions').value.trim()||p.due!==$('requestBatchDue').value)
  problem('Original findings, HUMAN request inventory or proposal changed. Preview again.');
 if(!confirm('Create '+p.rows.length+' PRIVATE human-only evidence follow-up drafts? No client contact, retest, scans or execution will occur.'))return;
 const staged=p.rows.map(x=>make(x.id,p.kind,str(x.assignee,120,'assignee'),p.due,p.text));
 state.requests.push(...staged);state.preview=null;
 $('requestBatchPreview').hidden=true;$('requestBatchApply').disabled=true;
 render();alert('Created '+staged.length+' PRIVATE HUMAN follow-up drafts; nothing sent or authorized.');
}
function forget(){
 if(!state.binding)return;
 if(!confirm('Discard '+state.requests.length+' LOCAL HUMAN request records and bind the desk to the currently loaded original source? Protect any prior PRIVATE exported handoff first.'))return;
 const c=B.context();state.binding=c.sha?bindingFor(c):null;
 state.requests=[];state.preview=null;state.ownerReplyPending=null;render();alert('Private request desk started fresh for current original source.');
}
function tag(name,text){
 const t=document.createElement(name);t.textContent=text;return t;
}
function field(parent,name,initial,max){
 const label=tag('label',name),input=document.createElement('textarea');
 input.value=initial;input.maxLength=max;input.rows=2;label.append(input);parent.append(label);return input;
}

/* Privacy-minimal, owner-specific HUMAN response handoff. A reply is untrusted
   human text; no identity proof, assessment execution, retest or grant. */
const OWNER_KEYS=['kind','schema_version','disposition','source_contract','source_sha256',
 'client_reference','engagement_reference','recipient_alias','reply_kind','issued_utc',
 'reply_utc','requests',...FLAGS];
const OWNER_ROW=['request_id','finding_id','request_kind','instructions','due_date','human_stage','human_response'];
function ownerPacketFor(alias){
 const c=current();
 const all=state.requests.filter(r=>r.assignee===alias&&r.human_stage!=='closed_human');
 const page=Number($('ownerPacketPage').value||0);
 if(!alias||!all.length||!Number.isSafeInteger(page)||page<0||page%60!==0||page>=all.length)
  problem('Select an existing ORIGINAL HUMAN owner request packet page.');
 const originals=all.slice(page,page+60);
 return {kind:'lightup.private_human_evidence_owner_handoff',schema_version:1,
  disposition:'UNVERIFIED_HUMAN_REQUEST_ONLY',source_contract:'lightup.finding_export._COLUMNS_v1',
  source_sha256:c.sha,client_reference:c.client,engagement_reference:c.engagement,
  recipient_alias:alias,reply_kind:'owner_request',issued_utc:new Date().toISOString(),
  reply_utc:null,...Object.fromEntries(FLAGS.map(x=>[x,false])),
  requests:originals.map(r=>({request_id:r.request_id,finding_id:r.finding_id,
   request_kind:r.request_kind,instructions:r.instructions,due_date:r.due_date,
   human_stage:'requested_human',human_response:''}))
 };
}
function exportOwnerPacket(){
 const c=current(),alias=$('requestOwner').value;
 const packet=ownerPacketFor(alias);
 if(!confirm('Export '+packet.requests.length+' PRIVATE owner-specific HUMAN evidence requests for "'+
  alias+'"? This shares no full Casework, file contents, filenames, SHA fingerprints or other owners. The recipient and secure channel are NOT authenticated by this application.'))return;
 const part=1+Number($('ownerPacketPage').value||0)/60;
 B.download('LightUp-PRIVATE-human-owner-request-part-'+part+'.json',JSON.stringify(packet,null,2)+'\n','application/json');
 alert('Exported owner-specific PRIVATE HUMAN request packet for '+alias+'. No request has been delivered or marked authorized.');
}
function admitOwnerReply(data,c){
 if(!exactKeys(data,OWNER_KEYS)||data.kind!=='lightup.private_human_evidence_owner_handoff'||
 data.schema_version!==1||data.disposition!=='UNVERIFIED_HUMAN_REQUEST_ONLY'||
 data.source_contract!=='lightup.finding_export._COLUMNS_v1'||
 data.source_sha256!==c.sha||data.client_reference!==c.client||
 data.engagement_reference!==c.engagement||FLAGS.some(k=>data[k]!==false)||
 data.reply_kind!=='unverified_human_reply'||typeof data.recipient_alias!=='string'||
 !data.recipient_alias.trim()||data.recipient_alias.length>120||
 !Array.isArray(data.requests)||data.requests.length<1||data.requests.length>60||
 typeof data.reply_utc!=='string')
  problem('PRIVATE reply sheet format/source or all-false authority envelope invalid.');
 stamp(data.issued_utc);stamp(data.reply_utc);
 const alias=data.recipient_alias;
 const seen=new Set(),updates=[];
 for(const row of data.requests){
  if(!exactKeys(row,OWNER_ROW))problem('Unknown HUMAN reply fields.');
  if(typeof row.request_id!=='string'||seen.has(row.request_id))problem('Repeated HUMAN response request ID.');
  seen.add(row.request_id);
  const original=state.requests.find(x=>x.request_id===row.request_id);
  if(!original||original.assignee!==alias||
    original.finding_id!==row.finding_id||original.request_kind!==row.request_kind||
    original.instructions!==row.instructions||original.due_date!==row.due_date)
   problem('Human reply has stale, changed, cross-owner or unknown ORIGINAL request context.');
  if(!['submitted_unverified','needs_changes'].includes(row.human_stage))
   problem('Owner reply must be submitted_unverified or needs_changes, never authorizing or closed.');
  str(row.human_response,1800,'HUMAN reply',true);
  updates.push({request_id:row.request_id,finding_id:row.finding_id,
   previous_stage:original.human_stage,next_stage:row.human_stage,
   previous_text:original.human_response,next_text:row.human_response});
 }
 return {alias,updates};
}
async function previewOwnerReply(){
 const c=current(),start=JSON.stringify(bindingFor(c)),
   baseline=JSON.stringify(state.requests);
 const data=B.strictJSON(await fileText($('ownerReplyImport').files[0]),MAX_FILE);
 const admitted=admitOwnerReply(data,c);
 if(start!==JSON.stringify(bindingFor(B.context()))||
  baseline!==JSON.stringify(state.requests)||!same(B.context()))
  problem('ORIGINAL source or HUMAN request baseline changed while reading owner reply.');
 state.ownerReplyPending={source:start,baseline,rows:admitted.updates,alias:admitted.alias};
 $('ownerReplyPreview').textContent=[
  'PRIVATE HUMAN owner response preview — NOT identity-authenticated',
  'Owner alias (unverified): '+admitted.alias,'Original source SHA-256: '+c.sha,
  'Request replies: '+admitted.updates.length,
  ...admitted.updates.map(x=>x.finding_id+' / '+x.request_id.slice(0,12)+
   ' · '+x.previous_stage+' → '+x.next_stage+
   ' · previous human response '+x.previous_text.length+' chars, new '+x.next_text.length+' chars'),
  'Import NEVER proves identity, permission, remediation or retest; confirm sender out of band.'
 ].join('\n');
 $('ownerReplyPreview').hidden=false;$('ownerReplyApply').disabled=false;
 $('ownerReplyImport').value='';
 alert('Owner-specific HUMAN reply staged, nothing applied. Independently verify its actual sender.');
}
function applyOwnerReply(){
 const p=state.ownerReplyPending,c=current();
 if(!p)problem('Preview an independently obtained HUMAN owner reply first.');
 if(p.source!==JSON.stringify(bindingFor(c))||p.baseline!==JSON.stringify(state.requests))
  problem('ORIGINAL source or HUMAN request records changed after reply preview.');
 if(!confirm('Apply '+p.rows.length+' UNVERIFIED HUMAN responses allegedly from "'+
   p.alias+'"? This does not authenticate the respondent, grant execution or verify remediation.'))return;
 const now=new Date().toISOString(),changes=new Map(p.rows.map(r=>[r.request_id,r]));
 for(const row of state.requests){
  const newData=changes.get(row.request_id);
  if(newData){row.human_stage=newData.next_stage;row.human_response=newData.next_text;row.updated_utc=now;}
 }
 state.ownerReplyPending=null;state.preview=null;
 $('ownerReplyPreview').hidden=true;$('ownerReplyApply').disabled=true;render();
 alert('Applied '+p.rows.length+' UNVERIFIED HUMAN replies to original-source PRIVATE drafts. No authentic identity or retest claim.');
}

function render(){
 const c=B.context();
 if(c.sha&&!state.binding)state.binding=bindingFor(c);
 const lock=!same(c);
 $('requestBound').textContent=state.binding?
  'Human request source SHA: '+state.binding.source_sha256+
  (lock?' · DIFFERENT ORIGINAL SOURCE — old private requests are locked until explicit reset':' · matches current original source'):
  'Import an independently checked original findings CSV first.';
 $('requestBound').dataset.error=String(lock&&!!state.binding);
 const enabled=Boolean(c.sha&&!lock);
 for(const id of ['requestFinding','requestKind','requestAssignee','requestDue',
   'requestInstructions','requestLinkFile','requestCreate','requestImport',
   'requestImportButton','requestBatchMode','requestBatchKind',
   'requestBatchInstructions','requestBatchDue','requestBatchPreviewButton'])
  $(id).disabled=!enabled;
 const currentOwner=$('requestOwner').value,previousOwnerPage=$('ownerPacketPage').value;
 $('requestOwner').replaceChildren();
 $('requestOwner').append(new Option('Choose HUMAN recipient alias',''));
 const assignees=[...new Set(state.requests.filter(r=>r.assignee.trim()&&r.human_stage!=='closed_human').map(r=>r.assignee))].sort();
 for(const alias of assignees)$('requestOwner').append(new Option(alias,alias));
 if(assignees.includes(currentOwner))$('requestOwner').value=currentOwner;
 const pages=$('ownerPacketPage');pages.replaceChildren();
 const owner=$('requestOwner').value,ownerRows=state.requests.filter(r=>r.assignee===owner&&r.human_stage!=='closed_human');
 for(let offset=0;offset<ownerRows.length;offset+=60){const to=Math.min(offset+60,ownerRows.length);
  pages.append(new Option('HUMAN requests '+(offset+1)+'–'+to+' / '+ownerRows.length,String(offset)));}
 if([...pages.options].some(op=>op.value===previousOwnerPage))pages.value=previousOwnerPage;
 pages.disabled=!enabled||!ownerRows.length;
 $('requestOwner').disabled=!enabled||!assignees.length;
 $('ownerPacketExport').disabled=!enabled||!owner||!ownerRows.length;
 $('ownerReplyImport').disabled=!enabled;$('ownerReplyPreviewButton').disabled=!enabled;
 $('ownerReplyApply').disabled=!enabled||!state.ownerReplyPending;
 $('requestExport').disabled=!state.binding;
 $('requestClear').disabled=!state.binding;
 $('requestBatchApply').disabled=!enabled||!state.preview;
 const orig=$('requestFinding').value;
 $('requestFinding').replaceChildren();
 if(enabled)for(const f of c.findings){
  const option=document.createElement('option');option.value=f.finding_id;
  option.textContent=f.finding_id+' · '+f.severity+' · '+f.title.slice(0,65);
  $('requestFinding').append(option);
 }
 if(c.findings.some(f=>f.finding_id===orig))$('requestFinding').value=orig;
 const links=$('requestLinkFile'),prev=links.value;links.replaceChildren();
 links.append(new Option('No current local file link',''));
 if(enabled)for(const a of c.artifacts.filter(x=>x.finding_id===$('requestFinding').value))
  links.append(new Option(a.file_name.slice(0,80)+' · '+a.sha256.slice(0,14),a.sha256));
 if([...links.options].some(o=>o.value===prev))links.value=prev;
 const body=$('requestRows');body.replaceChildren();
 const query=$('requestFilter').value;
 const shown=state.requests.filter(x=>query==='all'||query==='open'&&x.human_stage!=='closed_human'||
 query==='awaiting'&&x.human_stage==='requested_human'||
 query==='needs_changes'&&x.human_stage==='needs_changes'||
 query==='unassigned'&&!x.assignee.trim());
 for(const r of shown){
  const f=c.findings.find(x=>x.finding_id===r.finding_id);
  const tr=document.createElement('tr');
  tr.append(tag('td',r.finding_id+(f?' · '+f.severity:' · PREVIOUS ORIGINAL SOURCE')));
  tr.append(tag('td',r.request_kind));
  const cell=document.createElement('td');
  const owner=document.createElement('input');owner.value=r.assignee;owner.maxLength=120;
  owner.setAttribute('aria-label','HUMAN assignee '+r.finding_id);owner.disabled=lock;cell.append(owner);tr.append(cell);
  tr.append(tag('td',r.due_date||'none'));
  const edit=document.createElement('td'),select=document.createElement('select');select.disabled=lock;
  for(const stage of STAGES){const op=new Option(stage.replaceAll('_',' '),stage);
   select.append(op);}select.value=r.human_stage;edit.append(select);tr.append(edit);
  const responseCell=document.createElement('td'),response=field(responseCell,'Human response (unverified)',r.human_response,1800);
  response.disabled=lock;tr.append(responseCell);
  tr.append(tag('td',r.instructions));
  const link=document.createElement('td');
  link.textContent=r.linked_sha256?
   r.linked_sha256.slice(0,20)+'…'+(f&&!fingerprintsFor(c,r.finding_id).has(r.linked_sha256)?' · not in CURRENT local file index':''):
   'no local file reference';
  tr.append(link);
  const action=document.createElement('td'),save=tag('button','Save HUMAN update');
  save.type='button';save.disabled=lock;
  save.addEventListener('click',()=>{
   try{
    current();const row=state.requests.find(x=>x.request_id===r.request_id);
    if(row!==r)problem('This PRIVATE human request was replaced; reload the current record.');
    const draft={...r,assignee:str(owner.value.trim(),120,'assignee'),
     human_stage:select.value,human_response:str(response.value.trim(),1800,'human response'),
     updated_utc:new Date().toISOString()};
    validate(draft,B.context());Object.assign(r,draft);state.preview=null;render();
    alert('Saved PRIVATE HUMAN response for '+r.finding_id+'. No follow-up was sent or approved.');
   }catch(e){alert(e.message||'Invalid HUMAN response',true);}
  });
  const remove=tag('button','Delete local draft');remove.type='button';remove.disabled=lock;
  remove.addEventListener('click',()=>{
   if(!confirm('Delete this PRIVATE HUMAN request draft? External source evidence remains unchanged.'))return;
   state.requests=state.requests.filter(x=>x.request_id!==r.request_id);
   state.preview=null;render();
  });
  action.append(save,remove);tr.append(action);body.append(tr);
 }
 $('requestCount').textContent=state.requests.length+' PRIVATE HUMAN requests · '+
  shown.length+' displayed · '+state.requests.filter(x=>x.human_stage==='needs_changes').length+
  ' awaiting human changes; requests are NOT sent by this offline tool.';
 window.dispatchEvent(new Event('lightup-human-requests-updated'));
}
function bind(id,event,fn){
 $(id).addEventListener(event,async()=>{
  try{await fn();}catch(e){alert(e.message||'Invalid PRIVATE human request',true);}
 });
}
bind('ownerPacketPage','change',render);
bind('requestOwner','change',()=>{$('ownerPacketPage').value='';render();});
bind('ownerPacketExport','click',exportOwnerPacket);
bind('ownerReplyPreviewButton','click',previewOwnerReply);
bind('ownerReplyApply','click',applyOwnerReply);
bind('requestFinding','change',render);
bind('requestCreate','click',createOne);
bind('requestExport','click',exportPrivate);
bind('requestImportButton','click',importPrivate);
bind('requestBatchPreviewButton','click',makeBatchPreview);
bind('requestBatchApply','click',applyBatch);
bind('requestClear','click',forget);
bind('requestFilter','change',render);
/* Narrow interface for the already source-bound private Unified HUMAN handoff.
 * No mutable source references or execution capabilities escape this desk. */
window.LightUpArtifactRequests=Object.freeze({
 snapshot(){
  const c=current();
  return state.requests.map(r=>validate(r,c));
 },
 snapshotJSON(){return JSON.stringify(state.requests);},
 currentRows(){
  return same(B.context())?state.requests.map(r=>({...r})):[];
 },
 validateSnapshot(raw,c){
  if(!Array.isArray(raw)||raw.length>MAX_ROWS)
   problem('Invalid PRIVATE unified HUMAN request count.');
  const ids=new Set();
  return raw.map(item=>{
   const v=validate(item,c);
   if(ids.has(v.request_id))problem('Duplicate PRIVATE unified HUMAN request ID.');
   ids.add(v.request_id);return v;
  });
 },
 restore(rows){
  const c=current();
  const next=this.validateSnapshot(rows,c);
  state.requests=next;state.preview=null;state.ownerReplyPending=null;render();
 },
 forgetUnconditionally(){
  state.requests=[];state.preview=null;state.ownerReplyPending=null;state.binding=null;
  render();
 }
});
window.addEventListener('lightup-original-human-context',render);
render();
})();