/* LightUp private human Remediation Calendar. Browser-only; no authority or network. */
(function(global){
'use strict';
const $=id=>document.getElementById(id);
const MAX_FILE=2097152,FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const COLS=['finding_id','title','severity','retest_status','remediation'];
const CASE=['finding_id','owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
const PACKET=['kind','schema_version','disposition','source_contract','source_sha256','findings','cases','instructions',...FLAGS];
const PRIORITY=['critical','high','medium','low','info'];
let state=null,activeId=null,dirty=false,selectedDay=null,pendingRefresh=null,pendingSchedule=null,pendingAssignment=null,ownerFilter=null;
function fail(message){throw Error(message);}
function bytes(s){return new TextEncoder().encode(s).length;}
function exactKeys(o,keys,what){
 if(!o||typeof o!=='object'||Array.isArray(o))fail('Invalid '+what+' object.');
 const allowed=new Set(keys);
 if(Object.keys(o).length!==allowed.size||Object.keys(o).some(k=>!allowed.has(k)))fail('Unexpected or missing '+what+' fields.');
}
function strictJSON(s){
 if(typeof s!=='string'||bytes(s)>MAX_FILE)fail('Private draft exceeds 2 MiB.');
 let i=0,nodes=0; const ws=()=>{while(i<s.length&&/[\x20\t\r\n]/.test(s[i]))i++;};
 function str(){
  const start=i;if(s[i++]!=='"')fail('Expected JSON string.');
  while(i<s.length){const c=s[i++];
   if(c==='"')return JSON.parse(s.slice(start,i));
   if(c==='\\'){const e=s[i++];if(e==='u'){if(!/^[a-fA-F0-9]{4}$/.test(s.slice(i,i+4)))fail('Bad Unicode escape.');i+=4;}else if(!'"\\/bfnrt'.includes(e))fail('Invalid JSON escape.');}
   else if(c.charCodeAt(0)<32)fail('Unescaped control character.');
  }fail('Unclosed JSON string.');
 }
 function read(depth){
  if(++nodes>50000||depth>40)fail('JSON structure exceeds bounds.');
  ws();let c=s[i];
  if(c==='"')return str();
  if(c==='{'){i++;const o=Object.create(null),seen=new Set();ws();if(s[i]==='}'){i++;return o;}
   while(true){ws();const k=str();if(seen.has(k))fail('Duplicate JSON property.');seen.add(k);ws();if(s[i++]!==':')fail('Expected JSON colon.');o[k]=read(depth+1);ws();if(s[i]==='}'){i++;return o;}if(s[i++]!==',')fail('Expected JSON comma.');}
  }
  if(c==='['){i++;const a=[];ws();if(s[i]===']'){i++;return a;}
   while(true){a.push(read(depth+1));ws();if(s[i]===']'){i++;return a;}if(s[i++]!==',')fail('Expected array comma.');}
  }
  for(const [word,val] of [['true',true],['false',false],['null',null]])if(s.startsWith(word,i)){i+=word.length;return val;}
  const m=s.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);if(m){i+=m[0].length;const v=Number(m[0]);if(!Number.isFinite(v))fail('Invalid JSON number.');return v;}
  fail('Invalid JSON value.');
 }
 const v=read(0);ws();if(i!==s.length)fail('Trailing JSON data.');return v;
}
function safeDate(day){
 if(typeof day!=='string'||!/^20\d\d-\d\d-\d\d$/.test(day))return false;
 const ms=Date.parse(day+'T00:00:00Z');
 return Number.isFinite(ms)&&new Date(ms).toISOString().slice(0,10)===day&&day<='2100-12-30';
}
function dayAfter(day){return new Date(Date.parse(day+'T00:00:00Z')+86400000).toISOString().slice(0,10);}
function dateCompact(day){return day.replace(/-/g,'');}
function isOpen(c){return !['completed','deferred'].includes(c.status);}
function eligible(x){return isOpen(x.case)&&safeDate(x.case.due_date);}
function todayUTC(){return new Date().toISOString().slice(0,10);}
function classify(x){
 if(!eligible(x))return 'not_scheduled';
 if(x.case.due_date<todayUTC())return 'overdue';
 if(x.case.status==='blocked')return 'blocked';
 if(!x.case.owner.trim())return 'unassigned';
 if(x.case.status==='ready_for_retest')return 'retest';
 return 'scheduled';
}
function allRows(){
 if(!state)return [];
 const byId=new Map(state.cases.map(c=>[c.finding_id,c]));
 return state.findings.map(f=>({finding:f,case:byId.get(f.finding_id)})).sort((a,b)=>
  (a.case.due_date||'9999').localeCompare(b.case.due_date||'9999')||
  PRIORITY.indexOf(a.finding.severity)-PRIORITY.indexOf(b.finding.severity)||
  a.finding.finding_id.localeCompare(b.finding.finding_id));
}
function filtered(){
 const text=$('search').value.trim().toLowerCase(),scope=$('filter').value,sev=$('severity').value;
 return allRows().filter(x=>{
  const c=x.case,f=x.finding;
  if(ownerFilter!==null&&(c.owner.trim()||'(unassigned)')!==ownerFilter)return false;
  if(selectedDay&&(!eligible(x)||c.due_date!==selectedDay))return false;
  if(sev!=='all'&&f.severity!==sev)return false;
  if(text&&!((f.finding_id+' '+c.owner).toLowerCase().includes(text)))return false;
  if(scope==='all')return true;
  if(scope==='urgent')return ['critical','high'].includes(f.severity);
  if(scope==='blocked')return c.status==='blocked';
  if(scope==='unassigned')return !c.owner.trim();
  if(scope==='retest')return c.status==='ready_for_retest';
  if(scope==='overdue')return eligible(x)&&c.due_date<todayUTC();
  return true;
 });
}
function clearRefresh(){
 pendingRefresh=null;
 $('refresh-preview').hidden=true;$('refresh-apply-ack').checked=false;
 $('refresh-rows').replaceChildren();$('refresh-apply').disabled=true;
 $('refresh-receipt').disabled=true;
}
function refreshControls(){
 const ready=!!pendingRefresh&&!!state&&$('source-ack').checked&&
  $('refresh-ack').checked&&$('refresh-apply-ack').checked;
 $('refresh-apply').disabled=!ready;$('refresh-receipt').disabled=!ready;
}
async function previewRefresh(){
 clearRefresh();
 if(!state||!$('source-ack').checked||!$('refresh-ack').checked)
  fail('Confirm original source and independently verified same client/exact engagement.');
 const file=$('refresh-file').files[0];
 if(!file||file.size>global.LightUpCasework.MAX_BYTES)
  fail('Select original five-column CSV at most 1 MiB.');
 const baseline=state,priorCases=JSON.stringify(state.cases),priorSource=JSON.stringify(state.findings);
 const incoming=await file.text();
 if(state!==baseline||JSON.stringify(state.cases)!==priorCases)
  fail('Previous human notes changed during import. Preview again.');
 const prepared=await global.LightUpCalendarRefresh.prepare(baseline.findings,baseline.cases,incoming);
 if(state!==baseline||JSON.stringify(state.cases)!==priorCases||
    JSON.stringify(state.findings)!==priorSource)fail('Previous source changed during preview; held.');
 pendingRefresh={prepared,baseline,priorCases,priorSource};
 const diff=prepared.diff,tbody=$('refresh-rows');
 const add=(kind,id,fields)=>{
  const row=document.createElement('tr');
  row.append(textEl('td',kind),textEl('td',id),textEl('td',fields));
  tbody.append(row);
 };
 for(const id of diff.added)add('NEW: reset human work',id,'New original finding');
 for(const x of diff.changed)add('CHANGED: reset human work',x.finding_id,x.changed_fields.join(', '));
 for(const id of diff.missing)add('MISSING: not repaired',id,'Absent is NOT proof of remediation');
 if(!diff.added.length&&!diff.changed.length&&!diff.missing.length)
  add('No original source change','—','Existing human notes remain');
 $('refresh-summary').textContent=
  diff.unchanged.length+' original rows unchanged; '+diff.added.length+' new; '+
  diff.changed.length+' changed; '+diff.missing.length+' missing. Missing never means fixed.';
 $('refresh-preview').hidden=false;$('refresh-message').textContent=
  'Private changes previewed only in memory. Your old Casework draft is unchanged.';
 refreshControls();
}
function checkRefreshReady(){
 if(!state||!pendingRefresh||!$('source-ack').checked||
    !$('refresh-ack').checked||!$('refresh-apply-ack').checked)
  fail('Review original source preview and confirm same exact client/engagement before handoff.');
 const x=pendingRefresh;
 if(state!==x.baseline||JSON.stringify(state.cases)!==x.priorCases||
   JSON.stringify(state.findings)!==x.priorSource||
   !global.LightUpCalendarRefresh.stillCurrent(x.prepared,state.findings,state.cases)){
  clearRefresh();fail('Source or human notes changed. Preview anew before applying.');
 }
 return x;
}
function exportRefreshReceipt(){
 const x=checkRefreshReady();
 if(!global.confirm('Export PRIVATE original finding IDs and source differences through an approved protected channel? This is NOT an authenticated source or retest verdict.'))return;
 const receipt=global.LightUpCalendarRefresh.revisionReceipt(x.prepared,x.baseline.digest);
 saveFile('lightup-PRIVATE-source-change-review.json',JSON.stringify(receipt,null,2)+'\n',
          'application/json;charset=utf-8');
 $('refresh-message').textContent='Unsigned PRIVATE historical source-change receipt exported.';
}
function applyRefresh(){
 const x=checkRefreshReady();
 if(!global.confirm('You must retain the previous PRIVATE Casework draft separately. Apply newer original source and RESET all human notes for changed/new rows? Missing findings are NOT fixed.'))return;
 const data=x.prepared;
 const packet=global.LightUpCasework.makePacket(data.after,data.cases,data.digest);
 const clean=packetStructure(packet);
 state={...clean,digest:data.digest};ownerFilter=null;
 dirty=true;activeId=null;selectedDay=null;clearSchedule();$('edit-panel').hidden=true;
 $('month').value=todayUTC().slice(0,7);
 $('refresh-file').value='';$('refresh-ack').checked=false;
 $('draft-ack').checked=false;$('calendar-ack').checked=false;
 clearRefresh();render();
 $('refresh-message').textContent='New original CSV applied locally: '+data.diff.added.length+
 ' added, '+data.diff.changed.length+' changed, '+data.diff.missing.length+
 ' absent (NOT verified fixed); '+data.diff.unchanged.length+
 ' unchanged human plans retained. Export updated PRIVATE Casework before closing.';
}
function clearSchedule(){
 pendingSchedule=null;$('schedule-preview').hidden=true;$('schedule-ack').checked=false;
 $('schedule-apply').disabled=true;$('schedule-rows').replaceChildren();
}
function scheduleControls(){
 $('schedule-apply').disabled=!pendingSchedule||!state||
  !$('source-ack').checked||!$('schedule-ack').checked;
}
function previewSchedule(){
 clearSchedule();
 if(!state||!$('source-ack').checked)fail('Confirm original Casework first.');
 const anchor=$('schedule-anchor').value;
 const policy={};
 for(const sev of PRIORITY){
  const input=$('schedule-'+sev).value;
  if(!/^[1-9][0-9]{0,2}$/.test(input)||Number(input)>365)
   fail('Specify explicit human planning horizons of 1–365 calendar days for every severity.');
  policy[sev]=Number(input);
 }
 const snapshot=state,previous=JSON.stringify(state.cases);
 const plan=global.LightUpRemediationSchedule.prepare(state.findings,state.cases,anchor,policy);
 if(plan.kind!=='lightup.local_deadline_suggestions'||plan.authority!==false||
   plan.grant!==false||plan.contractual_sla!==false||plan.retention_enforced!==false)
  fail('Not an original non-authorizing planning proposal.');
 const visible=new Set(filtered().map(x=>x.finding.finding_id));
 const scope=$('schedule-scope').value;
 const selected=plan.entries.filter(x=>scope==='all'||visible.has(x.finding_id));
 if(!selected.length)fail('No unscheduled, open human cases match the selected scope. Clear the day filter or select All.');
 if(selected.length>350||selected.some(x=>!safeDate(x.proposed_due_date)))
  fail('Original human planning dates exceed the supported private calendar bounds.');
 if(state!==snapshot||JSON.stringify(state.cases)!==previous)
  fail('Casework changed while preparing human dates. Preview again.');
 pendingSchedule={snapshot,previous,selected,policy,anchor};
 const tbody=$('schedule-rows');
 for(const x of selected){
  const tr=document.createElement('tr');
  tr.append(textEl('td',x.severity),textEl('td',x.finding_id),
   textEl('td',x.proposed_due_date+' ('+x.days+' days)'));tbody.append(tr);
 }
 $('schedule-summary').textContent=selected.length+
  ' human-only dates proposed. Existing due dates and completed/deferred local cases are unchanged; none is a real SLA or approved retest window.';
 $('schedule-preview').hidden=false;$('schedule-message').textContent=
  'Source-bound private preview. Nothing has been changed.';
 scheduleControls();
}
function applySchedule(){
 if(!state||!pendingSchedule||!$('source-ack').checked||!$('schedule-ack').checked)
  fail('Confirm the original source and review the explicit human date proposal.');
 const stage=pendingSchedule;
 if(stage.snapshot!==state||JSON.stringify(state.cases)!==stage.previous){
  clearSchedule();fail('Human cases changed since the date preview. Preview again.');
 }
 if(!global.confirm('Apply '+stage.selected.length+' proposed HUMAN-ONLY dates? These are NOT contractual SLAs, authorized scan/retest windows or verified fixes.'))return;
 const additions=new Map(stage.selected.map(x=>[x.finding_id,x.proposed_due_date]));
 const ids=new Set(state.findings.map(f=>f.finding_id)),utc=new Date().toISOString();
 const cases=state.cases.map(c=>{
  const due=additions.get(c.finding_id);
  if(!due)return c;
  if(c.due_date!==null||!isOpen(c))fail('Planning eligibility changed. Apply refused.');
  return global.LightUpCasework.cleanCase({...c,due_date:due,updated_utc:utc},ids);
 });
 global.LightUpCasework.loadPacket(global.LightUpCasework.makePacket(state.findings,cases,state.digest));
 state={...state,cases};dirty=true;activeId=null;selectedDay=null;
 $('edit-panel').hidden=true;clearSchedule();clearRefresh();render();
 $('schedule-message').textContent=additions.size+
  ' HUMAN-ONLY due dates saved locally. Export the updated PRIVATE Casework draft; no original finding or retest was updated.';
}
function clearAssignments(){
 pendingAssignment=null;$('assign-preview').hidden=true;$('assign-ack').checked=false;
 $('assign-apply').disabled=true;$('assign-rows').replaceChildren();
}
function assignmentControls(){
 $('assign-apply').disabled=!pendingAssignment||!state||!$('source-ack').checked||!$('assign-ack').checked;
}
function renderOwners(){
 const tbody=$('owners');tbody.replaceChildren();
 $('owner-filter-message').textContent=ownerFilter===null?'No exact human owner filter is active.':
  'Exact HUMAN owner filter: '+ownerFilter+' (not an authenticated identity).';
 $('owner-filter-clear').hidden=ownerFilter===null;
 const entries=global.LightUpCalendarWorkload.report(state.findings,state.cases,todayUTC());
 for(const g of entries){
  const tr=document.createElement('tr');
  for(const v of [g.owner,g.total,g.criticalHigh,g.blocked,g.overdue,g.scheduled,g.readyForRetest])
   tr.append(textEl('td',v));
  const action=document.createElement('td'),button=textEl('button','Filter','muted-button');
  button.type='button';button.addEventListener('click',()=>{
   ownerFilter=g.owner;selectedDay=null;$('filter').value='all';
   $('search').value='';render();
  });
  action.append(button);tr.append(action);tbody.append(tr);
 }
 if(!entries.length){const tr=document.createElement('tr'),cell=textEl('td','No open human cases in this source.');cell.colSpan=8;tr.append(cell);tbody.append(tr);}
}
function previewAssignment(){
 clearAssignments();
 if(!state||!$('source-ack').checked)fail('Load and independently confirm the original private Casework source.');
 const current=state,before=JSON.stringify(state.cases),ids=filtered().map(x=>x.finding.finding_id);
 const proposal=global.LightUpCalendarWorkload.propose(state.findings,state.cases,ids,
  $('assign-owner').value,$('assign-empty-only').checked);
 if(state!==current||JSON.stringify(state.cases)!==before)fail('Human casework changed while preparing ownership. Preview again.');
 pendingAssignment={current,before,proposal};
 const tbody=$('assign-rows');
 for(const x of proposal.rows){
  const tr=document.createElement('tr');
  tr.append(textEl('td',x.finding_id),textEl('td',x.previous_owner||'(unassigned)'),
    textEl('td',x.next_owner));tbody.append(tr);
 }
 $('assign-summary').textContent=proposal.rows.length+' currently visible OPEN human cases would receive owner '+proposal.newOwner+'. Existing original source and retest do not change.';
 $('assign-preview').hidden=false;$('assign-message').textContent='Preview only. No human assignment changed.';
 assignmentControls();
}
function applyAssignment(){
 if(!state||!pendingAssignment||!$('source-ack').checked||!$('assign-ack').checked)
  fail('Explicit review and HUMAN-ONLY assignment confirmation required.');
 const p=pendingAssignment;
 if(state!==p.current||JSON.stringify(state.cases)!==p.before){
  clearAssignments();fail('Previous human work changed; source-bound assignment preview must be recreated.');
 }
 if(!global.confirm('Assign '+p.proposal.rows.length+' currently selected OPEN human cases to local HUMAN label '+p.proposal.newOwner+'? This is NOT authenticated identity, consent or permission.'))return;
 const cases=global.LightUpCalendarWorkload.apply(state.findings,state.cases,p.proposal);
 state={...state,cases};dirty=true;activeId=null;ownerFilter=null;
 $('edit-panel').hidden=true;clearRefresh();clearSchedule();
 render();
 $('assign-message').textContent=p.proposal.rows.length+
  ' human ownership notes updated locally. Export the PRIVATE Casework v1 draft for separate authorized handoff.';
}
function renderHandoffOwners(){
 const select=$('owner-handoff-label'),current=select.value;
 const owners=[...new Set(state.cases.map(c=>c.owner))]
  .filter(s=>typeof s==='string'&&s.trim()===s&&s&&s.length<=120&&
    !/[\u0000-\u001f\u007f-\u009f]/.test(s)).sort();
 select.replaceChildren(new Option('Select exact human owner',''));
 for(const name of owners)select.add(new Option(name,name));
 select.value=owners.includes(current)?current:'';
 if(select.value!==current)$('owner-handoff-ack').checked=false;
 updateHandoffControls();
}
function updateHandoffControls(){
 const ack=!!state&&$('source-ack').checked&&$('owner-handoff-ack').checked;
 $('owner-handoff-export').disabled=!ack||!$('owner-handoff-label').value;
 $('owner-reply-import').disabled=!ack||!$('owner-reply-file').files.length;
}
async function exportOwnerHandoff(){
 if(!state||!$('source-ack').checked||!$('owner-handoff-ack').checked)
  fail('Confirm the source and independent private sharing before owner handoff.');
 const before=state,baseline=JSON.stringify(state.cases),source=JSON.stringify(state.findings);
 const owner=$('owner-handoff-label').value;
 if(!owner)fail('Select one exact human owner.');
 if(!global.confirm('This packet includes ORIGINAL sensitive findings for human owner '+owner+'. Confirm approved independent recipient and exact engagement. It is not an authorization.'))return;
 const packet=await global.LightUpOwnerProtocol.createRequest(state.findings,state.cases,owner,state.digest);
 if(state!==before||JSON.stringify(state.cases)!==baseline||
    JSON.stringify(state.findings)!==source)fail('Casework changed during owner handoff. Export held.');
 const name='lightup-PRIVATE-owner-handoff.json';
 saveFile(name,JSON.stringify(packet,null,2)+'\n','application/json;charset=utf-8');
 $('owner-handoff-message').textContent=packet.rows.length+
  ' original findings included only for owner '+owner+'. Transfer privately; no identity or authorization established.';
}
let ownerReplyPreview=null;
function clearOwnerReplyPreview(){
 ownerReplyPreview=null;
 $('owner-reply-review').hidden=true;$('owner-reply-ack').checked=false;
 $('owner-reply-apply').disabled=true;$('owner-reply-changes').replaceChildren();
}
function updateOwnerReplyApplyControl(){
 $('owner-reply-apply').disabled=!ownerReplyPreview||
  !$('source-ack').checked||!$('owner-handoff-ack').checked||!$('owner-reply-ack').checked;
}
async function importOwnerReply(){
 clearOwnerReplyPreview();
 if(!state||!$('source-ack').checked||!$('owner-handoff-ack').checked)
  fail('Confirm original source, exact client/engagement and independent return sender.');
 const file=$('owner-reply-file').files[0];
 if(!file||file.size>2097152)fail('Select PRIVATE owner reply JSON of at most 2 MiB.');
 const snapshot=state,baseline=JSON.stringify(state.cases),original=JSON.stringify(state.findings);
 const packet=strictJSON(await file.text());
 if(packet.owner_label!==$('owner-handoff-label').value)
  fail('Select the exact human owner named in this PRIVATE reply before reviewing it.');
 const accepted=await global.LightUpOwnerProtocol.applyReply(
  state.findings,state.cases,state.digest,packet);
 if(state!==snapshot||JSON.stringify(state.cases)!==baseline||
    JSON.stringify(state.findings)!==original)
  fail('Source or human notes changed during owner reply preview. No update applied.');
 const previous=new Map(state.cases.map(x=>[x.finding_id,x]));
 const changes=[];
 for(const c of accepted.cases){
  const old=previous.get(c.finding_id);
  if(!old)fail('Owner reply contains an unrecognized original finding.');
  const keys=['status','due_date','next_action','blocker','owner'].filter(k=>old[k]!==c[k]);
  if(keys.length)changes.push({finding_id:c.finding_id,keys,before:old,after:c});
 }
 ownerReplyPreview={snapshot,baseline,original,accepted,changes};
 const tbody=$('owner-reply-changes');
 for(const change of changes){
  const tr=document.createElement('tr');
  tr.append(textEl('td',change.finding_id),textEl('td',change.keys.join(', ')));
  const details=(v)=>change.keys.map(k=>k+': '+String(v[k]??'(no date)')).join('\n');
  tr.append(textEl('td',details(change.before),'reply-value'),
    textEl('td',details(change.after),'reply-value'));tbody.append(tr);
 }
 $('owner-reply-summary').textContent=changes.length+' of '+accepted.changed+
  ' original finding(s) have changed HUMAN planning fields. Original source, authorizations, and retest are not modified.';
 $('owner-reply-review').hidden=false;
 $('owner-handoff-message').textContent=
  'PRIVATE reply previewed without local changes. Review all human field differences and explicitly confirm before applying.';
 updateOwnerReplyApplyControl();
}
function applyOwnerReply(){
 if(!state||!ownerReplyPreview||!$('source-ack').checked||
    !$('owner-handoff-ack').checked||!$('owner-reply-ack').checked)
  fail('Review and explicitly approve the PRIVATE human reply before applying.');
 const pending=ownerReplyPreview;
 if(state!==pending.snapshot||JSON.stringify(state.cases)!==pending.baseline||
    JSON.stringify(state.findings)!==pending.original){
  clearOwnerReplyPreview();fail('Private casework changed since the preview. Reimport the reply before any update.');
 }
 if(!pending.changes.length)fail('The owner reply contains no new HUMAN planning changes.');
 if(!global.confirm('Accept '+pending.changes.length+
    ' inspected HUMAN planning changes for '+pending.accepted.owner_label+
    '? Current actual consent, remediation and authorized retest remain UNVERIFIED.'))return;
 state={...state,cases:pending.accepted.cases};dirty=true;activeId=null;
 $('edit-panel').hidden=true;clearRefresh();clearSchedule();clearAssignments();
 $('owner-handoff-ack').checked=false;$('owner-reply-file').value='';
 clearOwnerReplyPreview();render();
 $('owner-handoff-message').textContent=pending.changes.length+
  ' approved HUMAN planning changes imported atomically. Export updated PRIVATE Casework v1 JSON before closing.';
}
function openEdit(id){
 if(!state||!$('source-ack').checked)fail('Source confirmation required.');
 const c=state.cases.find(x=>x.finding_id===id);
 if(!c)fail('Original finding is not in this private workspace.');
 activeId=id;
 $('edit-label').textContent='Editing human notes for original finding '+id+'. The original finding and source retest state remain read-only.';
 $('edit-owner').value=c.owner;$('edit-status').value=c.status;
 $('edit-date').value=c.due_date||'';$('edit-action').value=c.next_action;$('edit-blocker').value=c.blocker;
 $('edit-panel').hidden=false;$('edit-panel').scrollIntoView({block:'nearest'});
}
function saveEdit(event){
 event.preventDefault();
 if(!state||!$('source-ack').checked||!activeId)fail('No editable human case selected.');
 const index=state.cases.findIndex(x=>x.finding_id===activeId);
 if(index<0)fail('Original finding no longer present.');
 const old=state.cases[index],date=$('edit-date').value;
 if(date&&!safeDate(date))fail('Human follow-up date must be within 2020–2100.');
 const next=global.LightUpCasework.cleanCase({
  ...old,owner:$('edit-owner').value,status:$('edit-status').value,
  due_date:date||null,next_action:$('edit-action').value,
  blocker:$('edit-blocker').value,updated_utc:new Date().toISOString()
 },new Set(state.findings.map(f=>f.finding_id)));
 const cases=state.cases.slice();cases[index]=next;state={...state,cases};
 dirty=true;activeId=null;clearOwnerReplyPreview();clearSchedule();clearRefresh();$('edit-panel').hidden=true;render();
 $('export-message').textContent='Human-only local change saved in memory. Export a PRIVATE Casework v1 draft before closing.';
}
function exportDraft(){
 if(!state||!$('source-ack').checked||!$('draft-ack').checked)
  fail('Private Casework export requires separately confirmed source and handoff.');
 const packet=global.LightUpCasework.makePacket(state.findings,state.cases,state.digest);
 saveFile('lightup-PRIVATE-updated-casework.json',JSON.stringify(packet,null,2)+'\n','application/json;charset=utf-8');
 dirty=false;$('export-message').textContent='Updated PRIVATE human Casework draft saved. Return via a separately approved secure channel, never as proof of remediation.';
}
function textEl(tag,text,cls){const e=document.createElement(tag);e.textContent=String(text);if(cls)e.className=cls;return e;}
function renderMonth(){
 const grid=$('month-grid');grid.replaceChildren();
 const value=$('month').value,valid=/^\d{4}-\d{2}$/.test(value)&&value>='2020-01'&&value<='2100-12';
 if(!valid){$('month-message').textContent='Choose a month within 2020–2100.';return;}
 const first=Date.parse(value+'-01T00:00:00Z');if(!Number.isFinite(first))return;
 for(const name of ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'])grid.append(textEl('span',name,'month-head'));
 const offset=(new Date(first).getUTCDay()+6)%7;
 const counts=new Map();
 for(const x of allRows()){
  if(!eligible(x))continue;
  const day=x.case.due_date,existing=counts.get(day)||{total:0,urgent:0,blocked:0};
  existing.total++;if(['critical','high'].includes(x.finding.severity))existing.urgent++;
  if(x.case.status==='blocked')existing.blocked++;counts.set(day,existing);
 }
 for(let i=0;i<42;i++){
  const d=new Date(first+(i-offset)*86400000),day=d.toISOString().slice(0,10);
  const inMonth=day.slice(0,7)===value,metric=counts.get(day)||{total:0,urgent:0,blocked:0};
  const b=document.createElement('button');b.type='button';b.className='month-day'+(metric.total&&inMonth?' has-work':'')+(selectedDay===day?' selected':'');
  b.disabled=!inMonth;b.setAttribute('aria-pressed',selectedDay===day?'true':'false');
  b.setAttribute('aria-label',day+': '+metric.total+' human deadlines, '+metric.urgent+' critical/high, '+metric.blocked+' blocked. Filter this date.');
  b.append(textEl('span',d.getUTCDate(),'date-number'));
  if(metric.total&&inMonth){
   b.append(textEl('span',metric.total+' planned','day-count'));
   if(metric.urgent)b.append(textEl('span',metric.urgent+' critical/high','day-critical'));
   if(metric.blocked)b.append(textEl('span',metric.blocked+' blocked','day-critical'));
  }
  b.addEventListener('click',()=>{selectedDay=selectedDay===day?null:day;render();});
  grid.append(b);
 }
 $('month-message').textContent=selectedDay?'Date filter: '+selectedDay+'. Select it again or choose Clear day filter.':'Select a day to filter the human work queue. No deadlines are automatically scheduled.';
}
function adjustMonth(delta){
 const value=$('month').value;
 if(!/^\d{4}-\d{2}$/.test(value))return;
 const d=new Date(value+'-01T00:00:00Z');d.setUTCMonth(d.getUTCMonth()+delta);
 const next=d.toISOString().slice(0,7);if(next<'2020-01'||next>'2100-12')return;
 $('month').value=next;selectedDay=null;render();
}
function render(){
 if(!state)return;
 clearAssignments();renderOwners();renderHandoffOwners();renderMonth();
 const rows=filtered(),body=$('rows');body.replaceChildren();
 for(const x of rows){
  const f=x.finding,c=x.case,tr=document.createElement('tr');
  const id=document.createElement('td');id.append(textEl('strong',f.severity.toUpperCase(),['critical','high'].includes(f.severity)?'urgent':''));
  id.append(textEl('small',f.finding_id));tr.append(id);
  tr.append(textEl('td',f.retest_status));
  tr.append(textEl('td',c.status));
  tr.append(textEl('td',c.owner||'Unassigned'));
  tr.append(textEl('td',c.due_date||'No human date',!c.due_date?'muted':undefined));
  const next=document.createElement('td');next.append(textEl('span',c.next_action||'No human action'));if(c.blocker.trim())next.append(textEl('small','BLOCKED: '+c.blocker));tr.append(next);const action=document.createElement('td'),button=textEl('button','Edit','muted-button');button.type='button';button.addEventListener('click',()=>{try{openEdit(f.finding_id);}catch(e){$('export-message').textContent='HOLD: '+e.message;}});action.append(button);tr.append(action);body.append(tr);
 }
 if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.textContent='No matching original findings.';tr.append(td);body.append(tr);}
 const all=allRows(),counts=[
  ['Original findings',all.length],['Scheduled human dates',all.filter(eligible).length],
  ['Past-due human dates',all.filter(x=>eligible(x)&&x.case.due_date<todayUTC()).length],
  ['Human blockers',all.filter(x=>x.case.status==='blocked').length],
  ['Awaiting separate retest',all.filter(x=>x.case.status==='ready_for_retest').length],
  ['Missing a human due date',all.filter(x=>isOpen(x.case)&&!x.case.due_date).length]
 ];
 const m=$('metrics');m.replaceChildren();for(const [label,count] of counts){const d=textEl('div','', 'metric');d.append(textEl('strong',count),textEl('span',label));m.append(d);}
 $('scope-info').textContent=rows.length+' matching original findings'+(ownerFilter!==null?' for exact human owner '+ownerFilter:'')+'; '+rows.filter(eligible).length+' with eligible human follow-up dates. Missing dates are NOT assumed resolved.';
 $('download').disabled=!$('calendar-ack').checked||!$('source-ack').checked;
 $('casework-save').disabled=!$('draft-ack').checked||!$('source-ack').checked;
}
async function shaHex(s){
 if(!global.crypto||!global.crypto.subtle)fail('This browser cannot calculate SHA-256 offline; calendar export held.');
 const out=await global.crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
 return Array.from(new Uint8Array(out),x=>x.toString(16).padStart(2,'0')).join('');
}
function packetStructure(packet){
 exactKeys(packet,PACKET,'Casework packet');
 for(const k of FLAGS)if(packet[k]!==false)fail('Casework packet claims '+k+' authority.');
 if(typeof packet.instructions!=='string'||packet.instructions.length>2000)fail('Invalid source instructions.');
 if(!Array.isArray(packet.findings)||!Array.isArray(packet.cases))fail('Missing original findings/casework.');
 for(const row of packet.findings)exactKeys(row,COLS,'finding');
 for(const row of packet.cases)exactKeys(row,CASE,'case');
 return global.LightUpCasework.loadPacket(packet);
}
async function openFile(file){
 if(!file||file.size>MAX_FILE)fail('Select a Casework v1 JSON of 2 MiB or less.');
 if(!$('source-ack').checked)fail('Confirm the independently authorized original client and engagement before import.');
 const packet=strictJSON(await file.text());
 const clean=packetStructure(packet);
 const digest=await global.LightUpCasework.digest(clean.findings);
 if(clean.source_sha256&&(!digest||clean.source_sha256!==digest))fail('Original source fingerprint mismatch or browser digest unavailable.');
 const newState={...clean,digest};
 state=newState;ownerFilter=null;clearOwnerReplyPreview();clearSchedule();clearRefresh();$('refresh-file').value='';$('refresh-ack').checked=false;dirty=false;activeId=null;selectedDay=null;$('month').value=todayUTC().slice(0,7);$('edit-panel').hidden=true;$('draft-ack').checked=false;
 $('workspace').hidden=false;$('calendar-ack').checked=false;$('export-message').textContent='';
 render();
 $('message').textContent=clean.findings.length+' original findings loaded locally. Source is a historical unsigned draft; no current identity or consent checked.';
}
function icalEscape(s){
 return String(s).replace(/\r\n?/g,'\n').replace(/\\/g,'\\\\').replace(/\n/g,'\\n').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g,'');
}
function fold(line){
 let out='',length=0;
 for(const ch of line){const n=bytes(ch);if(length+n>75){out+='\r\n ';length=1;}out+=ch;length+=n;}
 return out;
}
function stamp(){return new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');}
function saveFile(name,content,type){
 const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function exportCalendar(){
 if(!state||!$('source-ack').checked||!$('calendar-ack').checked)fail('Private-calendar acknowledgment and source confirmation required.');
 const candidates=$('export-scope').value==='all'?allRows():filtered();
 const selected=candidates.filter(eligible),invalid=candidates.filter(x=>isOpen(x.case)&&x.case.due_date&&!safeDate(x.case.due_date));
 if(invalid.length)fail('One or more human dates cannot be represented safely in the calendar (2020–2100).');
 if(!selected.length)fail('No eligible human deadlines in the selected queue.');
 if(selected.length>350)fail('Calendar exceeds source bounds.');
 const privateMode=$('detail').value==='private',seen=new Set(),now=stamp();
 const base=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LightUp//Offline Human Remediation Calendar//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH'];
 for(const x of selected){
  const f=x.finding,c=x.case,uid=(await shaHex('lightup-human-due-v1\\0'+state.digest+'\\0'+f.finding_id)).slice(0,48)+'@local.lightup.invalid';
  if(seen.has(uid))fail('Calendar UID collision; export held.');seen.add(uid);
  const title=privateMode?('LightUp HUMAN PLAN: '+f.title):('LightUp human follow-up ('+f.severity+')');
  const description=privateMode?'UNVERIFIED HUMAN CASEWORK; NOT RETEST OR APPROVAL.\\nFinding: '+f.finding_id+'\\nOwner: '+(c.owner||'unassigned')+'\\nNext action: '+c.next_action+'\\nOriginal retest: '+f.retest_status+'\\nHuman stage: '+c.status:'UNVERIFIED HUMAN FOLLOW-UP; NOT RETEST OR APPROVAL.';
  base.push('BEGIN:VEVENT','UID:'+uid,'DTSTAMP:'+now,'DTSTART;VALUE=DATE:'+dateCompact(c.due_date),
   'DTEND;VALUE=DATE:'+dateCompact(dayAfter(c.due_date)),'SUMMARY:'+icalEscape(title),
   'DESCRIPTION:'+icalEscape(description),'STATUS:TENTATIVE','TRANSP:TRANSPARENT','CLASS:PRIVATE','END:VEVENT');
 }
 base.push('END:VCALENDAR');
 const result=base.map(fold).join('\r\n')+'\r\n';
 if(bytes(result)>1048576)fail('Calendar exceeds safe export size.');
 saveFile(privateMode?'lightup-PRIVATE-human-followup.ics':'lightup-redacted-human-followup.ics',result,'text/calendar;charset=utf-8');
 $('export-message').textContent=selected.length+' local tentative calendar events exported. They are NOT proof of current consent, remediation or retest.';
}
function exportAggregate(){
 if(!state)fail('Open original Casework first.');
 const list=allRows(),out=['severity,open,blocked,scheduled,overdue,ready_for_separate_retest,missing_due_date'];
 for(const sev of PRIORITY){
  const rows=list.filter(x=>x.finding.severity===sev);
  out.push([sev,rows.filter(x=>isOpen(x.case)).length,rows.filter(x=>x.case.status==='blocked').length,
    rows.filter(eligible).length,rows.filter(x=>eligible(x)&&x.case.due_date<todayUTC()).length,
    rows.filter(x=>x.case.status==='ready_for_retest').length,rows.filter(x=>isOpen(x.case)&&!x.case.due_date).length].join(','));
 }
 saveFile('lightup-anonymous-human-workload.csv',out.join('\r\n')+'\r\n','text/csv;charset=utf-8');
 $('export-message').textContent='Anonymous category counts exported. This is neither a retest outcome nor proof of a safe public disclosure.';
}
function reset(){
 state=null;activeId=null;dirty=false;selectedDay=null;ownerFilter=null;clearOwnerReplyPreview();clearAssignments();clearSchedule();clearRefresh();$('refresh-file').value='';$('refresh-ack').checked=false;$('file').value='';$('source-ack').checked=false;$('calendar-ack').checked=false;$('draft-ack').checked=false;$('edit-panel').hidden=true;
 $('workspace').hidden=true;$('message').textContent='Private workspace cleared from app state. Already exported files and calendar imports remain under your control.';
}
$('file').addEventListener('change',async e=>{
 if(dirty&&!global.confirm('Discard in-memory human changes? Export your PRIVATE Casework draft first.')){e.target.value='';return;}
 if(state&&!global.confirm('Replace the previous source? Independently verify the newly selected client and exact engagement first.')){e.target.value='';return;}
 state=null;activeId=null;dirty=false;$('edit-panel').hidden=true;$('workspace').hidden=true;
 try{await openFile(e.target.files[0]);}catch(err){$('message').textContent='HOLD: '+err.message;}
});
for(const id of ['filter','severity','search'])$(id).addEventListener('input',render);
$('refresh-preview-button').addEventListener('click',async()=>{try{await previewRefresh();}catch(e){clearRefresh();$('refresh-message').textContent='HOLD: '+e.message;}});
$('refresh-apply-ack').addEventListener('change',refreshControls);
$('refresh-ack').addEventListener('change',()=>{clearRefresh();});
$('refresh-file').addEventListener('change',clearRefresh);
$('refresh-apply').addEventListener('click',()=>{try{applyRefresh();}catch(e){$('refresh-message').textContent='HOLD: '+e.message;}});
$('refresh-receipt').addEventListener('click',()=>{try{exportRefreshReceipt();}catch(e){$('refresh-message').textContent='HOLD: '+e.message;}});
$('owner-filter-clear').addEventListener('click',()=>{ownerFilter=null;render();});
$('assign-preview-button').addEventListener('click',()=>{try{previewAssignment();}catch(e){clearAssignments();$('assign-message').textContent='HOLD: '+e.message;}});
$('assign-ack').addEventListener('change',assignmentControls);
$('assign-apply').addEventListener('click',()=>{try{applyAssignment();}catch(e){$('assign-message').textContent='HOLD: '+e.message;}});
for(const id of ['assign-owner','assign-empty-only'])$(id).addEventListener('change',clearAssignments);
$('schedule-preview-button').addEventListener('click',()=>{try{previewSchedule();}catch(e){clearSchedule();$('schedule-message').textContent='HOLD: '+e.message;}});
$('schedule-ack').addEventListener('change',scheduleControls);
$('schedule-apply').addEventListener('click',()=>{try{applySchedule();}catch(e){$('schedule-message').textContent='HOLD: '+e.message;}});
for(const id of ['schedule-anchor','schedule-scope',...PRIORITY.map(x=>'schedule-'+x)])$(id).addEventListener('change',clearSchedule);
$('owner-handoff-label').addEventListener('change',()=>{$('owner-handoff-ack').checked=false;clearOwnerReplyPreview();updateHandoffControls();});
$('owner-reply-file').addEventListener('change',()=>{clearOwnerReplyPreview();updateHandoffControls();});
$('owner-handoff-ack').addEventListener('change',()=>{if(!$('owner-handoff-ack').checked)clearOwnerReplyPreview();updateHandoffControls();});
$('owner-reply-ack').addEventListener('change',updateOwnerReplyApplyControl);
$('owner-reply-apply').addEventListener('click',()=>{try{applyOwnerReply();}catch(e){$('owner-handoff-message').textContent='HOLD: '+e.message;}});
$('owner-handoff-export').addEventListener('click',async()=>{try{await exportOwnerHandoff();}catch(e){$('owner-handoff-message').textContent='HOLD: '+e.message;}});
$('owner-reply-import').addEventListener('click',async()=>{try{await importOwnerReply();}catch(e){$('owner-handoff-message').textContent='HOLD: '+e.message;}});
$('calendar-ack').addEventListener('change',render);
$('draft-ack').addEventListener('change',render);
$('month').addEventListener('change',()=>{selectedDay=null;render();});
$('month-prev').addEventListener('click',()=>adjustMonth(-1));
$('month-next').addEventListener('click',()=>adjustMonth(1));
$('day-clear').addEventListener('click',()=>{selectedDay=null;render();});
$('edit-form').addEventListener('submit',e=>{try{saveEdit(e);}catch(err){e.preventDefault();$('export-message').textContent='HOLD: '+err.message;}});
$('edit-cancel').addEventListener('click',()=>{activeId=null;$('edit-panel').hidden=true;});
$('casework-save').addEventListener('click',()=>{try{exportDraft();}catch(err){$('export-message').textContent='HOLD: '+err.message;}});
$('source-ack').addEventListener('change',()=>{if(!$('source-ack').checked){clearRefresh();clearSchedule();clearOwnerReplyPreview();$('owner-handoff-ack').checked=false;}if(state)render();});
$('download').addEventListener('click',async()=>{try{await exportCalendar();}catch(e){$('export-message').textContent='HOLD: '+e.message;}});
$('aggregate').addEventListener('click',()=>{try{exportAggregate();}catch(e){$('export-message').textContent='HOLD: '+e.message;}});
$('clear').addEventListener('click',()=>{if(dirty&&!global.confirm('Discard unsaved human notes?'))return;reset();});
global.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
})(window);