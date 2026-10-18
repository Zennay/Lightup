/* LightUp remediation casework UI. No network, persisted browser state, or elevated capabilities. */
(function(){
'use strict';
const $=id=>document.getElementById(id);
const workflow=LightUpCasework.PROGRESS;
for(const status of workflow){const opt=document.createElement('option');opt.value=status;opt.textContent=status.replaceAll('_',' ');$('workflow').append(opt);}
let findings=[],cases=[],fingerprint=null,sourceLabel='',edited=false;
let pendingRefresh=null,pendingSchedule=null;
const byId=()=>new Map(cases.map(c=>[c.finding_id,c]));
const ids=()=>new Set(findings.map(f=>f.finding_id));
function inform(message){$('status').textContent=message;}
function safeText(parent,tag,text,cls){
 const el=document.createElement(tag);el.textContent=String(text??'');
 if(cls)el.className=cls;
 parent.append(el);return el;
}
function makeInput(container,label,key,selected,options){
 const wrap=document.createElement('label');wrap.textContent=label;container.append(wrap);
 let el;
 if(options){el=document.createElement('select');for(const [value,title] of options){
  const opt=document.createElement('option');opt.value=value;opt.textContent=title;el.append(opt);
 }}
 else if(key==='due_date'){el=document.createElement('input');el.type='date';}
 else if(['next_action','verification_plan','blocker','note'].includes(key)){el=document.createElement('textarea');el.rows=2;}
 else {el=document.createElement('input');el.type='text';}
 el.id='case-'+key+'-'+selected.finding_id;
 const max={owner:120,next_action:1800,verification_plan:1600,blocker:1200,note:1600};
 if(max[key])el.maxLength=max[key];
 el.value=selected[key]??'';
 wrap.append(el);
 el.addEventListener('change',()=>{
  const next={...selected,[key]:key==='due_date'?(el.value||null):el.value,updated_utc:new Date().toISOString()};
  try{
   const validated=LightUpCasework.cleanCase(next,ids());
   const index=cases.findIndex(c=>c.finding_id===selected.finding_id);
   cases[index]=validated;edited=true;clearSchedulePreview();
   inform('Unsaved local changes. Export casework JSON to keep your plan.');
   render();
  }catch(_){inform('Invalid case field; change not saved.');el.value=selected[key]??'';}
 });
 return el;
}
function filteredFindings(){
 const by=byId(),needle=$('search').value.trim().toLowerCase(),severity=$('severity').value,work=$('workflow').value;
 return findings.filter(f=>{
  const c=by.get(f.finding_id);
  return (!severity||f.severity===severity)&&(!work||c.status===work)&&
   (!needle||[f.finding_id,f.title,f.remediation,c.owner,c.next_action,c.blocker].some(s=>s.toLowerCase().includes(needle)));
 });
}
function render(){
 const available=findings.length>0,by=byId();
 const totals=LightUpCasework.metrics(findings,cases,new Date().toISOString().slice(0,10));
 for(const [ui,key] of [['total','findings'],['urgent','critical_or_high'],['open','open'],['blocked','blocked'],['overdue','overdue'],['retest','ready_for_retest']])
  $(ui).textContent=totals[key];
 for(const id of ['save','exportCSV','exportMD','print'])$(id).disabled=!available;
 $('reference').textContent=available?'Source: '+sourceLabel+' · unverified content SHA-256: '+(fingerprint||'unavailable in this browser')+
   ' · '+findings.length+' findings · '+(edited?'unsaved local changes':'no unsaved changes')+'.':'No source imported.';
 $('empty').style.display=available?'none':'block';
 const listed=filteredFindings();
 $('bulkApply').disabled=!available||!listed.length;
 $('schedulePreview').disabled=!available;
 $('scheduleApply').disabled=!available||!pendingSchedule;
 $('bulkCount').textContent=listed.length+' matching findings';
 const kind=$('sort').value;
 listed.sort((a,b)=>{
  const ca=by.get(a.finding_id),cb=by.get(b.finding_id);
  if(kind==='title')return a.title.localeCompare(b.title);
  if(kind==='due')return (ca.due_date||'9999').localeCompare(cb.due_date||'9999')||
    LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity);
  return LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity)||
   (a.retest_status==='regression'?-1:0)-(b.retest_status==='regression'?-1:0)||
   a.finding_id.localeCompare(b.finding_id);
 });
 const board=$('board');board.replaceChildren();
 if(available&&!listed.length)safeText(board,'p','No cases match the current filter.','small');
 for(const f of listed){
  const c=by.get(f.finding_id),card=document.createElement('article');card.className='finding';board.append(card);
  const meta=document.createElement('div');meta.className='meta';card.append(meta);
  safeText(meta,'span',f.severity,'badge '+(f.severity==='critical'||f.severity==='high'?f.severity:''));
  safeText(meta,'span',f.retest_status.replaceAll('_',' '),'badge '+(f.retest_status==='fixed'?'fixed':''));
  safeText(meta,'span',c.status.replaceAll('_',' '),'badge '+(c.status==='blocked'?'blocked':''));
  safeText(card,'h3',f.title);safeText(card,'p','Finding ID: '+f.finding_id,'small');
  const details=document.createElement('details');card.append(details);
  safeText(details,'summary','Recommended source remediation');safeText(details,'div',f.remediation,'inline');
  const two=document.createElement('div');two.className='grid';card.append(two);
  makeInput(two,'Responsible owner / team','owner',c);
  makeInput(two,'Target due date','due_date',c);
  makeInput(card,'Planning stage','status',c,workflow.map(t=>[t,t.replaceAll('_',' ')]));
  makeInput(card,'Next repair action','next_action',c);
  makeInput(card,'Retest coordination / verification plan','verification_plan',c);
  makeInput(card,'Blocker / dependency','blocker',c);
  makeInput(card,'Private local planning notes','note',c);
  const msg=c.status==='completed'&&f.retest_status!=='fixed'
   ? 'Completed in local plan only: the original LightUp finding is not marked fixed. Independent evidence and authenticated retest are required.'
   : 'This assignment remains a local planning note. It does not modify LightUp domain findings or certify a repaired issue.';
  safeText(card,'p',msg,'note');
 }
 const packet=available?LightUpCasework.makePacket(findings,cases,fingerprint):null;
 const preview=available?{
  kind:packet.kind,disposition:packet.disposition,authority:{authenticated:false,grant:false,execution:false},
  summary:totals,source_sha256:fingerprint,
  actions:cases.slice(0,8).map(c=>({finding_id:c.finding_id,status:c.status,owner:c.owner,due_date:c.due_date})),
  additional_actions_hidden:Math.max(0,cases.length-8)
 }:null;
 $('preview').textContent=preview?JSON.stringify(preview,null,2):'Nothing to preview.';
}
function download(name,mime,content){
 const file=new Blob([content],{type:mime}),url=URL.createObjectURL(file),link=document.createElement('a');
 link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),500);
}
async function withCsv(file){
 if(!file||file.size>LightUpCasework.MAX_BYTES)throw Error('CSV exceeds 1 MiB.');
 const source=LightUpCasework.parseCSV(await file.text());
 const hash=await LightUpCasework.digest(source);
 if(findings.length && !window.confirm('Replace current unsaved casework with imported findings?'))return false;
 findings=source;cases=source.map(LightUpCasework.newCase);fingerprint=hash;sourceLabel='LightUp CSV: '+file.name.slice(0,100);
 edited=true;pendingRefresh=null;resetRefreshUI();clearSchedulePreview();return true;
}
async function withPacket(file){
 if(!file||file.size>2097152)throw Error('Saved casework exceeds 2 MiB.');
 const payload=JSON.parse(await file.text(),(k,v)=>['__proto__','constructor','prototype'].includes(k)?undefined:v);
 const loaded=LightUpCasework.loadPacket(payload),actual=await LightUpCasework.digest(loaded.findings);
 if(loaded.source_sha256 && (!actual||loaded.source_sha256!==actual))throw Error('Finding source revision does not match saved casework.');
 if(findings.length && !window.confirm('Replace current unsaved casework with this saved draft?'))return false;
 findings=loaded.findings;cases=loaded.cases;fingerprint=actual;sourceLabel='Saved local casework: '+file.name.slice(0,100);
 edited=false;pendingRefresh=null;resetRefreshUI();clearSchedulePreview();return true;
}
for(const [id,load] of [['csvSource',withCsv],['caseworkSource',withPacket]]){
 $(id).addEventListener('change',async event=>{
  const file=event.target.files[0];event.target.value='';if(!file)return;
  try{
   const changed=await load(file);
   if(changed){inform('Imported '+findings.length+' finding(s) into a local repair plan. Save your changes to JSON.');render();}
   else inform('Import cancelled; existing local plan unchanged.');
  }catch(err){inform('Import rejected: '+(err.message||'invalid or unsupported file')+'. Current plan unchanged.');}
 });
}


function clearSchedulePreview(){
 pendingSchedule=null;
 $('scheduleApply').disabled=true;
 $('scheduleText').textContent='No pending planning date suggestions. Preview again after editing or changing a source.';
}
function severityPolicy(){
 return {
  critical:Number($('daysCritical').value),high:Number($('daysHigh').value),
  medium:Number($('daysMedium').value),low:Number($('daysLow').value),
  info:Number($('daysInfo').value)
 };
}
for(const id of ['scheduleAnchor','daysCritical','daysHigh','daysMedium','daysLow','daysInfo'])
 $(id).addEventListener('input',clearSchedulePreview);
const date=new Date();
$('scheduleAnchor').value=new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,10);
$('schedulePreview').addEventListener('click',()=>{
 if(!findings.length)return;
 try{
  pendingSchedule=LightUpRemediationSchedule.prepare(findings,cases,$('scheduleAnchor').value,severityPolicy());
  $('scheduleApply').disabled=!pendingSchedule.entries.length;
  const examples=pendingSchedule.entries.slice(0,15).map(e=>e.finding_id+' · '+e.severity+' · '+e.proposed_due_date);
  $('scheduleText').textContent=pendingSchedule.entries.length+' local due dates suggested. Existing deadlines are never overwritten.\n'+
    (examples.join('\n')||'No eligible cases without deadlines.')+
    (pendingSchedule.entries.length>examples.length?'\n… '+(pendingSchedule.entries.length-examples.length)+' more':'')+
    '\nThese are not verified or contractually binding SLAs.';
  inform('Review proposed dates; apply only after explicit confirmation. Unassigned dates remain unchanged until then.');
 }catch(err){clearSchedulePreview();inform('Planning policy rejected: '+(err.message||'invalid date')+'.');}
});
$('scheduleApply').addEventListener('click',()=>{
 if(!pendingSchedule||!findings.length)return;
 let current;
 try{current=LightUpRemediationSchedule.prepare(findings,cases,$('scheduleAnchor').value,severityPolicy());}
 catch(err){clearSchedulePreview();inform('Planning dates require a new preview: '+(err.message||'invalid policy'));return;}
 if(JSON.stringify(current)!==JSON.stringify(pendingSchedule)){clearSchedulePreview();inform('Planning source changed; preview dates again.');return;}
 if(!window.confirm('Assign '+current.entries.length+' suggested deadlines to eligible open local cases? This does not override existing dates or establish contractual SLAs.'))return;
 const choices=new Map(current.entries.map(entry=>[entry.finding_id,entry.proposed_due_date]));
 const existingIds=ids(),now=new Date().toISOString();
 let updated;
 try{updated=cases.map(c=>choices.has(c.finding_id)?
  LightUpCasework.cleanCase({...c,due_date:choices.get(c.finding_id),updated_utc:now},existingIds):c);}
 catch(err){clearSchedulePreview();inform('Deadline plan refused: '+(err.message||'invalid value'));return;}
 cases=updated;edited=true;
 const count=choices.size;
 clearSchedulePreview();render();
 inform(count+' local deadline proposals assigned; source findings and genuine SLAs remain unchanged. Export JSON to retain the plan.');
});

function resetRefreshUI(){
 $('refreshReview').replaceChildren();
 safeText($('refreshReview'),'p','No source refresh pending. Import newer findings CSV to preview a difference without changing current work.');
 $('sameSource').checked=false;$('applyRefresh').disabled=true;$('refreshSource').value='';
}
function showRefresh(){
 $('refreshReview').replaceChildren();
 const pending=pendingRefresh;
 if(!pending){resetRefreshUI();return;}
 const d=pending.diff;
 safeText($('refreshReview'),'h3','Proposed source refresh (not yet applied)');
 safeText($('refreshReview'),'p','New findings: '+d.added.length+' · changed: '+d.changed.length+
  ' · absent from new export: '+d.missing.length+' · unchanged: '+d.unchanged.length+'.');
 safeText($('refreshReview'),'p','Only unchanged IDs keep local actions; new/changed findings are reset. Absent IDs leave the current board but remain in your separately saved old draft.');
 const list=document.createElement('ul');$('refreshReview').append(list);
 for(const id of d.added.slice(0,50))safeText(list,'li','NEW: '+id);
 for(const item of d.changed.slice(0,50))safeText(list,'li','CHANGED '+item.finding_id+' · '+item.changed_fields.join(', '));
 for(const id of d.missing.slice(0,50))safeText(list,'li','ABSENT, NOT VERIFIED FIXED: '+id);
 if(d.added.length>50||d.changed.length>50||d.missing.length>50)
  safeText($('refreshReview'),'p','Review preview truncated; save the old draft and compare full source exports outside this non-authorizing tool.');
 $('applyRefresh').disabled=!$('sameSource').checked;
}
$('refreshSource').addEventListener('change',async e=>{
 const file=e.target.files[0];e.target.value='';
 if(!file)return;
 if(!findings.length){inform('Import an existing LightUp source CSV or saved draft before refreshing.');return;}
 try{
  if(file.size>LightUpCasework.MAX_BYTES)throw Error('CSV exceeds 1 MiB.');
  const incoming=LightUpCasework.parseCSV(await file.text());
  const hash=await LightUpCasework.digest(incoming);
  const diff=LightUpCasework.compareSource(findings,incoming);
  pendingRefresh={incoming,hash,diff,label:file.name.slice(0,100)};
  $('sameSource').checked=false;showRefresh();
  inform('Review source additions and removals. Export your current casework JSON before applying a refresh.');
 }catch(err){pendingRefresh=null;resetRefreshUI();inform('Refresh preview rejected: '+(err.message||'invalid source')+'. Current plan unchanged.');}
});
$('sameSource').addEventListener('change',()=>{$('applyRefresh').disabled=!(pendingRefresh&&$('sameSource').checked);});
$('cancelRefresh').addEventListener('click',()=>{pendingRefresh=null;resetRefreshUI();inform('Refresh preview cleared. Existing casework unchanged.');});
$('applyRefresh').addEventListener('click',()=>{
 if(!pendingRefresh||!$('sameSource').checked||!findings.length)return;
 if(!window.confirm('Apply revised source? Changed findings lose old casework assignments and absent findings are removed from the working board. Save your current casework JSON first.'))return;
 const {findings:newFindings,cases:newCases,change_summary:d}=LightUpCasework.reconcileSource(findings,cases,pendingRefresh.incoming);
 findings=newFindings;cases=newCases;fingerprint=pendingRefresh.hash;sourceLabel='Refreshed LightUp CSV: '+pendingRefresh.label;
 edited=true;pendingRefresh=null;resetRefreshUI();clearSchedulePreview();render();
 inform('Source refreshed locally: '+d.added.length+' new, '+d.changed.length+' changed/reset, '+d.missing.length+' absent/not fixed, '+d.unchanged.length+' unchanged assignments kept. Export updated JSON.');
});

for(const id of ['search','severity','workflow','sort'])$(id).addEventListener(id==='search'?'input':'change',render);

$('bulkApply').addEventListener('click',()=>{
 const matching=filteredFindings();if(!matching.length)return;
 const owner=$('bulkOwner').value.trim(),due=$('bulkDue').value||null;
 if(!owner&&!due){inform('Specify an owner/team and/or a target date before bulk assignment.');return;}
 if(owner.length>120){inform('Team name is too long.');return;}
 if(!window.confirm('Apply '+(owner?'owner/team ':'')+(due?'due date ':'')+'to '+matching.length+' currently filtered findings? This changes local planning only.'))return;
 const matched=new Set(matching.map(f=>f.finding_id)),all=ids(),now=new Date().toISOString();
 let revised;
 try{
  revised=cases.map(c=>{
   if(!matched.has(c.finding_id))return c;
   return LightUpCasework.cleanCase({...c,...(owner?{owner}:{}),...(due?{due_date:due}:{}),updated_utc:now},all);
  });
 }catch(err){inform('Bulk change rejected: '+(err.message||'invalid field')+'. No changes made.');return;}
 cases=revised;edited=true;clearSchedulePreview();
 inform('Updated '+matched.size+' filtered local remediation assignments. Export JSON to save.');
 render();
});
window.addEventListener('beforeunload',event=>{
 if(!edited||!findings.length)return;
 event.preventDefault();event.returnValue='';
});

$('save').addEventListener('click',()=>{
 if(!findings.length)return;
 const packet=LightUpCasework.makePacket(findings,cases,fingerprint);
 download('lightup-remediation-casework.json','application/json',JSON.stringify(packet,null,2)+'\n');
 edited=false;inform('Local JSON casework draft exported; it is not signed or submitted to LightUp.');render();
});
$('exportCSV').addEventListener('click',()=>{
 if(!findings.length)return;
 download('lightup-remediation-actions.csv','text/csv',LightUpCasework.exportActionsCSV(findings,cases));
 inform('Local action CSV exported; planning statuses are not real retest outcomes.');
});
function safeMD(s){
 return String(s??'').replace(/[\x60\\*_{}\[\]<>#!|]/g,'\\$&').replace(/\r/g,'').replace(/\n/g,' ');
}
function brief(){
 const by=byId(),totals=LightUpCasework.metrics(findings,cases,new Date().toISOString().slice(0,10));
 const out=['# LightUp client remediation coordination draft','',
 'Local planning only: not authenticated evidence, permission, grant, verified retest, or remediation closure.','',
 'Source SHA-256 (unsigned): '+(fingerprint||'unavailable'),'',
 '## Portfolio overview','',
 '- Findings: '+totals.findings,'- Critical/high: '+totals.critical_or_high,
 '- Blocked: '+totals.blocked,'- Overdue: '+totals.overdue,'- Ready for retest coordination: '+totals.ready_for_retest,''];
 for(const f of findings.slice().sort((a,b)=>LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity))){
  const c=by.get(f.finding_id);
  out.push('## '+safeMD(f.title),'','- ID: '+safeMD(f.finding_id),
   '- Severity: '+f.severity,'- Source retest status (unverified here): '+f.retest_status,
   '- Local work stage: '+c.status,'- Assigned team: '+safeMD(c.owner||'unassigned'),
   '- Due date: '+(c.due_date||'unplanned'),'','### Source remediation recommendation','',
   safeMD(f.remediation),'','### Action / retest / dependency','',
   'Action: '+safeMD(c.next_action||'not planned'),'',
   'Verification approach: '+safeMD(c.verification_plan||'not planned'),'',
   'Blocker: '+safeMD(c.blocker||'none recorded'),'');
 }
 out.push('---','All entries require independent owner and authorization checks and genuine authenticated retest before closure.','');
 return out.join('\n');
}
$('exportMD').addEventListener('click',()=>{
 if(!findings.length)return;
 download('lightup-remediation-brief.md','text/markdown',brief());
 inform('Local Markdown remediation brief exported.');
});
$('print').addEventListener('click',()=>{if(findings.length)window.print();});
$('reset').addEventListener('click',()=>{
 if(!findings.length)return;
 if(!window.confirm('Erase all imported findings and unsaved edits from this tab?'))return;
 findings=[];cases=[];fingerprint=null;sourceLabel='';edited=false;pendingRefresh=null;resetRefreshUI();clearSchedulePreview();
 $('search').value='';$('severity').value='';$('workflow').value='';
 inform('Workspace cleared; no browser storage or server request was used.');render();
});
resetRefreshUI();render();
})();