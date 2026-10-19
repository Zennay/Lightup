/* LightUp ticket desk: HUMAN-only local Markdown drafting. No network, state store, or issue API. */
(() => {
'use strict';
const byId = id => document.getElementById(id);
const ui = Object.fromEntries(['source-file','casework-file','search','severity','select-visible','clear-visible','select-urgent','findings','forget','chosen','owner','due','stage','action','review','blocker','apply','preview','notice','preview-output','private-ack','export-one','export-all','export-counts','source-diff','historical-holds','export-holds','metric-count','metric-risk','metric-picked','metric-hash'].map(k=>[k,byId(k)]));
const engine = window.LightUpCasework;
if (!engine || typeof engine.parseCSV !== 'function' || typeof engine.digest !== 'function') {
 ui.notice.textContent='Original source-owned Casework engine unavailable. Do not use this page without the complete pinned parent checkout.';
 ui.notice.classList.add('error');
 return;
}
const MAX_BYTES=1048576, MAX_DRAFTS=350;
const stages=['triage','planned','blocked','in_progress','ready_for_review'];
const forbidden = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const todayUTC=()=>new Date().toISOString().slice(0,10);
let state=null, active='';
function show(msg, bad=false){ui.notice.textContent=msg;ui.notice.classList.toggle('error',bad);}
function setControls(ready){
 for(const id of ['search','severity','select-visible','clear-visible','select-urgent','forget','chosen','export-counts','casework-file','private-ack'])ui[id].disabled=!ready;
 updateEditor();
 updateButtons();
}
function updateButtons(){
 const chosen=state&&active&&state.selected.has(active);
 const permitted=!!(state&&ui['private-ack'].checked);
 ui['export-one'].disabled=!(chosen&&permitted);
 ui['export-all'].disabled=!(state&&state.selected.size&&permitted);
 ui['export-counts'].disabled=!state;
 ui['export-holds'].disabled=!(state&&state.holds.length&&permitted);
}
function byteHex(buf){return Array.from(new Uint8Array(buf),b=>b.toString(16).padStart(2,'0')).join('');}
async function sha(bytes){if(!crypto?.subtle)throw Error('Secure SHA-256 unavailable in this local browser; source-bound export is disabled.');return byteHex(await crypto.subtle.digest('SHA-256',bytes));}
function checkText(x,field){
 if(typeof x!=='string'||forbidden.test(x))throw Error('Ambiguous control/invisible format character in '+field+'; no source imported.');
}
function draft(){return {owner:'',due:'',stage:'triage',action:'',review:'',blocker:''};}
function forget(){
 state=null;active='';
 ui['source-file'].value='';ui['casework-file'].value='';ui.search.value='';ui.severity.value='all';ui['private-ack'].checked=false;
 ui.findings.replaceChildren();const row=ui.findings.insertRow();const cell=row.insertCell();cell.colSpan=4;cell.textContent='Import a local source file to begin.';
 ui.chosen.replaceChildren(new Option('No finding selected',''));
 ui['preview-output'].textContent='Nothing selected yet.';
 ui['source-diff'].textContent='No source revision imported.';
 ui['historical-holds'].replaceChildren();const hrow=ui['historical-holds'].insertRow(),hcell=hrow.insertCell();hcell.colSpan=3;hcell.textContent='No historical source HOLD records.';
 ui['metric-count'].textContent='—';ui['metric-risk'].textContent='—';ui['metric-picked'].textContent='—';ui['metric-hash'].textContent='—';
 setControls(false);show('Private source and HUMAN notes forgotten from this tab. Any previously downloaded files require separate secure deletion.');
}
function filterItems(){
 if(!state)return[];
 const needle=ui.search.value.trim().toLocaleLowerCase();
 return state.rows.filter(f=>(ui.severity.value==='all'||f.severity===ui.severity.value)&&
 (!needle||(f.finding_id+' '+f.title).toLocaleLowerCase().includes(needle)));
}
function refresh(){
 if(!state)return;
 const list=filterItems(),frag=document.createDocumentFragment();
 for(const f of list){
  const tr=document.createElement('tr');tr.dataset.active=String(f.finding_id===active);
  const checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.checked=state.selected.has(f.finding_id);checkbox.setAttribute('aria-label','Select '+f.finding_id);checkbox.dataset.id=f.finding_id;
  const a=tr.insertCell();a.appendChild(checkbox);
  const name=tr.insertCell();const btn=document.createElement('button');btn.type='button';btn.textContent=f.finding_id+' · '+f.title;btn.dataset.pick=f.finding_id;name.appendChild(btn);
  const risk=tr.insertCell();const pill=document.createElement('span');pill.className='severity '+f.severity;pill.textContent=f.severity;risk.appendChild(pill);
  tr.insertCell().textContent=f.retest_status;frag.appendChild(tr);
 }
 if(!list.length){const tr=document.createElement('tr'),td=tr.insertCell();td.colSpan=4;td.textContent='No rows match your filter.';frag.appendChild(tr);}
 ui.findings.replaceChildren(frag);
 const chosen=active;
 ui.chosen.replaceChildren(new Option('Choose a selected finding',''));
 for(const f of state.rows.filter(x=>state.selected.has(x.finding_id))) ui.chosen.add(new Option(f.finding_id+' · '+f.title.slice(0,65),f.finding_id));
 if(chosen&&state.selected.has(chosen)){ui.chosen.value=chosen;}else{active='';}
 ui['metric-picked'].textContent=state.selected.size;
 renderHolds();updateEditor();updateButtons();
}
function renderHolds(){
 if(!state)return;
 const frag=document.createDocumentFragment();
 for(const h of state.holds){
  const tr=document.createElement('tr');tr.insertCell().textContent=h.finding.finding_id+' · '+h.finding.title;
  tr.insertCell().textContent=h.reason.toUpperCase()+' (never transferred)';
  tr.insertCell().textContent=(h.draft.owner||'Unassigned')+' · '+(h.draft.action||'No HUMAN action')+' · '+h.draft.stage;
  frag.appendChild(tr);
 }
 if(!state.holds.length){const tr=document.createElement('tr'),td=tr.insertCell();td.colSpan=3;td.textContent='No historical HUMAN source HOLD records.';frag.appendChild(tr);}
 ui['historical-holds'].replaceChildren(frag);
}
function updateEditor(){
 const enabled=!!(state&&active&&state.selected.has(active));
 for(const name of ['owner','due','stage','action','review','blocker','apply','preview'])ui[name].disabled=!enabled;
 if(!enabled){
  for(const name of ['owner','due','action','review','blocker'])ui[name].value='';
  ui.stage.value='triage';return;
 }
 const d=state.drafts.get(active)||draft();
 for(const name of ['owner','due','stage','action','review','blocker'])ui[name].value=d[name];
}
function markSelected(id,choice){
 if(!state||!state.byId.has(id))return;
 if(choice)state.selected.add(id);else state.selected.delete(id);
 if(!choice&&active===id)active='';
 refresh();
}
function setMany(ids,which){
 if(!state)return;
 for(const id of ids)which?state.selected.add(id):state.selected.delete(id);
 refresh();
}
function validDate(day){
 if(!day)return true;
 if(!/^\d{4}-\d{2}-\d{2}$/.test(day))return false;
 const x=new Date(day+'T00:00:00.000Z');return !Number.isNaN(x.valueOf())&&x.toISOString().slice(0,10)===day;
}
function collectDraft(){
 const d={};
 for(const n of ['owner','due','stage','action','review','blocker'])d[n]=ui[n].value;
 for(const [key,max] of [['owner',120],['action',1200],['review',1200],['blocker',800]]){
  if(d[key].length>max)throw Error('Too long: '+key);
  checkText(d[key],key);
 }
 if(!stages.includes(d.stage)||!validDate(d.due))throw Error('Invalid stage or date.');
 return d;
}
function escapeMarkdown(value){
 const str=String(value);
 checkText(str,'ticket field');
 // Escape Markdown, HTML, task syntax and autolink/mention delimiters rather than rendering source text as markup.
 return str.replace(/[\r\n\t]+/g,' ').replace(/[\\`*_{}\[\]()#+.!|>~<>@&]/g,c=>'\\'+c);
}
function ticket(f){
 const d=state.drafts.get(f.finding_id)||draft();
 const md=escapeMarkdown;
 return '# HUMAN remediation proposal — '+md(f.title)+'\n\n'+
  '> PRIVATE DRAFT / UNVERIFIED SOURCE CLAIM / PLAN-LAB ONLY / NOT AN AUTHORIZATION OR COMPLETED RETEST.\n'+
  '> Independently confirm client identity, recipient and owner before any manual issue creation.\n\n'+
  '## Original LightUp source summary (read-only)\n'+
  '- Finding ID: '+md(f.finding_id)+'\n'+
  '- Source severity: '+md(f.severity)+'\n'+
  '- Source retest label (unverified): '+md(f.retest_status)+'\n'+
  '- Source-reported remediation proposal: '+md(f.remediation)+'\n\n'+
  '## HUMAN work coordination (self-declared, unverified)\n'+
  '- Proposed owner alias: '+md(d.owner||'Unassigned')+'\n'+
  '- Tentative date: '+md(d.due||'Unscheduled')+'\n'+
  '- HUMAN stage: '+md(d.stage)+'\n'+
  '- Proposed next action: '+md(d.action||'Triage with a human owner')+'\n'+
  '- Proposed verification plan (no execution requested): '+md(d.review||'Independent review needed')+'\n'+
  '- Blocking dependency: '+md(d.blocker||'None recorded')+'\n\n'+
  '## Non-authority and source trace\n'+
  '- Original Casework canonical summary SHA-256 (unsigned): '+state.canonical+'\n'+
  '- Imported original CSV byte SHA-256 (unsigned): '+state.bytesHash+'\n'+
  '- This draft is NOT authenticated, NOT evidence verification, NOT a grant, NOT client/operator consent, NOT a scan permission, NOT a confirmed fix or retest, and NOT release approval.\n'+
  '- Source disappearance or a source \"fixed\" label is NOT proof of remediation.\n';
}
function counts(){
 const severities=Object.fromEntries(engine.SEVERITY.map(k=>[k,0]));
 const retests=Object.fromEntries(engine.RETEST.map(k=>[k,0]));
 const picked=Object.fromEntries(engine.SEVERITY.map(k=>[k,0]));
 for(const f of state.rows){severities[f.severity]++;retests[f.retest_status]++;if(state.selected.has(f.finding_id))picked[f.severity]++;}
 return {kind:'lightup.anonymous_human_ticket_counts',schema_version:1,disposition:'PRIVATE_REVIEW_ONLY',
  authenticated:false,source_authorized:false,assessment_authorized:false,grant:false,client_consent:false,operator_consent:false,execution:false,scan:false,retest_verified:false,release:false,
  findings:state.rows.length,selected:state.selected.size,historical_human_source_hold:state.holds.length,severities,source_retest_labels:retests,selected_severities:picked,
  warning:'Aggregates count unverified source labels and human selections only. Not a verified fix, retest, grant, consent or authority.'};
}
function download(text,name,type){
 const blob=new Blob([text],{type});const url=URL.createObjectURL(blob);
 try{const a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();}
 finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
function canDownload(){
 if(!state||!ui['private-ack'].checked)throw Error('Approve the PRIVATE channel and recipient review first.');
 if(!confirm('This PRIVATE plaintext draft contains original findings and HUMAN notes. Confirm independently authorized local storage and recipients. No remote issue will be created.'))return false;
 return true;
}
function hasHumanWork(d){
 return !!(d&&(d.owner||d.due||d.action||d.review||d.blocker||d.stage!=='triage'));
}
async function importCSV(file){
 if(!file)return;
 if(!Number.isSafeInteger(file.size)||file.size>MAX_BYTES)throw Error('Source exceeds original 1 MiB.');
 const bytes=await file.arrayBuffer();
 if(bytes.byteLength>MAX_BYTES)throw Error('CSV too large.');
 let text;
 try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch(e){throw Error('Invalid UTF-8 source bytes.');}
 const imported=engine.parseCSV(text);
 for(const f of imported)for(const col of ['finding_id','title','severity','retest_status','remediation'])checkText(f[col],col);
 const [canonical,bytesHash]=await Promise.all([engine.digest(imported),sha(bytes)]);
 if(!canonical||!/^[0-9a-f]{64}$/.test(canonical))throw Error('Canonical SHA-256 unavailable; import blocked.');
 const byId=new Map(imported.map(f=>[f.finding_id,f]));
 const previous=state;
 const next={rows:imported,byId,selected:new Set(),drafts:new Map(),canonical,bytesHash,holds:[]};
 let message='First original source imported. No source revision compared.';
 if(previous){
  if(previous.bytesHash===bytesHash){show('Identical source bytes: prior HUMAN work remains untouched.');return;}
  const diff=engine.compareSource(previous.rows,imported);
  const same=new Set(diff.unchanged),holdIds=new Set([...diff.missing,...diff.changed.map(x=>x.finding_id)]);
  const holds=previous.holds.slice();
  for(const f of previous.rows){
   if(!holdIds.has(f.finding_id))continue;
   const d=previous.drafts.get(f.finding_id)||draft();
   if(hasHumanWork(d)||previous.selected.has(f.finding_id))
    holds.push({finding:{...f},draft:{...d},canonical:previous.canonical,bytesHash:previous.bytesHash,
     reason:diff.missing.includes(f.finding_id)?'missing':'changed'});
  }
  if(holds.length>MAX_DRAFTS)throw Error('Historical HUMAN source HOLD inbox would exceed 350. Export/archive existing holds privately before changing source.');
  // Original five-field unchanged classification is the only basis for HUMAN carry.
  for(const id of same){
   if(previous.drafts.has(id))next.drafts.set(id,previous.drafts.get(id));
   if(previous.selected.has(id))next.selected.add(id);
  }
  next.holds=holds;
  message='Source revision: '+diff.added.length+' added, '+diff.changed.length+' changed, '+diff.missing.length+' missing, '+diff.unchanged.length+' exactly unchanged. '+holds.length+' prior HUMAN draft(s) in historical SOURCE HOLD. No missing/“fixed” source claim proves a resolved issue.';
  if(!confirm('SOURCE REVISION — independently verify this NEW export is the SAME client and engagement. '+message+' Only exact unchanged original five-field findings may keep HUMAN notes. Changed/missing notes are quarantined, never promoted. Continue?'))return;
 }
 state=next;active='';ui['casework-file'].value='';ui['private-ack'].checked=false;ui.search.value='';ui.severity.value='all';
 ui['metric-count'].textContent=imported.length;
 ui['metric-risk'].textContent=imported.filter(f=>['critical','high'].includes(f.severity)).length;
 ui['metric-hash'].textContent=canonical.slice(0,10)+'…';
 ui['source-diff'].textContent=message;
 setControls(true);refresh();
 show('Original CSV source bound to canonical '+canonical.slice(0,16)+'… and bytes '+bytesHash.slice(0,16)+'…. '+message);
}

ui['source-file'].addEventListener('change',async event=>{
 try{await importCSV(event.target.files[0]);}catch(err){show('IMPORT HOLD: '+err.message,true);}
});
ui['casework-file'].addEventListener('change',async event=>{
 const file=event.target.files[0];
 if(!file)return;
 try{
  if(!state)throw Error('Import the original five-column CSV first.');
  if(!Number.isSafeInteger(file.size)||file.size>2*MAX_BYTES)throw Error('Casework packet exceeds 2 MiB.');
  const bytes=await file.arrayBuffer();
  let text;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch(e){throw Error('Invalid Casework UTF-8.');}
  if(!window.LightUpTicketIntake)throw Error('Offline Casework intake unavailable.');
  const reviewed=window.LightUpTicketIntake.decode(text,state.rows,state.canonical);
  if(!confirm('Import '+reviewed.drafts.size+' source-bound original HUMAN Casework entries? Existing local HUMAN edits will be replaced. Prior completed/deferred labels become unverified triage. This does NOT prove client identity, consent or a verified retest.'))return;
  state.drafts=reviewed.drafts;
  for(const id of reviewed.suggested)state.selected.add(id);
  if(!active&&state.selected.size)active=state.rows.find(f=>state.selected.has(f.finding_id)).finding_id;
  ui['private-ack'].checked=false;
  refresh();
  show('Loaded '+reviewed.drafts.size+' original Casework HUMAN entries, preselected '+reviewed.suggested.size+' with existing work; '+reviewed.resetCompleted+' completed/deferred HUMAN labels reset to triage. No source mutation. Re-approve any private export.');
 }catch(err){show('CASEWORK HOLD: '+err.message,true);}
});
ui.findings.addEventListener('change',event=>{const id=event.target?.dataset?.id;if(id)markSelected(id,event.target.checked);});
ui.findings.addEventListener('click',event=>{const id=event.target?.dataset?.pick;if(!id)return;state.selected.add(id);active=id;refresh();});
ui.search.addEventListener('input',refresh);
ui.severity.addEventListener('change',refresh);
ui['select-visible'].addEventListener('click',()=>setMany(filterItems().map(x=>x.finding_id),true));
ui['clear-visible'].addEventListener('click',()=>setMany(filterItems().map(x=>x.finding_id),false));
ui['select-urgent'].addEventListener('click',()=>setMany(state.rows.filter(x=>['critical','high'].includes(x.severity)).map(x=>x.finding_id),true));
ui.chosen.addEventListener('change',()=>{active=ui.chosen.value;refresh();});
ui.apply.addEventListener('click',()=>{
 try{const d=collectDraft();state.drafts.set(active,Object.freeze(d));ui['private-ack'].checked=false;updateButtons();show('Saved HUMAN draft for '+active+' only in browser memory. Re-approve before exporting.');}
 catch(err){show('DRAFT HOLD: '+err.message,true);}
});
ui.preview.addEventListener('click',()=>{try{ui['preview-output'].textContent=ticket(state.byId.get(active));show('Read-only Markdown preview; no issue has been created.');}catch(err){show(err.message,true);}});
ui['private-ack'].addEventListener('change',updateButtons);
ui['export-counts'].addEventListener('click',()=>{if(!state)return;download(JSON.stringify(counts(),null,2)+'\n','lightup-anonymous-ticket-counts.json','application/json;charset=utf-8');show('Anonymous counts-only export created without source IDs, titles, owner aliases or source hashes.');});
ui['export-one'].addEventListener('click',()=>{
 try{if(!canDownload())return;download(ticket(state.byId.get(active)),'lightup-PRIVATE-human-ticket.md','text/markdown;charset=utf-8');show('One PRIVATE HUMAN Markdown draft downloaded locally. Manual approved issue creation only.');}
 catch(err){show('EXPORT HOLD: '+err.message,true);}
});
ui['export-all'].addEventListener('click',()=>{
 try{
  if(!canDownload())return;
  const selected=state.rows.filter(f=>state.selected.has(f.finding_id));
  if(!selected.length||selected.length>MAX_DRAFTS)throw Error('Invalid selection size.');
  const body=selected.map((f,i)=>'<!-- HUMAN DRAFT '+(i+1)+'/'+selected.length+'; manually separate tickets; DO NOT POST AS ONE PUBLIC ISSUE -->\n\n'+ticket(f)).join('\n\n---\n\n');
  if(new TextEncoder().encode(body).length>5*MAX_BYTES)throw Error('Private handoff too large.');
  download(body,'lightup-PRIVATE-human-ticket-bundle.md','text/markdown;charset=utf-8');
  show(selected.length+' PRIVATE HUMAN ticket drafts downloaded in one local Markdown bundle. They have NOT been posted to GitHub.');
 }catch(err){show('BUNDLE HOLD: '+err.message,true);}
});
ui['export-holds'].addEventListener('click',()=>{
 try{
  if(!canDownload())return;
  if(!state.holds.length)throw Error('No historical source HOLD notes.');
  const md=state.holds.map((h,i)=>
   '# HISTORICAL HUMAN SOURCE HOLD '+(i+1)+' / '+state.holds.length+'\n\n'+
   '> OLD SOURCE: '+h.reason.toUpperCase()+' — not current finding; never resolved by absence.\n\n'+
   '- Old original finding ID: '+escapeMarkdown(h.finding.finding_id)+'\n'+
   '- Old original title: '+escapeMarkdown(h.finding.title)+'\n'+
   '- Old original severity: '+escapeMarkdown(h.finding.severity)+'\n'+
   '- Old original source retest label: '+escapeMarkdown(h.finding.retest_status)+'\n'+
   '- Old original proposed remediation: '+escapeMarkdown(h.finding.remediation)+'\n'+
   '- Old source canonical SHA-256 (unsigned): '+h.canonical+'\n'+
   '- Old CSV bytes SHA-256 (unsigned): '+h.bytesHash+'\n'+
   '- OLD HUMAN owner: '+escapeMarkdown(h.draft.owner)+'\n'+
   '- OLD HUMAN stage (unverified): '+escapeMarkdown(h.draft.stage)+'\n'+
   '- OLD HUMAN tentative due: '+escapeMarkdown(h.draft.due)+'\n'+
   '- OLD HUMAN next action: '+escapeMarkdown(h.draft.action)+'\n'+
   '- OLD HUMAN verification plan: '+escapeMarkdown(h.draft.review)+'\n'+
   '- OLD HUMAN blocker: '+escapeMarkdown(h.draft.blocker)+'\n'+
   '- HOLD does not establish authenticity, retest, fix, grant, consent or action permission.\n'
  ).join('\n---\n\n');
  if(new TextEncoder().encode(md).length>5*MAX_BYTES)throw Error('Historical private HOLD handoff exceeds size limit.');
  download(md,'lightup-PRIVATE-historical-source-HOLD.md','text/markdown;charset=utf-8');
  show('PRIVATE historical source-HOLD snapshot downloaded; not an active ticket or verified resolution.');
 }catch(err){show('HISTORICAL HOLD EXPORT: '+err.message,true);}
});
ui.forget.addEventListener('click',()=>{if(!state||confirm('Forget all source findings, selections and HUMAN drafts in this tab?'))forget();});
window.addEventListener('beforeunload',e=>{if(state){e.preventDefault();e.returnValue='';}});
forget();
})();