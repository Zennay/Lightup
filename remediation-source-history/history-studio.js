/* LightUp Source History Studio — local HUMAN planning only. No authorization or security verdicts. */
(() => {
"use strict";
const $ = id => document.getElementById(id);
const state = { snapshots:[], notes:new Map(), decisions:[], merges:[], active:null, revision:0, importing:false };
const FIELDS = ['finding_id','title','severity','retest_status','remediation'];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const severityRank = {critical:0,high:1,medium:2,low:3,info:4};
const limits = {maxSnapshots:12,maxBytes:1048576,maxRows:350,maxNotes:350,maxDecisions:200,maxMerges:50};
const toB64=bytes=>{let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s);};
function message(value, error=false) { $('message').textContent=value; $('message').className=error?'error':'info'; }
function exact(a,b) { return FIELDS.every(k=>a[k]===b[k]); }
function csvCell(v) {
 let s=String(v??'');
 const probe=s.replace(/^[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202e\u205f\u2060-\u206f\u3000\ufeff]*/u,'').normalize('NFKC');
 if(/^[=+\-@]/u.test(probe))s="'"+s;
 return '"'+s.replace(/"/g,'""')+'"';
}
function download(name,content,mime) {
 const url=URL.createObjectURL(new Blob([content],{type:mime}));
 const a=document.createElement('a');a.href=url;a.download=name;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function context() {
 const client=$('client').value.trim(), engagement=$('engagement').value.trim();
 if (!client||!engagement||client.length>120||engagement.length>120||!$('ack').checked)
  throw Error('Enter independently verified client and engagement labels, and acknowledge the PRIVATE handling requirement. Labels are not authentication.');
 return {client,engagement};
}
function requireContext() {
 const current=context();
 if (!state.active) state.active=current;
 if (state.active.client!==current.client||state.active.engagement!==current.engagement)
  throw Error('Human context changed. Forget current private data before switching client or engagement.');
 return current;
}
function protect() {
 if (!$('privateAck').checked) throw Error('Acknowledge approved PRIVATE destination and recipient before exporting finding-level data.');
}
async function sha(bytes) {
 if(!window.crypto?.subtle)throw Error('SHA-256 unavailable: secure browser context required. No file loaded.');
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function ingest(files) {
 if(state.importing)throw Error('Original import already underway; finish it before importing more.');
 const ctx=requireContext(),baseline=state.revision;const input=Array.from(files);
 if (!input.length) throw Error('Choose at least one original CSV.');
 if (state.snapshots.length+input.length>limits.maxSnapshots) throw Error('At most 12 chronological exports.');
 state.importing=true;
 try {
 let parsed=[];
 for (const file of input) {
  if (file.size>limits.maxBytes||file.size===0) throw Error('Original CSV must be 1 MiB or smaller and nonempty.');
  const buf=await file.arrayBuffer(),data=new TextDecoder('utf-8',{fatal:true}).decode(buf);
  const findings=LightUpCasework.parseCSV(data);
  const hash=await LightUpCasework.digest(findings),fileHash=await sha(buf);
  if(!hash)throw Error('Original SHA-256 source digest unavailable.');
  if(state.snapshots.some(s=>s.sourceHash===hash)||parsed.some(s=>s.sourceHash===hash))throw Error('Duplicate canonical source snapshot; import only meaningful separate revisions.');
  const name=file.name.slice(0,160);
  parsed.push({name,label:'Revision '+(state.snapshots.length+parsed.length+1),sourceHash:hash,fileHash,findings,csvBase64:toB64(new Uint8Array(buf))});
 }
 // Multiple await boundaries: fail closed on user context switching while files are loading.
 const same=context();
 if(state.revision!==baseline||same.client!==ctx.client||same.engagement!==ctx.engagement||state.active?.client!==ctx.client||state.active?.engagement!==ctx.engagement)
  throw Error('Client/engagement context changed during import; no imported data committed.');
 state.snapshots.push(...parsed);state.revision++;render();
 message(parsed.length+' original source revision(s) loaded locally. Chronological order is your responsibility; missing does not mean fixed.');
 } finally {state.importing=false;}
}
function latestFinding(id) {return state.snapshots.at(-1)?.findings.find(f=>f.finding_id===id)||null;}
function noteBinding(id) {
 const n=state.notes.get(id),latest=latestFinding(id);
 if(!n)return 'none';
 if(!latest)return 'missing';
 return n.sourceRecord && exact(n.sourceRecord,latest)?'bound':'stale';
}
function boundNote(id) {return noteBinding(id)==='bound'?state.notes.get(id):null;}
function idSet() {const ids=new Set();state.snapshots.forEach(s=>s.findings.forEach(f=>ids.add(f.finding_id)));return ids;}
function timeline() {
 const snaps=state.snapshots,maps=snaps.map(s=>new Map(s.findings.map(f=>[f.finding_id,f])));
 const results=[];
 for(const id of idSet()) {
  const series=maps.map(m=>m.get(id)||null), present=series.filter(Boolean);
  let changed=0,added=0,missing=0,up=0,down=0,statusChanges=0,edits=[];
  for(let i=1;i<series.length;i++){
   const a=series[i-1],b=series[i];
   if(!a&&b){added++;edits.push('appeared at '+(i+1));}
   else if(a&&!b){missing++;edits.push('absent at '+(i+1));}
   else if(a&&b&&!exact(a,b)){
    changed++;edits.push('source changed at '+(i+1));
    if(severityRank[b.severity]<severityRank[a.severity])up++;
    if(severityRank[b.severity]>severityRank[a.severity])down++;
    if(b.retest_status!==a.retest_status)statusChanges++;
   }
  }
  const latest=series.at(-1),representative=latest||[...present].at(-1);
  const category=latest?(changed||added||missing?'changed':'stable'):'absent';
  results.push({id,series,latest,representative,changed,added,missing,up,down,statusChanges,category,edits});
 }
 return results.sort((a,b)=>(severityRank[a.representative.severity]-severityRank[b.representative.severity])||a.id.localeCompare(b.id));
}
function summary() {
 const snaps=state.snapshots;
 if(!snaps.length){$('summary').textContent='Import two or more original CSV exports to see change history.';return;}
 const views=timeline(),last=snaps.at(-1),critical=last.findings.filter(f=>severityRank[f.severity]<=1).length;
 const variations=views.filter(x=>x.changed||x.added||x.missing).length,vanished=views.filter(x=>!x.latest).length;
 const held=[...state.notes.keys()].filter(id=>noteBinding(id)!=='bound').length;
 $('summary').textContent=snaps.length+' snapshots · '+last.findings.length+' latest source findings · '+critical+' source-labelled critical/high · '+variations+' changed trajectories · '+vanished+' absent from latest (NOT confirmed fixed) · '+held+' HUMAN note(s) needing explicit source review';
}
function filtered() {
 const filter=$('filter').value.trim().toLowerCase(),kind=$('kind').value,sev=$('severity').value;
 return timeline().filter(x=>{
  const r=x.representative;
  if(kind==='held'&&!['stale','missing'].includes(noteBinding(x.id)))return false;
  if(kind==='bound'&&noteBinding(x.id)!=='bound')return false;
  if(kind==='changed'&&!x.changed)return false;
  if(kind==='added'&&!x.added)return false;
  if(kind==='absent'&&x.latest)return false;
  if(kind==='severity'&&!x.up&&!x.down)return false;
  if(kind==='retest'&&!x.statusChanges)return false;
  if(kind==='high'&&severityRank[r.severity]>1)return false;
  if(sev!=='all'&&r.severity!==sev)return false;
  return !filter||[x.id,r.title,r.remediation,boundNote(x.id)?.owner||''].join(' ').toLowerCase().includes(filter);
 });
}
function renderSnapshots() {
 $('snapshots').innerHTML=state.snapshots.map((s,i)=>'<li><div><label>Revision '+(i+1)+' label<input data-label="'+i+'" maxlength="100" value="'+esc(s.label)+'" aria-label="Revision '+(i+1)+' label"></label><small>'+s.findings.length+' original rows · canonical '+esc(s.sourceHash.slice(0,12))+'… · file '+esc(s.fileHash.slice(0,12))+'…</small></div><div class="tools"><button data-move="'+i+'" data-shift="-1" '+(i===0?'disabled':'')+'>↑</button><button data-move="'+i+'" data-shift="1" '+(i===state.snapshots.length-1?'disabled':'')+'>↓</button><button data-remove="'+i+'">Remove</button></div></li>').join('');
}
function renderGrid() {
 const rows=filtered(),stale=[...state.notes.keys()].filter(id=>noteBinding(id)!=='bound').length;
 $('count').textContent=rows.length+' trajectories matching current filters · '+stale+' HUMAN notes held for source review';
 $('grid').innerHTML=rows.slice(0,350).map(x=>{
  const r=x.representative,tag=x.latest?'present':'absent',binding=noteBinding(x.id);
  const cells=x.series.map((f,i)=>'<td class="'+(f?'':'missing')+'">'+(f?'<strong>'+esc(f.severity)+'</strong><br>'+esc(f.retest_status):'—')+'</td>').join('');
  return '<tr><td><button class="link" data-view="'+esc(x.id)+'">'+esc(x.id)+'</button><small>'+esc(r.title.slice(0,110))+'</small></td>'+cells+'<td><span class="pill">'+tag+'</span><small>'+esc(x.edits.join(' · ')||'No observed source delta')+'</small>'+(binding==='stale'||binding==='missing'?'<small><strong>HUMAN NOTE HELD — '+esc(binding)+'; not transferable without review</strong></small>':'')+'</td></tr>';
 }).join('');
 $('headers').innerHTML='<th>Original finding</th>'+state.snapshots.map((s,i)=>'<th>'+esc((i+1)+'. '+s.label.slice(0,36))+'</th>').join('')+'<th>Source change only</th>';
}
function renderDetail() {
 const id=state.selected;
 const entry=timeline().find(x=>x.id===id);
 if(!entry){$('detail').hidden=true;return;}
 $('detail').hidden=false;
 const r=entry.representative,n=state.notes.get(id)||{owner:'',action:'',due:''};
 $('detailTitle').textContent=r.title+' · '+id;
 $('detailSource').innerHTML=entry.series.map((f,i)=>'<article class="snapshot"><h4>'+esc((i+1)+'. '+state.snapshots[i].label)+'</h4>'+(f?'<p><b>Source claim:</b> '+esc(f.severity)+' / '+esc(f.retest_status)+'</p><p><b>Suggested remediation (source text):</b> '+esc(f.remediation)+'</p>':'<p>Absent from this export; not proof of remediation.</p>')+'</article>').join('');
 $('humanOwner').value=n.owner;$('humanAction').value=n.action;$('humanDue').value=n.due;
 $('caseworkNative').hidden=!n.caseworkOriginal;
 if(n.caseworkOriginal){
   const c=n.caseworkOriginal;
   $('caseworkNative').innerHTML='<b>Original HUMAN Casework v1 (unverified source-only)</b>'+
   '<p>Human status: '+esc(c.status)+' · last HUMAN updated: '+esc(c.updated_utc||'not recorded')+'</p>'+
   '<p><b>Original blocker:</b> '+esc(c.blocker||'none')+'</p>'+
   '<p><b>Original HUMAN verification plan:</b> '+esc(c.verification_plan||'none')+'</p>'+
   '<p><b>Original HUMAN note:</b> '+esc(c.note||'none')+'</p>';
 }
 const priorDecisions=state.decisions.filter(x=>x.id===id);
 $('carryJournal').innerHTML=priorDecisions.length?'<h4>PRIVATE HUMAN carry decision history (not security approval)</h4>'+priorDecisions.map(d=>
   '<article class="snapshot"><p><b>Human local time:</b> '+esc(d.decidedUTC)+'</p><p><b>Reason:</b> '+esc(d.reason)+'</p>'+
   '<p>Previous original: '+esc(d.from.severity)+' / '+esc(d.from.retest_status)+' → current original at human carry: '+esc(d.to.severity)+' / '+esc(d.to.retest_status)+'</p></article>').join(''):'';
 const binding=noteBinding(id),held=binding==='stale'||binding==='missing';
 const original=n.sourceRecord;
 $('sourceChangeReview').hidden=!held;
 if(held){
   const changes=original&&entry.latest?FIELDS.filter(k=>original[k]!==entry.latest[k]):FIELDS;
   $('sourceChangeReview').innerHTML='<strong>HUMAN SOURCE HOLD</strong><p>The note was attached to an older exact original row, or lacks a verified row binding. Current source differences: <b>'+esc(changes.join(', '))+'</b>.</p>'+
    (original?'<div class="revisions"><article class="snapshot"><h4>Prior original note binding</h4>'+FIELDS.map(k=>'<p><b>'+esc(k)+':</b> '+esc(original[k])+'</p>').join('')+'</article>'+
    (entry.latest?'<article class="snapshot"><h4>Latest original source</h4>'+FIELDS.map(k=>'<p><b>'+esc(k)+':</b> '+esc(entry.latest[k])+'</p>').join('')+'</article>':'<article class="snapshot"><h4>Missing from latest original export</h4><p>Absence is not evidence of a fix. The HUMAN note stays quarantined.</p></article>')+'</div>':'<p>Prior exact row binding unavailable (older archive). Treat the old note as unverified and review before manual carry.</p>');
 }
 $('humanBinding').textContent=held
  ? (binding==='missing'?'HOLD: original finding is absent from the latest source. No carry or export permitted.':'HOLD: exact original five-field finding changed (or old note has no original row binding). Review both source versions before deliberate HUMAN carry.')
  : (binding==='bound'?'Current HUMAN note is bound to the exact five-field latest original source.':'New HUMAN note will be tied to the exact latest original source row.');
 $('saveHuman').disabled=held||!entry.latest;
 $('carryHuman').hidden=!held||!entry.latest;
 $('carryAckLabel').hidden=!held||!entry.latest;
 $('carryAck').checked=false;$('carryReason').value='';
 $('carryReasonLabel').hidden=!held||!entry.latest;
 $('discardHuman').hidden=!held;
}
function render() {renderSnapshots();summary();renderGrid();renderDetail();$('forget').disabled=!state.snapshots.length;window.dispatchEvent(new Event('lightup-history-changed'));}
function notesFromFields(){
 const id=state.selected;
 if(!id)throw Error('Select an exact original finding.');
 const current=latestFinding(id);
 if(!current||['stale','missing'].includes(noteBinding(id)))throw Error('HOLD: existing HUMAN note requires explicit source-change review; cannot silently overwrite.');
 const owner=$('humanOwner').value.trim(),action=$('humanAction').value.trim(),due=$('humanDue').value;
 if(owner.length>120||action.length>1200|| (due && (new Date(due+'T00:00:00Z').toISOString().slice(0,10)!==due)))throw Error('Invalid HUMAN plan fields.');
 const previous=state.notes.get(id);
 const retainNative=previous?.caseworkOriginal && ['blocker','verification_plan','note','status'].some(k=>{
   const base=LightUpCasework.newCase(current);return previous.caseworkOriginal[k]!==base[k];
 });
 if(!owner&&!action&&!due&&!retainNative)state.notes.delete(id);
 else {if(state.notes.size>=limits.maxNotes&&!state.notes.has(id))throw Error('Local HUMAN notes limit reached.');state.notes.set(id,{owner,action,due,sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,current[k]])),caseworkOriginal:state.notes.get(id)?.caseworkOriginal||null});}
 state.revision++;renderGrid();renderDetail();message('Private HUMAN coordination note saved in memory only; no source finding, grant or retest changed.');
}
function carryHuman() {
 const id=state.selected,existing=state.notes.get(id),current=latestFinding(id);
 const reason=$('carryReason').value.trim();
 if(!existing||!existing.sourceRecord||!current||noteBinding(id)!=='stale'||!$('carryAck').checked||
  reason.length<8||reason.length>800||state.decisions.length>=limits.maxDecisions)
  throw Error('HOLD: exact prior/current source, human acknowledgment and a specific 8–800 character rationale are required.');
 if(!window.confirm('PRIVATE HUMAN REVIEW: Carry existing HUMAN notes to the CHANGED original five-field source record? This is NOT a verified fix, consent or authorization.'))return;
 const prior=Object.fromEntries(FIELDS.map(k=>[k,existing.sourceRecord[k]]));
 const latest=Object.fromEntries(FIELDS.map(k=>[k,current[k]]));
 const notes={...existing,sourceRecord:latest,caseworkOriginal:null};
 state.decisions.push({id,from:prior,to:latest,reason,decidedUTC:new Date().toISOString()});
 state.notes.set(id,notes);state.revision++;renderGrid();renderDetail();
 message('Human note deliberately carried to the exact latest original finding after acknowledgment; no security status or source changed.');
}
function discardHeldHuman(){
 const id=state.selected;
 if(!id||!state.notes.has(id)||noteBinding(id)==='bound')throw Error('Only an explicitly selected held HUMAN note can be discarded.');
 if(!window.confirm('Discard the currently held PRIVATE HUMAN note? This does not affect original source findings, prior private downloads or HUMAN carry decisions. Preserve a separate encrypted checkpoint if necessary.'))return;
 state.notes.delete(id);state.revision++;renderGrid();renderDetail();
 message('Selected held HUMAN note discarded locally; original findings and the separate private decision journal are unchanged.');
}
function exportAggregate(){
 if(!state.snapshots.length)throw Error('Load original source history first.');
 const t=timeline(),snaps=state.snapshots;
 const rows=[['revision','user_label','source_rows','source_critical_high','introduced_vs_previous','absent_vs_previous','exact_source_changes','severity_escalations','source_retest_changes','canonical_source_sha256','original_file_sha256']];
 snaps.forEach((s,i)=>{const p=i?new Map(snaps[i-1].findings.map(f=>[f.finding_id,f])):new Map();const now=new Map(s.findings.map(f=>[f.finding_id,f]));let intro=0,absent=0,chg=0,up=0,retest=0;
  if(i) {for(const f of s.findings){const old=p.get(f.finding_id);if(!old)intro++;else if(!exact(old,f)){chg++;if(severityRank[f.severity]<severityRank[old.severity])up++;if(f.retest_status!==old.retest_status)retest++;}}for(const id of p.keys())if(!now.has(id))absent++;}
  rows.push([i+1,s.label,s.findings.length,s.findings.filter(f=>severityRank[f.severity]<=1).length,intro,absent,chg,up,retest,s.sourceHash,s.fileHash]);
 });
 download('lightup-remediation-source-history-aggregate.csv','\uFEFF'+rows.map(r=>r.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');message('Aggregate-only human source delta CSV exported; source field labels are unverified.');
}
function exportPrivate() {
 requireContext();protect();if(!state.snapshots.length)throw Error('No original source loaded.');
 const headers=['original_finding_id','original_title','latest_original_severity','latest_original_retest','original_history','human_source_binding','human_owner_alias','human_next_action','human_due_date'];
 const rows=filtered().map(x=>{const n=boundNote(x.id)||{};return [x.id,x.representative.title,x.representative.severity,x.representative.retest_status,x.series.map((f,i)=>i+1+':'+(f?f.severity+'/'+f.retest_status:'ABSENT_NOT_FIXED')).join(' | '),noteBinding(x.id)==='bound'?'EXACT_ORIGINAL_ROW':(state.notes.has(x.id)?'HOLD_STALE_OR_MISSING':'NO_NOTE'),n.owner||'',n.action||'',n.due||''];});
 if(!rows.length)throw Error('No filtered source findings for private handoff.');
 download('lightup-PRIVATE-source-history-human-handoff.csv','\uFEFF'+[headers,...rows].map(r=>r.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
 message('PRIVATE original-ID handoff exported; verify destination and recipients. Never a grant, verified fix or retest.');
}
function exportCasework() {
 const packet=window.LightUpHistory.exportCasework();
 const status=window.LightUpHistory.noteSummary();
 if(status.held)message(status.held+' source-changed/missing HUMAN note(s) held out of original Casework export; no implicit carry. Confirm private recipient.',true);
 download('lightup-PRIVATE-original-source-casework-human-v1.json',JSON.stringify(packet,null,2),'application/json;charset=utf-8');
 message('PRIVATE native original Casework v1 HUMAN draft exported; '+status.bound+' exact-row-bound note(s) included, '+status.held+' stale held. All consent/grant/retest/scan authority claims false.');
}
function forget(){state.snapshots=[];state.notes.clear();state.decisions=[];state.merges=[];state.active=null;state.selected=null;state.revision++;$('client').value='';$('engagement').value='';$('ack').checked=false;$('privateAck').checked=false;$('files').value='';$('archivePass').value='';$('archiveFile').value='';render();message('Original imported source and private HUMAN notes forgotten from app memory. Previously downloaded exports remain on your device.');}
$('load').addEventListener('click',()=>ingest($('files').files).catch(e=>message(e.message,true)));
$('filter').addEventListener('input',renderGrid);
$('kind').addEventListener('change',renderGrid);
$('severity').addEventListener('change',renderGrid);
$('saveHuman').addEventListener('click',()=>{try{notesFromFields();}catch(e){message(e.message,true);}});
$('carryHuman').addEventListener('click',()=>{try{carryHuman();}catch(e){message(e.message,true);}});
$('discardHuman').addEventListener('click',()=>{try{discardHeldHuman();}catch(e){message(e.message,true);}});
$('aggregate').addEventListener('click',()=>{try{exportAggregate();}catch(e){message(e.message,true);}});
$('privateExport').addEventListener('click',()=>{try{exportPrivate();}catch(e){message(e.message,true);}});
$('caseworkExport').addEventListener('click',()=>{try{exportCasework();}catch(e){message(e.message,true);}});
$('decisionExport').addEventListener('click',()=>{try{window.LightUpHistory.exportHumanCarries();}catch(e){message(e.message,true);}});
$('forget').addEventListener('click',forget);
$('grid').addEventListener('click',event=>{const button=event.target.closest('button[data-view]');if(button){state.selected=button.dataset.view;renderDetail();$('detail').scrollIntoView({behavior:'smooth',block:'start'});}});
$('snapshots').addEventListener('change',event=>{
 const el=event.target.closest('input[data-label]');
 if(!el)return;
 const i=Number(el.dataset.label),label=el.value.trim();
 if(!Number.isSafeInteger(i)||i<0||i>=state.snapshots.length)return;
 if(!label||label.length>100){el.value=state.snapshots[i].label;message('A private local revision label must contain 1–100 characters.',true);return;}
 if(state.snapshots[i].label!==label){state.snapshots[i].label=label;state.revision++;render();message('Revision label updated locally. Aggregate exports include these human-chosen labels; avoid client-identifying text.');}
});
$('snapshots').addEventListener('click',event=>{
 const move=event.target.closest('button[data-move]'),remove=event.target.closest('button[data-remove]');
 if(move){const i=Number(move.dataset.move),j=i+Number(move.dataset.shift);if(j>=0&&j<state.snapshots.length){[state.snapshots[i],state.snapshots[j]]=[state.snapshots[j],state.snapshots[i]];state.revision++;render();}}
 if(remove){const i=Number(remove.dataset.remove);const target=state.snapshots[i],referenced=state.decisions.some(d=>
  target.findings.some(f=>(exact(f,d.from)||exact(f,d.to))&&
   !state.snapshots.some((other,j)=>j!==i&&other.findings.some(keep=>exact(keep,f)))));
 if(referenced){message('PRIVATE HUMAN carry history references original source rows unique to this revision. Save an encrypted checkpoint or Forget all before removing it.',true);return;}
 state.snapshots.splice(i,1);const remaining=idSet();for(const id of state.notes.keys())if(!remaining.has(id))state.notes.delete(id);state.revision++;if(!state.snapshots.length){state.active=null;state.selected=null;}render();}
});
/* Controlled archive bridge: no browser persistence or authority, atomic restoration only. */
window.LightUpHistory=Object.freeze({
  capture(){
    const ctx=requireContext();protect();
    if(!state.snapshots.length)throw Error('Import original source revisions before saving.');
    if(state.snapshots.some(s=>!s.csvBase64))throw Error('Original file bytes unavailable; re-import before private checkpoint.');
    return {revision:state.revision,context:{...ctx},snapshots:state.snapshots.map(s=>({...s})),notes:[...state.notes].map(([id,n])=>({id,...n})),decisions:state.decisions.map(d=>({...d,from:{...d.from},to:{...d.to}})),merges:state.merges.map(m=>structuredClone(m))};
  },
  empty(){return !state.snapshots.length&&!state.notes.size;},
  restore(packet,revision){
    const ctx=requireContext();
    if(!this.empty()||state.revision!==revision)throw Error('Active session changed; Forget before restore.');
    if(!packet||packet.context.client!==ctx.client||packet.context.engagement!==ctx.engagement)throw Error('The original client/engagement context must be independently reconfirmed.');
    state.snapshots=packet.snapshots;
    state.notes=new Map(packet.notes.map(n=>[n.id,{owner:n.owner,action:n.action,due:n.due,sourceRecord:n.sourceRecord?{...n.sourceRecord}:null,caseworkOriginal:n.caseworkOriginal?{...n.caseworkOriginal}:null}]));
    state.decisions=(packet.decisions||[]).map(d=>({...d,from:{...d.from},to:{...d.to}}));
    state.merges=(packet.merges||[]).map(m=>structuredClone(m));
    state.active={...ctx};state.selected=null;state.revision++;render();
  },
  revision(){return state.revision;},
  view(){return state.snapshots.map(x=>({label:x.label,sourceHash:x.sourceHash,fileHash:x.fileHash,findings:x.findings.map(y=>({...y}))}));},
  privateAllowed(){requireContext();protect();return true;},
  reviewCasework(packet,expectedRevision){
    const ctx=requireContext();protect();
    if(state.importing||expectedRevision!==state.revision)
      throw Error('HOLD: source or private HUMAN notes changed. Reopen the original Casework review.');
    const latest=state.snapshots.at(-1);
    if(!latest)throw Error('Load original source CSV before reviewing private original Casework.');
    const loaded=LightUpCasework.loadPacket(packet);
    if(loaded.source_sha256!==latest.sourceHash||loaded.findings.length!==latest.findings.length)
      throw Error('HOLD: incoming original Casework canonical source SHA256 or row count does not match the latest source.');
    const actual=new Map(loaded.findings.map(f=>[f.finding_id,f]));
    for(const f of latest.findings)
      if(!actual.has(f.finding_id)||!exact(f,actual.get(f.finding_id)))
        throw Error('HOLD: original five-field finding values disagree with the latest local source.');
    const records=new Map(loaded.cases.map(c=>[c.finding_id,c]));
    const keys=['owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
    const rows=latest.findings.map(f=>{
      const incoming=records.get(f.finding_id),base=LightUpCasework.newCase(f);
      if(!incoming)throw Error('HOLD: incomplete original native Casework entries.');
      const incomingHasValues=keys.some(k=>incoming[k]!==base[k]);
      const local=state.notes.get(f.finding_id),binding=noteBinding(f.finding_id);
      // The active short HUMAN editor may have newer owner/action/date values
      // than an earlier imported full Casework object. Never silently roll back
      // those local values when merging an unrelated incoming field.
      const current=local?.caseworkOriginal?
        {...local.caseworkOriginal,owner:local.owner,next_action:local.action,
          due_date:local.due||null}:{
        ...base,owner:local?.owner||'',next_action:local?.action||'',due_date:local?.due||null,
        status:local?'planned':'unassigned'
      };
      const differences=keys.filter(k=>incoming[k]!==current[k]);
      const classification=binding==='stale'||binding==='missing'?'HOLD_SOURCE_CHANGED':
        !incomingHasValues?'INCOMING_EMPTY':
        !local?'NEW_HUMAN_NOTES':
        !differences.length?'IDENTICAL_HUMAN_NOTES':'REVIEW_CONFLICT';
      return {id:f.finding_id,title:f.title,severity:f.severity,sourceRetest:f.retest_status,
        classification,localBinding:binding,changedFields:differences,
        incoming:{...incoming},current:{...current}};
    });
    if(state.revision!==expectedRevision||context().client!==ctx.client||context().engagement!==ctx.engagement)
      throw Error('HOLD: client/engagement or HUMAN source revision changed during review.');
    return {sourceHash:latest.sourceHash,revision:state.revision,rows};
  },
  mergeCasework(packet,expectedRevision,selectedDecisions,reason){
    if(typeof reason!=='string'||reason.trim().length<8||reason.length>500||state.merges.length>=limits.maxMerges)throw Error('PRIVATE HUMAN merge reason (8–500 chars) and available journal capacity required.');
    const ctx=requireContext();protect();
    if(!Array.isArray(selectedDecisions)||!selectedDecisions.length||selectedDecisions.length>350||
      selectedDecisions.some(x=>!x||typeof x!=='object'||Array.isArray(x)||
       typeof x.id!=='string'||!Array.isArray(x.fields)||!x.fields.length||
       x.fields.length>8||new Set(x.fields).size!==x.fields.length)||
      new Set(selectedDecisions.map(x=>x.id)).size!==selectedDecisions.length)
      throw Error('Select distinct original HUMAN Casework records with explicit nonempty HUMAN field choices.');
    const review=this.reviewCasework(packet,expectedRevision);
    const byId=new Map(review.rows.map(r=>[r.id,r]));
    const proposed=new Map(state.notes);
    const latest=new Map(state.snapshots.at(-1).findings.map(f=>[f.finding_id,f]));
    const allowed=['owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
    let fieldsMerged=0,receiptRows=[];
    for(const choice of selectedDecisions){
      const id=choice.id,row=byId.get(id),f=latest.get(id);
      if(!row||!f||!['NEW_HUMAN_NOTES','REVIEW_CONFLICT'].includes(row.classification))
        throw Error('HOLD: selected original finding has no imported HUMAN notes or has a stale/mismatched source.');
      if(choice.fields.some(k=>typeof k!=='string'||!allowed.includes(k)||!row.changedFields.includes(k)))
        throw Error('HOLD: selection requested a HUMAN field that was not changed in the admitted original packet.');
      const copy={...row.current};
      receiptRows.push({id,fields:[...choice.fields],previous:Object.fromEntries(choice.fields.map(k=>[k,row.current[k]])),accepted:Object.fromEntries(choice.fields.map(k=>[k,row.incoming[k]]))});
      for(const field of choice.fields)copy[field]=row.incoming[field];
      const c=LightUpCasework.cleanCase(copy,new Set([id]));
      proposed.set(id,{owner:c.owner,action:c.next_action,due:c.due_date||'',
        sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,f[k]])),caseworkOriginal:c});
      fieldsMerged+=choice.fields.length;
    }
    if(proposed.size>limits.maxNotes||state.importing||state.revision!==expectedRevision||
       context().client!==ctx.client||context().engagement!==ctx.engagement)
      throw Error('HOLD: private note limit or original source/context changed. Entire merge rejected.');
    state.notes=proposed;state.merges.push({dateUtc:new Date().toISOString(),sourceHash:review.sourceHash,reason:reason.trim(),records:receiptRows});state.revision++;render();
    return {accepted:selectedDecisions.length,fieldsMerged,retained:review.rows.length-selectedDecisions.length};
  },
  importCasework(packet,sourceRevision,replaceNotes){
    const ctx=requireContext();protect();
    if(state.importing||state.revision!==sourceRevision)throw Error('Current source changed while reading original Casework. No changes committed.');
    const last=state.snapshots.at(-1);
    if(!last)throw Error('Import original findings CSV before its native Casework packet.');
    const loaded=LightUpCasework.loadPacket(packet);
    if(loaded.source_sha256!==last.sourceHash||
      loaded.findings.length!==last.findings.length)throw Error('Native Casework original canonical SHA or row count differs from latest imported source.');
    const byId=new Map(loaded.findings.map(f=>[f.finding_id,f]));
    for(const f of last.findings)if(!byId.has(f.finding_id)||!exact(byId.get(f.finding_id),f))
      throw Error('Native Casework source contains a changed or mismatched original finding.');
    if(state.notes.size&&!replaceNotes)throw Error('Existing private HUMAN notes must be explicitly retained in their current workspace or independently approved for replacement.');
    const notes=new Map();
    const canonical=new Map(last.findings.map(f=>[f.finding_id,f]));
    for(const c of loaded.cases){
      const f=canonical.get(c.finding_id);
      if(!f)throw Error('Original Casework HUMAN record has an unknown exact finding ID.');
      const empty=LightUpCasework.newCase(f);
      const changed=['owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'].some(k=>c[k]!==empty[k]);
      if(!changed)continue;
      notes.set(c.finding_id,{owner:c.owner,action:c.next_action,due:c.due_date||'',
        sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,f[k]])),caseworkOriginal:{...c}});
      if(notes.size>limits.maxNotes)throw Error('Original Casework has more than the maximum private HUMAN notes; no partial import.');
    }
    if(state.revision!==sourceRevision||context().client!==ctx.client||context().engagement!==ctx.engagement)
      throw Error('Original source/context changed during PRIVATE native Casework preparation.');
    state.notes=notes;state.revision++;render();
    return {imported:notes.size,original:last.findings.length};
  },
  exportHumanCarries(){
    requireContext();protect();
    if(!state.decisions.length)throw Error('No completed HUMAN source-carry decisions to hand off privately.');
    const hdr=['original_finding_id','human_decision_utc','human_reason','from_source_severity','to_source_severity','from_source_retest','to_source_retest','changed_original_fields'];
    const rows=state.decisions.map(d=>[d.id,d.decidedUTC,d.reason,d.from.severity,d.to.severity,d.from.retest_status,d.to.retest_status,FIELDS.filter(k=>d.from[k]!==d.to[k]).join(' | ')]);
    download('lightup-PRIVATE-human-original-source-carry-journal.csv','\uFEFF'+[hdr,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
    message(state.decisions.length+' PRIVATE HUMAN source-carry decisions exported, not an authenticated approval or a security verdict.');
  },
  noteSummary(){
    return {bound:[...state.notes.keys()].filter(id=>noteBinding(id)==='bound').length,held:[...state.notes.keys()].filter(id=>noteBinding(id)!=='bound').length};
  },
  caseworkRows(){
    const latest=state.snapshots.at(-1);
    if(!latest)return [];
    return latest.findings.map(f=>{
      const binding=noteBinding(f.finding_id),n=boundNote(f.finding_id);
      const row=n?.caseworkOriginal||LightUpCasework.newCase(f);
      return {id:f.finding_id,title:f.title,severity:f.severity,sourceRetest:f.retest_status,
        binding,hasNote:!!n,owner:n?.owner||'',
        action:n?.action||'',due:n?.due||'',status:n?.caseworkOriginal?row.status:(n?'planned':'unassigned'),
        blocker:n?row.blocker:'',verification_plan:n?row.verification_plan:'',
        note:n?row.note:'',updatedUTC:n?row.updated_utc:null};
    });
  },
  batchHumanPlan(ids,changes,expectedRevision){
    const ctx=requireContext();protect();
    if(state.importing||expectedRevision!==state.revision)throw Error('Original source/HUMAN state changed before bulk operation. Reopen the batch.');
    if(!Array.isArray(ids)||!ids.length||ids.length>100||new Set(ids).size!==ids.length)
      throw Error('Select 1–100 unique original findings in a single explicit HUMAN batch.');
    if(!changes||typeof changes!=='object'||Array.isArray(changes))throw Error('Unsupported HUMAN batch action.');
    const canOwner=changes.applyOwner===true,canDate=changes.applyDue===true,canStatus=changes.applyStatus===true;
    if(!canOwner&&!canDate&&!canStatus)throw Error('Choose which HUMAN planning fields you intend to update.');
    if(typeof changes.owner!=='string'||changes.owner.length>120||
       typeof changes.due!=='string'||changes.due.length>10||
       typeof changes.status!=='string')throw Error('Malformed HUMAN batch planning fields.');
    const owner=changes.owner.trim(),due=changes.due,status=changes.status;
    if(canStatus&&!['unassigned','planned','in_progress','blocked','deferred'].includes(status))
      throw Error('Cannot assert completed remediation or verified retest in HUMAN batch planning.');
    if(canDate&&due&&(!/^\d{4}-\d{2}-\d{2}$/.test(due)||
      !Number.isFinite(Date.parse(due+'T00:00:00Z'))||
      new Date(due+'T00:00:00Z').toISOString().slice(0,10)!==due))
      throw Error('Invalid tentative HUMAN batch due date.');
    const proposed=new Map(state.notes),now=new Date().toISOString();
    for(const id of ids){
      if(typeof id!=='string')throw Error('Invalid original finding selection.');
      const f=latestFinding(id);
      if(!f||['stale','missing'].includes(noteBinding(id)))
        throw Error('HOLD: original finding absent or has a stale HUMAN source binding; no rows changed.');
      const n=boundNote(id),row=n?.caseworkOriginal||LightUpCasework.newCase(f);
      const updated={...row,owner:canOwner?owner:(n?n.owner:row.owner),
        due_date:canDate?(due||null):(n?(n.due||null):row.due_date),
        status:canStatus?status:(n?.caseworkOriginal?row.status:(n?'planned':'unassigned')),
        next_action:n?n.action:row.next_action,updated_utc:now};
      const normalized=LightUpCasework.cleanCase(updated,new Set([id]));
      proposed.set(id,{owner:normalized.owner,action:normalized.next_action,due:normalized.due_date||'',
        sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,f[k]])),caseworkOriginal:normalized});
    }
    if(proposed.size>limits.maxNotes)throw Error('Private HUMAN note capacity exceeded. Select a smaller batch.');
    if(state.revision!==expectedRevision||context().client!==ctx.client||context().engagement!==ctx.engagement)
      throw Error('Original source/context changed before batch commit; no rows changed.');
    state.notes=proposed;state.revision++;render();
    return {changed:ids.length};
  },
  saveCaseworkEdit(id,form,expectedRevision){
    const ctx=requireContext();protect();
    if(state.importing||expectedRevision!==state.revision)throw Error('Original source or HUMAN workspace changed: refresh the current work item.');
    if(typeof id!=='string'||!form||typeof form!=='object'||Array.isArray(form))throw Error('Invalid HUMAN Casework edit.');
    const f=latestFinding(id);
    if(!f||noteBinding(id)==='stale'||noteBinding(id)==='missing')throw Error('HOLD: original finding absent or HUMAN note not tied to the latest exact original five-field row.');
    const owner=String(form.owner??'').trim(),action=String(form.action??'').trim(),
      due=String(form.due??''),blocker=String(form.blocker??'').trim(),
      verification=String(form.verification_plan??'').trim(),note=String(form.note??'').trim(),
      status=form.status;
    if(!['unassigned','planned','in_progress','blocked','deferred'].includes(status))
      throw Error('Only non-conclusive HUMAN planning progress can be newly selected, never completion or verified retest.');
    const current=boundNote(id),base=current?.caseworkOriginal||LightUpCasework.newCase(f);
    const proposed={...base,owner,next_action:action,due_date:due||null,blocker,
      verification_plan:verification,note,status,updated_utc:new Date().toISOString()};
    const normalized=LightUpCasework.cleanCase(proposed,new Set([id]));
    if(owner.length>120||action.length>1800||blocker.length>1200||verification.length>1600||
       note.length>1600)throw Error('HUMAN Casework field exceeds original native source length bounds.');
    const hasValues=owner||action||due||blocker||verification||note||status!=='unassigned';
    if(!hasValues){
      state.notes.delete(id);
    }else{
      if(!state.notes.has(id)&&state.notes.size>=limits.maxNotes)throw Error('Private HUMAN source note capacity exceeded.');
      state.notes.set(id,{owner,action,due,sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,f[k]])),
        caseworkOriginal:normalized});
    }
    if(context().client!==ctx.client||context().engagement!==ctx.engagement)
      throw Error('Original client context changed; no cross-client updates permitted.');
    state.revision++;render();
    return {status:normalized.status,updatedUTC:normalized.updated_utc};
  },
  selectFinding(id){
    const f=latestFinding(id);if(!f)throw Error('Original finding not present in latest source.');
    state.selected=id;renderDetail();$('detail').scrollIntoView({behavior:'smooth',block:'start'});
  },
  exportCasework(){
    requireContext();protect();
    const latest=state.snapshots.at(-1);if(!latest)throw Error('Import original source before creating a Casework handoff.');
    const cases=latest.findings.map(f=>{
      const n=boundNote(f.finding_id),row=n?.caseworkOriginal?{...n.caseworkOriginal}:LightUpCasework.newCase(f);
      // An original source "fixed" label is not HUMAN completion. No source row
      // may silently acquire a completed Casework status during first export.
      return {...row,status:n?.caseworkOriginal?row.status:(n?'planned':'unassigned'),
       owner:n?.owner??'',next_action:n?.action??'',due_date:n?.due||null};
    });
    return LightUpCasework.makePacket(latest.findings,cases,latest.sourceHash);
  },
  limits:Object.freeze({...limits})
});
render();
})();
