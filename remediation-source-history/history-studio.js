/* LightUp Source History Studio — local HUMAN planning only. No authorization or security verdicts. */
(() => {
"use strict";
const $ = id => document.getElementById(id);
const state = { snapshots:[], notes:new Map(), active:null, revision:0, importing:false };
const FIELDS = ['finding_id','title','severity','retest_status','remediation'];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const severityRank = {critical:0,high:1,medium:2,low:3,info:4};
const limits = {maxSnapshots:12,maxBytes:1048576,maxRows:350,maxNotes:250};
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
 $('carryAck').checked=false;
}
function render() {renderSnapshots();summary();renderGrid();renderDetail();$('forget').disabled=!state.snapshots.length;window.dispatchEvent(new Event('lightup-history-changed'));}
function notesFromFields(){
 const id=state.selected;
 if(!id)throw Error('Select an exact original finding.');
 const current=latestFinding(id);
 if(!current||['stale','missing'].includes(noteBinding(id)))throw Error('HOLD: existing HUMAN note requires explicit source-change review; cannot silently overwrite.');
 const owner=$('humanOwner').value.trim(),action=$('humanAction').value.trim(),due=$('humanDue').value;
 if(owner.length>120||action.length>1200|| (due && (new Date(due+'T00:00:00Z').toISOString().slice(0,10)!==due)))throw Error('Invalid HUMAN plan fields.');
 if(!owner&&!action&&!due)state.notes.delete(id);
 else {if(state.notes.size>=limits.maxNotes&&!state.notes.has(id))throw Error('Local HUMAN notes limit reached.');state.notes.set(id,{owner,action,due,sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,current[k]]))});}
 state.revision++;renderGrid();renderDetail();message('Private HUMAN coordination note saved in memory only; no source finding, grant or retest changed.');
}
function carryHuman() {
 const id=state.selected,existing=state.notes.get(id),current=latestFinding(id);
 if(!existing||!current||noteBinding(id)!=='stale'||!$('carryAck').checked)
  throw Error('Source change needs selected current finding and explicit human review acknowledgement.');
 if(!window.confirm('PRIVATE HUMAN REVIEW: Carry existing HUMAN notes to the CHANGED original five-field source record? This is NOT a verified fix, consent or authorization.'))return;
 const notes={...existing,sourceRecord:Object.fromEntries(FIELDS.map(k=>[k,current[k]]))};
 state.notes.set(id,notes);state.revision++;renderGrid();renderDetail();
 message('Human note deliberately carried to the exact latest original finding after acknowledgment; no security status or source changed.');
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
function forget(){state.snapshots=[];state.notes.clear();state.active=null;state.selected=null;state.revision++;$('client').value='';$('engagement').value='';$('ack').checked=false;$('privateAck').checked=false;$('files').value='';$('archivePass').value='';$('archiveFile').value='';render();message('Original imported source and private HUMAN notes forgotten from app memory. Previously downloaded exports remain on your device.');}
$('load').addEventListener('click',()=>ingest($('files').files).catch(e=>message(e.message,true)));
$('filter').addEventListener('input',renderGrid);
$('kind').addEventListener('change',renderGrid);
$('severity').addEventListener('change',renderGrid);
$('saveHuman').addEventListener('click',()=>{try{notesFromFields();}catch(e){message(e.message,true);}});
$('carryHuman').addEventListener('click',()=>{try{carryHuman();}catch(e){message(e.message,true);}});
$('aggregate').addEventListener('click',()=>{try{exportAggregate();}catch(e){message(e.message,true);}});
$('privateExport').addEventListener('click',()=>{try{exportPrivate();}catch(e){message(e.message,true);}});
$('caseworkExport').addEventListener('click',()=>{try{exportCasework();}catch(e){message(e.message,true);}});
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
 if(remove){const i=Number(remove.dataset.remove);state.snapshots.splice(i,1);const remaining=idSet();for(const id of state.notes.keys())if(!remaining.has(id))state.notes.delete(id);state.revision++;if(!state.snapshots.length){state.active=null;state.selected=null;}render();}
});
/* Controlled archive bridge: no browser persistence or authority, atomic restoration only. */
window.LightUpHistory=Object.freeze({
  capture(){
    const ctx=requireContext();protect();
    if(!state.snapshots.length)throw Error('Import original source revisions before saving.');
    if(state.snapshots.some(s=>!s.csvBase64))throw Error('Original file bytes unavailable; re-import before private checkpoint.');
    return {revision:state.revision,context:{...ctx},snapshots:state.snapshots.map(s=>({...s})),notes:[...state.notes].map(([id,n])=>({id,...n}))};
  },
  empty(){return !state.snapshots.length&&!state.notes.size;},
  restore(packet,revision){
    const ctx=requireContext();
    if(!this.empty()||state.revision!==revision)throw Error('Active session changed; Forget before restore.');
    if(!packet||packet.context.client!==ctx.client||packet.context.engagement!==ctx.engagement)throw Error('The original client/engagement context must be independently reconfirmed.');
    state.snapshots=packet.snapshots;
    state.notes=new Map(packet.notes.map(n=>[n.id,{owner:n.owner,action:n.action,due:n.due}]));
    state.active={...ctx};state.selected=null;state.revision++;render();
  },
  revision(){return state.revision;},
  view(){return state.snapshots.map(x=>({label:x.label,sourceHash:x.sourceHash,fileHash:x.fileHash,findings:x.findings.map(y=>({...y}))}));},
  privateAllowed(){requireContext();protect();return true;},
  noteSummary(){
    return {bound:[...state.notes.keys()].filter(id=>noteBinding(id)==='bound').length,held:[...state.notes.keys()].filter(id=>noteBinding(id)!=='bound').length};
  },
  exportCasework(){
    requireContext();protect();
    const latest=state.snapshots.at(-1);if(!latest)throw Error('Import original source before creating a Casework handoff.');
    const cases=latest.findings.map(f=>{
      const n=boundNote(f.finding_id),row=LightUpCasework.newCase(f);
      return {...row,status:n?'planned':'unassigned',owner:n?.owner||'',next_action:n?.action||'',due_date:n?.due||null};
    });
    return LightUpCasework.makePacket(latest.findings,cases,latest.sourceHash);
  },
  limits:Object.freeze({...limits})
});
render();
})();
