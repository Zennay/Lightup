/* PRIVATE offline HUMAN intervention brief. Derived read-only from exact original Casework rows.
   Not a security assessment, verified fix, dispatch, permission or client communication. */
(()=>{
'use strict';
const H=window.LightUpHistory, $=id=>document.getElementById(id);
const rank={critical:0,high:1,medium:2,low:3,info:4};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const today=()=>{const d=new Date(),p=x=>String(x).padStart(2,'0');return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate());};
const addDays=(iso,n)=>{const d=new Date(iso+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10);};
const isHold=r=>r.binding==='stale'||r.binding==='missing';
const isConclusive=r=>r.status==='completed'||r.status==='ready_for_retest';
function signal(r,now,end){
 if(isHold(r))return 'SOURCE_HOLD';
 if(r.status==='blocked'||r.blocker)return 'HUMAN_BLOCKED';
 if(r.due&&r.due<now)return 'HUMAN_OVERDUE';
 if(!r.owner)return 'HUMAN_UNASSIGNED';
 if((rank[r.severity]??5)<=1)return 'ORIGINAL_HIGH_CRITICAL';
 if(r.due&&r.due<=end)return 'HUMAN_DUE_SOON';
 return 'HUMAN_PLANNED';
}
function decision(){
 const snapshots=H.view();
 if(!snapshots.length)return null;
 const horizon=Number($('briefDays').value);
 if(![0,7,14,30].includes(horizon))throw Error('Invalid HUMAN meeting horizon.');
 const now=today(),end=addDays(now,horizon),focus=$('briefFocus').value,owner=$('briefOwner').value;
 const last=snapshots.at(-1);
 const all=H.caseworkRows().map(r=>({...r,signal:signal(r,now,end)}));
 let rows=all.filter(r=>{
  if(owner!=='' && r.owner!==owner)return false;
  if(focus==='all')return true;
  if(focus==='urgent')return ['SOURCE_HOLD','HUMAN_BLOCKED','HUMAN_OVERDUE','HUMAN_UNASSIGNED','ORIGINAL_HIGH_CRITICAL'].includes(r.signal);
  if(focus==='due')return r.due&&r.due<=end;
  return r.signal===focus;
 });
 rows=rows.sort((a,b)=>isHold(a)-isHold(b)||(priority(a)-priority(b))||(a.due||'9999').localeCompare(b.due||'9999')||a.id.localeCompare(b.id));
 return {all,rows,now,end,last,owner,focus,revision:H.revision(),held:H.noteSummary().held};
}
function priority(r){
 return {'SOURCE_HOLD':0,'HUMAN_BLOCKED':1,'HUMAN_OVERDUE':2,'HUMAN_UNASSIGNED':3,'ORIGINAL_HIGH_CRITICAL':4,'HUMAN_DUE_SOON':5,'HUMAN_PLANNED':6}[r.signal]??7;
}
function updateOwners(){
 const selected=$('briefOwner').value,all=H.caseworkRows();
 const aliases=[...new Set([...all,...H.heldHumanRows()].map(r=>r.owner).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 $('briefOwner').replaceChildren(new Option('All HUMAN owners',''),new Option('Only unassigned originals','__UNASSIGNED__'),...aliases.map(x=>new Option(x,'alias:'+x)));
 // Identity is literal: a real alias '__UNASSIGNED__' cannot collide with the sentinel.
 const option=selected.startsWith('alias:')?selected:'';
 $('briefOwner').value=[...$('briefOwner').options].some(o=>o.value===selected)?selected:option;
}
function selectedOwner(row,owner){return owner===''||(owner==='__UNASSIGNED__'&&!row.owner)||(owner.startsWith('alias:')&&row.owner===owner.slice(6));}
function get(){
 const snap=decision();if(!snap)return null;
 // The owner filter uses a prefixed identity to distinguish a literal alias from unassigned.
 snap.heldNotes=H.heldHumanRows().filter(r=>selectedOwner(r,snap.owner));
 snap.rows=snap.all.filter(r=>selectedOwner(r,snap.owner)).filter(r=>{
  if(snap.focus==='all')return true;
  if(snap.focus==='urgent')return ['SOURCE_HOLD','HUMAN_BLOCKED','HUMAN_OVERDUE','HUMAN_UNASSIGNED','ORIGINAL_HIGH_CRITICAL'].includes(r.signal);
  if(snap.focus==='due')return r.due&&r.due<=snap.end;
  return r.signal===snap.focus;
 }).sort((a,b)=>priority(a)-priority(b)||(a.due||'9999').localeCompare(b.due||'9999')||(rank[a.severity]-rank[b.severity])||a.id.localeCompare(b.id));
 return snap;
}
function notice(s,err=false){$('message').textContent=s;$('message').className=err?'error':'info';}
function render(){
 updateOwners();
 const d=get();
 if(!d){$('briefSummary').textContent='Import original findings to assemble a HUMAN intervention agenda.';$('briefRows').replaceChildren();$('briefHoldRows').replaceChildren();$('briefHoldCount').textContent='No held notes.';$('briefCount').textContent='No source loaded.';return;}
 const counts={};for(const r of d.all)counts[r.signal]=(counts[r.signal]||0)+1;
 $('briefSummary').textContent=d.all.length+' latest original source records · '+d.held+' HUMAN notes on HOLD across latest/missing source · '+(counts.HUMAN_BLOCKED||0)+' HUMAN blocked · '+(counts.HUMAN_OVERDUE||0)+' HUMAN overdue · '+(counts.HUMAN_UNASSIGNED||0)+' unassigned. Source labels are unverified.';
 $('briefCount').textContent=d.rows.length+' HUMAN discussion entries visible through '+d.end+'. '+d.heldNotes.length+' PRIVATE source-HOLD note(s) in this HUMAN owner group; none are copied or verified.';
 $('briefRows').innerHTML=d.rows.slice(0,350).map(r=>'<tr><td><button class="link" type="button" data-brief-id="'+esc(r.id)+'">'+esc(r.id)+'</button><small>'+esc(r.title.slice(0,140))+'</small></td><td>'+esc(r.signal)+'<small>'+esc(r.severity)+' • '+esc(r.sourceRetest)+' (original source claim)</small></td><td>'+esc(r.owner||'Unassigned')+'<small>'+esc(r.due||'No HUMAN date')+'</small></td><td>'+esc((r.blocker||r.action||'HUMAN clarification required').slice(0,200))+(isConclusive(r)?'<small>Imported HUMAN completion/retest label: UNVERIFIED</small>':'')+'</td></tr>').join('')||'<tr><td colspan="4">No HUMAN discussion items meet the current filters.</td></tr>';
 $('briefHoldCount').textContent=d.heldNotes.length+' PRIVATE historical HUMAN notes on source HOLD for selected HUMAN owners. This is a read-only quarantine; manually review old versus latest original source.';
 $('briefHoldRows').innerHTML=d.heldNotes.map(r=>'<tr><td>'+esc(r.id)+'<small>'+esc(r.lastMatchingSource?.label||'Legacy source unknown')+'</small></td><td>'+esc(r.binding)+'<small>Earlier: '+esc(r.sourceRecord?.title||'Unbound legacy')+' / '+esc(r.sourceRecord?.severity||'unknown')+'</small><small>Latest: '+esc(r.currentSource?.title||'ABSENT')+' / '+esc(r.currentSource?.severity||'unknown')+'</small></td><td>'+esc(r.owner||'Unassigned')+'<small>'+esc(r.due||'No HUMAN date')+'</small></td><td>'+esc((r.blocker||r.action||'Historical HUMAN plan held pending original source review').slice(0,200))+'</td></tr>').join('')||'<tr><td colspan="4">No held HUMAN notes in selected owner group.</td></tr>';
}
function fresh(d){
 if(H.revision()!==d.revision||H.view().at(-1)?.sourceHash!==d.last.sourceHash)
  throw Error('HOLD: original source or HUMAN Casework changed during briefing; reopen current agenda.');
}
function save(name,content,type){const u=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}
function exportCounts(){
 const d=get();if(!d)throw Error('Import original source before exporting anonymous counts.');
 fresh(d);
 const n={};
 for(const r of d.rows)n[r.signal]=(n[r.signal]||0)+1;
 // No original IDs, owner names, finding titles, client labels, source hashes or dates.
 const report={kind:'LightUp HUMAN intervention aggregate / NON-AUTHORIZING',version:1,
  source_revision_count:H.view().length,total_source_records:d.all.length,visible_human_items:d.rows.length,
  source_hold_note_count:d.held,signal_counts:Object.fromEntries(['SOURCE_HOLD','HUMAN_BLOCKED','HUMAN_OVERDUE','HUMAN_UNASSIGNED','ORIGINAL_HIGH_CRITICAL','HUMAN_DUE_SOON','HUMAN_PLANNED'].map(k=>[k,n[k]||0])),
  caveat:'Source findings and locally declared HUMAN progress are unverified. No verified fix, retest, consent, grant, dispatch or release.'};
 fresh(d);save('lightup-HUMAN-intervention-anonymous-counts.json',JSON.stringify(report,null,2),'application/json;charset=utf-8');
 notice('Aggregate HUMAN signal counts downloaded with no finding IDs, owner labels or source hashes.');
}
function exportPrivate(){
 // Explicit original-file recipient acknowledgement plus private source/context guard.
 H.privateAllowed();
 const d=get();if(!d||(!d.rows.length&&!d.heldNotes.length))throw Error('No source-bound HUMAN agenda or historical held notes to hand off.');
 fresh(d);
 if(d.rows.length>350)throw Error('HUMAN private briefing exceeds bounded source capacity.');
 if(!confirm('Export a PLAINTEXT PRIVATE HTML file containing ORIGINAL finding IDs, titles and HUMAN owner/action/notes? Only use an independently approved private destination and verified recipients. This does not transmit anything.'))return;
 const grouped=new Map();
 for(const r of d.rows){
  const key=r.owner?'owner:'+r.owner:'unassigned';
  if(!grouped.has(key))grouped.set(key,{name:r.owner||'Unassigned',rows:[]});
  grouped.get(key).rows.push(r);
 }
 const groups=[...grouped.values()].sort((a,b)=>a.name.localeCompare(b.name));
 const table=groups.map(g=>'<h2>'+esc(g.name)+' · '+g.rows.length+' HUMAN discussions</h2><table><thead><tr><th>Exact original finding</th><th>Review reason</th><th>Human-only next steps</th></tr></thead><tbody>'+
  g.rows.map(r=>'<tr><td><strong>'+esc(r.id)+'</strong><br>'+esc(r.title)+'<br>Original severity: '+esc(r.severity)+'<br>Original retest claim: '+esc(r.sourceRetest)+'</td><td>'+esc(r.signal)+'<br>'+esc(r.binding)+' exact-row binding<br>Human due: '+esc(r.due||'Unset')+'<br>Human status: '+esc(r.status)+' (unverified)</td><td>Action: '+esc(r.action||'Unassigned')+'<br>Blocker: '+esc(r.blocker||'None declared')+'<br>Human verification plan (NOT performed): '+esc(r.verification_plan||'Not set')+'<br>PRIVATE note: '+esc(r.note||'')+'</td></tr>').join('')+'</tbody></table>').join('');
 const holdTable=d.heldNotes.length?'<h2>HISTORICAL HUMAN SOURCE HOLD / PRIVATE · '+d.heldNotes.length+'</h2><p>Read-only quarantine. Changed or absent original source records are not proved fixed. These older HUMAN notes are not carried to the latest source.</p><table><thead><tr><th>Original ID and historical exact source</th><th>Latest original source claim</th><th>PRIVATE historical HUMAN plan</th></tr></thead><tbody>'+d.heldNotes.map(r=>'<tr><td>'+esc(r.id)+'<br>Previous: '+esc(JSON.stringify(r.sourceRecord||null))+'<br>Source label: '+esc(r.lastMatchingSource?.label||'Unbound legacy source')+'</td><td>'+esc(JSON.stringify(r.currentSource||null))+'<br>Binding: '+esc(r.binding)+' HOLD</td><td>Owner: '+esc(r.owner||'Unassigned')+'<br>Date: '+esc(r.due||'Unset')+'<br>Action: '+esc(r.action)+'<br>Blocker: '+esc(r.blocker)+'<br>Human verification plan: '+esc(r.verification_plan)+'<br>PRIVATE note: '+esc(r.note)+'</td></tr>').join('')+'</tbody></table>':'';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; form-action &#39;none&#39;; base-uri &#39;none&#39;"><title>PRIVATE HUMAN intervention brief</title><style>body{font:15px system-ui;max-width:1100px;margin:3em auto;padding:0 1em;line-height:1.5}h1,h2{margin-top:2em}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{padding:10px;border:1px solid #bbb;overflow-wrap:anywhere;vertical-align:top}small{color:#555}.hold{border:2px solid #444;padding:1em}</style></head><body><h1>PRIVATE · Human intervention briefing</h1><p class="hold"><b>INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.</b> Original source claims and PRIVATE HUMAN coordination only. No real client permission, scan, confirmed remediation, verified retest, authorization, release or dispatched work.</p><p>Original canonical source SHA-256: <code>'+esc(d.last.sourceHash)+'</code><br>Original file-byte SHA-256: <code>'+esc(d.last.fileHash)+'</code><br>Local sequence position: '+H.view().length+'<br>Local agenda window through '+esc(d.end)+'; HUMAN date selections are not SLAs.</p><p>'+d.rows.length+' selected original HUMAN discussions; '+d.held+' private HUMAN source-HOLD notes overall (missing original findings may not appear in current rows). IDs are sensitive; privately verify recipients and storage.</p>'+table+holdTable+'<footer>Prepared locally without contacting recipients or executing tools. Original source mismatch, disappearance and imported completed/retest labels do not certify remediation.</footer></body></html>';
 if(new TextEncoder().encode(html).byteLength>2097152)throw Error('PRIVATE briefing exceeds 2 MiB; narrow the filters.');
 fresh(d);save('lightup-PRIVATE-source-bound-HUMAN-intervention-brief.html',html,'text/html;charset=utf-8');
 notice('PRIVATE offline HUMAN intervention HTML prepared for separately approved recipients. Nothing sent, scanned, verified or authorized.');
}
for(const key of ['briefDays','briefFocus','briefOwner'])$(key).addEventListener('change',()=>{try{render();}catch(e){notice(e.message,true);}});
$('briefAggregate').addEventListener('click',()=>{try{exportCounts();}catch(e){notice(e.message,true);}});
$('briefPrivate').addEventListener('click',()=>{try{exportPrivate();}catch(e){notice(e.message,true);}});
$('briefRows').addEventListener('click',e=>{const b=e.target.closest('button[data-brief-id]');if(b)try{H.selectFinding(b.dataset.briefId);}catch(err){notice(err.message,true);}});
window.addEventListener('lightup-history-changed',()=>{try{render();}catch(e){notice(e.message,true);}});
render();
})();
