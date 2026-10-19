/* PRIVATE longitudinal original finding dossier; source assertions and HUMAN-only history. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const fields=['finding_id','title','severity','retest_status','remediation'];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let chosen='',revision=-1,page=0;const pageSize=36;
const notice=(s,bad=false)=>{const m=$('message');m.textContent=s;m.className=bad?'error':'info';};
function sourceIndex(){
 const sources=H.view(),entries=new Map();
 sources.forEach((s,i)=>s.findings.forEach(f=>{
  if(!entries.has(f.finding_id))entries.set(f.finding_id,{id:f.finding_id,firstIndex:i,lastIndex:i,title:f.title});
  const e=entries.get(f.finding_id);e.lastIndex=i;e.title=f.title;
 }));
 return {sources,entries:[...entries.values()].sort((a,b)=>a.id.localeCompare(b.id))};
}
function compose(id){
 const at=H.revision(),{sources,entries}=sourceIndex();
 if(!entries.some(e=>e.id===id))throw Error('Original finding ID was not present in the currently imported original CSV revisions.');
 const series=sources.map((s,i)=>({
   index:i+1,label:s.label,canonicalSourceSHA256:s.sourceHash,originalFileSHA256:s.fileHash,
   originalFinding:s.findings.find(f=>f.finding_id===id)||null
 }));
 const visible=H.caseworkRows().find(r=>r.id===id)||null;
 const held=H.heldHumanRows().find(r=>r.id===id)||null;
 const linked=H.journalEvents().events.filter(e=>e.ids.includes(id));
 const history=linked.map(e=>({
  type:e.kind,declaredUTC:e.time,exactOriginalSourceSHA256:e.sourceHashes,
  detail:H.journalDetail(e.kind,e.index,at)
 }));
 if(H.revision()!==at)throw Error('HOLD: original source/HUMAN history changed during private finding dossier assembly.');
 return {version:1,id,revision:at,sources:series,currentSourcePresent:!!series.at(-1)?.originalFinding,
  currentUnverifiedHumanCasework:visible,heldHistoricalHumanNote:held,
  originalSourceBoundHumanDecisions:history,
  warning:'Original five-field source and locally declared HUMAN notes are not independent findings verification, authenticated consent, client identity, grant, remediation, retest or release.'};
}
function preview(){
 if(!chosen){$('dossierSummary').textContent='Choose an original finding, including an ID absent from latest source.';$('dossierDetail').hidden=true;$('dossierDetail').replaceChildren();return;}
 const d=compose(chosen);
 $('dossierDetail').hidden=false;
 const blocks=d.sources.map(r=>'<article class="snapshot"><h4>Original revision '+r.index+' · '+esc(r.label)+'</h4>'+
  '<p><b>Original canonical SHA-256:</b> <code>'+esc(r.canonicalSourceSHA256)+'</code><br>'+
  '<b>Original file-byte SHA-256:</b> <code>'+esc(r.originalFileSHA256)+'</code></p>'+
  (r.originalFinding?fields.map(k=>'<p><strong>'+esc(k)+':</strong> '+esc(r.originalFinding[k])+'</p>').join(''):
   '<p><strong>ABSENT FROM THIS ORIGINAL SOURCE</strong> — this does not mean fixed, closed or verified retested.</p>')+'</article>').join('');
 const safeJSON=x=>'<pre class="dossier-json">'+esc(JSON.stringify(x,null,2))+'</pre>';
 $('dossierDetail').innerHTML='<h3>PRIVATE exact original history · '+esc(d.id)+'</h3>'+
  '<p>This is a locally assembled human dossier from separately imported original files; never proof of client identity, original source ownership, a fixed finding, true retest, consent or work authorization.</p>'+
  '<p><b>Latest original presence:</b> '+(d.currentSourcePresent?'Present in latest original export':'ABSENT in latest original export — NOT independently fixed')+
  ' · '+d.sources.length+' original revisions · '+d.originalSourceBoundHumanDecisions.length+' historical HUMAN decision event(s).</p>'+
  '<div class="revisions">'+blocks+'</div>'+
  '<h4>Latest original-bound HUMAN Casework (unverified, read-only)</h4>'+safeJSON(d.currentUnverifiedHumanCasework)+
  '<h4>Historical private HUMAN source HOLD note (quarantined, read-only)</h4>'+safeJSON(d.heldHistoricalHumanNote)+
  '<h4>Full original source-bound PRIVATE HUMAN decisions (read-only)</h4>'+safeJSON(d.originalSourceBoundHumanDecisions);
 $('dossierSummary').textContent='Original '+d.id+' · '+d.sources.length+' imported revisions · '+
  d.sources.filter(r=>r.originalFinding).length+' original source presences · '+d.originalSourceBoundHumanDecisions.length+
  ' original-source HUMAN decision(s). Imported source and HUMAN statuses are unverified.';
}
function render(){
 const current=H.revision(),data=sourceIndex();
 if(revision!==current){revision=current;page=0;if(chosen&&!data.entries.some(e=>e.id===chosen))chosen='';}
 const query=$('dossierQuery').value.trim().toLowerCase();
 const list=data.entries.filter(e=>!query||[e.id,e.title].join(' ').toLowerCase().includes(query));
 const pages=Math.max(1,Math.ceil(list.length/pageSize));page=Math.min(Math.max(0,page),pages-1);
 $('dossierRows').innerHTML=list.slice(page*pageSize,(page+1)*pageSize).map(e=>
  '<tr><td><button type="button" class="link" data-dossier-id="'+esc(e.id)+'">'+esc(e.id)+'</button></td>'+
  '<td>'+esc(e.title.slice(0,140))+'</td><td>Original revisions '+(e.firstIndex+1)+'–'+(e.lastIndex+1)+'</td>'+
  '<td>'+ (data.sources.at(-1)?.findings.some(f=>f.finding_id===e.id)?
   'Present in latest original':'Absent in latest original — NOT confirmed fixed')+'</td></tr>'
 ).join('')||'<tr><td colspan="4">No original findings match this local selection.</td></tr>';
 $('dossierPage').textContent=(list.length?page*pageSize+1:0)+'–'+Math.min(list.length,(page+1)*pageSize)+' of '+list.length+' original IDs';
 $('dossierPrev').disabled=page===0;$('dossierNext').disabled=page===pages-1;
 $('dossierExport').disabled=!chosen;
 try{preview();}catch(err){$('dossierDetail').hidden=true;notice(err.message,true);}
}
function openDossier(id){
 if(typeof id!=='string'||!sourceIndex().entries.some(e=>e.id===id))
   throw Error('Exact original finding ID is no longer present in local source history.');
 chosen=id;
 $('dossierQuery').value='';
 page=0;render();
 $('originalFindingDossier').scrollIntoView({behavior:'smooth',block:'start'});
 $('dossierDetail').scrollIntoView({behavior:'smooth',block:'nearest'});
}
window.LightUpDossier=Object.freeze({open:openDossier});
$('dossierRows').addEventListener('click',e=>{
 const button=e.target.closest('button[data-dossier-id]');if(!button)return;
 try{openDossier(button.dataset.dossierId);}
 catch(err){notice(err.message,true);}
});
$('dossierQuery').addEventListener('input',()=>{page=0;render();});
$('dossierPrev').addEventListener('click',()=>{page=Math.max(0,page-1);render();});
$('dossierNext').addEventListener('click',()=>{page++;render();});
$('dossierExport').addEventListener('click',()=>{
 try{
  H.privateAllowed();
  if(!chosen)throw Error('Select an exact original finding ID first.');
  const before=H.revision(),d=compose(chosen);
  if(!confirm('Create a PLAINTEXT PRIVATE HTML dossier for original finding '+chosen+'? It contains exact original title/remediation, original SHA256, HUMAN owner, notes and historic decisions. Verify approved destination and recipients independently. Nothing is transmitted.'))return;
  // Print-friendly static document, no javascript, network fetch, links or forms.
  const sourceRows=d.sources.map(s=>
   '<h2>Original revision '+s.index+' · '+esc(s.label)+'</h2>'+
   '<p>Canonical SHA-256: <code>'+esc(s.canonicalSourceSHA256)+'</code><br>File-byte SHA-256: <code>'+esc(s.originalFileSHA256)+'</code></p>'+
   (s.originalFinding?fields.map(k=>'<p><b>'+esc(k)+':</b> '+esc(s.originalFinding[k])+'</p>').join(''):
     '<p>ABSENT FROM THIS ORIGINAL FILE — NOT VERIFIED FIXED.</p>')).join('');
  const json=x=>'<pre>'+esc(JSON.stringify(x,null,2))+'</pre>';
  const body='<!doctype html><html lang="en"><head><meta charset="utf-8">'+
    '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; form-action &#39;none&#39;; base-uri &#39;none&#39;">'+
    '<title>PRIVATE original source HUMAN dossier</title>'+
    '<style>body{font:15px system-ui;line-height:1.6;max-width:1000px;margin:35px auto;padding:15px}p{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eee;padding:15px}h2{margin-top:2.3em}.hold{border:2px solid #222;padding:15px}@media print{h2{break-before:page}}</style></head><body>'+
    '<h1>PRIVATE · Source-bound HUMAN original finding dossier</h1>'+
    '<p class="hold">INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. '+esc(d.warning)+'</p>'+
    '<p>Exact original finding ID: '+esc(d.id)+'; imported revisions: '+d.sources.length+
    '; source-labelled latest presence: '+(d.currentSourcePresent?'present':'absent, NOT verified fixed')+
    '. All source claims remain unverified; no permission/scan/retest performed.</p>'+sourceRows+
    '<h2>Latest original-bound unverified HUMAN Casework</h2>'+json(d.currentUnverifiedHumanCasework)+
    '<h2>Historical HUMAN source-HOLD quarantine</h2>'+json(d.heldHistoricalHumanNote)+
    '<h2>Original-source HUMAN carry / merge / HOLD decisions</h2>'+json(d.originalSourceBoundHumanDecisions)+
    '<footer>Locally created for separately approved PRIVATE recipients. No proof of source authenticity, signed approvals, verified remediation, retest, consent, grant or release.</footer></body></html>';
  if(new TextEncoder().encode(body).byteLength>2097152)
    throw Error('PRIVATE exact-source dossier exceeds 2 MiB. Narrow the original source history or use the encrypted checkpoint instead.');
  if(H.revision()!==before)throw Error('HOLD: original source or HUMAN decisions changed before dossier export.');
  const u=URL.createObjectURL(new Blob([body],{type:'text/html;charset=utf-8'}));
  const a=document.createElement('a');a.href=u;a.download='lightup-PRIVATE-original-HUMAN-finding-dossier.html';a.click();
  setTimeout(()=>URL.revokeObjectURL(u),15000);
  notice('PRIVATE original-source HUMAN dossier saved locally with no network, target, approval or verified security claims.');
 }catch(err){notice(err.message,true);}
});
window.addEventListener('lightup-history-changed',render);render();
})();
