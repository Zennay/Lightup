/* PRIVATE original source-bound HUMAN decision register. No security verdict or consent. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const names={
 HUMAN_SOURCE_CARRY:'Original-source HUMAN note carry',
 HUMAN_CASEWORK_MERGE:'Original Casework HUMAN field reconciliation',
 HUMAN_SOURCE_HOLD_REVIEW:'Historical source-HOLD HUMAN discussion'
};
let revision=-1,page=0,chosen=null;
const perPage=30;
function say(t,error=false){$('message').textContent=t;$('message').className=error?'error':'info';}
function dataset(){
 const result=H.journalEvents();
 if(revision!==result.revision){
  revision=result.revision;page=0;chosen=null;
  $('ledgerDetail').hidden=true;$('ledgerDetail').replaceChildren();
 }
 const kind=$('ledgerKind').value,query=$('ledgerQuery').value.trim().toLowerCase();
 const events=result.events.filter(e=>(kind==='all'||e.kind===kind)&&
  (!query||[...e.ids,e.summary,names[e.kind]].join(' ').toLowerCase().includes(query)));
 return {source:result,events};
}
function showDetail(kind,index){
 const data=H.journalDetail(kind,index,revision);
 $('ledgerDetail').hidden=false;
 const heading=document.createElement('h3');heading.textContent=names[kind]+' · PRIVATE original-source event';
 const warning=document.createElement('p');
 warning.textContent='Read-only locally declared HUMAN actions. Original source hashes only match locally loaded five-column exports; no actual identity, permission, verified mitigation, retest, completion or release.';
 const description=document.createElement('p');
 description.textContent='The exact original source and previous/current HUMAN choices are shown below. Keep this content strictly PRIVATE.';
 const pre=document.createElement('pre');pre.textContent=JSON.stringify(data,null,2);
 pre.style.whiteSpace='pre-wrap';pre.style.overflowWrap='anywhere';
 $('ledgerDetail').replaceChildren(heading,warning,description,pre);
 chosen={kind,index};
}
function render(){
 const {source,events}=dataset(),pages=Math.max(1,Math.ceil(events.length/perPage));
 page=Math.min(Math.max(page,0),pages-1);
 const display=events.slice(page*perPage,(page+1)*perPage);
 const kinds=Object.fromEntries(Object.keys(names).map(k=>[k,source.events.filter(e=>e.kind===k).length]));
 $('ledgerSummary').textContent=source.events.length+' original-source HUMAN decisions: '+kinds.HUMAN_SOURCE_CARRY+
  ' exact-source carry events, '+kinds.HUMAN_CASEWORK_MERGE+' native Casework field merges, '+
  kinds.HUMAN_SOURCE_HOLD_REVIEW+' historical HOLD decisions. '+events.length+
  ' visible. All are self-declared local discussion history, not authenticated approvals.';
 $('ledgerPage').textContent=(events.length?page*perPage+1:0)+'–'+Math.min(events.length,(page+1)*perPage)+' of '+events.length;
 $('ledgerPrev').disabled=page<=0;$('ledgerNext').disabled=page>=pages-1;
 $('ledgerRows').innerHTML=display.map(e=>{
  const sha=[...new Set(e.sourceHashes)].map(hash=>{
   const s=source.labels[hash];return (s?'Revision '+s.sequence+' · '+esc(s.label)+' · ':'')+esc(hash.slice(0,16))+'…';
  }).join(' / ');
  return '<tr><td>'+esc(e.time)+'<small>'+esc(names[e.kind])+'</small></td>'+
   '<td><button type="button" class="link" data-ledger-kind="'+esc(e.kind)+'" data-ledger-index="'+e.index+'">Read exact original details</button>'+
   '<small>'+esc(e.ids.length)+' original finding ID(s): '+esc(e.ids.slice(0,12).join(', '))+
   (e.ids.length>12?' …':'')+'</small><small>'+e.changedCount+' original/HUMAN field delta(s)</small></td>'+
   '<td>'+esc(e.summary.slice(0,320))+'</td><td>'+sha+'</td></tr>';
 }).join('')||'<tr><td colspan="4">No original source-bound HUMAN decisions in the current filter.</td></tr>';
 if(chosen&&events.some(x=>x.kind===chosen.kind&&x.index===chosen.index)){
  try{showDetail(chosen.kind,chosen.index);}catch(e){chosen=null;$('ledgerDetail').hidden=true;say(e.message,true);}
 }else{$('ledgerDetail').hidden=true;$('ledgerDetail').replaceChildren();chosen=null;}
}
$('ledgerRows').addEventListener('click',e=>{
 const btn=e.target.closest('button[data-ledger-kind][data-ledger-index]');
 if(!btn)return;
 try{showDetail(btn.dataset.ledgerKind,Number(btn.dataset.ledgerIndex));}
 catch(err){say(err.message,true);}
});
$('ledgerKind').addEventListener('change',()=>{page=0;render();});
$('ledgerQuery').addEventListener('input',()=>{page=0;render();});
$('ledgerPrev').addEventListener('click',()=>{page--;render();});
$('ledgerNext').addEventListener('click',()=>{page++;render();});
$('ledgerAnonymous').addEventListener('click',()=>{
 try{
  const {source,events}=dataset();
  if(!source.events.length)throw Error('No original HUMAN decision history is loaded.');
  const count=Object.fromEntries(Object.keys(names).map(k=>[k,events.filter(x=>x.kind===k).length]));
  const report={kind:'LightUp anonymous HUMAN decision counts / NON-AUTHORIZING',version:1,
   source_revision_count:Object.keys(source.labels).length,
   total_local_human_events:source.events.length,filtered_human_events:events.length,
   source_carries:count.HUMAN_SOURCE_CARRY,
   original_casework_merges:count.HUMAN_CASEWORK_MERGE,
   historical_source_hold_reviews:count.HUMAN_SOURCE_HOLD_REVIEW,
   caveat:'Counts may disclose PRIVATE context for small cohorts. Source/HUMAN claims unverified; never consent, grant, mitigation, verified retest or release.'};
  const v=JSON.stringify(report,null,2),u=URL.createObjectURL(new Blob([v],{type:'application/json;charset=utf-8'})),a=document.createElement('a');
  a.download='lightup-HUMAN-decisions-anonymous-counts.json';a.href=u;a.click();setTimeout(()=>URL.revokeObjectURL(u),15000);
  say('Anonymous HUMAN decision counts saved locally without finding IDs, source hashes, owner labels or original note text.');
 }catch(err){say(err.message,true);}
});
$('ledgerPrivate').addEventListener('click',()=>{
 try{
  H.privateAllowed();
  const {source,events}=dataset();
  if(!events.length)throw Error('No original HUMAN decisions in the current filter.');
  if(!confirm('Download PLAINTEXT PRIVATE complete HUMAN source decisions with original finding IDs, exact before/after fields, source digests and prior HUMAN values? Confirm separately approved private recipient and secure device. Nothing is transmitted.'))return;
  const before=H.revision();
  const exported=events.map(e=>({
   type:e.kind,event_index:e.index,declared_human_time:e.time,
   original_finding_ids:e.ids,exact_source_sha256:e.sourceHashes,
   original_source_metadata:e.sourceHashes.map(sha=>source.labels[sha]||null),
   details:H.journalDetail(e.kind,e.index,before)
  }));
  if(H.revision()!==before)throw Error('HOLD: original source/HUMAN history changed during PRIVATE export.');
  const packet={
   kind:'LightUp PRIVATE exact-source HUMAN decision register',version:1,
   disposition:'HUMAN_ONLY_NON_AUTHORIZING',authenticated:false,client_consent:false,
   operator_consent:false,verified_retest:false,mitigation_verified:false,
   grant:false,scan:false,release:false,
   source_revision_count:Object.keys(source.labels).length,
   filtered_event_count:exported.length,events:exported
  };
  const body=JSON.stringify(packet,null,2);
  if(new TextEncoder().encode(body).byteLength>2097152)
   throw Error('PRIVATE exact-source decision register exceeds 2 MiB. Narrow the kind/search filter.');
  const u=URL.createObjectURL(new Blob([body],{type:'application/json;charset=utf-8'})),a=document.createElement('a');
  a.download='lightup-PRIVATE-exact-source-human-decision-register.json';a.href=u;a.click();
  setTimeout(()=>URL.revokeObjectURL(u),15000);
  say('PRIVATE source-bound HUMAN decision register downloaded locally. It does not authenticate a human or security result.');
 }catch(err){say(err.message,true);}
});
window.addEventListener('lightup-history-changed',render);
render();
})();
