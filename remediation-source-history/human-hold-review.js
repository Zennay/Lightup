/* LightUp PRIVATE source-HOLD human decision desk. Local offline coordination only. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const kinds=[
 ['request_new_source','Request a newer original export from human source owner'],
 ['ask_human_owner','Clarify original finding with separately verified HUMAN owner'],
 ['await_separate_evidence','Await independently obtained evidence (NOT verified)'],
 ['defer_private_discussion','Defer HUMAN discussion; keep source HOLD']
];
const selected=new Map();let revision=-1,page=0;const limit=25;
function note(text,bad=false){$('message').textContent=text;$('message').className=bad?'error':'info';}
function rows(){const q=$('holdReviewQuery').value.trim().toLowerCase();
 return H.heldHumanRows().filter(r=>r.sourceRecord&&r.lastMatchingSource)
 .filter(r=>!q||[r.id,r.owner,r.action,r.sourceRecord.title,r.currentSource?.title||''].join(' ').toLowerCase().includes(q));}
function render(){
 if(revision!==H.revision()){revision=H.revision();selected.clear();page=0;$('holdReviewAck').checked=false;}
 const all=rows(),pages=Math.max(1,Math.ceil(all.length/limit));page=Math.min(Math.max(page,0),pages-1);
 const visible=all.slice(page*limit,(page+1)*limit);
 $('holdReviewRows').innerHTML=visible.map(r=>{
  const value=selected.get(r.id),before=r.sourceRecord,after=r.currentSource;
  const options=kinds.map(([v,n])=>'<option value="'+v+'" '+(value?.disposition===v?'selected':'')+'>'+esc(n)+'</option>').join('');
  const changed=after?['finding_id','title','severity','retest_status','remediation'].filter(k=>before[k]!==after[k]).join(', '):'ABSENT from newest original source';
  return '<tr><td><label class="check"><input type="checkbox" data-hold-select="'+esc(r.id)+'" '+(value?'checked':'')+'>Review original HUMAN HOLD</label><strong>'+esc(r.id)+'</strong><small>'+esc(r.binding)+' · earlier original '+esc(r.lastMatchingSource.label)+'</small><small>PRIVATE owner '+esc(r.owner||'unassigned')+'</small><button type="button" class="link" data-hold-dossier="'+esc(r.id)+'">Open complete original finding dossier</button></td>'+
    '<td>'+esc(before.title)+'<small>Original fields changed: '+esc(changed)+'</small><details><summary>Show entire original before/after source</summary><pre>'+esc(JSON.stringify({originalBefore:before,latestOriginal:after},null,2))+'</pre></details></td>'+
    '<td><label>HUMAN follow-up category<select data-hold-kind="'+esc(r.id)+'">'+options+'</select></label><label>PRIVATE HUMAN rationale (12–800 chars)<textarea data-hold-reason="'+esc(r.id)+'" rows="3" maxlength="800">'+esc(value?.reason||'')+'</textarea></label><label>PRIVATE next HUMAN discussion action (8–1200 chars)<textarea data-hold-action="'+esc(r.id)+'" rows="3" maxlength="1200">'+esc(value?.nextAction||'')+'</textarea></label></td></tr>';
 }).join('')||'<tr><td colspan="3">No original source-bound historical HUMAN notes are currently on HOLD.</td></tr>';
 $('holdReviewSummary').textContent=all.length+' source-bound historical HUMAN notes awaiting private review · '+H.holdReviewHistory().length+' retained past HUMAN decisions · '+selected.size+' chosen now; all remain on source HOLD after review.';
 $('holdReviewPage').textContent='Original HOLD review '+(all.length?page*limit+1:0)+'–'+Math.min(all.length,(page+1)*limit)+' / '+all.length;
 $('holdReviewPrev').disabled=page===0;$('holdReviewNext').disabled=page===pages-1;
 $('holdReviewApply').disabled=!selected.size;
 const history=H.holdReviewHistory().slice(-80).reverse();
 $('holdReviewHistory').innerHTML=history.map(r=>'<tr><td>'+esc(r.reviewedUTC)+'<small>'+esc(r.id)+'</small></td><td>'+esc(r.binding)+' · '+esc(r.disposition)+'<small>'+esc(r.originalSourceHash.slice(0,12))+' → '+esc(r.reviewSourceHash.slice(0,12))+'</small></td><td>'+esc(r.reason)+'<small>Next HUMAN action: '+esc(r.nextAction)+'</small></td></tr>').join('')||'<tr><td colspan="3">No historical HUMAN review decisions.</td></tr>';
}
$('holdReviewQuery').addEventListener('input',()=>{page=0;render();});
$('holdReviewPrev').addEventListener('click',()=>{page--;render();});
$('holdReviewNext').addEventListener('click',()=>{page++;render();});
$('holdReviewClear').addEventListener('click',()=>{selected.clear();$('holdReviewAck').checked=false;render();});
$('holdReviewRows').addEventListener('click',e=>{
 const button=e.target.closest('button[data-hold-dossier]');
 if(!button)return;
 try{window.LightUpDossier.open(button.dataset.holdDossier);}
 catch(err){note(err.message,true);}
});
$('holdReviewRows').addEventListener('change',e=>{
 const target=e.target,id=target.dataset.holdSelect||target.dataset.holdKind;if(!id)return;
 if(target.dataset.holdSelect){
  if(target.checked){if(selected.size>=50){target.checked=false;note('No more than 50 PRIVATE HUMAN decisions at once.',true);return;}
   const r=H.heldHumanRows().find(x=>x.id===id);
   selected.set(id,{disposition:'request_new_source',reason:'',nextAction:r?.action||''});
  }else selected.delete(id);
 }else if(selected.has(id))selected.get(id).disposition=target.value;
 render();
});
$('holdReviewRows').addEventListener('input',e=>{
 const target=e.target;
 const id=target.dataset.holdReason||target.dataset.holdAction;
 if(id&&selected.has(id))selected.get(id)[target.dataset.holdReason?'reason':'nextAction']=target.value;
});
$('holdReviewApply').addEventListener('click',()=>{
 try{
  if(!$('holdReviewAck').checked)throw Error('Explicit HUMAN-only original source HOLD review acknowledgment required.');
  const all=new Set(H.heldHumanRows().filter(r=>r.sourceRecord&&r.lastMatchingSource).map(r=>r.id));
  const selections=[...selected].map(([id,fields])=>({id,...fields}));
  if(!selections.length||selections.length>50||selections.some(r=>!all.has(r.id)))
   throw Error('Selected original notes no longer meet source-bound HOLD admission.');
  if(!confirm('Record '+selections.length+' PRIVATE HUMAN discussion decision(s), without changing original evidence or clearing any source HOLD? This does NOT authenticate a sender, declare a fix/retest, notify anyone or confer grant/consent.'))return;
  const result=H.reviewHeldSources(selections,revision);
  selected.clear();$('holdReviewAck').checked=false;
  note('Recorded '+result.recorded+' exact-source PRIVATE HUMAN review decisions. '+result.remainingHeld+' notes remain on original-source HOLD; no notifications or security actions performed.');
 }catch(err){note(err.message,true);}
});
const csv=x=>{let s=String(x??'');const p=s.replace(/^[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202e\u205f\u2060-\u206f\u3000\ufeff]*/u,'').normalize('NFKC');if(/^[=+\-@]/u.test(p))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};
$('holdReviewPrivateExport').addEventListener('click',()=>{
 try{
  H.privateAllowed();
  const journal=H.holdReviewHistory();if(!journal.length)throw Error('No PRIVATE original-source HUMAN HOLD decisions to export.');
  if(!confirm('Export PLAINTEXT PRIVATE original-source IDs, exact before/after source rows and HUMAN explanations to an independently approved recipient/destination? No data is sent.'))return;
  const columns=['human_review_utc','PRIVATE_original_finding_id','previous_original_source_sha256','reviewed_original_source_sha256','original_binding_status','HUMAN_only_disposition','PRIVATE_human_reason','PRIVATE_next_human_action','previous_original_five_fields','reviewed_original_five_fields'];
  const text='\ufeff'+[columns,...journal.map(x=>[x.reviewedUTC,x.id,x.originalSourceHash,x.reviewSourceHash,x.binding,x.disposition,x.reason,x.nextAction,JSON.stringify(x.oldSource),JSON.stringify(x.currentSource)])].map(a=>a.map(csv).join(',')).join('\r\n')+'\r\n';
  if(new TextEncoder().encode(text).length>2097152)throw Error('PRIVATE original-source HUMAN review CSV exceeds 2 MiB.');
  const u=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'})),a=document.createElement('a');a.href=u;a.download='lightup-PRIVATE-original-HUMAN-HOLD-discussion-history.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
  note('PRIVATE HUMAN source-HOLD discussion journal downloaded locally, without contacting anyone.');
 }catch(err){note(err.message,true);}
});
window.addEventListener('lightup-history-changed',render);render();
})();
