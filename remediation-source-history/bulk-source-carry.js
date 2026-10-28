/* LightUp PRIVATE HUMAN bulk source-carry inbox. No verified remediation or authority. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const keys=['finding_id','title','severity','retest_status','remediation'];
let page=0,stagedRevision=-1;
const selected=new Map(),pageSize=30;
function msg(s,bad=false){$('message').textContent=s;$('message').className=bad?'error':'info';}
function candidate(r){return r.binding==='stale'&&r.currentSource&&r.sourceRecord&&r.lastMatchingSource;}
function eligible(){
 const search=$('bulkCarryQuery').value.trim().toLowerCase();
 return H.heldHumanRows().filter(candidate).filter(r=>
   !search||[r.id,r.sourceRecord.title,r.currentSource.title,r.owner].join(' ').toLowerCase().includes(search));
}
function summary(n){
 $('bulkCarrySummary').textContent=n+' changed-original HUMAN notes eligible for independent review · '+selected.size+' deliberately selected (max 50 per batch) · missing and unbound source notes remain HOLD.';
 $('bulkCarryApply').disabled=!selected.size;
}
function render(){
 if(stagedRevision!==H.revision()){selected.clear();page=0;stagedRevision=H.revision();$('bulkCarryAck').checked=false;$('bulkNativeBackupAck').checked=false;}
 const rows=eligible(),pages=Math.max(1,Math.ceil(rows.length/pageSize));
 page=Math.max(0,Math.min(page,pages-1));
 const shown=rows.slice(page*pageSize,(page+1)*pageSize);
 $('bulkCarryRows').innerHTML=shown.map(r=>{
  const checked=selected.has(r.id),old=r.sourceRecord,now=r.currentSource;
  const exactReview='<details><summary>Review all FIVE unchanged original field names</summary><table class="mini"><thead><tr><th>Original field</th><th>Historical note-bound row</th><th>Current exact original row</th></tr></thead><tbody>'+keys.map(k=>'<tr><td>'+esc(k)+'</td><td>'+esc(old[k])+'</td><td>'+esc(now[k])+'</td></tr>').join('')+'</tbody></table></details>';
  return '<tr><td><label class="check"><input type="checkbox" data-carry-check="'+esc(r.id)+'" '+(checked?'checked ':'')+'>Deliberately review this original ID</label><strong>'+esc(r.id)+'</strong><small>Earlier source: '+esc(r.lastMatchingSource.label)+'</small><small>Previous source claim: '+esc(old.severity)+' / '+esc(old.retest_status)+'</small></td>'+
  '<td><strong>'+esc(now.title.slice(0,130))+'</strong><small>Current original: '+esc(now.severity)+' / '+esc(now.retest_status)+'</small><small>Original-only changed fields: '+esc(keys.filter(k=>old[k]!==now[k]).join(', '))+'</small>'+exactReview+'</td>'+
  '<td>'+esc(r.owner||'Unassigned HUMAN owner')+'<small>Human date: '+esc(r.due||'Unset')+'</small><small>'+ (r.hasNativeCasework?'⚠ Native imported Casework fields WILL BE CLEARED':'No imported full native Casework packet')+'</small>'+(r.hasNativeCasework?'<details><summary>Inspect historical imported HUMAN metadata to preserve privately</summary><p>Unverified HUMAN status: '+esc(r.status)+'</p><p>Blocker: '+esc(r.blocker)+'</p><p>Verification plan (NOT performed): '+esc(r.verification_plan)+'</p><p>PRIVATE old note: '+esc(r.note)+'</p></details>':'')+'</td>'+
  '<td><label>Per-original-ID PRIVATE human reason (8–800 chars)<textarea data-carry-reason="'+esc(r.id)+'" maxlength="800" rows="3" placeholder="Why can HUMAN planning follow this changed original source?">'+esc(selected.get(r.id)||'')+'</textarea></label></td></tr>';
 }).join('')||'<tr><td colspan="4">No changed exact-original HUMAN notes for this filter. Historical missing/unbound notes remain HOLD.</td></tr>';
 $('bulkCarryPage').textContent='Showing eligible originals '+(rows.length?page*pageSize+1:0)+'–'+Math.min(rows.length,(page+1)*pageSize)+' of '+rows.length;
 $('bulkCarryPrev').disabled=page===0;
 $('bulkCarryNext').disabled=page===pages-1;
 summary(rows.length);
}
$('bulkCarryQuery').addEventListener('input',()=>{page=0;render();});
$('bulkCarryPrev').addEventListener('click',()=>{page=Math.max(0,page-1);render();});
$('bulkCarryNext').addEventListener('click',()=>{page++;render();});
$('bulkCarryRows').addEventListener('change',event=>{
 const checkbox=event.target.closest('input[data-carry-check]');
 if(!checkbox)return;
 const id=checkbox.dataset.carryCheck;
 if(checkbox.checked){
  if(selected.size>=50){checkbox.checked=false;msg('Maximum 50 HUMAN source decisions per atomic batch. Complete the current batch before selecting more.',true);return;}
  const textarea=[...$('bulkCarryRows').querySelectorAll('textarea[data-carry-reason]')].find(x=>x.dataset.carryReason===id);
  selected.set(id,textarea?.value||'');
 }else selected.delete(id);
 summary(eligible().length);
});
$('bulkCarryRows').addEventListener('input',event=>{
 const area=event.target.closest('textarea[data-carry-reason]');
 if(area&&selected.has(area.dataset.carryReason))selected.set(area.dataset.carryReason,area.value);
});
$('bulkCarryClear').addEventListener('click',()=>{selected.clear();$('bulkCarryAck').checked=false;$('bulkNativeBackupAck').checked=false;render();});
$('bulkCarryApply').addEventListener('click',()=>{
 try{
  if(!$('bulkCarryAck').checked)throw Error('Confirm explicit HUMAN-only original source review and deliberate replacement of source binding.');
  if(!selected.size||selected.size>50)throw Error('Select 1–50 exact source-changed historical HUMAN notes.');
  const revision=stagedRevision,current=new Set(eligible().map(r=>r.id));
  const total=new Set(H.heldHumanRows().filter(candidate).map(r=>r.id));
  // A filter is only a display convenience; selections from preceding pages
  // remain eligible as long as their exact source revision has not changed.
  const choices=[...selected].map(([id,reason])=>({id,reason}));
  if(choices.some(x=>!total.has(x.id)||typeof x.reason!=='string'||x.reason.trim().length<8||x.reason.length>800))
    throw Error('HOLD: a selected original row changed or its private HUMAN reason is missing/invalid.');
  const requiresNativeBackup=H.heldHumanRows().some(r=>selected.has(r.id)&&r.hasNativeCasework);
  if(requiresNativeBackup&&!$('bulkNativeBackupAck').checked)
    throw Error('HOLD: selected imported native Casework blocker/status/notes will be cleared. Privately preserve a prior encrypted checkpoint and explicitly confirm backup before continuing.');
  if(H.revision()!==revision)throw Error('HOLD: source revision changed since queue display. Review again.');
  if(!confirm('Carry '+choices.length+' locally declared HUMAN owner/action/date note(s) to the changed ORIGINAL five-field source, with each individual reason? Imported old HUMAN status, blockers and security labels will NOT be carried. This is not a fix, verified retest or authority.'))return;
  const result=H.carryHumanBatch(choices,revision,$('bulkNativeBackupAck').checked);
  selected.clear();$('bulkCarryAck').checked=false;$('bulkNativeBackupAck').checked=false;
  msg('Atomically reviewed '+result.carried+' PRIVATE HUMAN source carries; '+result.held+' old HUMAN notes remain source HOLD. No original evidence, grant or verification changed.');
 }catch(e){msg(e.message,true);}
});
window.addEventListener('lightup-history-changed',render);
render();
})();
