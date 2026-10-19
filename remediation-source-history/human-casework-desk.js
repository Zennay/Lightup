/* LightUp local HUMAN Casework Desk. Native Casework v1 metadata only; never an assessment or remediation executor. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
let selected='',seenRevision=-1,checkRevision=-1;
const checked=new Set();
const ranking={critical:0,high:1,medium:2,low:3,info:4};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const csv=s=>{let t=String(s??'');const p=t.replace(/^[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202e\u205f\u2060-\u206f\u3000\ufeff]*/u,'').normalize('NFKC');if(/^[=+\-@]/u.test(p))t="'"+t;return '"'+t.replace(/"/g,'""')+'"';};
function notice(value,bad=false){$('message').textContent=value;$('message').className=bad?'error':'info';}
function deadline(row,today){return !!row.due&&row.due<today&& !['deferred','completed'].includes(row.status);}
function humanRank(row,today){
 if(row.binding==='stale'||row.binding==='missing')return -1;
 if(row.status==='blocked')return 0;
 if(deadline(row,today))return 1;
 if(!row.owner&&(ranking[row.severity]??5)<=1)return 2;
 if((ranking[row.severity]??5)<=1)return 3;
 if(row.status==='unassigned')return 4;
 return 5;
}
const todayUTC=()=>{
 const now=new Date(),pad=x=>String(x).padStart(2,'0');
 return now.getFullYear()+'-'+pad(now.getMonth()+1)+'-'+pad(now.getDate());
};
function filtered(rows){
 const text=$('deskQuery').value.trim().toLowerCase(),severity=$('deskSeverity').value,status=$('deskStatus').value,filter=$('deskFocus').value;
 const today=todayUTC();
 return rows.filter(row=>{
  if(severity!=='all'&&row.severity!==severity)return false;
  if(status!=='all'&&row.status!==status)return false;
  if(filter==='held'&&!['stale','missing'].includes(row.binding))return false;
  if(filter==='blocked'&&row.status!=='blocked')return false;
  if(filter==='overdue'&&!deadline(row,today))return false;
  if(filter==='unassigned'&&row.owner)return false;
  if(filter==='critical'&&ranking[row.severity]>1)return false;
  if(filter==='due'&&(!row.due||row.due<today))return false;
  return !text||[row.id,row.title,row.owner,row.action,row.blocker,row.note].join(' ').toLowerCase().includes(text);
 }).sort((a,b)=>humanRank(a,today)-humanRank(b,today)||ranking[a.severity]-ranking[b.severity]||(a.due||'9999').localeCompare(b.due||'9999')||a.id.localeCompare(b.id));
}
function render(){
 const all=H.caseworkRows(),rows=filtered(all),today=todayUTC();
 if(checkRevision!==H.revision()){checked.clear();checkRevision=H.revision();}
 $('deskSummary').textContent=all.length+' original-source findings · '+all.filter(x=>ranking[x.severity]<=1).length+
  ' source-labelled critical/high · '+all.filter(x=>x.status==='blocked').length+' HUMAN blocked · '+
  all.filter(x=>deadline(x,today)).length+' HUMAN overdue · '+
  all.filter(x=>['stale','missing'].includes(x.binding)).length+' HUMAN HOLD · '+rows.length+' visible';
 $('deskRows').innerHTML=rows.map(row=>{
  const held=['stale','missing'].includes(row.binding),late=deadline(row,today);
  const tags=[row.severity,row.status,held?'SOURCE HOLD':row.binding==='bound'?'ORIGINAL ROW':'NO HUMAN NOTES',late?'HUMAN overdue':''].filter(Boolean);
  return '<tr><td><label class="check"><input type="checkbox" data-check="'+esc(row.id)+'" '+(checked.has(row.id)?'checked ':'')+(held?'disabled ':'')+'aria-label="Select original finding for HUMAN batch"></label><button class="link" type="button" data-case="'+esc(row.id)+'">'+esc(row.id)+'</button><small>'+esc(row.title.slice(0,130))+'</small></td>'+
    '<td>'+tags.map(t=>'<small>'+esc(t)+'</small>').join('')+'</td>'+
    '<td>'+esc(row.owner||'Human owner unassigned')+'<small>'+esc(row.due||'No HUMAN due date')+'</small></td>'+
    '<td>'+esc((row.blocker||row.action||'No HUMAN action').slice(0,150))+'</td></tr>';
 }).join('');
 $('deskCount').textContent='Human queue showing '+rows.length+' original finding rows · '+checked.size+' selected for HUMAN batch';
 if(selected&&seenRevision!==H.revision()){
   // Reject silently reusing an edit form after a source revision or another HUMAN edit.
   selected='';$('deskEditor').hidden=true;
 }
 if(selected&&!all.some(row=>row.id===selected)){$('deskEditor').hidden=true;selected='';}
}
function open(id){
 const row=H.caseworkRows().find(row=>row.id===id);if(!row)throw Error('Original finding no longer available.');
 selected=id;seenRevision=H.revision();
 $('deskEditor').hidden=false;
 $('deskTitle').textContent=row.title+' · '+id;
 $('deskBinding').textContent=['stale','missing'].includes(row.binding)?
  'SOURCE HOLD: original HUMAN notes belong to a different exact original row. Use the historical source review panel, not this editor.':
  'HUMAN-only work planning on the exact latest original five-column finding; not a verified remediation or authorized scan.';
 const held=['stale','missing'].includes(row.binding);
 for(const id of ['deskOwner','deskAction','deskBlocker','deskVerification','deskNote','deskDue','deskProgress'])
  $(id).disabled=held;
 $('deskSave').disabled=held;
 $('deskOwner').value=row.owner;$('deskAction').value=row.action;
 $('deskBlocker').value=row.blocker;$('deskVerification').value=row.verification_plan;
 $('deskNote').value=row.note;$('deskDue').value=row.due;
 const allowed=['unassigned','planned','in_progress','blocked','deferred'];
 $('deskProgress').value=allowed.includes(row.status)?row.status:'unassigned';
 if(!allowed.includes(row.status))
   $('deskBinding').textContent+=' Previous source-imported HUMAN status "'+row.status+'" cannot be freshly asserted by this offline editor; you must explicitly pick a non-conclusive planning status.';
 $('deskEditor').scrollIntoView({behavior:'smooth',block:'start'});
}
function save(){
 if(!selected)throw Error('Select a source finding before editing HUMAN planning.');
 const data={owner:$('deskOwner').value,action:$('deskAction').value,
   blocker:$('deskBlocker').value,verification_plan:$('deskVerification').value,
   note:$('deskNote').value,due:$('deskDue').value,status:$('deskProgress').value};
 const outcome=H.saveCaseworkEdit(selected,data,seenRevision);
 selected='';$('deskEditor').hidden=true;render();
 notice('Native HUMAN Casework v1 updated locally ('+outcome.status+'). Use encrypted PRIVATE checkpoint or original Casework export to save it. Never proof of a security fix.');
}
function download(){
 H.privateAllowed();
 const rows=filtered(H.caseworkRows());if(!rows.length)throw Error('No filtered HUMAN worklist records to export.');
 const hdr=['original_finding_id','original_severity','original_retest_claim','human_source_binding','human_status','human_owner','human_due_date','human_next_action','human_blocker','human_verification_plan','human_note'];
 const data=rows.map(r=>[r.id,r.severity,r.sourceRetest,r.binding,r.status,
   r.binding==='bound'?r.owner:'',r.binding==='bound'?r.due:'',
   r.binding==='bound'?r.action:'',r.binding==='bound'?r.blocker:'',
   r.binding==='bound'?r.verification_plan:'',r.binding==='bound'?r.note:'']);
 const blob=new Blob(['\ufeff'+[hdr,...data].map(row=>row.map(csv).join(',')).join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='lightup-PRIVATE-source-bound-human-casework-queue.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 notice('PRIVATE HUMAN worklist exported. Source-HOLD note contents remain excluded; recipient must be separately approved.');
}
function markVisible(){
 const rows=filtered(H.caseworkRows()).filter(row=>!['stale','missing'].includes(row.binding));
 if(rows.length>100)throw Error('HUMAN bulk plan is limited to 100 original source rows. Filter the queue more narrowly.');
 checked.clear();for(const row of rows)checked.add(row.id);
 checkRevision=H.revision();render();
}
function batch(){
 H.privateAllowed();
 if(checkRevision!==H.revision())throw Error('Source changed since selection; choose the original finding rows again.');
 const ids=[...checked];if(!ids.length)throw Error('Select at least one eligible exact-source original finding.');
 if(ids.length>100)throw Error('A HUMAN batch may change at most 100 original findings.');
 const changes={
  applyOwner:$('batchApplyOwner').checked,owner:$('batchOwner').value,
  applyDue:$('batchApplyDue').checked,due:$('batchDue').value,
  applyStatus:$('batchApplyStatus').checked,status:$('batchStatus').value
 };
 if(!changes.applyOwner&&!changes.applyDue&&!changes.applyStatus)
  throw Error('Choose at least one specific HUMAN owner/status/date field to change.');
 if(!$('batchHumanAck').checked)throw Error('Confirm that these are HUMAN-only tentative planning edits and not actual remediation/authorization.');
 if(!window.confirm('Apply HUMAN-only planning edits to '+ids.length+' exact original source findings? This replaces the selected HUMAN fields only, leaves source and blockers untouched, and does NOT verify fixes or authorize targets.'))return;
 const result=H.batchHumanPlan(ids,changes,checkRevision);
 checked.clear();$('batchHumanAck').checked=false;render();
 notice('Updated '+result.changed+' source-bound original HUMAN Casework rows atomically. Save an encrypted PRIVATE checkpoint or native Casework v1 handoff to retain the plan.');
}
$('deskRows').addEventListener('change',event=>{
 const box=event.target.closest('input[data-check]');if(!box)return;
 if(checkRevision!==H.revision()){checked.clear();render();return;}
 if(box.checked)checked.add(box.dataset.check);else checked.delete(box.dataset.check);
 $('deskCount').textContent=checked.size+' HUMAN original findings selected';
});
$('deskSelectVisible').addEventListener('click',()=>{try{markVisible();}catch(e){notice(e.message,true);}});
$('deskClearSelection').addEventListener('click',()=>{checked.clear();render();});
$('deskBatchApply').addEventListener('click',()=>{try{batch();}catch(e){notice(e.message,true);}});
$('deskRows').addEventListener('click',event=>{
 const button=event.target.closest('button[data-case]');if(!button)return;
 try{open(button.dataset.case);}catch(e){notice(e.message,true);}
});
for(const name of ['deskQuery','deskSeverity','deskStatus','deskFocus'])
 $(name).addEventListener(name==='deskQuery'?'input':'change',render);
$('deskSave').addEventListener('click',()=>{try{save();}catch(e){notice(e.message,true);}});
$('deskPrivateExport').addEventListener('click',()=>{try{download();}catch(e){notice(e.message,true);}});
$('deskReview').addEventListener('click',()=>{if(selected){try{H.selectFinding(selected);}catch(e){notice(e.message,true);}}});
window.addEventListener('lightup-history-changed',render);
render();
})();
