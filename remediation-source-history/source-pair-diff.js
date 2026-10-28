/* Read-only original two-cohort source-delta comparison, local HUMAN triage only. */
(()=>{
'use strict';
const $=id=>document.getElementById(id),H=window.LightUpHistory;
const fields=['finding_id','title','severity','retest_status','remediation'];
const ranks={critical:0,high:1,medium:2,low:3,info:4};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const csv=s=>{
 let t=String(s??'');
 const probe=t.replace(/^[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202e\u205f\u2060-\u206f\u3000\ufeff]*/u,'').normalize('NFKC');
 if(/^[=+\-@]/u.test(probe))t="'"+t;
 return '"'+t.replace(/"/g,'""')+'"';
};
let compared=null;
function message(s,fail=false){$('message').textContent=s;$('message').className=fail?'error':'info';}
function download(filename,rows){const txt='\uFEFF'+rows.map(r=>r.map(csv).join(',')).join('\r\n')+'\r\n';const u=URL.createObjectURL(new Blob([txt],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=u;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}
function updateSelectors(){
 const snapshots=H.view(),from=$('diffFrom'),to=$('diffTo'),priorFrom=from.value,priorTo=to.value;
 const options=snapshots.map((s,i)=>'<option value="'+esc(s.sourceHash)+'">'+esc((i+1)+'. '+s.label)+'</option>').join('');
 from.innerHTML=to.innerHTML=options;
 if(snapshots.some(x=>x.sourceHash===priorFrom))from.value=priorFrom;
 if(snapshots.some(x=>x.sourceHash===priorTo))to.value=priorTo;
 else if(snapshots.length)to.value=snapshots.at(-1).sourceHash;
 $('diffGo').disabled=snapshots.length<2;
 $('diffAggregate').disabled=snapshots.length<2;
 $('diffProvenance').disabled=snapshots.length<2;
 $('diffPrivate').disabled=snapshots.length<2;
 $('diffSummary').textContent=snapshots.length<2?'Import two or more separately verified original source revisions.':'Select an earlier and a later historical export. Source labels are not security findings.';
 $('diffRows').innerHTML='';compared=null;
}
function compute(){
 const snapshots=H.view(),start=snapshots.findIndex(x=>x.sourceHash===$('diffFrom').value),end=snapshots.findIndex(x=>x.sourceHash===$('diffTo').value);
 if(start<0||end<0||start>=end)throw Error('Choose two distinct revisions in chronological order: earlier first, later second.');
 const before=snapshots[start],after=snapshots[end],native=LightUpCasework.compareSource(before.findings,after.findings);
 const old=new Map(before.findings.map(x=>[x.finding_id,x])),current=new Map(after.findings.map(x=>[x.finding_id,x]));
 const all=new Set([...old.keys(),...current.keys()]),out=[];
 for(const id of all){
  const a=old.get(id),b=current.get(id);
  const status=!a?'introduced':!b?'absent':fields.every(k=>a[k]===b[k])?'unchanged':'changed';
  const changes=a&&b?fields.filter(k=>a[k]!==b[k]):[];
  out.push({id,a,b,status,changes});
 }
 out.sort((x,y)=>Math.min(ranks[x.a?.severity]??5,ranks[x.b?.severity]??5)-Math.min(ranks[y.a?.severity]??5,ranks[y.b?.severity]??5)||x.id.localeCompare(y.id));
 const severityUps=out.filter(x=>x.a&&x.b&&ranks[x.b.severity]<ranks[x.a.severity]).length;
 const severityDowns=out.filter(x=>x.a&&x.b&&ranks[x.b.severity]>ranks[x.a.severity]).length;
 const retestChanges=out.filter(x=>x.a&&x.b&&x.a.retest_status!==x.b.retest_status).length;
 const summary={introduced:native.added.length,absent:native.missing.length,changed:native.changed.length,unchanged:native.unchanged.length,severityUps,severityDowns,retestChanges};
 return {before,after,summary,rows:out,start,end};
}
function renderComparison(){
 const c=compute(),s=c.summary;
 compared={...c,revision:H.revision()};
 $('diffSummary').textContent=c.before.label+' → '+c.after.label+' · '+s.introduced+' newly present · '+s.absent+' missing (NOT fixed) · '+s.changed+' source changed · '+s.unchanged+' identical · '+s.severityUps+' severity increases · '+s.severityDowns+' decreases · '+s.retestChanges+' source retest label changes';
 const shown=c.rows.filter(r=>r.status!=='unchanged'||$('showUnchanged').checked);
 $('diffCount').textContent=shown.length+' source trajectories displayed (no evidence of actual fixes or retests)';
 $('diffRows').innerHTML=shown.map(r=>{
  const older=r.a,newer=r.b,orig=older||newer;
  return '<tr><td><strong>'+esc(r.status.toUpperCase())+'</strong><small>'+esc(r.changes.join(', ')|| (r.status==='absent'?'No longer in later export — NOT verified fixed':'Exact original fields'))+'</small></td>'+
   '<td>'+esc(r.id)+'<small>'+esc(orig.title.slice(0,115))+'</small></td>'+
   '<td>'+esc(older?older.severity+' / '+older.retest_status:'— not in earlier export')+'</td>'+
   '<td>'+esc(newer?newer.severity+' / '+newer.retest_status:'— NOT proof of remediation')+'</td></tr>';
 }).join('');
}
function handleGo(){try{renderComparison();}catch(e){compared=null;$('diffRows').innerHTML='';message(e.message,true);}}
function verified(){
 const c=compute();if(!compared||compared.revision!==H.revision()||compared.start!==c.start||compared.end!==c.end||compared.before.sourceHash!==c.before.sourceHash||compared.after.sourceHash!==c.after.sourceHash||compared.before.fileHash!==c.before.fileHash||compared.after.fileHash!==c.after.fileHash)throw Error('HOLD: preview the current exact source pair after any revision or selection change before export.');
 return c;
}
function exportAggregate(privateProvenance=false){
 if(privateProvenance)H.privateAllowed();
 const c=verified(),s=c.summary;
 const columns=['earlier_revision_index','later_revision_index','introduced_source_records','absent_not_verified_fixed','exact_source_changes','unchanged','source_severity_escalations','source_severity_decreases','source_retest_label_changes'];
 const values=[c.start+1,c.end+1,s.introduced,s.absent,s.changed,s.unchanged,s.severityUps,s.severityDowns,s.retestChanges];
 if(privateProvenance){
  columns.push('PRIVATE_earlier_label','PRIVATE_later_label','PRIVATE_earlier_canonical_source_sha256','PRIVATE_later_canonical_source_sha256','PRIVATE_earlier_original_file_sha256','PRIVATE_later_original_file_sha256');
  values.push(c.before.label,c.after.label,c.before.sourceHash,c.after.sourceHash,c.before.fileHash,c.after.fileHash);
 }
 download(privateProvenance?'lightup-PRIVATE-source-pair-provenance.csv':'lightup-source-pair-anonymous-counts.csv',[columns,values]);
 message(privateProvenance?'PRIVATE original source provenance exported to an explicitly approved destination.':'Aggregate comparison counts exported without original source hashes, labels or finding identifiers; small-group context may remain sensitive.');
}
function exportPrivate(){
 H.privateAllowed();
 const c=verified(),rows=c.rows.filter(r=>r.status!=='unchanged'||$('showUnchanged').checked);
 if(!rows.length)throw Error('No source changes for private handoff at this selection.');
 const cols=['original_before_revision_index','original_after_revision_index','PRIVATE_original_before_canonical_sha256','PRIVATE_original_after_canonical_sha256','PRIVATE_original_before_file_sha256','PRIVATE_original_after_file_sha256','source_finding_id','source_change','original_changed_fields','old_source_severity','new_source_severity','old_source_retest_claim','new_source_retest_claim','original_old_title','original_new_title','original_old_remediation','original_new_remediation'];
 const data=rows.map(x=>[c.start+1,c.end+1,c.before.sourceHash,c.after.sourceHash,c.before.fileHash,c.after.fileHash,x.id,x.status,x.changes.join(' | '),x.a?.severity||'',x.b?.severity||'',x.a?.retest_status||'',x.b?.retest_status||'',x.a?.title||'',x.b?.title||'',x.a?.remediation||'',x.b?.remediation||'']);
 download('lightup-PRIVATE-source-pair-review.csv',[cols,...data]);
 message('PRIVATE original-ID and original remediation-text comparison saved to the approved local device; no permission or verified fix implied.');
}
$('diffGo').addEventListener('click',handleGo);
$('showUnchanged').addEventListener('change',()=>{if(compared)handleGo();});
$('diffAggregate').addEventListener('click',()=>{try{exportAggregate();}catch(e){message(e.message,true);}});
$('diffProvenance').addEventListener('click',()=>{try{exportAggregate(true);}catch(e){message(e.message,true);}});
$('diffPrivate').addEventListener('click',()=>{try{exportPrivate();}catch(e){message(e.message,true);}});
window.addEventListener('lightup-history-changed',updateSelectors);
updateSelectors();
})();
