/* LightUp private HUMAN workload and tentative date view; no actual fixes, SLAs, retests or authorization. */
(()=>{
'use strict';
const H=window.LightUpHistory,$=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&#39;','"':'&quot;',"'":'&#39;'}[c]));
const ranks={critical:0,high:1,medium:2,low:3,info:4};
const pad=x=>String(x).padStart(2,'0');
function localToday(){const d=new Date();return [d.getFullYear(),pad(d.getMonth()+1),pad(d.getDate())].join('-');}
function week(date){
 const d=new Date(date+'T12:00:00Z');
 if(!Number.isFinite(d.valueOf()))throw Error('Unexpected original HUMAN date in timeline.');
 const wd=(d.getUTCDay()+6)%7;d.setUTCDate(d.getUTCDate()-wd);
 return d.toISOString().slice(0,10);
}
function offsetMonday(start,offset){
 const d=new Date(start+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+7*offset);return d.toISOString().slice(0,10);
}
function csv(v){
 let t=String(v??''),probe=t.replace(/^[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202e\u205f\u2060-\u206f\u3000\ufeff]*/u,'').normalize('NFKC');
 if(/^[=+\-@]/u.test(probe))t="'"+t;return '"'+t.replace(/"/g,'""')+'"';
}
const inScope=row=>!['stale','missing'].includes(row.binding);
const isOpen=row=>!['deferred','completed'].includes(row.status);
function data(){
 const all=H.caseworkRows(),owner=$('weeklyOwner').value,capacity=Number($('weeklyCapacity').value);
 if(!Number.isSafeInteger(capacity)||capacity<1||capacity>30)throw Error('Choose a HUMAN target between 1 and 30 findings per owner/week.');
 return {all,owner,capacity,today:localToday()};
}
function refreshOwnerOptions(all){
 const options=$('weeklyOwner'),current=options.value;
 const owners=[...new Set(all.filter(inScope).map(x=>x.owner.trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 options.innerHTML='<option value="">All HUMAN owners / unassigned</option><option value="__UNASSIGNED__">Unassigned HUMAN work</option>'+
  owners.map(o=>'<option value="'+esc('owner:'+o)+'">'+esc(o)+'</option>').join('');
 if([...options.options].some(o=>o.value===current))options.value=current;
 else options.value='';
}
function ownerMatches(row,chosen){
 if(chosen==='')return true;
 if(chosen==='__UNASSIGNED__')return !row.owner.trim();
 return chosen.startsWith('owner:')&&chosen.slice(6)===row.owner.trim();
}
function render(){
 const all=H.caseworkRows();refreshOwnerOptions(all);
 const {owner,capacity,today}=data();
 const rows=all.filter(r=>inScope(r)&&isOpen(r)&&ownerMatches(r,owner));
 const current=week(today),weeks=Array.from({length:8},(_,i)=>offsetMonday(current,i));
 const overdue=rows.filter(r=>r.due&&r.due<today),undated=rows.filter(r=>!r.due);
 const beyond=rows.filter(r=>r.due&&r.due>=today&&week(r.due)>weeks.at(-1));
 const held=all.filter(r=>!inScope(r));
 $('weeklySummary').textContent=rows.length+' HUMAN unresolved planning rows · '+overdue.length+
  ' tentative overdue · '+undated.length+' no tentative due date · '+held.length+
  ' source-HOLD excluded · '+beyond.length+' beyond 8-week window. Counts are not actual delivery capacity.';
 const groups=new Map();
 for(const r of rows){
  const alias=r.owner.trim(),key=alias?'owner:'+alias:'unassigned';
  if(!groups.has(key))groups.set(key,{name:alias||'UNASSIGNED HUMAN OWNER',rows:[],weeks:new Map()});
  const group=groups.get(key);group.rows.push(r);
  if(r.due&&r.due>=today){const monday=week(r.due);group.weeks.set(monday,(group.weeks.get(monday)||0)+1);}
 }
 const sorted=[...groups.values()].sort((a,b)=>b.rows.filter(x=>ranks[x.severity]<=1).length-a.rows.filter(x=>ranks[x.severity]<=1).length||a.name.localeCompare(b.name));
 $('weeklyHeaders').innerHTML='<th>PRIVATE HUMAN owner / signal</th>'+weeks.map(w=>'<th>Week '+esc(w)+'</th>').join('');
 $('weeklyRows').innerHTML=sorted.map(group=>{
  const urgent=group.rows.filter(x=>ranks[x.severity]<=1).length,blocked=group.rows.filter(x=>x.status==='blocked').length;
  return '<tr><td><strong>'+esc(group.name)+'</strong><small>'+group.rows.length+' HUMAN open · '+urgent+' original critical/high · '+blocked+' HUMAN blocked</small></td>'+
   weeks.map(w=>{
     const n=group.weeks.get(w)||0;
     return '<td><strong>'+(n||'—')+'</strong><small>'+ (n>capacity?'EXCEEDS tentative count target':'')+'</small></td>';
   }).join('')+'</tr>';
 }).join('');
 if(!sorted.length)$('weeklyRows').innerHTML='<tr><td colspan="9">No HUMAN planning rows for the selected owner.</td></tr>';
 const focus=rows.slice().sort((a,b)=>{
  const signal=r=>(r.status==='blocked'?-4:0)+(r.due&&r.due<today?-3:0)+(ranks[r.severity]<=1?-2:0)+(!r.owner?-1:0);
  return signal(a)-signal(b)||(a.due||'9999-12-31').localeCompare(b.due||'9999-12-31')||a.id.localeCompare(b.id);
 }).slice(0,40);
 $('weeklyFollowups').innerHTML=focus.map(r=>'<tr><td><button class="link" data-week-id="'+esc(r.id)+'">'+esc(r.id)+'</button><small>'+esc(r.title.slice(0,90))+'</small></td>'+
  '<td>'+esc(r.severity)+' / '+esc(r.status)+'</td><td>'+esc(r.due||'No human date')+'</td><td>'+esc((r.blocker||r.action||'Unassigned HUMAN follow-up').slice(0,140))+'</td></tr>').join('');
}
function privateExport(){
 H.privateAllowed();
 const {all,owner,capacity,today}=data();
 const rows=all.filter(r=>inScope(r)&&isOpen(r)&&ownerMatches(r,owner));
 if(!rows.length)throw Error('No current source-bound HUMAN planning records for private week export.');
 const hdr=['original_finding_id','original_severity','original_retest_claim','human_owner_alias','human_status','human_due_date','tentative_week_of','human_blocker','human_action','weekly_count_target_NOT_CAPACITY','original_source_binding'];
 const values=rows.map(r=>[r.id,r.severity,r.sourceRetest,r.owner,r.status,r.due,r.due?week(r.due):'',r.blocker,r.action,capacity,r.binding]);
 const blob=new Blob(['\ufeff'+[hdr,...values].map(row=>row.map(csv).join(',')).join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='lightup-PRIVATE-human-weekly-workplan.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 $('message').textContent='PRIVATE HUMAN week plan exported with original IDs. Dates and capacity targets are illustrative local planning only, not real commitments or consent.';
}
$('weeklyCapacity').addEventListener('input',()=>{try{render();}catch(e){$('message').textContent=e.message;}});
$('weeklyOwner').addEventListener('change',()=>{try{render();}catch(e){$('message').textContent=e.message;}});
$('weeklyPrivateExport').addEventListener('click',()=>{try{privateExport();}catch(e){$('message').textContent=e.message;$('message').className='error';}});
$('weeklyFollowups').addEventListener('click',event=>{const b=event.target.closest('button[data-week-id]');if(b)try{H.selectFinding(b.dataset.weekId);}catch(e){$('message').textContent=e.message;}});
window.addEventListener('lightup-history-changed',render);
render();
})();
