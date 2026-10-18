/* LightUp: private single-owner HUMAN planning replies, entirely offline. */
(function(global){
'use strict';
const $=id=>document.getElementById(id);
const MAX=2097152;
const STATUS=[
 ['unassigned','Unassigned HUMAN work'],['planned','Planned'],['in_progress','In progress'],
 ['blocked','Blocked'],['ready_for_retest','Ready for separately authorized retest'],
 ['deferred','Deferred locally'],['completed','Locally completed — NOT a verified fix']
];
let request=null,draft=null,dirty=false;
function fail(msg){throw Error(msg);}
function el(tag,text){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);return e;}
function save(name,content){
 const b=new Blob([content],{type:'application/json;charset=utf-8'});
 const url=URL.createObjectURL(b),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function controls(){
 $('export').disabled=!request||!$('ack').checked||!$('return-ack').checked||
  !$('return-review-ack').checked||returnReviewFingerprint!==JSON.stringify(draft);
}
function field(labelText,control){
 const label=el('label',labelText);label.append(control);return label;
}
function visibleRows(){
 if(!draft)return [];
 const mode=$('recipient-filter').value,search=$('recipient-search').value.trim().toLowerCase();
 const severity=['critical','high','medium','low','info'];
 const today=new Date().toISOString().slice(0,10);
 return draft.map((r,i)=>({r,i})).filter(({r})=>{
  if(search&&!((r.finding_id+' '+r.title).toLowerCase().includes(search)))return false;
  if(mode==='urgent'&&!['critical','high'].includes(r.severity))return false;
  if(mode==='overdue'&&!(r.due_date&&r.due_date<today&&!['completed','deferred'].includes(r.status)))return false;
  if(mode==='blocked'&&r.status!=='blocked')return false;
  if(mode==='missing_date'&&(r.due_date||['completed','deferred'].includes(r.status)))return false;
  if(mode==='retest'&&r.status!=='ready_for_retest')return false;
  return true;
 }).sort((a,b)=>{
  const sort=$('recipient-sort').value;
  if(sort==='due')return (a.r.due_date||'9999').localeCompare(b.r.due_date||'9999')||
    severity.indexOf(a.r.severity)-severity.indexOf(b.r.severity);
  if(sort==='title')return a.r.title.localeCompare(b.r.title);
  return severity.indexOf(a.r.severity)-severity.indexOf(b.r.severity)||
    (a.r.due_date||'9999').localeCompare(b.r.due_date||'9999');
 });
}
function renderRecipientMetrics(){
 const target=$('recipient-metrics');target.replaceChildren();if(!draft)return;
 const today=new Date().toISOString().slice(0,10);
 const counts=[
  ['Original assigned',draft.length],
  ['Critical/high',draft.filter(r=>['critical','high'].includes(r.severity)).length],
  ['Human blocked',draft.filter(r=>r.status==='blocked').length],
  ['Past-due local',draft.filter(r=>r.due_date&&r.due_date<today&&!['completed','deferred'].includes(r.status)).length],
  ['Missing human date',draft.filter(r=>!r.due_date&&!['completed','deferred'].includes(r.status)).length],
  ['Awaiting separate retest',draft.filter(r=>r.status==='ready_for_retest').length]
 ];
 for(const [label,count] of counts){
  const box=el('div');box.className='metric';
  box.append(el('strong',count),el('span',label));target.append(box);
 }
}
function applyRecipientBulk(){
 if(!request||!draft||!$('ack').checked)throw Error('Private source and recipient acknowledgment required.');
 const stage=$('recipient-bulk-stage').value;
 if(!STATUS.some(x=>x[0]===stage))throw Error('Select a valid HUMAN-ONLY planning stage.');
 const visible=visibleRows();
 if(!visible.length)throw Error('There are no visible original findings to update.');
 if(!global.confirm('Apply HUMAN stage '+stage+' to '+visible.length+
  ' currently visible original findings? This NEVER updates original retest, authorization, consent or real remediation.'))return;
 for(const item of visible)item.r.status=stage;
 dirty=true;clearReturnReview();render();
 $('recipient-bulk-message').textContent=visible.length+
  ' original findings updated in PRIVATE memory only. Export a return JSON through the approved channel.';
}
let returnReviewFingerprint=null;
function clearReturnReview(){
 returnReviewFingerprint=null;$('return-review').hidden=true;
 $('return-review-ack').checked=false;$('return-review-rows').replaceChildren();
 controls();
}
function reviewReturn(){
 if(!request||!draft||!$('ack').checked)
  throw Error('Private handoff and intended recipient acknowledgment required.');
 const previous=new Map(request.rows.map(x=>[x.finding_id,x]));
 const fields=['status','due_date','next_action','blocker'];
 const changes=[];
 for(const current of draft){
  const prior=previous.get(current.finding_id);
  if(!prior)throw Error('Original handoff finding ID changed.');
  const changed=fields.filter(k=>current[k]!==prior[k]);
  if(changed.length)changes.push({current,prior,changed});
 }
 const target=$('return-review-rows');
 target.replaceChildren();
 for(const item of changes){
  const card=el('div');card.className='card';
  card.append(el('h3','Original finding ID: '+item.current.finding_id));
  for(const key of item.changed){
   const row=el('p',key+': '+String(item.prior[key]??'(no date)')+
    '  →  '+String(item.current[key]??'(no date)'));
   row.className='review-delta';card.append(row);
  }
  target.append(card);
 }
 if(!changes.length)target.append(el('p','No HUMAN-only planning edits versus this original owner handoff. An unchanged private response may still be explicitly returned.'));
 $('return-review-summary').textContent=changes.length+' of '+draft.length+
  ' original findings contain changed HUMAN-only planning fields. This is not a verified fix, original retest or grant.';
 returnReviewFingerprint=JSON.stringify(draft);
 $('return-review').hidden=false;$('return-review-ack').checked=false;
 $('reply-message').textContent='PRIVATE human changes prepared for review; confirm review and separately authorized return channel before export.';
 controls();
}
function render(){
 const cards=$('cards');cards.replaceChildren();
 if(!request)return;
 $('owner').textContent='Human owner/team label: '+request.owner_label+' (not authenticated identity)';
 $('count').textContent=request.rows.length+' original findings, shared exclusively for this single owner label. Original retest remains read-only.';
 renderRecipientMetrics();
 const visible=visibleRows();
 $('count').textContent=visible.length+' visible of '+request.rows.length+' assigned original findings. Original retest is read-only.';
 for(const {r,i} of visible){
  const card=el('section');card.className='card';
  const h=el('h3',r.title),sev=el('span',r.severity.toUpperCase()+' · Original retest: '+r.retest_status);sev.className='tag';
  const fid=el('p','Original finding ID: '+r.finding_id);
  const rem=el('div',r.remediation);rem.className='source';
  card.append(sev,h,fid,el('p','Original remediation summary (read-only)'),rem);
  const row=el('div');row.className='row';
  const select=el('select');
  for(const [value,title] of STATUS){
   const option=el('option',title);option.value=value;select.append(option);
  }
  select.value=r.status;
  select.addEventListener('change',()=>{r.status=select.value;dirty=true;clearReturnReview();});
  const date=el('input');date.type='date';date.min='2020-01-01';date.max='2100-12-30';date.value=r.due_date||'';
  date.addEventListener('change',()=>{r.due_date=date.value||null;dirty=true;clearReturnReview();});
  row.append(field('Local human status',select),field('Human follow-up date, NOT scan window',date));
  const action=el('textarea');action.maxLength=1800;action.value=r.next_action;action.rows=3;
  action.addEventListener('input',()=>{r.next_action=action.value;dirty=true;clearReturnReview();});
  const blocker=el('textarea');blocker.maxLength=1200;blocker.value=r.blocker;blocker.rows=2;
  blocker.addEventListener('input',()=>{r.blocker=blocker.value;dirty=true;clearReturnReview();});
  card.append(row,field('Human next action',action),field('Human blocker / dependency',blocker));
  cards.append(card);
 }
 if(!visible.length){const p=el('p','No original findings match these local filters.');cards.append(p);}
 $('workspace').hidden=false;controls();
}
async function load(file){
 if(!file||file.size>MAX)fail('Select the PRIVATE owner handoff JSON no larger than 2 MiB.');
 if(!$('ack').checked)fail('Confirm independent actual client/engagement and intended recipient first.');
 const raw=global.LightUpOwnerPrivateJson.read(await file.text());
 const accepted=await global.LightUpOwnerProtocol.validateRequest(raw);
 request=accepted;draft=accepted.rows.map(x=>({...x}));dirty=false;clearReturnReview();
 $('resume').value='';$('resume-message').textContent='';
 $('recipient-filter').value='all';$('recipient-search').value='';$('recipient-sort').value='priority';
 $('return-ack').checked=false;$('reply-message').textContent='';
 $('message').textContent='PRIVATE owner-specific handoff loaded. Source hash is not proof of identity, consent, or current authorization.';
 render();
}
async function resumeReply(file){
 if(!request||!draft||!$('ack').checked)
  fail('First load the independently verified original PRIVATE single-owner handoff.');
 if(!file||file.size>MAX)fail('Select saved PRIVATE owner reply JSON of 2 MiB or less.');
 const baseline=request,current=draft,original=JSON.stringify(draft);
 const loaded=global.LightUpOwnerPrivateJson.read(await file.text());
 const accepted=await global.LightUpOwnerProtocol.validateReply(loaded);
 if(request!==baseline||draft!==current||JSON.stringify(draft)!==original)
  fail('The current original or human notes changed during resume. No draft replaced.');
 if(accepted.source_sha256!==request.source_sha256||
    accepted.owner_label!==request.owner_label||
    accepted.baseline_sha256!==request.baseline_sha256||
    accepted.rows.length!==request.rows.length)
  fail('Saved PRIVATE reply is for a DIFFERENT original handoff/owner/source. No import.');
 const expected=new Map(request.rows.map(r=>[r.finding_id,r]));
 const originalFields=['finding_id','title','severity','retest_status','remediation',
  'owner','status','due_date','next_action','blocker'];
 for(const row of accepted.rows){
  const previous=expected.get(row.finding_id);
  if(!previous||originalFields.some(k=>row[k]!==previous[k]))
   fail('Saved PRIVATE reply does not match the EXACT original handoff baseline.');
 }
 if(!global.confirm('Resume '+accepted.reply_rows.length+
   ' HUMAN-ONLY entries from this source-bound PRIVATE draft? The current unsaved local human edits will be replaced. This is not authority or retest.'))return;
 draft=accepted.reply_rows.map(x=>({...x}));dirty=true;clearReturnReview();
 $('resume').value='';$('return-ack').checked=false;
 $('resume-message').textContent=accepted.reply_rows.length+
  ' original source-bound HUMAN entries safely resumed from PRIVATE reply. Export again before closing.';
 render();
}
function clear(){
 request=null;draft=null;dirty=false;clearReturnReview();$('file').value='';$('resume').value='';
 $('ack').checked=false;$('return-ack').checked=false;$('workspace').hidden=true;
 $('cards').replaceChildren();$('message').textContent=
  'In-memory private handoff cleared. Already downloaded files remain under your control.';
}
async function exportReply(){
 if(!request||!draft||!$('ack').checked||!$('return-ack').checked||
    !$('return-review-ack').checked||returnReviewFingerprint!==JSON.stringify(draft))
  fail('Explicit independently approved return channel acknowledgment required.');
 const base=request;const before=JSON.stringify(draft);
 const reply=await global.LightUpOwnerProtocol.createReply(base,draft);
 if(request!==base||JSON.stringify(draft)!==before)fail('Human notes changed during reply preparation. Review and retry.');
 if(!global.confirm('Export PRIVATE owner reply with '+draft.length+
   ' original findings and HUMAN-ONLY notes via the approved confidential return channel? This is NOT authenticated consent or verified remediation.'))return;
 save('lightup-PRIVATE-calendar-owner-reply.json',JSON.stringify(reply,null,2)+'\n');
 dirty=false;$('reply-message').textContent='PRIVATE human reply exported. Share through the independently approved recipient channel only.';
}
$('file').addEventListener('change',async e=>{
 if(dirty&&!global.confirm('Discard unsaved PRIVATE human notes and replace handoff?')){e.target.value='';return;}
 request=null;draft=null;$('workspace').hidden=true;
 try{await load(e.target.files[0]);}catch(err){$('message').textContent='HOLD: '+err.message;}
});
for(const id of ['recipient-filter','recipient-search','recipient-sort'])$(id).addEventListener('input',()=>{if(request)render();});
$('recipient-bulk-apply').addEventListener('click',()=>{try{applyRecipientBulk();}catch(err){$('recipient-bulk-message').textContent='HOLD: '+err.message;}});
$('resume').addEventListener('change',async e=>{try{await resumeReply(e.target.files[0]);}catch(err){$('resume-message').textContent='HOLD: '+err.message;e.target.value='';}});
$('return-preview-button').addEventListener('click',()=>{try{reviewReturn();}catch(err){clearReturnReview();$('reply-message').textContent='HOLD: '+err.message;}});
$('return-review-ack').addEventListener('change',controls);
$('ack').addEventListener('change',controls);
$('return-ack').addEventListener('change',controls);
$('export').addEventListener('click',async()=>{try{await exportReply();}catch(err){$('reply-message').textContent='HOLD: '+err.message;}});
$('clear').addEventListener('click',()=>{if(dirty&&!global.confirm('Discard unsaved human notes?'))return;clear();});
global.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
})(window);
