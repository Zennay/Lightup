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
 $('export').disabled=!request||!$('ack').checked||!$('return-ack').checked;
}
function field(labelText,control){
 const label=el('label',labelText);label.append(control);return label;
}
function render(){
 const cards=$('cards');cards.replaceChildren();
 if(!request)return;
 $('owner').textContent='Human owner/team label: '+request.owner_label+' (not authenticated identity)';
 $('count').textContent=request.rows.length+' original findings, shared exclusively for this single owner label. Original retest remains read-only.';
 for(let i=0;i<draft.length;i++){
  const r=draft[i],card=el('section');card.className='card';
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
  select.addEventListener('change',()=>{r.status=select.value;dirty=true;});
  const date=el('input');date.type='date';date.min='2020-01-01';date.max='2100-12-30';date.value=r.due_date||'';
  date.addEventListener('change',()=>{r.due_date=date.value||null;dirty=true;});
  row.append(field('Local human status',select),field('Human follow-up date, NOT scan window',date));
  const action=el('textarea');action.maxLength=1800;action.value=r.next_action;action.rows=3;
  action.addEventListener('input',()=>{r.next_action=action.value;dirty=true;});
  const blocker=el('textarea');blocker.maxLength=1200;blocker.value=r.blocker;blocker.rows=2;
  blocker.addEventListener('input',()=>{r.blocker=blocker.value;dirty=true;});
  card.append(row,field('Human next action',action),field('Human blocker / dependency',blocker));
  cards.append(card);
 }
 $('workspace').hidden=false;controls();
}
async function load(file){
 if(!file||file.size>MAX)fail('Select the PRIVATE owner handoff JSON no larger than 2 MiB.');
 if(!$('ack').checked)fail('Confirm independent actual client/engagement and intended recipient first.');
 const raw=global.LightUpOwnerPrivateJson.read(await file.text());
 const accepted=await global.LightUpOwnerProtocol.validateRequest(raw);
 request=accepted;draft=accepted.rows.map(x=>({...x}));dirty=false;
 $('return-ack').checked=false;$('reply-message').textContent='';
 $('message').textContent='PRIVATE owner-specific handoff loaded. Source hash is not proof of identity, consent, or current authorization.';
 render();
}
function clear(){
 request=null;draft=null;dirty=false;$('file').value='';
 $('ack').checked=false;$('return-ack').checked=false;$('workspace').hidden=true;
 $('cards').replaceChildren();$('message').textContent=
  'In-memory private handoff cleared. Already downloaded files remain under your control.';
}
async function exportReply(){
 if(!request||!draft||!$('ack').checked||!$('return-ack').checked)
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
$('ack').addEventListener('change',controls);
$('return-ack').addEventListener('change',controls);
$('export').addEventListener('click',async()=>{try{await exportReply();}catch(err){$('reply-message').textContent='HOLD: '+err.message;}});
$('clear').addEventListener('click',()=>{if(dirty&&!global.confirm('Discard unsaved human notes?'))return;clear();});
global.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
})(window);
