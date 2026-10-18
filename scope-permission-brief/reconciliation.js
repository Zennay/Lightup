/* LightUp: bounded offline human reply reconciliation. No identity, consent, approval or execution. */
(() => {
'use strict';
const $=id=>document.getElementById(id);
const runtime=window.LightUpBriefRuntime;
const roles=['client','operator'],states=['unanswered','question_sent','answered_unverified'];
const MAX=65536;
const uploads={client:null,operator:null};
let revision=0;
function reset(){
 revision++;
 uploads.client=null;uploads.operator=null;
 $('reconcileClient').value='';$('reconcileOperator').value='';
 $('reconcileClientState').textContent='No client preparation note';
 $('reconcileOperatorState').textContent='No operator preparation note';
 refresh();
}
function demand(condition){if(!condition)throw Error('Unsafe or incompatible local packet');}
function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function current(){return runtime.snapshot();}
function accept(packet,source,role){
 demand(packet&&typeof packet==='object'&&!Array.isArray(packet));
 const skip=['audience','question_states','outstanding_questions'];
 demand(Object.keys(packet).length===Object.keys(source).length);
 demand(Object.keys(packet).every(k=>Object.hasOwn(source,k)));
 for(const key of Object.keys(source)){
  if(skip.includes(key))continue;
  demand(same(packet[key],source[key]));
 }
 demand(packet.audience===role);
 demand(Array.isArray(packet.question_states)&&packet.question_states.length===source.question_states.length);
 const statuses={};
 for(let i=0;i<source.question_states.length;i++){
  const got=packet.question_states[i],known=source.question_states[i];
  demand(got&&typeof got==='object'&&!Array.isArray(got));
  demand(Object.keys(got).length===3&&Object.keys(got).every(k=>['code','role','status'].includes(k)));
  demand(got.code===known.code&&got.role===known.role&&states.includes(got.status));
  // Each self-labelled role may only report progress on its own assigned questions.
  demand(got.role===role||got.status==='unanswered');
  if(got.role===role)statuses[got.code]=got.status;
 }
 demand(packet.outstanding_questions===packet.question_states.filter(q=>q.status!=='answered_unverified').length);
 return Object.freeze({source_sha256:source.source_sha256,role,statuses:Object.freeze(statuses)});
}
async function read(role,file){
 const source=current();
 if(!source){$('reconcile'+cap(role)+'State').textContent='Load an original Studio draft first · HOLD';return;}
 if(!file || file.size===0 || file.size>MAX){$('reconcile'+cap(role)+'State').textContent='Invalid local review size · HOLD';return;}
 const token=revision,sha=source.source_sha256;
 try{
  const bytes=await file.arrayBuffer();
  demand(bytes.byteLength>0&&bytes.byteLength<=MAX);
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  demand(!text.startsWith('\ufeff'));
  runtime.assertUnambiguousJSON(text);
  const pkt=JSON.parse(text);
  const accepted=accept(pkt,source,role);
  demand(token===revision && current()?.source_sha256===sha);
  if(uploads[role]&&!same(uploads[role].statuses,accepted.statuses)){
   // Replacing a human reply must never silently discard the first source.
   if(!confirm('A different '+role+' preparation note is already loaded. Replace this unverified note?'))return;
  }
  uploads[role]=accepted;
  $('reconcile'+cap(role)+'State').textContent='Self-labelled '+role+' note checked against exact draft bytes · UNVERIFIED / HOLD';
  refresh();
 }catch(_){
  $('reconcile'+cap(role)+'State').textContent='Rejected: unrelated, contradictory or unsafe '+role+' note · HOLD';
 }
}
function cap(s){return s[0].toUpperCase()+s.slice(1);}
function model(){
 const source=current();if(!source)return null;
 const items=source.question_states.map(q=>{
  const reported=uploads[q.role]?.statuses[q.code]||'not_reported';
  // A returned status is only an unverified human statement.
  const action=reported==='not_reported'?'await_'+q.role+'_response':
   reported==='unanswered'?'ask_'+q.role:
   reported==='question_sent'?'follow_up_'+q.role:'independently_verify';
  return {code:q.code,assigned_role:q.role,reported_status:reported,next_action:action};
 });
 return {
  kind:'lightup.scope_permission_reply_reconciliation',schema_version:1,
  disposition:'REVIEW_ONLY_HOLD',source_kind:source.source_kind,source_sha256:source.source_sha256,
  client_note_present:uploads.client!==null,operator_note_present:uploads.operator!==null,
  requested_mode:source.requested_mode,requested_risk:source.requested_risk,
  proposed_assets_count:source.proposed_assets_count,excluded_assets_count:source.excluded_assets_count,
  window_status:source.window_status,
  questions:items,attention_count:items.filter(q=>q.reported_status!=='answered_unverified').length,
  ...{flags:structuredClone(source.flags)},
  notice:'Self-labelled human replies are NOT verified identity, client consent, operator approval, grant, authority, executable permission or release.'
 };
}
function writeFile(filename,mime,body){
 const objectURL=URL.createObjectURL(new Blob([body],{type:mime}));
 const a=document.createElement('a');a.href=objectURL;a.download=filename;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(objectURL),1000);
}
function csvCell(value){
 // Currently all fields are internal fixed enums and SHA256; retain spreadsheet-injection fence.
 let s=String(value);
 if(/^[=+\-@\t\r\n]/.test(s))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
function csv(m){
 const rows=[['question_code','assigned_role','reported_status','next_action','source_sha256','disposition']];
 for(const q of m.questions)rows.push([q.code,q.assigned_role,q.reported_status,q.next_action,m.source_sha256,m.disposition]);
 return rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
function refresh(){
 const modelNow=model();
 $('reconcileBoard').replaceChildren();
 const active=Boolean(modelNow);
 $('reconcileJSON').disabled=!active;
 $('reconcileCSV').disabled=!active;
 if(!active){
  $('reconcileStatus').textContent='Load an original Studio proposal to start · HOLD';
  $('reconcileSummary').textContent='';return;
 }
 const n=modelNow.questions.length;
 const present=Number(modelNow.client_note_present)+Number(modelNow.operator_note_present);
 $('reconcileStatus').textContent=present+'/2 self-labelled role notes received · '+modelNow.attention_count+'/'+n+' follow-ups still unverified or missing · HOLD';
 $('reconcileSummary').textContent='Source SHA-256: '+modelNow.source_sha256+' · This is a coordination summary only; none of the replies is independently authenticated.';
 for(const item of modelNow.questions){
  const row=document.createElement('div');row.className='question';
  const left=document.createElement('div'),title=document.createElement('h3'),msg=document.createElement('p');
  title.textContent=item.code.replaceAll('_',' ');
  msg.textContent='Assigned to '+item.assigned_role+' · '+item.reported_status.replaceAll('_',' ')+' · Next: '+item.next_action.replaceAll('_',' ');
  left.append(title,msg);
  const tag=document.createElement('strong');
  tag.className='tag';
  tag.textContent=item.reported_status==='answered_unverified'?'UNVERIFIED RESPONSE':'FOLLOW UP';
  row.append(left,tag);
  $('reconcileBoard').append(row);
 }
}
$('reconcileClient').addEventListener('change',e=>read('client',e.target.files?.[0]));
$('reconcileOperator').addEventListener('change',e=>read('operator',e.target.files?.[0]));
$('reconcileJSON').addEventListener('click',()=>{
 const m=model();if(m)writeFile('lightup-human-reply-reconciliation-HOLD.json','application/json',JSON.stringify(m,null,2)+'\n');
});
$('reconcileCSV').addEventListener('click',()=>{
 const m=model();if(m)writeFile('lightup-human-followups-HOLD.csv','text/csv;charset=utf-8',csv(m));
});
$('reconcileForget').addEventListener('click',reset);
document.addEventListener('lightup:brief-source-change',reset);
refresh();
})();