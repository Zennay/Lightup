/* PRIVATE offline HUMAN Evidence Reply. No target access, scanner, authentication or grants. */
(function(){
'use strict';
const $=id=>document.getElementById(id);
const LIMIT=1048576;
const KINDS=['missing_evidence','patch_change','deployment_record','rollback_plan','retest_request','followup_question','other'];
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const ENVELOPE=['kind','schema_version','disposition','source_contract','source_sha256','client_reference',
 'engagement_reference','recipient_alias','reply_kind','issued_utc','reply_utc','requests',...FLAGS];
const ROW_KEYS=['request_id','finding_id','request_kind','instructions','due_date','human_stage','human_response'];
let packet=null,edits=[];
function fail(message){throw Error(message);}
function note(message,bad=false){$('replyNotice').textContent=message;$('replyNotice').dataset.error=bad?'true':'false';}
function exact(obj,keys){return obj&&Object.getPrototypeOf(obj)===Object.prototype&&Object.keys(obj).length===keys.length&&Object.keys(obj).every(k=>keys.includes(k));}
function string(x,max,label,required=false){
 if(typeof x!=='string'||x.length>max||x.includes('\0')||
 /[\u202a-\u202e\u2066-\u2069]/.test(x)||(required&&!x.trim()))fail('Malformed PRIVATE '+label+'.');
 return x;
}
function utc(x){if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)||Number.isNaN(Date.parse(x)))fail('Invalid local request timestamp.');return x;}
function due(x){
 if(x==='')return x;
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\d$/.test(x)||!Number.isFinite(Date.parse(x+'T00:00:00Z'))||
 new Date(x+'T00:00:00Z').toISOString().slice(0,10)!==x)fail('Invalid tentative HUMAN due date.');
 return x;
}
/* Syntax-aware duplicate-key rejecting JSON parser, bounded recursion and nodes. */
function strictJSON(s){
 if(typeof s!=='string'||new TextEncoder().encode(s).length>LIMIT)fail('PRIVATE JSON exceeds 1 MiB.');
 let i=0,n=0;
 const ws=()=>{while(i<s.length&&/[ \t\r\n]/.test(s[i]))i++;};
 function quoted(){
  if(s[i]!=='"')fail('Expected original JSON text field.');
  const a=i++;let escaped=false;
  while(i<s.length){
   const c=s[i++];
   if(escaped){escaped=false;continue;}
   if(c==='\\'){escaped=true;continue;}
   if(c==='"')return JSON.parse(s.slice(a,i));
   if(c<' ')fail('Unescaped JSON control character.');
  }
  fail('Unclosed JSON string.');
 }
 function value(depth){
  if(++n>20000||depth>28)fail('PRIVATE owner request structure too deep.');
  ws();const c=s[i];
  if(c==='{'){
   i++;ws();const seen=new Set();
   if(s[i]==='}'){i++;return;}
   while(true){
    ws();const key=quoted();if(seen.has(key))fail('Duplicate PRIVATE owner JSON key.');seen.add(key);
    ws();if(s[i++]!==':')fail('Missing JSON colon.');
    value(depth+1);ws();const separator=s[i++];
    if(separator==='}')return;
    if(separator!==',')fail('Missing JSON comma.');
   }
  }
  if(c==='['){
   i++;ws();if(s[i]===']'){i++;return;}
   while(true){
    value(depth+1);ws();const separator=s[i++];
    if(separator===']')return;
    if(separator!==',')fail('Missing array separator.');
   }
  }
  if(c==='"'){quoted();return;}
  const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!match)fail('Invalid JSON scalar.');i+=match[0].length;
 }
 value(0);ws();if(i!==s.length)fail('Trailing owner JSON content.');
 return JSON.parse(s);
}
function admit(value){
 if(!exact(value,ENVELOPE)||value.kind!=='lightup.private_human_evidence_owner_handoff'||
 value.schema_version!==1||value.disposition!=='UNVERIFIED_HUMAN_REQUEST_ONLY'||
 value.source_contract!=='lightup.finding_export._COLUMNS_v1'||
 !/^[0-9a-f]{64}$/.test(value.source_sha256)||FLAGS.some(k=>value[k]!==false)||
 value.reply_kind!=='owner_request'||value.reply_utc!==null||
 !Array.isArray(value.requests)||value.requests.length<1||value.requests.length>60)
  fail('Not a valid PRIVATE, strictly non-authorizing HUMAN owner request packet.');
 string(value.client_reference,120,'client reference',true);
 string(value.engagement_reference,120,'engagement reference',true);
 string(value.recipient_alias,120,'human recipient',true);utc(value.issued_utc);
 const ids=new Set();
 for(const r of value.requests){
  if(!exact(r,ROW_KEYS)||typeof r.request_id!=='string'||!/^[0-9a-f]{32}$/.test(r.request_id)||
   ids.has(r.request_id)||typeof r.finding_id!=='string'||r.finding_id.length>160||!r.finding_id.trim()||
   !KINDS.includes(r.request_kind)||r.human_stage!=='requested_human'||r.human_response!=='')
    fail('Incorrect or ambiguous HUMAN finding request.');
  string(r.instructions,1400,'evidence request instructions',true);due(r.due_date);
  ids.add(r.request_id);
 }
 return value;
}
function clear(){
 packet=null;edits=[];$('replySource').value='';$('replyIdentity').textContent='No original HUMAN packet loaded.';
 $('replyCount').textContent='Load an original HUMAN owner request packet.';
 $('replyRows').replaceChildren();$('replyDownload').disabled=true;
 note('All human replies and source metadata were forgotten in this browser memory. Previously downloaded files still exist.');
}
async function load(){
 const f=$('replySource').files[0];if(!f||f.size>LIMIT)fail('Select a bounded PRIVATE owner request JSON.');
 const parsed=admit(strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(await f.arrayBuffer())));
 if(packet&&!confirm('Replace ALL current unexported PRIVATE HUMAN replies with the next packet?'))return;
 packet=parsed;edits=parsed.requests.map(r=>({...r}));
 $('replySource').value='';draw();
 note('Loaded '+edits.length+' PRIVATE HUMAN requests. Independently verify the sender and exact engagement before replying.');
}
function create(t,text){const e=document.createElement(t);e.textContent=text;return e;}
function draw(){
 const b=$('replyRows');b.replaceChildren();
 if(!packet){clear();return;}
 $('replyIdentity').textContent='Recipient HUMAN alias (UNVERIFIED): '+packet.recipient_alias+
 ' · Declared client: '+packet.client_reference+' · Engagement: '+packet.engagement_reference+
 ' · Original SHA-256: '+packet.source_sha256;
 $('replyCount').textContent=edits.length+' original source-bound PRIVATE HUMAN requests, not authentic source/consent proof.';
 for(const r of edits){
  const tr=document.createElement('tr');
  for(const value of [r.finding_id,r.request_kind,r.due_date||'no HUMAN date',r.instructions])
   tr.append(create('td',value));
  const st=document.createElement('td'),sel=document.createElement('select');
  for(const label of ['submitted_unverified','needs_changes']){
   const op=new Option(label.replaceAll('_',' '),label);sel.append(op);
  }
  sel.value=['submitted_unverified','needs_changes'].includes(r.human_stage)?r.human_stage:'submitted_unverified';
  sel.addEventListener('change',()=>r.human_stage=sel.value);r.human_stage=sel.value;
  st.append(sel);tr.append(st);
  const cell=document.createElement('td'),area=document.createElement('textarea');area.rows=3;area.maxLength=1800;
  area.setAttribute('aria-label','Unverified HUMAN reply for original '+r.finding_id);area.value=r.human_response;
  area.addEventListener('input',()=>r.human_response=area.value);
  cell.append(area);tr.append(cell);b.append(tr);
 }
 $('replyDownload').disabled=false;
}
function download(){
 if(!packet)fail('No HUMAN owner request loaded.');
 const outgoing=edits.filter(r=>r.human_response.trim()).map(r=>{
  string(r.human_response.trim(),1800,'reply',true);
  if(!['submitted_unverified','needs_changes'].includes(r.human_stage))fail('Invalid HUMAN reply stage.');
  return {...r,human_response:r.human_response.trim()};
 });
 if(!outgoing.length)fail('Write at least one HUMAN response before exporting; unanswered requests stay open.');
 if(!confirm('Save '+outgoing.length+' of '+edits.length+' PRIVATE UNVERIFIED HUMAN responses locally (remaining '+(edits.length-outgoing.length)+' unanswered)? This does not authenticate you, transmit to the operator, prove any security fix or authorize a retest. Return through a separately approved HUMAN channel.'))return;
 const response={...packet,reply_kind:'unverified_human_reply',reply_utc:new Date().toISOString(),
  requests:outgoing};
 const blob=new Blob([JSON.stringify(response,null,2)+'\n'],{type:'application/json'});
 const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download='LightUp-PRIVATE-unverified-human-owner-reply.json';
 document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
 note('Saved PRIVATE human response JSON to this device. No data were sent or authenticated.');
}
function listen(id,fn){
 $(id).addEventListener('click',async()=>{try{await fn();}catch(e){note(e.message||'Invalid PRIVATE input',true);}});
}
listen('replyLoad',load);
listen('replyDownload',download);
listen('replyForget',()=>{if(confirm('Clear all locally held HUMAN replies?'))clear();});
clear();
})();