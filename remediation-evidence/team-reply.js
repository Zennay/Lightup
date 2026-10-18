/* LightUp private offline team reply. Human-only fields, never authorization or verification. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const STATES=['missing','submitted','needs_changes','ready_for_authorized_retest'];
const FIELDS=[['change_reference',240,'Patch/change reference'],['deployment_reference',240,'Deployment reference'],['rollback_reference',240,'Rollback plan reference'],['retest_request_reference',240,'Authorized retest request reference'],['review_question',700,'Open reviewer question']];
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const SOURCE=['finding_id','title','severity','original_retest_status','original_remediation','casework_status','due_date','local_owner','next_action','verification_plan','blocker','review_stage','evidence_reference','local_reviewer','human_follow_up','warnings'];
const MAX_BYTES=2097152;
const BIDI=/[\u202a-\u202e\u2066-\u2069]/;
let packet=null,dirty=false;
function status(s,fail=false){$('status').textContent=s;$('status').dataset.error=fail?'true':'false';}
function text(node,tag,value,cls){const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=String(value);node.append(e);return e;}
function jsonExact(input){
 if(typeof input!=='string'||input.length>MAX_BYTES)throw Error('Oversize JSON.');
 let i=0,count=0,depthMax=24;
 const skip=()=>{while(i<input.length&&/[ \r\n\t]/.test(input[i]))i++;};
 const string=()=>{
  if(input[i]!=='"')throw Error('Invalid JSON string.');
  const start=i++;let escape=false,end=false;
  while(i<input.length){const c=input[i++];
   if(escape){escape=false;continue;}
   if(c==='\\'){escape=true;continue;}
   if(c==='"'){end=true;break;}
   if(c<' ')throw Error('Invalid JSON control character.');
  }
  if(!end)throw Error('Unterminated JSON string.');
  return JSON.parse(input.slice(start,i));
 };
 function value(depth){
  if(depth>depthMax||++count>40000)throw Error('JSON object complexity limit.');
  skip();const token=input[i];
  if(token==='{'){
   i++;skip();if(input[i]==='}'){i++;return;}
   const keys=new Set();
   while(true){
    skip();const key=string();if(keys.has(key))throw Error('Duplicate JSON object key.');keys.add(key);
    skip();if(input[i++]!==':')throw Error('Invalid JSON separator.');
    value(depth+1);skip();const end=input[i++];
    if(end==='}')return;if(end!==',')throw Error('Invalid JSON object comma.');
   }
  }
  if(token==='['){
   i++;skip();if(input[i]===']'){i++;return;}
   while(true){
    value(depth+1);skip();const end=input[i++];
    if(end===']')return;if(end!==',')throw Error('Invalid JSON array comma.');
   }
  }
  if(token==='"'){string();return;}
  const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(input.slice(i));
  if(!match)throw Error('Invalid JSON scalar.');
  i+=match[0].length;
 }
 value(0);skip();
 if(i!==input.length)throw Error('Trailing JSON data.');
 return JSON.parse(input);
}
function local(s,max,required=false){
 if(typeof s!=='string'||s.length>max||s.includes('\u0000')||BIDI.test(s)||(required&&!s.trim()))
  throw Error('Unsafe or malformed team text.');
 return s;
}
function validate(input){
 if(!input||Object.getPrototypeOf(input)!==Object.prototype)throw Error('Not an original private team handoff.');
 const allowed=new Set(['kind','schema_version','disposition','source_contract','source_sha256',
  'team_label','original_findings_total','selected_findings_total','original_review_sha256',
  'cases','warning',...FLAGS]);
 if(Object.keys(input).some(k=>!allowed.has(k))||input.kind!=='lightup.remediation_private_team_handoff'||
  ![1,2].includes(input.schema_version)||input.disposition!=='UNVERIFIED_PRIVATE_HUMAN_COORDINATION'||
  input.source_contract!=='lightup.finding_export._COLUMNS_v1'||
  typeof input.source_sha256!=='string'||!/^[a-f0-9]{64}$/.test(input.source_sha256)||
  typeof input.original_review_sha256!=='string'||!/^[a-f0-9]{64}$/.test(input.original_review_sha256)||
  FLAGS.some(k=>input[k]!==false)||!Array.isArray(input.cases)||input.cases.length<1||
  input.cases.length>350||input.selected_findings_total!==input.cases.length||
  !Number.isInteger(input.original_findings_total)||input.original_findings_total<input.cases.length||
  input.original_findings_total>350||input.team_label!==null&&
   (typeof input.team_label!=='string'||!input.team_label.trim()||input.team_label.length>120))
  throw Error('Invalid original source binding or non-authority envelope.');
 local(input.warning,1200);
 const keys=new Set([...SOURCE,...(input.schema_version===2?FIELDS.map(([name])=>name):[])]);
 const seen=new Set();
 for(const row of input.cases){
  if(!row||Object.getPrototypeOf(row)!==Object.prototype||
   Object.keys(row).some(k=>!keys.has(k))||typeof row.finding_id!=='string'||
   !row.finding_id.trim()||row.finding_id.length>160||seen.has(row.finding_id))
   throw Error('Duplicate, unexpected or invalid source finding.');
  seen.add(row.finding_id);
  for(const field of ['title','original_remediation','original_retest_status','severity','casework_status',
    'local_owner','next_action','verification_plan','blocker','review_stage','evidence_reference',
    'local_reviewer','human_follow_up']){
    const x=row[field];
    if(typeof x!=='string'||x.length>6000)throw Error('Malformed private row '+field+'.');
  }
  if(!['critical','high','medium','low','info'].includes(row.severity)||
   !['not_tested','fix_pending','fixed','regression'].includes(row.original_retest_status)||
   !STATES.includes(row.review_stage))throw Error('Unsupported original finding status.');
  if(row.due_date!==null&&(typeof row.due_date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(row.due_date)))throw Error('Invalid local planning date.');
  if(!Array.isArray(row.warnings)||row.warnings.length>16||
   row.warnings.some(x=>typeof x!=='string'||x.length>240))throw Error('Invalid local human warning list.');
  for(const [name,max] of [['evidence_reference',240],['local_reviewer',120],['human_follow_up',500]]){
   local(row[name],max);
  }
  if(input.schema_version===2)for(const [name,max] of FIELDS)local(row[name],max);
 }
 return input;
}
async function readFile(file){
 if(!file||file.size<1||file.size>MAX_BYTES)throw Error('Choose a private JSON under 2 MiB.');
 const value=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
 if(value.charCodeAt(0)===0xfeff)throw Error('Unexpected JSON byte-order marker.');
 return validate(jsonExact(value));
}
function editable(parent,label,value,max,save,long=false){
 const box=document.createElement('label');
 text(box,'span',label);
 const input=document.createElement(long?'textarea':'input');
 if(!long)input.type='text';
 input.value=value;input.maxLength=max;
 input.addEventListener('input',()=>{save(input.value);dirty=true;updateCounters();});
 box.append(input);parent.append(box);
}
function updateCounters(){
 if(!packet)return;
 const total=packet.cases.length;
 const missing=packet.schema_version===2?packet.cases.reduce((n,row)=>n+
  FIELDS.slice(0,4).filter(([name])=>!row[name]?.trim()).length,0):0;
 $('findings').textContent=String(total);
 $('references').textContent=packet.schema_version===2?
  String(missing)+' outstanding reference fields across '+total+' local findings':
  'Legacy v1 packet (no structured evidence fields)';
 $('dirty').textContent=dirty?'Unexported local changes':'No unsaved edits';
}
function render(){
 const board=$('board');board.replaceChildren();
 $('workspace').hidden=!packet;$('importPanel').hidden=!!packet;
 if(!packet)return;
 $('team').textContent=packet.team_label||'Unassigned human team';
 $('source').textContent=packet.source_sha256+' (UNSIGNED, not identity or permission)';
 const ordered=packet.cases.slice().sort((a,b)=>
  ['critical','high','medium','low','info'].indexOf(a.severity)-
  ['critical','high','medium','low','info'].indexOf(b.severity)||
  a.finding_id.localeCompare(b.finding_id));
 for(const row of ordered){
  const item=document.createElement('article');item.className='finding';
  text(item,'h3',row.title);
  text(item,'p',row.severity.toUpperCase()+' · original retest '+row.original_retest_status+
   ' · local casework '+row.casework_status,'meta');
  text(item,'p','Original finding ID '+row.finding_id+' · local due '+(row.due_date||'not planned'),'meta');
  const plan=document.createElement('details');const sum=document.createElement('summary');
  sum.textContent='Read original remediation advice and local Casework context';plan.append(sum);
  text(plan,'p',row.original_remediation,'source');
  text(plan,'p','Local proposed owner '+(row.local_owner||'none')+' · next action '+(row.next_action||'none'),'meta');
  text(plan,'p','Local blocker '+(row.blocker||'none')+' · verification plan '+(row.verification_plan||'none'),'meta');
  if(row.warnings.length){
   const ul=document.createElement('ul');
   for(const warning of row.warnings)text(ul,'li',warning);plan.append(ul);
  }
  item.append(plan);
  const stageBox=document.createElement('label');text(stageBox,'span','Local human coordination stage');
  const select=document.createElement('select');
  for(const stage of STATES){const o=document.createElement('option');o.value=stage;o.textContent=stage.replaceAll('_',' ');select.append(o);}
  select.value=row.review_stage;select.addEventListener('change',()=>{row.review_stage=select.value;dirty=true;updateCounters();});
  stageBox.append(select);item.append(stageBox);
  editable(item,'Descriptive private evidence reference',row.evidence_reference,240,v=>{row.evidence_reference=v;});
  editable(item,'Human reviewer label',row.local_reviewer,120,v=>{row.local_reviewer=v;});
  editable(item,'Next human follow-up action',row.human_follow_up,500,v=>{row.human_follow_up=v;},true);
  if(packet.schema_version===2){
   const dossier=document.createElement('details');const title=document.createElement('summary');
   title.textContent='Human evidence references · NOT verified';dossier.append(title);
   text(dossier,'p','Only record references to approved private systems; no raw evidence or passwords.','meta');
   for(const [name,max,label] of FIELDS)editable(dossier,label,row[name],max,v=>{row[name]=v;},name==='review_question');
   item.append(dossier);
  }
  board.append(item);
 }
 updateCounters();
}
$('load').addEventListener('click',async()=>{
 try{
  if(dirty&&!confirm('Discard unsaved local team notes?'))return;
  const next=await readFile($('file').files[0]);
  packet=next;dirty=false;render();
  status('Private unsigned single-team packet loaded. This application cannot authenticate the sender, client, consent, grant or retest.');
 }catch(err){status('Import denied: '+err.message,true);}
});
$('export').addEventListener('click',()=>{
 try{
  if(!packet)throw Error('Import an original private team JSON first.');
  validate(packet);
  if(!confirm('Download PRIVATE returned human notes for this exact original team packet? Verify the recipient independently. This does not attest to a patch, authorize a retest or establish client consent.'))return;
  const blob=new Blob([JSON.stringify(packet,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download='lightup-private-team-return.json';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  dirty=false;updateCounters();
  status('Private returned team JSON downloaded. Deliver only over independently approved channels.');
 }catch(err){status('Private export denied: '+err.message,true);}
});
$('clear').addEventListener('click',()=>{
 if(dirty&&!confirm('Discard unsaved private team edits?'))return;
 packet=null;dirty=false;$('file').value='';$('board').replaceChildren();
 render();status('All private team source and draft notes forgotten from this browser tab.');
});
window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
status('Load a separately received original private LightUp single-team handoff JSON. No authorization is provided by this page.');
})();