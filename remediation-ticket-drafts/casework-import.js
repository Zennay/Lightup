/* Original LightUp Casework v1 -> HUMAN ticket draft intake.
   Private and offline. Does not authenticate client, grant, consent or retest. */
(function (global) {
'use strict';
const MAX_PACKET_BYTES=2*1024*1024;
const MAX_NODES=16000;
const TEXT_FIELDS=['finding_id','title','severity','retest_status','remediation'];
function duplicateSafeJSON(text,maxBytes=MAX_PACKET_BYTES){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>maxBytes)throw Error('PRIVATE JSON exceeds permitted byte limit.');
 let i=0,nodes=0;
 const invalid=()=>{throw Error('Malformed or ambiguous Casework JSON.');};
 const ws=()=>{while(/[\u0020\u0009\u000a\u000d]/.test(text[i]||'')&&i<text.length)i++;};
 function str(){
  if(text[i]!=='"')invalid();
  const start=i++;
  while(i<text.length){
   const c=text[i++];
   if(c==='"')return JSON.parse(text.slice(start,i));
   if(c==='\\'){if(i>=text.length)invalid();const escaped=text[i++];if(escaped==='u'){
     const hex=text.slice(i,i+4);if(!/^[0-9a-fA-F]{4}$/.test(hex))invalid();i+=4;
   }else if(!'"\\/bfnrt'.includes(escaped))invalid();
   }else if(c.charCodeAt(0)<32)invalid();
  }
  invalid();
 }
 function value(depth){
  if(++nodes>MAX_NODES||depth>16)throw Error('Casework JSON exceeds nesting/token limits.');
  ws();const c=text[i];
  if(c==='{'){
   i++;ws();const keys=new Set();
   if(text[i]==='}'){i++;return;}
   for(;;){
    ws();const key=str();
    if(keys.has(key)||['__proto__','constructor','prototype'].includes(key))throw Error('Duplicate or dangerous Casework JSON key.');
    keys.add(key);ws();if(text[i++]!==':')invalid();
    value(depth+1);ws();
    const end=text[i++];
    if(end==='}')break;
    if(end!==',')invalid();
   }
  }else if(c==='['){
   i++;ws();if(text[i]===']'){i++;return;}
   for(;;){value(depth+1);ws();const end=text[i++];if(end===']')break;if(end!==',')invalid();}
  }else if(c==='"'){str();}
  else if(c==='t'&&text.slice(i,i+4)==='true')i+=4;
  else if(c==='f'&&text.slice(i,i+5)==='false')i+=5;
  else if(c==='n'&&text.slice(i,i+4)==='null')i+=4;
  else{
   const m=text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
   if(!m)invalid();i+=m[0].length;
  }
 }
 value(0);ws();if(i!==text.length)invalid();
 const packet=JSON.parse(text);
 if(!packet||typeof packet!=='object'||Array.isArray(packet))invalid();
 return packet;
}
function decode(text,current,sourceHash){
 const e=global.LightUpCasework;
 if(!e||!Array.isArray(current)||!sourceHash)throw Error('Original CSV must be loaded first.');
 const packet=duplicateSafeJSON(text);
 const restored=e.loadPacket(packet);
 if(restored.source_sha256!==sourceHash)throw Error('Casework source SHA does not equal the current original findings CSV. HOLD.');
 if(restored.findings.length!==current.length)throw Error('Casework finding count mismatch.');
 const byId=new Map(current.map(f=>[f.finding_id,f]));
 if(byId.size!==current.length)throw Error('Duplicate source findings.');
 for(const row of restored.findings){
  const original=byId.get(row.finding_id);
  if(!original||TEXT_FIELDS.some(key=>row[key]!==original[key]))
   throw Error('Casework source finding differs from current original five fields. HOLD.');
 }
 const drafts=new Map(),suggested=new Set();let resetCompleted=0;
 for(const row of restored.cases){
  const stageMap={unassigned:'triage',planned:'planned',in_progress:'in_progress',blocked:'blocked',ready_for_retest:'ready_for_review',completed:'triage',deferred:'triage'};
  const stage=stageMap[row.status];
  if(!stage)throw Error('Unknown HUMAN Casework status.');
  if(row.status==='completed'||row.status==='deferred')resetCompleted++;
  const d={owner:row.owner,due:row.due_date||'',stage,action:row.next_action,review:row.verification_plan,blocker:row.blocker};
  for(const key of ['owner','action','review','blocker']){
   const limit={owner:120,action:1200,review:1200,blocker:800}[key];
   if(d[key].length>limit||/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(d[key]))
    throw Error('Unsafe source Casework HUMAN field: '+key);
  }
  drafts.set(row.finding_id,Object.freeze(d));
  if(d.owner||d.due||d.action||d.review||d.blocker||row.status!=='unassigned')suggested.add(row.finding_id);
 }
 if(drafts.size!==current.length)throw Error('Casework admission incomplete.');
 return {drafts,suggested,resetCompleted};
}
global.LightUpTicketIntake=Object.freeze({decode,parsePrivateJSON:(text,maxBytes=4*1024*1024)=>duplicateSafeJSON(text,maxBytes)});
})(window);
