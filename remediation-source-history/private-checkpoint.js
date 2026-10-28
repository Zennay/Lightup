/* Encrypted PRIVATE history checkpoint; local Web Crypto only. No auth or verified security assertions. */
(() => {
'use strict';
const $=id=>document.getElementById(id), H=window.LightUpHistory;
const KIND='lightup.human_source_history_encrypted',ROUNDS=600000;
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const bytes=s=>new TextEncoder().encode(s);
const b64=x=>{let s='';for(let i=0;i<x.length;i+=32768)s+=String.fromCharCode(...x.subarray(i,i+32768));return btoa(s);};
function decode64(s,max){
 if(typeof s!=='string'||!s||s.length>Math.ceil(max/3)*4+8||!/^(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?$/.test(s))throw Error('Invalid or oversized encoded PRIVATE record.');
 const x=Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 if(x.length>max||b64(x)!==s)throw Error('Non-canonical private payload encoding.');
 return x;
}
const shape=(o,fields)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
async function hex(x){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',x))].map(b=>b.toString(16).padStart(2,'0')).join('');}
async function key(password,salt){
 if(typeof password!=='string'||password.length<14||password.length>256)throw Error('Passphrase must contain 14–256 characters.');
 const base=await crypto.subtle.importKey('raw',bytes(password),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',iterations:ROUNDS,salt},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function saveFile(name,content){
 const u=URL.createObjectURL(new Blob([content],{type:'application/json;charset=utf-8'}));
 const a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function say(x,fail=false){const el=$('message');el.textContent=x;el.className=fail?'error':'info';}
function secure(){if(!crypto?.subtle||!crypto?.getRandomValues)throw Error('Secure Web Crypto not available.');}
async function save(){
 secure();
 const p=H.capture(),password=$('archivePass').value;
 const payload={kind:'lightup.private_human_source_history',version:1,disposition:'UNVERIFIED_LOCAL_HUMAN_PLANNING',
  ...Object.fromEntries(FLAGS.map(x=>[x,false])),context:p.context,
  snapshots:p.snapshots.map(x=>({name:x.name,label:x.label,sourceHash:x.sourceHash,fileHash:x.fileHash,csvBase64:x.csvBase64})),
  notes:p.notes,decisions:p.decisions,merges:p.merges,holdReviews:p.holdReviews};
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const k=await key(password,salt);
 const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes(KIND+':1')},k,bytes(JSON.stringify(payload))));
 if(H.revision()!==p.revision||p.context.client!==$('client').value.trim()||p.context.engagement!==$('engagement').value.trim())
  throw Error('Source or context changed while encrypting; checkpoint refused.');
 const wrapper={kind:KIND,version:1,kdf:'PBKDF2-SHA256',rounds:ROUNDS,cipher:'AES-256-GCM',
  salt:b64(salt),iv:b64(iv),ciphertext:b64(encrypted),authority:false};
 saveFile('lightup-PRIVATE-source-history.encrypted.json',JSON.stringify(wrapper));
 H.checkpointPrepared(p.revision);
 say('Encrypted PRIVATE checkpoint download prepared. Independently verify the browser really saved it at an approved secure destination; the application cannot confirm disk storage, sender identity, consent or a security verdict.');
}
async function open(){
 secure();
 if(!H.empty())throw Error('Forget your current local source history before restoring a separate private checkpoint.');
 const f=$('archiveFile').files[0];
 if(!f||f.size<100||f.size>25000000)throw Error('Select a PRIVATE encrypted history checkpoint under 25 MiB.');
 const currentVersion=H.revision(),ctx={client:$('client').value.trim(),engagement:$('engagement').value.trim()};
 if(!ctx.client||!ctx.engagement||ctx.client.length>120||ctx.engagement.length>120||!$('ack').checked)
  throw Error('Independently reconfirm exact same client and engagement and private-handling acknowledgment before restore.');
 const raw=await f.text(),wrapper=JSON.parse(raw);
 if(JSON.stringify(wrapper)!==raw||!shape(wrapper,['kind','version','kdf','rounds','cipher','salt','iv','ciphertext','authority'])||
  wrapper.kind!==KIND||wrapper.version!==1||wrapper.kdf!=='PBKDF2-SHA256'||wrapper.rounds!==ROUNDS||
  wrapper.cipher!=='AES-256-GCM'||wrapper.authority!==false)throw Error('Unsupported or ambiguous encrypted checkpoint header.');
 const salt=decode64(wrapper.salt,16),iv=decode64(wrapper.iv,12),data=decode64(wrapper.ciphertext,25000000);
 if(salt.length!==16||iv.length!==12||data.length<17)throw Error('Invalid AES-GCM metadata.');
 let plain;
 try{
  const k=await key($('archivePass').value,salt);
  plain=new TextDecoder('utf-8',{fatal:true}).decode(await crypto.subtle.decrypt(
   {name:'AES-GCM',iv,additionalData:bytes(KIND+':1')},k,data));
 }catch{throw Error('Passphrase invalid, encrypted archive altered, or AES-GCM authentication failed; no workspace changed.');}
 const packet=JSON.parse(plain);
 if(JSON.stringify(packet)!==plain||
  !(shape(packet,['kind','version','disposition',...FLAGS,'context','snapshots','notes','decisions','merges','holdReviews'])||
    shape(packet,['kind','version','disposition',...FLAGS,'context','snapshots','notes','decisions','merges'])||
    shape(packet,['kind','version','disposition',...FLAGS,'context','snapshots','notes','decisions'])||
    shape(packet,['kind','version','disposition',...FLAGS,'context','snapshots','notes']))||
  packet.kind!=='lightup.private_human_source_history'||packet.version!==1||
  packet.disposition!=='UNVERIFIED_LOCAL_HUMAN_PLANNING'||FLAGS.some(k=>packet[k]!==false)||
  !shape(packet.context,['client','engagement'])||packet.context.client!==ctx.client||packet.context.engagement!==ctx.engagement||
  !Array.isArray(packet.snapshots)||!packet.snapshots.length||packet.snapshots.length>H.limits.maxSnapshots||
  !Array.isArray(packet.notes)||packet.notes.length>H.limits.maxNotes||
  (Object.prototype.hasOwnProperty.call(packet,'merges')&&(!Array.isArray(packet.merges)||packet.merges.length>H.limits.maxMerges))||
  (Object.prototype.hasOwnProperty.call(packet,'decisions')&&(!Array.isArray(packet.decisions)||packet.decisions.length>H.limits.maxDecisions))||
  (Object.prototype.hasOwnProperty.call(packet,'holdReviews')&&(!Array.isArray(packet.holdReviews)||packet.holdReviews.length>H.limits.maxHoldReviews)))
   throw Error('Authenticated archive content has invalid original source/context/non-authority contract.');
 const restored=[],seen=new Set();
 for(const s of packet.snapshots){
  if(!shape(s,['name','label','sourceHash','fileHash','csvBase64'])||
   typeof s.name!=='string'||s.name.length>160||typeof s.label!=='string'||!s.label.trim()||s.label.length>100||
   typeof s.sourceHash!=='string'||!/^[a-f0-9]{64}$/.test(s.sourceHash)||
   typeof s.fileHash!=='string'||!/^[a-f0-9]{64}$/.test(s.fileHash)||
   typeof s.csvBase64!=='string')throw Error('Unsupported historical source record.');
  const originalBytes=decode64(s.csvBase64,H.limits.maxBytes);
  const source=new TextDecoder('utf-8',{fatal:true}).decode(originalBytes);
  const parsed=LightUpCasework.parseCSV(source),sourceDigest=await LightUpCasework.digest(parsed);
  if(sourceDigest!==s.sourceHash||
   await hex(originalBytes)!==s.fileHash||seen.has(s.sourceHash))throw Error('Original file bytes or canonical findings mismatch; archive remains unopened.');
  seen.add(s.sourceHash);restored.push({...s,findings:parsed});
 }
 const ids=new Set(restored.flatMap(s=>s.findings.map(x=>x.finding_id))),notes=[],noted=new Set();
 for(const n of packet.notes){
  if(!(shape(n,['id','owner','action','due','sourceRecord','caseworkOriginal'])||shape(n,['id','owner','action','due','sourceRecord'])||shape(n,['id','owner','action','due']))||typeof n.id!=='string'||!ids.has(n.id)||noted.has(n.id)||
   typeof n.owner!=='string'||n.owner.length>120||
   typeof n.action!=='string'||n.action.length>1200||
   typeof n.due!=='string'||(n.due&&!/^\d{4}-\d{2}-\d{2}$/.test(n.due)))
   throw Error('Unknown/ambiguous original finding HUMAN note.');
  if(n.due&&(!Number.isFinite(Date.parse(n.due+'T00:00:00Z'))||
   new Date(n.due+'T00:00:00Z').toISOString().slice(0,10)!==n.due))throw Error('Invalid tentative HUMAN due date.');
  if(Object.prototype.hasOwnProperty.call(n,'sourceRecord')){
   if(!shape(n.sourceRecord,['finding_id','title','severity','retest_status','remediation'])||
    n.sourceRecord.finding_id!==n.id)throw Error('Invalid original five-field HUMAN note binding.');
   const verified=LightUpCasework.normalizeSource([n.sourceRecord])[0];
   if(!restored.some(snapshot=>snapshot.findings.some(f=>
    ['finding_id','title','severity','retest_status','remediation'].every(k=>f[k]===verified[k]))))
     throw Error('Private HUMAN note cites a source row absent from authenticated original exports.');
  }
  if(Object.prototype.hasOwnProperty.call(n,'caseworkOriginal')&&n.caseworkOriginal!==null){
    const c=n.caseworkOriginal;
    if(!n.sourceRecord||!shape(c,['finding_id','owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'])||
      c.finding_id!==n.id)throw Error('Imported HUMAN Casework must retain its exact original source.');
    const original=LightUpCasework.cleanCase(c,new Set([n.id]));
    for(const field of ['finding_id','owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'])
      if(original[field]!==c[field])throw Error('Non-canonical native HUMAN Casework metadata.');
  }
  // Legacy encrypted notes without exact row binding remain HUMAN HOLD until operator review.
  noted.add(n.id);notes.push({...n,sourceRecord:n.sourceRecord||null,caseworkOriginal:n.caseworkOriginal||null});
 }
 const allOriginal=restored.flatMap(snapshot=>snapshot.findings);
 const validSource=row=>{
   if(!shape(row,['finding_id','title','severity','retest_status','remediation']))return false;
   const record=LightUpCasework.normalizeSource([row])[0];
   return allOriginal.some(f=>['finding_id','title','severity','retest_status','remediation'].every(k=>f[k]===record[k]));
 };
 const decisions=packet.decisions||[];
 for(const d of decisions){
   if(!shape(d,['id','from','to','reason','decidedUTC'])||typeof d.id!=='string'||
    !validSource(d.from)||!validSource(d.to)||d.from.finding_id!==d.id||d.to.finding_id!==d.id||
    typeof d.reason!=='string'||d.reason.trim().length<8||d.reason.length>800||
    typeof d.decidedUTC!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(d.decidedUTC)||
    !Number.isFinite(Date.parse(d.decidedUTC)))throw Error('PRIVATE HUMAN carry decision is not bound to authenticated original source history.');
 }
 const allowedHumanFields=['owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
 const merges=packet.merges||[];
 for(const m of merges){
   if(!shape(m,['dateUtc','sourceHash','reason','records'])||
     typeof m.dateUtc!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(m.dateUtc)||
     !Number.isFinite(Date.parse(m.dateUtc))||
     typeof m.sourceHash!=='string'||!/^[a-f0-9]{64}$/.test(m.sourceHash)||
     !restored.some(x=>x.sourceHash===m.sourceHash)||
     typeof m.reason!=='string'||m.reason.trim().length<8||m.reason.length>500||
     !Array.isArray(m.records)||!m.records.length||m.records.length>350)
     throw Error('Source-bound private HUMAN reconciliation metadata invalid.');
   const original=restored.find(x=>x.sourceHash===m.sourceHash),inSource=new Set(original.findings.map(x=>x.finding_id)),identifiers=new Set();
   for(const record of m.records){
     if(!shape(record,['id','fields','previous','accepted'])||
       typeof record.id!=='string'||!inSource.has(record.id)||identifiers.has(record.id)||
       !Array.isArray(record.fields)||!record.fields.length||record.fields.length>8||
       record.fields.some(k=>typeof k!=='string'||!allowedHumanFields.includes(k))||
       new Set(record.fields).size!==record.fields.length||
       !shape(record.previous,record.fields)||!shape(record.accepted,record.fields))
       throw Error('Original HUMAN field merge contains unknown source identity or changed keys.');
     identifiers.add(record.id);
     for(const k of record.fields){
       const before=record.previous[k],after=record.accepted[k];
       if((before!==null&&typeof before!=='string')||(after!==null&&typeof after!=='string')||
         (typeof before==='string'&&before.length>6000)||
         (typeof after==='string'&&after.length>6000))
         throw Error('Invalid private HUMAN old/new field value in encrypted merge archive.');
     }
   }
 }
 const holdReviews=packet.holdReviews||[];
 for(const entry of holdReviews){
   if(!shape(entry,['id','originalSourceHash','reviewSourceHash','oldSource','currentSource','binding','disposition','reason','nextAction','reviewedUTC'])||
      typeof entry.id!=='string'||typeof entry.originalSourceHash!=='string'||!/^[a-f0-9]{64}$/.test(entry.originalSourceHash)||
      typeof entry.reviewSourceHash!=='string'||!/^[a-f0-9]{64}$/.test(entry.reviewSourceHash)||
      !['stale','missing'].includes(entry.binding)||
      !['request_new_source','ask_human_owner','await_separate_evidence','defer_private_discussion'].includes(entry.disposition)||
      typeof entry.reason!=='string'||entry.reason.trim().length<12||entry.reason.length>800||
      typeof entry.nextAction!=='string'||entry.nextAction.trim().length<8||entry.nextAction.length>1200||
      typeof entry.reviewedUTC!=='string'||!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$/.test(entry.reviewedUTC)||
      !Number.isFinite(Date.parse(entry.reviewedUTC)))
     throw Error('PRIVATE historical HUMAN source-HOLD review is malformed; archive remains unopened.');
   const old=restored.find(x=>x.sourceHash===entry.originalSourceHash);
   const reviewed=restored.find(x=>x.sourceHash===entry.reviewSourceHash);
   if(!old||!reviewed||!validSource(entry.oldSource)||entry.oldSource.finding_id!==entry.id||
      !old.findings.some(f=>['finding_id','title','severity','retest_status','remediation'].every(k=>f[k]===entry.oldSource[k])))
     throw Error('HOLD: historical HUMAN review original source does not match authenticated archive.');
   const current=reviewed.findings.find(x=>x.finding_id===entry.id)||null;
   if((current===null)!==(entry.currentSource===null)||
      (current&&(!validSource(entry.currentSource)||!['finding_id','title','severity','retest_status','remediation'].every(k=>current[k]===entry.currentSource[k])))||
      (entry.binding==='missing'&&current!==null)||
      (entry.binding==='stale'&&(!current||['finding_id','title','severity','retest_status','remediation'].every(k=>current[k]===entry.oldSource[k]))))
     throw Error('HOLD: reviewed original source changed or the HUMAN hold type is inconsistent.');
 }
 if(new TextEncoder().encode(JSON.stringify(holdReviews)).length>1048576)
   throw Error('PRIVATE historical HUMAN source-HOLD journal exceeds 1 MiB.');
 H.restore({context:ctx,snapshots:restored,notes,decisions,merges,holdReviews},currentVersion);
 say('Encrypted checkpoint reopened with exact CSV-byte and original canonical source SHA-256 verification. No permission, fix or retest verified.');
}
$('archiveSave').addEventListener('click',async()=>{try{await save();}catch(e){say(e.message,true);}finally{$('archivePass').value='';}});
$('archiveRestore').addEventListener('click',async()=>{try{await open();}catch(e){say(e.message,true);}finally{$('archivePass').value='';$('archiveFile').value='';}});
})();
