/* Strict private import of existing LightUpCasework drafts. Aggregate-only; never an authority check. */
(function(global){
'use strict';
const ALLOWED=new Set(['kind','schema_version','disposition','authenticated','tenant_verified',
 'source_authorized','assessment_authorized','grant','client_consent','operator_consent',
 'execution','scan','audit_verdict','retest_verified','release','source_contract',
 'source_sha256','findings','cases','instructions']);
const FIELDS=['finding_id','title','severity','retest_status','remediation'];
const MAX_BYTES=3*1024*1024;
function rejectDuplicateJSONKeys(text){
 // JSON.parse silently accepts duplicate keys. Scan JSON string tokens while following
 // object boundaries, with JSON.parse doing complete grammar and Unicode validation.
 const stack=[];
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(c==='"'){
   const start=i;let closed=false;
   for(i++;i<text.length;i++){
    if(text[i]==='\\'){i++;continue;}
    if(text[i]==='"'){closed=true;break;}
   }
   if(!closed)throw Error('Malformed JSON string.');
   const top=stack.at(-1);
   if(top&&top.type==='object'&&top.expecting){
    let next=i+1;
    while(next<text.length&&/\s/.test(text[next]))next++;
    if(text[next]===':'){
     const key=JSON.parse(text.slice(start,i+1));
     if(key==='__proto__'||key==='constructor'||key==='prototype'||top.keys.has(key))
      throw Error('Duplicate or forbidden object member.');
     top.keys.add(key);top.expecting=false;
    }
   }
  }else if(c==='{')stack.push({type:'object',keys:new Set(),expecting:true});
  else if(c==='[')stack.push({type:'array'});
  else if(c==='}'||c===']'){
   const top=stack.pop();
   if(!top||(c==='}'&&top.type!=='object')||(c===']'&&top.type!=='array'))
    throw Error('Malformed JSON containers.');
  }else if(c===','&&stack.at(-1)?.type==='object'){
   stack.at(-1).expecting=true;
  }
 }
 if(stack.length)throw Error('Unclosed JSON container.');
}
function strictJSON(text){rejectDuplicateJSONKeys(text);return JSON.parse(text);}
async function readAndSummarize(file,currentRows){
 if(!file||!file.size||file.size>MAX_BYTES)throw Error('Expected a nonempty Casework draft JSON no larger than 3 MiB.');
 const buffer=await file.arrayBuffer();
 if(buffer.byteLength!==file.size)throw Error('Casework file changed during import.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer);
 if(text.charCodeAt(0)===0xfeff)throw Error('Unexpected JSON byte-order mark.');
 const packet=strictJSON(text);
 if(!packet||typeof packet!=='object'||Array.isArray(packet)||Object.keys(packet).some(k=>!ALLOWED.has(k)))
  throw Error('Unknown or unsupported Casework draft envelope.');
 const parsed=LightUpCasework.loadPacket(packet);
 const current=LightUpCasework.normalizeSource(currentRows);
 if(parsed.findings.length!==current.length)throw Error('Casework source length does not match the CSV.');
 const sort=(a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0;
 const reference=current.slice().sort(sort),given=parsed.findings.slice().sort(sort);
 for(let i=0;i<reference.length;i++)
  if(FIELDS.some(k=>reference[i][k]!==given[i][k]))
   throw Error('Casework was made from another source revision; no state imported.');
 const digest=await LightUpCasework.digest(current);
 if(parsed.source_sha256!==null&&digest!==null&&digest!==parsed.source_sha256)
  throw Error('Casework source digest conflicts with current exact fields.');
 const counts=Object.fromEntries(LightUpCasework.PROGRESS.map(k=>[k,0]));
 let overdue=0,urgentBlocked=0;
 const today=new Date().toISOString().slice(0,10),index=new Map(reference.map(f=>[f.finding_id,f]));
 for(const c of parsed.cases){
  counts[c.status]++;
  if(c.due_date&&c.due_date<today&&c.status!=='completed'&&c.status!=='deferred')overdue++;
  if(c.status==='blocked'&&['critical','high'].includes(index.get(c.finding_id)?.severity))urgentBlocked++;
 }
 // Never return casework titles, IDs, owners, notes, tickets, exported raw JSON or timestamps.
 return Object.freeze({counts,overdue,urgentBlocked,sourceRecordCount:current.length,
  sourceFieldsMatch:true,sourceDigestChecked:digest!==null&&parsed.source_sha256!==null,
  authenticated:false,client_consent:false,operator_consent:false,grant:false,
  execution:false,scan:false,retest_verified:false,release:false});
}
global.LightUpBriefCasework=Object.freeze({readAndSummarize,strictJSON});
})(window);