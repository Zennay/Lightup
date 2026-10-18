/* LightUp: PRIVATE owner-specific HUMAN planning packet. No identity or authority.
 * The original Casework five-column source and current human baseline are immutable.
 */
(function(global){
'use strict';
const engine=()=>global.LightUpCasework;
const COLS=['finding_id','title','severity','retest_status','remediation'];
const HUMAN=['owner','status','due_date','next_action','blocker'];
const ROW=[...COLS,...HUMAN];
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const FIELDS=['kind','schema_version','disposition','source_contract','source_sha256','owner_label','baseline_sha256','rows','instructions',...FLAGS];
const REPLY_FIELDS=[...FIELDS,'reply_rows'];
const MAX=350,MAX_JSON=2097152;
const KIND='lightup.private_calendar_owner_handoff';
const ANSWER='lightup.private_calendar_owner_reply';
const DISPOSITION='UNVERIFIED_HUMAN_PLANNING_ONLY';
const CONTRACT='lightup.finding_export._COLUMNS_v1';
function fail(msg){throw Error(msg);}
function exact(o,keys,what){
 if(!o||Object.getPrototypeOf(o)===null&&typeof o!=='object'||typeof o!=='object'||Array.isArray(o))fail('Invalid '+what+'.');
 const set=new Set(keys),present=Object.keys(o);
 if(present.length!==set.size||present.some(k=>!set.has(k)))fail('Unknown or missing '+what+' field.');
}
function str(s,max=1800){
 if(typeof s!=='string'||s.length>max||/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(s))fail('Invalid human text field.');
 return s;
}
function sourceDate(value){
 if(value===null)return null;
 if(typeof value!=='string'||!/^(?:20\d{2}|2100)-\d\d-\d\d$/.test(value))
  fail('Invalid human due date.');
 const ms=Date.parse(value+'T00:00:00Z');
 if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==value||value>'2100-12-30')
  fail('Invalid human due date.');
 return value;
}
function rowFrom(f,c){
 return {finding_id:f.finding_id,title:f.title,severity:f.severity,
  retest_status:f.retest_status,remediation:f.remediation,
  owner:c.owner,status:c.status,due_date:c.due_date,next_action:c.next_action,blocker:c.blocker};
}
function checkRows(rows,label){
 if(!Array.isArray(rows)||!rows.length||rows.length>MAX)fail('Owner handoff must have 1–350 rows.');
 const seen=new Set();
 return rows.map(row=>{
  exact(row,ROW,'owner row');
  const original={};
  for(const k of COLS)original[k]=row[k];
  const validated=engine().normalizeSource([original])[0];
  if(seen.has(validated.finding_id))fail('Duplicate original finding ID.');
  seen.add(validated.finding_id);
  if(str(row.owner,120)!==label)fail('Owner team label changed.');
  const progress=engine().PROGRESS;
  if(!progress.includes(row.status))fail('Invalid human work stage.');
  sourceDate(row.due_date);str(row.next_action,1800);str(row.blocker,1200);
  return {...validated,...Object.fromEntries(HUMAN.map(k=>[k,row[k]]))};
 });
}
function canonical(rows){
 return JSON.stringify(rows.slice().sort((a,b)=>
  a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));
}
async function sha(value){
 if(!global.crypto||!global.crypto.subtle)fail('Secure SHA-256 is unavailable: private owner handoff HELD.');
 const digest=await global.crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 return Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
}
function flags(){return Object.fromEntries(FLAGS.map(f=>[f,false]));}
function validateHeader(packet,kind,fields){
 exact(packet,fields,'handoff envelope');
 if(packet.kind!==kind||packet.schema_version!==1||packet.disposition!==DISPOSITION||
    packet.source_contract!==CONTRACT)fail('Unknown owner handoff schema or disposition.');
 if(typeof packet.owner_label!=='string'||packet.owner_label.length>120||
    !packet.owner_label.trim()||packet.owner_label!==packet.owner_label.trim()||
    /[\u0000-\u001f\u007f-\u009f]/.test(packet.owner_label))fail('Invalid owner identity label.');
 if(typeof packet.instructions!=='string'||packet.instructions.length>1500)fail('Invalid safety instructions.');
 if(packet.source_sha256!==null&&
    (typeof packet.source_sha256!=='string'||!/^[0-9a-f]{64}$/.test(packet.source_sha256)))
  fail('Invalid original source fingerprint.');
 if(typeof packet.baseline_sha256!=='string'||!/^[0-9a-f]{64}$/.test(packet.baseline_sha256))
  fail('Invalid owner human baseline fingerprint.');
 for(const k of FLAGS)if(packet[k]!==false)fail('Owner handoff claims '+k+' authority.');
}
async function validateRequest(request){
 validateHeader(request,KIND,FIELDS);
 const rows=checkRows(request.rows,request.owner_label);
 const digest=await sha(canonical(rows));
 if(digest!==request.baseline_sha256)fail('Original handoff baseline mismatch.');
 return {...request,rows};
}
function fromSource(findings,cases,label){
 const fs=engine().normalizeSource(findings);
 const ids=new Set(fs.map(f=>f.finding_id));
 if(!Array.isArray(cases)||cases.length!==fs.length)fail('Incomplete original casework.');
 const original=engine().loadPacket(engine().makePacket(fs,cases,null));
 const byId=new Map(original.cases.map(c=>[c.finding_id,c]));
 const rows=fs.filter(f=>byId.get(f.finding_id).owner===label)
  .map(f=>rowFrom(f,byId.get(f.finding_id)));
 return checkRows(rows,label);
}
async function createRequest(findings,cases,label,sourceSha){
 if(typeof label!=='string'||!label.trim()||label!==label.trim())fail('Choose a specific original human owner label.');
 if(sourceSha!==null&&sourceSha!==undefined&&
   (typeof sourceSha!=='string'||!/^[a-f0-9]{64}$/.test(sourceSha)))fail('Invalid original source fingerprint.');
 const rows=fromSource(findings,cases,label);
 const packet={
  kind:KIND,schema_version:1,disposition:DISPOSITION,source_contract:CONTRACT,
  source_sha256:sourceSha||null,owner_label:label,baseline_sha256:await sha(canonical(rows)),
  rows,instructions:'PRIVATE original findings and human-only planning. This unsigned handoff is not an identity, tenant/consent, authorization, verified repair or retest claim.',
  ...flags()
 };
 return await validateRequest(packet);
}
async function createReply(request,replyRows){
 const validated=await validateRequest(request);
 const latest=checkRows(replyRows,validated.owner_label);
 if(latest.length!==validated.rows.length)fail('Owner response omitted original findings.');
 const before=new Map(validated.rows.map(x=>[x.finding_id,x])),seen=new Set();
 for(const row of latest){
  const old=before.get(row.finding_id);
  if(!old||seen.has(row.finding_id)||COLS.some(k=>row[k]!==old[k]))
   fail('Owner response attempted to alter original finding identity or source.');
  seen.add(row.finding_id);
 }
 const packet={...validated,kind:ANSWER,reply_rows:latest};
 await validateReply(packet);
 return packet;
}
async function validateReply(reply){
 validateHeader(reply,ANSWER,REPLY_FIELDS);
 const request={...reply,kind:KIND};
 delete request.reply_rows;
 const admitted=await validateRequest(request);
 const after=checkRows(reply.reply_rows,reply.owner_label);
 if(after.length!==admitted.rows.length)fail('Incomplete owner response.');
 const byId=new Map(admitted.rows.map(x=>[x.finding_id,x])),seen=new Set();
 for(const row of after){
  const baseline=byId.get(row.finding_id);
  if(!baseline||seen.has(row.finding_id)||COLS.some(k=>row[k]!==baseline[k]))
   fail('Owner reply changed immutable original source.');
  seen.add(row.finding_id);
 }
 return {...reply,rows:admitted.rows,reply_rows:after};
}
async function applyReply(findings,cases,sourceSha,reply){
 const accepted=await validateReply(reply);
 const original=engine().normalizeSource(findings);
 const before=engine().loadPacket(engine().makePacket(original,cases,null));
 const computed=await engine().digest(original);
 if(reply.source_sha256!==null&&reply.source_sha256!==computed)
  fail('Original source has changed since owner handoff.');
 if(sourceSha!==null&&sourceSha!==undefined&&computed!==sourceSha)
  fail('Current private source digest has changed.');
 const existing=fromSource(original,before.cases,accepted.owner_label);
 if(existing.length!==accepted.rows.length||await sha(canonical(existing))!==accepted.baseline_sha256)
  fail('Current owner assignment, original source, or human notes have changed. No auto-merge.');
 const changed=new Map(accepted.reply_rows.map(x=>[x.finding_id,x])),idSet=new Set(original.map(f=>f.finding_id));
 const casesNext=before.cases.map(c=>{
  const r=changed.get(c.finding_id);
  if(!r)return c;
  return engine().cleanCase({...c,owner:r.owner,status:r.status,due_date:r.due_date,
    next_action:r.next_action,blocker:r.blocker,updated_utc:new Date().toISOString()},idSet);
 });
 engine().loadPacket(engine().makePacket(original,casesNext,computed));
 return {cases:casesNext,changed:accepted.reply_rows.length,owner_label:accepted.owner_label};
}
global.LightUpOwnerProtocol=Object.freeze({createRequest,validateRequest,createReply,validateReply,applyReply,MAX_JSON});
})(window);
