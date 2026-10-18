/* Source-byte bound local client-brief review draft; no consent, authority, targets or source findings. */
(function(global){
'use strict';
const SHA=/^[a-f0-9]{64}$/;
const AUTHORITIES=['authenticated','tenant_verified','client_consent','operator_consent','grant','assessment_authorized','execution','scan','retest_verified','release'];
const STAGES=['discussion_pending','client_question_outstanding','operator_question_outstanding','joint_discussion_recorded'];
const KEYS=['kind','schema_version','disposition','source_sha256','earlier_sha256','authority','fields','warning'];
const REVIEW_FIELDS=['title','anchor','urgent_days','medium_days','low_days','discussion'];
function object(x){return !!x&&typeof x==='object'&&!Array.isArray(x);}
function keys(x,expected){return object(x)&&Object.keys(x).length===expected.length&&expected.every(k=>Object.hasOwn(x,k));}
function date(s){
 if(s==='')return true;
 if(typeof s!=='string'||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(s))return false;
 const d=new Date(s+'T00:00:00Z');
 return Number.isFinite(d.valueOf())&&d.toISOString().slice(0,10)===s;
}
function normalise(fields){
 if(!keys(fields,REVIEW_FIELDS)||typeof fields.title!=='string'||fields.title.trim()!==fields.title
    ||fields.title.length>100||!date(fields.anchor)||!keys(fields.discussion,['urgent','medium','low']))
  throw Error('Unsupported local review fields.');
 for(const key of ['urgent_days','medium_days','low_days'])
  if(!Number.isSafeInteger(fields[key])||fields[key]<1||fields[key]>365)
   throw Error('Invalid human planning horizon.');
 for(const k of ['urgent','medium','low'])
  if(!STAGES.includes(fields.discussion[k]))throw Error('Invalid self-reported discussion status.');
 return {title:fields.title,anchor:fields.anchor,
  urgent_days:fields.urgent_days,medium_days:fields.medium_days,low_days:fields.low_days,
  discussion:{urgent:fields.discussion.urgent,medium:fields.discussion.medium,low:fields.discussion.low}};
}
function exactSHA(x){return typeof x==='string'&&SHA.test(x);}
function sources(current,earlier){
 if(!exactSHA(current)||!(earlier===null||exactSHA(earlier)))
  throw Error('WebCrypto source SHA-256 unavailable: cannot source-bind review draft.');
}
function make(current,earlier,fields){
 sources(current,earlier);
 return {kind:'lightup.client_brief_working_draft',schema_version:1,disposition:'LOCAL_REVIEW_ONLY',
  source_sha256:current,earlier_sha256:earlier,
  authority:Object.fromEntries(AUTHORITIES.map(k=>[k,false])),
  fields:normalise(fields),
  warning:'Unsigned local human preparation only. Restore does not authenticate the source, consent, scope, client or operator; never enables assessment or release.'};
}
function restore(packet,current,earlier){
 sources(current,earlier);
 if(!keys(packet,KEYS)||packet.kind!=='lightup.client_brief_working_draft'
   ||packet.schema_version!==1||packet.disposition!=='LOCAL_REVIEW_ONLY'
   ||packet.source_sha256!==current||packet.earlier_sha256!==earlier
   ||!keys(packet.authority,AUTHORITIES)||!AUTHORITIES.every(k=>packet.authority[k]===false)
   ||typeof packet.warning!=='string'||packet.warning.length>600)
  throw Error('Review draft does not match the exact current original source bytes or non-authorising contract.');
 return normalise(packet.fields);
}
async function read(file,current,earlier){
 if(!file||file.size<10||file.size>32768)throw Error('Expected a small private review draft JSON (≤32 KiB).');
 const data=await file.arrayBuffer();
 if(data.byteLength!==file.size)throw Error('Review file changed during import.');
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(data);
 if(raw.charCodeAt(0)===0xfeff)throw Error('Unexpected UTF-8 BOM.');
 const obj=LightUpBriefCasework.strictJSON(raw);
 return restore(obj,current,earlier);
}
global.LightUpBriefDraft=Object.freeze({make,restore,read});
})(window);
