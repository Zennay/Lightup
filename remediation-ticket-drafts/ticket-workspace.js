/* Confidential source-bound HUMAN-only ticket workspace checkpoint; no network or browser persistence. */
(function(global){
'use strict';
const e=global.LightUpCasework,intake=global.LightUpTicketIntake;
const KIND='lightup.human_ticket_workspace_checkpoint';
const FALSE=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const FIELDS=['finding_id','title','severity','retest_status','remediation'];
const DRAFT=['owner','due','stage','action','review','blocker'];
const MAX=350, MAX_BYTES=4*1024*1024;
const STAGES=['triage','planned','blocked','in_progress','ready_for_review'];
const FORMAT=/[\u0000-\u001f\u007f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u;
function exactKeys(object,keys,label){
 if(!object||typeof object!=='object'||Array.isArray(object)||
  Object.keys(object).length!==keys.length||!keys.every(k=>Object.prototype.hasOwnProperty.call(object,k)))
  throw Error('Invalid or unknown '+label+' field.');
}
function string(v,max,label,blank=true){
 if(typeof v!=='string'||v.length>max||FORMAT.test(v)||(!blank&&!v.trim()))
  throw Error('Unsafe '+label+'.');
 return v;
}
function date(day){
 if(!day)return '';
 if(typeof day!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(day))throw Error('Invalid tentative date.');
 const x=new Date(day+'T00:00:00.000Z');
 if(Number.isNaN(x.valueOf())||x.toISOString().slice(0,10)!==day)throw Error('Invalid calendar date.');
 return day;
}
function digest(x,label){if(typeof x!=='string'||!/^[0-9a-f]{64}$/.test(x))throw Error('Invalid '+label+' SHA-256.');return x;}
function validDraft(raw){
 exactKeys(raw,DRAFT,'HUMAN draft');
 const d={owner:string(raw.owner,120,'owner'),due:date(raw.due),stage:raw.stage,
  action:string(raw.action,1200,'action'),review:string(raw.review,1200,'review'),blocker:string(raw.blocker,800,'blocker')};
 if(!STAGES.includes(d.stage))throw Error('Unrecognised HUMAN stage.');
 return d;
}
function validateHold(raw){
 exactKeys(raw,['finding','draft','canonical','bytesHash','reason'],'historical HOLD');
 const original=raw.finding;
 exactKeys(original,FIELDS,'original source finding');
 // Original immutable Casework parser retains the literal five-column validation contract.
 const safe=e.normalizeSource([original])[0];
 for(const k of FIELDS)string(safe[k],6000,'historical source '+k,k!=='finding_id'&&k!=='title'&&k!=='remediation');
 const reason=raw.reason;
 if(!['changed','missing'].includes(reason))throw Error('Unknown historical HOLD reason.');
 return {finding:{...safe},draft:validDraft(raw.draft),canonical:digest(raw.canonical,'historical canonical'),
  bytesHash:digest(raw.bytesHash,'historical byte'),reason};
}
function normalizeSource(source){
 exactKeys(source,['contract','canonical','bytesHash'],'checkpoint source');
 if(source.contract!=='lightup.finding_export._COLUMNS_v1')throw Error('Unsupported original source contract.');
 return {contract:source.contract,canonical:digest(source.canonical,'canonical'),bytesHash:digest(source.bytesHash,'original byte')};
}
function packet(state){
 if(!e||!intake||!state||!Array.isArray(state.rows))throw Error('No admitted original CSV.');
 if(state.rows.length<1||state.rows.length>MAX)throw Error('Unbounded source.');
 const ids=new Set(state.rows.map(f=>f.finding_id));
 if(ids.size!==state.rows.length)throw Error('Duplicate original source ID.');
 const selected=[...state.selected].sort();
 if(selected.length>MAX||selected.some(id=>!ids.has(id)))throw Error('Invalid ticket selections.');
 const drafts=[...state.drafts].map(([id,d])=>{
  if(!ids.has(id))throw Error('Unmatched HUMAN draft.');
  return {finding_id:id,human:validDraft(d)};
 }).sort((a,b)=>a.finding_id.localeCompare(b.finding_id,'en'));
 if(drafts.length>MAX)throw Error('Too many HUMAN drafts.');
 const holds=state.holds.map(validateHold);
 if(holds.length>MAX)throw Error('Historical HUMAN HOLD limit exceeded.');
 const source=normalizeSource({contract:'lightup.finding_export._COLUMNS_v1',canonical:state.canonical,bytesHash:state.bytesHash});
 const obj={kind:KIND,schema_version:1,disposition:'PRIVATE_LOCAL_HUMAN_ONLY',
  ...Object.fromEntries(FALSE.map(k=>[k,false])),source,selected,drafts,holds,
  warning:'Unverified PRIVATE HUMAN notes only. Not authentication, client/operator consent, grant, scan, fixed finding, retest or release.'};
 const text=JSON.stringify(obj,null,2)+'\n';
 if(new TextEncoder().encode(text).length>MAX_BYTES)throw Error('PRIVATE workspace checkpoint exceeds 4 MiB.');
 return text;
}
function restore(text,state){
 if(!state||!e||!intake||typeof intake.parsePrivateJSON!=='function')throw Error('Load the exact original source CSV first.');
 const raw=intake.parsePrivateJSON(text);
 exactKeys(raw,['kind','schema_version','disposition',...FALSE,'source','selected','drafts','holds','warning'],'workspace checkpoint');
 if(raw.kind!==KIND||raw.schema_version!==1||raw.disposition!=='PRIVATE_LOCAL_HUMAN_ONLY'||
  !FALSE.every(k=>raw[k]===false)||typeof raw.warning!=='string')
  throw Error('Unsupported or authority-claiming workspace checkpoint.');
 const source=normalizeSource(raw.source);
 if(source.canonical!==state.canonical||source.bytesHash!==state.bytesHash)
  throw Error('Private HUMAN workspace was authored for different original source CSV bytes. HOLD, never transfer across source revisions.');
 const ids=new Set(state.rows.map(f=>f.finding_id));
 if(!Array.isArray(raw.selected)||raw.selected.length>MAX)throw Error('Malformed ticket selection array.');
 const selected=new Set();
 for(const id of raw.selected){
  string(id,160,'selected source ID',false);
  if(!ids.has(id)||selected.has(id))throw Error('Duplicate or unknown selected original finding.');
  selected.add(id);
 }
 if(!Array.isArray(raw.drafts)||raw.drafts.length>MAX)throw Error('Malformed HUMAN draft array.');
 const drafts=new Map();
 for(const item of raw.drafts){
  exactKeys(item,['finding_id','human'],'workspace HUMAN item');
  string(item.finding_id,160,'HUMAN finding ID',false);
  if(!ids.has(item.finding_id)||drafts.has(item.finding_id))throw Error('Duplicate or unknown source-bound HUMAN draft.');
  drafts.set(item.finding_id,Object.freeze(validDraft(item.human)));
 }
 if(!Array.isArray(raw.holds)||raw.holds.length>MAX)throw Error('Malformed historical HUMAN HOLD array.');
 const holds=raw.holds.map(validateHold);
 // Return fresh isolated values only after full cross-record admission.
 return {selected,drafts,holds};
}
global.LightUpTicketWorkspace=Object.freeze({packet,restore});
})(window);
