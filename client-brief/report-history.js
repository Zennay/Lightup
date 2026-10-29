/* Redacted historical LightUp briefing comparison. Offline, review-only.
   Prior client-brief JSONs are unsigned and never evidence of scope identity, chronology, consent or repairs. */
(function (global) {
'use strict';
const MAX_FILE=262144, MAX_PRIOR=6, MAX_COUNT=350;
const SEVERITIES=['critical','high','medium','low','info'];
const STATES=['not_tested','fix_pending','fixed','regression'];
const AUTH=['authenticated','tenant_verified','client_consent','operator_consent','grant','assessment_authorized','execution','scan','retest_verified','release'];
const SHA=/^[a-f0-9]{64}$/;
function object(x){return x!==null&&typeof x==='object'&&!Array.isArray(x);}
function count(x,max=MAX_COUNT){return typeof x==='number'&&Number.isSafeInteger(x)&&x>=0&&x<=max;}
function required(obj,keys){return object(obj)&&keys.every(k=>Object.hasOwn(obj,k));}
function tally(obj,categories,n){
 if(!required(obj,categories)||Object.keys(obj).some(k=>!categories.includes(k)))throw Error('Source count categories do not match original exporter.');
 let sum=0;
 const result={};
 for(const k of categories){if(!count(obj[k]))throw Error('Invalid original source count '+k);result[k]=obj[k];sum+=obj[k];}
 if(sum!==n)throw Error('Original briefing count totals conflict.');
 return result;
}
function source(x){
 if(!object(x)||x.kind!=='lightup.client_security_brief_review'||x.schema_version!==1||
   x.disposition!=='REVIEW_ONLY_DRAFT_HOLD'||x.source_contract!=='lightup.finding_export._COLUMNS_v1'||
   x.scope_identity_authenticated!==false||x.source_fingerprint_signed!==false||
   !count(x.imported_findings)||x.imported_findings<1||
   typeof x.source_sha256!=='string'||!SHA.test(x.source_sha256)||
   !AUTH.every(k=>Object.hasOwn(x,k)&&x[k]===false))
   throw Error('Require original unsigned, non-authorizing LightUp aggregate briefing with a source SHA-256.');
 const sev=tally(x.severity_counts,SEVERITIES,x.imported_findings);
 const ret=tally(x.source_retest_counts,STATES,x.imported_findings);
 let scope=null;
 if(x.proposed_scope_review!==null && x.proposed_scope_review!==undefined){
  const p=x.proposed_scope_review;
  if(!object(p)||p.kind!=='lightup.client_brief_scope_draft_review'||
     !SHA.test(p.source_revision_sha256||'')||p.authorization!==false||
     p.client_consent!==false||p.operator_consent!==false||p.grant!==false||
     p.execution!==false||p.scan!==false||p.release!==false||
     !['analysis_only','authorized_assessment'].includes(p.requested_mode)||
     !count(p.requested_risk,4)||p.requested_risk<1||
     !count(p.requested_assets_count,80)||!count(p.excluded_assets_count,80))
    throw Error('Malformed non-authorizing proposed scope aggregate.');
  scope={revision:p.source_revision_sha256,risk:p.requested_risk,mode:p.requested_mode,
   proposed_assets:p.requested_assets_count,exclusions:p.excluded_assets_count};
 }
 return Object.freeze({source_sha256:x.source_sha256,findings:x.imported_findings,
  critical_high:sev.critical+sev.high,critical:sev.critical,high:sev.high,
  severity:sev,retest:ret,proposed_scope:scope,
  source_authenticated:false,consent:false,grant:false,repair_verified:false});
}
async function read(file){
 if(!file||file.size<12||file.size>MAX_FILE)throw Error('Each prior original redacted briefing must be ≤256 KiB.');
 const bytes=await file.arrayBuffer();if(bytes.byteLength!==file.size)throw Error('Briefing file changed during import.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(text.charCodeAt(0)===0xfeff)throw Error('Unexpected UTF-8 BOM in prior JSON.');
 return source(LightUpBriefCasework.strictJSON(text));
}
async function importAll(files,current){
 if(!Array.isArray(files)||files.length<1||files.length>MAX_PRIOR)
  throw Error('Select between one and six prior aggregate briefings, oldest first.');
 const now=source(current),imported=[];
 const seen=new Set([now.source_sha256]);
 for(const file of files){
  const item=await read(file);
  if(seen.has(item.source_sha256))throw Error('Duplicate source fingerprint or current source reused; history not changed.');
  seen.add(item.source_sha256);imported.push(item);
 }
 return imported;
}
function diffs(prev,current){
 if(!prev)return Object.freeze({risk_change:null,urgent_change:null,regressions_change:null,
  reported_fixed_change:null,scope_risk_change:null,scope_identity_changed:null});
 return Object.freeze({
  risk_change:current.findings-prev.findings,
  urgent_change:current.critical_high-prev.critical_high,
  regressions_change:current.retest.regression-prev.retest.regression,
  reported_fixed_change:current.retest.fixed-prev.retest.fixed,
  scope_risk_change:prev.proposed_scope&&current.proposed_scope
     ?current.proposed_scope.risk-prev.proposed_scope.risk:null,
  scope_identity_changed:prev.proposed_scope&&current.proposed_scope
     ?prev.proposed_scope.revision!==current.proposed_scope.revision:null
 });
}
function timeline(prior,current){
 const last=source(current);
 if(!Array.isArray(prior)||prior.length>MAX_PRIOR)throw Error('Invalid briefing comparison input.');
 const seen=new Set([last.source_sha256]),history=[];
 for(const item of prior){
  if(!item||!SHA.test(item.source_sha256)||seen.has(item.source_sha256))throw Error('Duplicate briefing revision.');
  seen.add(item.source_sha256);history.push(item);
 }
 history.push(last);
 return Object.freeze({
  kind:'lightup.client_brief_aggregate_history',disposition:'REVIEW_ONLY_DRAFT_HOLD',
  source_history_count:history.length,
  entries:history.map((value,index)=>Object.freeze({order:index+1,is_current:index===history.length-1,
    ...value,delta:diffs(history[index-1]??null,value)})),
  caveat:'Input order is reviewer-declared, not authenticated chronology. No client or engagement identity has been verified. No scope, grant, consent, retest or remediation is inferred.',
  authority:{client_consent:false,operator_consent:false,grant:false,execution:false,scan:false,release:false}
 });
}
function safeCSV(value){
 const raw=String(value??''),guarded=/^[\s\x00-\x1f]*[=+@-]/.test(raw)?"'"+raw:raw;
 return '"'+guarded.replace(/"/g,'""')+'"';
}
function csv(history){
 if(!history||history.kind!=='lightup.client_brief_aggregate_history')throw Error('Invalid historical review.');
 const h=['declared_order','current','reported_findings','critical_high','source_regressions','source_reported_fixed',
  'findings_count_change','critical_high_change','regressions_change','proposed_scope_present',
  'proposed_scope_risk','scope_risk_change','proposal_revision_changed',
  'identity_verified','client_consent','operator_consent','grant','repair_verified'];
 const rows=history.entries.map(e=>[e.order,e.is_current,e.findings,e.critical_high,e.retest.regression,e.retest.fixed,
  e.delta.risk_change,e.delta.urgent_change,e.delta.regressions_change,
  !!e.proposed_scope,e.proposed_scope?.risk??'',e.delta.scope_risk_change,e.delta.scope_identity_changed,
  false,false,false,false,false]);
 return '\ufeff'+[h,...rows].map(row=>row.map(safeCSV).join(',')).join('\r\n')+'\r\n';
}
global.LightUpBriefHistory=Object.freeze({source,read,importAll,timeline,csv});
})(window);
