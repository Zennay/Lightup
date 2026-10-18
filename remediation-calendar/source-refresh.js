/* LightUp offline original-source revision handoff. Never authenticates a CSV or approves remediation. */
(function(global){
'use strict';
const SOURCE_COLS=Object.freeze(['finding_id','title','severity','retest_status','remediation']);
function ensureBaseline(findings,cases){
 const engine=global.LightUpCasework;
 const current=engine.normalizeSource(findings);
 if(!Array.isArray(cases)||cases.length!==current.length)throw Error('Incomplete previous human Casework draft.');
 const packet=engine.makePacket(current,cases,null);
 const checked=engine.loadPacket(packet);
 return {findings:checked.findings,cases:checked.cases};
}
function sameSource(a,b){
 if(!Array.isArray(a)||!Array.isArray(b)||a.length!==b.length)return false;
 const old=new Map(a.map(f=>[f.finding_id,f]));
 return b.every(f=>{
  const was=old.get(f.finding_id);
  return was&&SOURCE_COLS.every(k=>was[k]===f[k]);
 });
}
function sameHumanCases(a,b){
 if(!Array.isArray(a)||!Array.isArray(b)||a.length!==b.length)return false;
 return JSON.stringify(a)===JSON.stringify(b);
}
async function prepare(beforeFindings,beforeCases,newOriginalCSV){
 const old=ensureBaseline(beforeFindings,beforeCases);
 const incoming=global.LightUpCasework.parseCSV(newOriginalCSV);
 const reconciled=global.LightUpCasework.reconcileSource(old.findings,old.cases,incoming);
 const diff=reconciled.change_summary;
 if(diff.added.length+diff.changed.length+diff.unchanged.length!==incoming.length)
  throw Error('Source change partition is incomplete.');
 if(diff.missing.length+diff.changed.length+diff.unchanged.length!==old.findings.length)
  throw Error('Original source change partition is incomplete.');
 const digest=await global.LightUpCasework.digest(reconciled.findings);
 global.LightUpCasework.loadPacket(global.LightUpCasework.makePacket(reconciled.findings,reconciled.cases,digest));
 const changedFields=diff.changed.map(x=>({finding_id:x.finding_id,changed_fields:x.changed_fields.slice()}));
 return Object.freeze({
  before:old,digest,after:reconciled.findings,cases:reconciled.cases,
  diff:Object.freeze({
   added:diff.added.slice(),missing:diff.missing.slice(),
   changed:changedFields,unchanged:diff.unchanged.slice()
  })
 });
}
function stillCurrent(prepared,currentFindings,currentCases){
 return sameSource(prepared.before.findings,currentFindings)&&
   sameHumanCases(prepared.before.cases,currentCases);
}
function revisionReceipt(prepared,previousDigest){
 if(!prepared||!prepared.diff)throw Error('Missing completed original source preview.');
 const normalize=xs=>xs.slice().sort();
 const changed=prepared.diff.changed.map(x=>({finding_id:x.finding_id,changed_fields:normalize(x.changed_fields)}))
  .sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0);
 return {
  kind:'lightup.private_human_casework_source_revision',schema_version:1,
  disposition:'UNVERIFIED_HUMAN_FOLLOWUP_ONLY',
  authenticated:false,source_authorized:false,tenant_verified:false,
  assessment_authorized:false,client_consent:false,operator_consent:false,
  grant:false,scan:false,execution:false,retest_verified:false,release:false,
  previous_source_sha256:previousDigest||null,
  next_source_sha256:prepared.digest||null,
  added:normalize(prepared.diff.added),changed,missing_NOT_VERIFIED_FIXED:normalize(prepared.diff.missing),
  exact_unchanged_human_notes_retained:prepared.diff.unchanged.length,
  warning:'Human source revision only. Absent findings are NEVER verified fixed. These unsigned source digests do not prove client identity, consent, authorization or a retest.'
 };
}
global.LightUpCalendarRefresh=Object.freeze({prepare,stillCurrent,revisionReceipt});
})(window);
