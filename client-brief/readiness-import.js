/* Original operator readiness JSON → privacy-minimal OFFLINE review-only aggregates.
   Input is untrusted even when previously exported from the authenticated CLI.
   This must never assert current identity, tenant, grant, consent or authorization. */
(function(global){
'use strict';
const MAX_BYTES=2097152, MAX_FLAGS=16, MAX_ROWS=1200, SHA=/^[0-9a-f]{64}$/;
const BAD_FLAGS=Object.freeze({
 TENANT_LINEAGE_MISMATCH:'Cross-tenant grant lineage',
 INVALID_APPROVED_REQUEST_BINDING:'Invalid request/grant binding',
 UNBOUND_APPROVAL_REQUEST:'Grant without durable request binding',
 UNTRUSTED_APPROVED_REQUEST_ORIGIN:'Untrusted stored approval origin',
 UNTRUSTED_ADMINISTRATIVE_APPROVAL:'Untrusted administrative decision',
 INVALID_CLIENT_REQUEST_ORIGIN:'Invalid submitted-request origin',
 CLOSED_ENGAGEMENT_GRANT:'Grant linked to a closed engagement',
 INACTIVE_CLIENT_GRANT:'Grant linked to an inactive client',
 INVALID_GRANT_CREATION_TIME:'Invalid grant creation instant',
 INVALID_GRANT_WINDOW:'Invalid stored authorization window',
 EXPIRED_GRANT_WINDOW:'Stored window already expired',
 INVALID_GRANT_ASSETS:'Malformed stored grant assets',
 NO_COMPATIBLE_APPROVED_REQUEST:'No compatible approved request',
 AMBIGUOUS_APPROVED_REQUEST_MATCH:'Ambiguous candidate request binding',
 INVALID_REQUEST_ASSETS:'Invalid request scope payload',
 INVALID_REQUEST_RISK:'Invalid request risk',
 INVALID_REQUEST_CREATION_TIME:'Invalid request creation instant',
 NON_AUTHORIZED_ASSESSMENT_MODE:'Unexpected assessment mode',
 PENDING_OPERATOR_REVIEW:'Submitted request pending review',
 RECORDED_ADMINISTRATIVE_APPROVAL:'Historical administrative approval, not consent',
 RECORDED_ADMINISTRATIVE_REJECTION:'Historical administrative rejection',
 UNKNOWN_REQUEST_STATUS:'Unknown request status'
});
const TRUE_FALSE=['client_consent_verified','operator_consent_verified',
 'authorization_granted','execution_allowed','release_approved'];
const GROUPS=[
 {name:'Tenant / source lineage',codes:['TENANT_LINEAGE_MISMATCH','INVALID_APPROVED_REQUEST_BINDING','CLOSED_ENGAGEMENT_GRANT','INACTIVE_CLIENT_GRANT','UNTRUSTED_APPROVED_REQUEST_ORIGIN']},
 {name:'Missing or ambiguous request review',codes:['UNBOUND_APPROVAL_REQUEST','NO_COMPATIBLE_APPROVED_REQUEST','AMBIGUOUS_APPROVED_REQUEST_MATCH','UNTRUSTED_ADMINISTRATIVE_APPROVAL','INVALID_CLIENT_REQUEST_ORIGIN']},
 {name:'Window / assets / request integrity',codes:['INVALID_GRANT_CREATION_TIME','INVALID_GRANT_WINDOW','EXPIRED_GRANT_WINDOW','INVALID_GRANT_ASSETS','INVALID_REQUEST_ASSETS','INVALID_REQUEST_RISK','INVALID_REQUEST_CREATION_TIME','NON_AUTHORIZED_ASSESSMENT_MODE','UNKNOWN_REQUEST_STATUS']},
 {name:'Client-wide pending review (not engagement-specific)',codes:['PENDING_OPERATOR_REVIEW']}
];
function record(v) {return !!v&&typeof v==='object'&&!Array.isArray(v);}
function integer(v,max){return typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=max;}
function flags(input,label){
 if(!Array.isArray(input)||input.length>MAX_FLAGS||new Set(input).size!==input.length)
  throw Error('Malformed '+label+' flags.');
 for(const f of input)if(typeof f!=='string'||!(f in BAD_FLAGS))
  throw Error('Unsupported readiness source flag.');
 return input;
}
function unsignedFingerprint(obj){
 if(!record(obj)||typeof obj.scope_fingerprint!=='string'||!SHA.test(obj.scope_fingerprint))
  throw Error('Invalid readiness scope fingerprint.');
}
async function readAndSummarize(file){
 if(!file||file.size<5||file.size>MAX_BYTES)throw Error('Readiness JSON must be between 5 bytes and 2 MiB.');
 const raw=await file.arrayBuffer();
 if(raw.byteLength!==file.size)throw Error('Readiness report changed during import.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
 if(text.charCodeAt(0)===0xfeff)throw Error('Unexpected UTF-8 BOM in report.');
 const p=LightUpBriefCasework.strictJSON(text);
 if(!record(p)||p.format!=='lightup.authorization_readiness_operator_v1'||p.disposition!=='REVIEW_ONLY'
   ||p.scope_description!=='single_engagement') throw Error('Require an original single-engagement operator readiness JSON.');
 unsignedFingerprint(p);
 if(!record(p.authority)||!TRUE_FALSE.every(k=>Object.hasOwn(p.authority,k)&&p.authority[k]===false)
   ||Object.keys(p.authority).some(k=>!TRUE_FALSE.includes(k)))
  throw Error('Original readiness envelope must explicitly deny all authority.');
 if(!record(p.summary)||!integer(p.summary.engagements,1)||p.summary.engagements!==1
   ||!integer(p.summary.clients,1)||p.summary.clients!==1
   ||!integer(p.summary.requests,MAX_ROWS)||!integer(p.summary.pending_requests,MAX_ROWS)
   ||!integer(p.summary.grants,MAX_ROWS)
   ||!Array.isArray(p.engagements)||p.engagements.length>1
   ||!Array.isArray(p.review_queue)||p.review_queue.length>MAX_ROWS
   ||!Array.isArray(p.request_history)||p.request_history.length>MAX_ROWS)
  throw Error('Readiness source selection or totals are inconsistent.');
 if(!record(p.summary.flag_counts))throw Error('Missing readiness flag counters.');
 // A selected engagement with no grants AND no requests may have no entry.
 if(p.engagements.length===0&&(p.summary.grants!==0||p.summary.requests!==0))
  throw Error('Incomplete selected engagement review records.');
 const counts=Object.fromEntries(Object.keys(BAD_FLAGS).map(k=>[k,0]));
 let observedGrants=0,reviewRequests=0;
 const grantIds=new Set();
 for(const entry of p.engagements){
  if(!record(entry)||!integer(entry.grants,MAX_ROWS)||!integer(entry.requests,MAX_ROWS)
    ||!Array.isArray(entry.grant_findings)||entry.grant_findings.length!==entry.grants
    ||entry.grants>MAX_ROWS||entry.requests>MAX_ROWS)
   throw Error('Incomplete engagement review entries.');
  if(entry.grants>p.summary.grants||entry.requests>p.summary.requests)
   throw Error('Readiness summary counts disagree with engagement.');
  observedGrants+=entry.grants;
  for(const item of entry.grant_findings){
   if(!record(item)||!SHA.test(item.source_key||'')||!SHA.test(item.identity_key||'')
     ||!['missing','invalid','recorded_coherent_review_only'].includes(item.binding)
     ||!['invalid','expired','within_window','future'].includes(item.window))
    throw Error('Malformed grant review record.');
   if(grantIds.has(item.identity_key))throw Error('Repeated stored grant identity.');
   grantIds.add(item.identity_key);
   flags(item.flags,'grant').forEach(k=>counts[k]++);
  }
 }
 if(observedGrants!==p.summary.grants)
  throw Error('Incomplete grant review collection; no partial summary.');
 if(p.request_history.length!==p.summary.requests)throw Error('Incomplete original request lifecycle history.');
 const knownRequests=new Map();
 for(const row of p.request_history){
  if(!record(row)||!SHA.test(row.source_key||'')||!SHA.test(row.identity_key||'')
    ||!['submitted','under_review','approved','rejected'].includes(row.status)
    ||knownRequests.has(row.identity_key))throw Error('Malformed or duplicate request history.');
  flags(row.flags,'history');
  knownRequests.set(row.identity_key,row);
 }
 const pendingSeen=new Set();
 for(const row of p.review_queue){
  if(!record(row)||!SHA.test(row.source_key||'')||!SHA.test(row.identity_key||'')
    ||!['submitted','under_review'].includes(row.status))
   throw Error('Malformed pending request record.');
  const original=knownRequests.get(row.identity_key);
  if(!original||pendingSeen.has(row.identity_key)||original.source_key!==row.source_key
    ||original.status!==row.status||JSON.stringify(original.flags)!==JSON.stringify(row.flags))
   throw Error('Pending request is not an exact member of original history.');
  pendingSeen.add(row.identity_key);
  flags(row.flags,'request').forEach(k=>counts[k]++);
  reviewRequests++;
 }
 if(reviewRequests!==p.summary.pending_requests||[...knownRequests.values()].filter(x=>['submitted','under_review'].includes(x.status)).length!==reviewRequests)
  throw Error('Incomplete client-wide review queue.');
 // Compare every original source flag counter with independently read record rows
 // except orphan grants (not necessarily attributable to a selected engagement).
 for(const [k,v] of Object.entries(p.summary.flag_counts)){
  if(k==='ORPHAN_GRANT'){if(!integer(v,MAX_ROWS))throw Error('Invalid orphan count.');continue;}
  if(!(k in counts)||!integer(v,MAX_ROWS)||v!==counts[k])
   throw Error('Readiness flag summary contradicts source records.');
 }
 for(const [k,v] of Object.entries(counts))if(v&&p.summary.flag_counts[k]!==v)
  throw Error('Incomplete readiness flag counts.');
 const risks=GROUPS.map(g=>({name:g.name,count:g.codes.reduce((n,k)=>n+counts[k],0)}));
 const issueCodes=Object.entries(counts).filter(([,count])=>count>0)
  .map(([code,count])=>({code,label:BAD_FLAGS[code],count}))
  .sort((a,b)=>b.count-a.count||a.code.localeCompare(b.code));
 return Object.freeze({
  kind:'lightup.client_readiness_aggregate_review',review_only:true,
  selected_engagement:true,records:observedGrants,pending_client_wide:reviewRequests,
  risk_groups:risks,issue_codes:issueCodes,
  warning:'Readiness is an unsigned historical operator review; even zero flags is not an authorization, consent, grant, revocation or permission.',
  authority:{client_consent:false,operator_consent:false,grant:false,execution:false,scan:false,release:false}
 });
}
global.LightUpBriefReadiness=Object.freeze({readAndSummarize});
})(window);
