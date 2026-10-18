/* LightUp local draft lineage: unsigned planning custody, NEVER an approval lineage. */
(function(global){
'use strict';
const HASH=/^[0-9a-f]{64}$/;
const CHANGE_KEYS=Object.freeze([
 'requested_assets','excluded_assets','requested_risk','requested_mode','activities',
 'time_window','safety_notes','client_label','proposal_name'
]);
const PREPARATION=Object.freeze([
 'client_evidence','scope_boundary','client_consent','operator_review',
 'window_stop','privacy_handoff'
]);
const FALSE_FIELDS=Object.freeze([
 'authenticated','client_consent','operator_consent','authorization',
 'risk_approved','grant','revocation_checked','execution','scan','release'
]);
function isObject(o){return o!==null&&typeof o==='object'&&!Array.isArray(o);}
function exactKeys(object,keys){
 return isObject(object)&&Object.keys(object).length===keys.length&&
  Object.keys(object).every(key=>keys.includes(key));
}
function uniqueAllowlist(list,allowed){
 return Array.isArray(list)&&list.length<=allowed.length&&
  list.every(x=>typeof x==='string'&&allowed.includes(x))&&
  new Set(list).size===list.length;
}
function validate(link,sourceSha){
 if(link===null||link===undefined)return true; // old version-1 casework exports
 if(!HASH.test(sourceSha||''))return false;
 const keys=['kind','parent_source_sha256','change_categories','affected_workstreams',
  'review_only','authenticated','client_consent','operator_consent','authorization',
  'risk_approved','grant','revocation_checked','execution','scan','release'];
 if(!exactKeys(link,keys)||link.kind!=='lightup.local_scope_revision_link/v1'||
   !HASH.test(link.parent_source_sha256)||link.parent_source_sha256===sourceSha||
   link.review_only!==true)return false;
 if(!uniqueAllowlist(link.change_categories,CHANGE_KEYS)||
    !uniqueAllowlist(link.affected_workstreams,PREPARATION))return false;
 return FALSE_FIELDS.every(field=>link[field]===false);
}
function create(from,to,comparison){
 if(!HASH.test(from)||!HASH.test(to)||from===to||!comparison||
   !Array.isArray(comparison.summary)||!Array.isArray(comparison.affectedStages))
   throw Error('Two different source originals and a human comparison are required.');
 const categories=comparison.summary.map(change=>change.key),stages=comparison.affectedStages;
 const value={
  kind:'lightup.local_scope_revision_link/v1',parent_source_sha256:from,
  change_categories:categories,affected_workstreams:stages,review_only:true
 };
 for(const key of FALSE_FIELDS)value[key]=false;
 if(!validate(value,to))throw Error('Unsafe or ambiguous review link.');
 return value;
}
function inspect(records){
 if(!Array.isArray(records)||records.length>20)throw Error('Review board exceeds local limit.');
 const bySha=new Map();
 for(const r of records){
  if(!r||!HASH.test(r.source_sha256)||bySha.has(r.source_sha256)||
    !validate(r.revision_link,r.source_sha256))throw Error('Invalid or duplicate source lineage.');
  bySha.set(r.source_sha256,r);
 }
 const seenGlobal=new Set(),chains=[],missing=[],forks=[];
 for(const r of records){
  const seenLocal=new Set();let cursor=r;
  while(cursor&&cursor.revision_link){
   if(seenLocal.has(cursor.source_sha256))throw Error('Revision ancestry cycle: HOLD.');
   seenLocal.add(cursor.source_sha256);
   const prior=bySha.get(cursor.revision_link.parent_source_sha256);
   if(!prior){missing.push(cursor.source_sha256);break;}
   if(prior.source_sha256===r.source_sha256)throw Error('Self-referential revision ancestry: HOLD.');
   cursor=prior;
  }
  seenGlobal.add(r.source_sha256);
  chains.push({sha:r.source_sha256,
   parent:r.revision_link?.parent_source_sha256||null,
   missingParent:!!r.revision_link&&!bySha.has(r.revision_link.parent_source_sha256),
   affected:r.revision_link?.affected_workstreams||[],
   changes:r.revision_link?.change_categories||[]});
 }
 const children=new Map();
 for(const r of records)if(r.revision_link){
  const key=r.revision_link.parent_source_sha256;
  children.set(key,(children.get(key)||0)+1);
 }
 for(const [sha,count] of children)if(count>1)forks.push({sha,count});
 return {chains,orphans:missing.length,forks,linked:chains.filter(c=>c.parent).length};
}
global.LightUpLocalLineage=Object.freeze({validate,create,inspect});
})(window);
