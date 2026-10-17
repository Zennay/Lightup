/* Revision identity for local proposal drafts only. A checksum is never consent, a signature or authorization. */
(function(global){
'use strict';
function canonicalObject(d){
 if(!d||d.kind!=='lightup.scope_proposal_draft'||d.schema_version!==1||d.state!=='DRAFT_ONLY')return null;
 const normalizeAssets=list=>{
  if(!Array.isArray(list)||list.length>80)return null;
  const items=list.map(s=>global.LightUpScopeNetwork.parse(s));
  if(items.some(item=>!item))return null;
  return items.map(item=>item.canonical).sort();
 };
 const assets=normalizeAssets(d.requested_assets),excluded=normalizeAssets(d.excluded_assets);
 if(!assets||!excluded)return null;
 if(!d.proposed_activities||!d.proposed_window_local)return null;
 if(typeof d.proposal_name!=='string'||typeof d.client_label!=='string'||typeof d.notes!=='string')return null;
 const a=d.proposed_activities,w=d.proposed_window_local;
 if(!['passive_analysis','configuration_review','private_lab_network_checks'].every(k=>typeof a[k]==='boolean'))return null;
 return {
  format:'LIGHTUP_NON_AUTHORIZING_SCOPE_DRAFT_REVISION_V1',
  proposal_name:d.proposal_name,client_label:d.client_label,notes:d.notes,
  requested_assets:assets,excluded_assets:excluded,
  requested_mode:d.requested_mode,requested_risk:d.requested_risk,
  proposed_activities:{passive_analysis:a.passive_analysis,configuration_review:a.configuration_review,private_lab_network_checks:a.private_lab_network_checks},
  proposed_window_local:{start:w.start??null,end:w.end??null}
 };
}
async function fingerprint(d){
 const obj=canonicalObject(d);
 if(!obj || !global.crypto || !global.crypto.subtle || !global.TextEncoder)return null;
 const bytes=new TextEncoder().encode(JSON.stringify(obj));
 const buffer=await global.crypto.subtle.digest('SHA-256',bytes);
 return [...new Uint8Array(buffer)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
global.LightUpScopeDigest=Object.freeze({canonicalObject,fingerprint});
})(window);
