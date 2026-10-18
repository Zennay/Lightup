/* LightUp original Studio v1 proposal import for private, offline planning review.
 * A proposal is never evidence of authentication, asset ownership or permission.
 */
(function(global){
'use strict';
const MAX=65536;
const ALLOWED=['kind','schema_version','state','authorization','client_consent',
 'operator_consent','grant','execution','revocation_checked','proposal_name',
 'client_label','requested_assets','excluded_assets','requested_mode',
 'requested_risk','notes','proposed_activities','proposed_window_local',
 'proposed_window_utc','exported_at_utc','scope_fingerprint_sha256'];
const AUTH=['authorization','client_consent','operator_consent','grant','execution','revocation_checked'];
const ACTIVITIES=['passive_analysis','configuration_review','private_lab_network_checks'];
const SHA=/^[a-f0-9]{64}$/;
const sources=new WeakMap();
function object(x){return !!x&&typeof x==='object'&&!Array.isArray(x);}
function keys(o,allowed){return Object.keys(o).every(k=>allowed.includes(k));}
function own(o,k){return Object.prototype.hasOwnProperty.call(o,k);}
function short(x,n){return typeof x==='string'&&x.length<=n;}
function pair(o){
 return object(o)&&keys(o,['start','end'])&&['start','end'].every(k=>own(o,k)&&
  (o[k]===null||(typeof o[k]==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(o[k]))));
}
function countAssets(list){
 if(!Array.isArray(list)||list.length>80)throw Error('Too many proposal asset identities.');
 const seen=new Set(),counts={hostname:0,ipv4:0,ipv6:0};
 for(const value of list){
  const parsed=global.LightUpScopeNetwork.parse(value);
  if(!parsed||seen.has(parsed.canonical))throw Error('Invalid or duplicate canonical asset.');
  seen.add(parsed.canonical);counts[parsed.family]++;
 }
 return counts;
}
async function importOriginal(file){
 if(!file||file.size<10||file.size>MAX)throw Error('Original Studio proposal must be 10 bytes–64 KiB.');
 const bytes=await file.arrayBuffer();
 if(bytes.byteLength!==file.size)throw Error('Original proposal changed during import.');
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(raw.charCodeAt(0)===0xfeff)throw Error('Unexpected Studio UTF-8 BOM.');
 const d=global.LightUpBriefCasework.strictJSON(raw);
 if(!object(d)||!keys(d,ALLOWED)||d.kind!=='lightup.scope_proposal_draft'||
  d.schema_version!==1||d.state!=='DRAFT_ONLY'||AUTH.some(k=>d[k]!==false))
  throw Error('Not an original non-authorizing Studio v1 proposal.');
 if(!short(d.proposal_name,120)||!short(d.client_label,100)||!short(d.notes,3000)
  ||!['analysis_only','authorized_assessment'].includes(d.requested_mode)
  ||!Number.isSafeInteger(d.requested_risk)||d.requested_risk<1||d.requested_risk>4
  ||!Array.isArray(d.requested_assets)||d.requested_assets.length===0)
  throw Error('Invalid proposed scope, risk or client label.');
 const requested=countAssets(d.requested_assets);
 const excluded=countAssets(d.excluded_assets);
 const activity=d.proposed_activities;
 if(!object(activity)||!keys(activity,ACTIVITIES)||
   !ACTIVITIES.every(k=>own(activity,k)&&typeof activity[k]==='boolean'))
  throw Error('Invalid proposed activity declarations.');
 if(!pair(d.proposed_window_local)||!own(d,'proposed_window_utc')||
   !global.LightUpPlanningWindow.validateStored(d.proposed_window_local,d.proposed_window_utc))
  throw Error('Missing or invalid original Studio UTC planning evidence.');
 const warnings=global.LightUpScopeNetwork.inspect(d.requested_assets,d.excluded_assets);
 if(warnings.some(x=>x.level==='error'))throw Error('Original proposed assets contain fatal syntax errors.');
 const effective=global.LightUpScopeNetwork.describeEffective(d.requested_assets,d.excluded_assets,100);
 if(!effective)throw Error('Original effective scope preview is invalid.');
 const fingerprint=await global.LightUpScopeDigest.fingerprint(d);
 if(!fingerprint||!SHA.test(fingerprint))throw Error('Canonical Studio SHA-256 unavailable; refuse unsigned mismatch.');
 if(own(d,'scope_fingerprint_sha256')&&d.scope_fingerprint_sha256!==fingerprint)
  throw Error('Original Studio canonical fingerprint mismatch.');
 const window=d.proposed_window_utc;
 const notes=['Proposal only: asset ownership and client/operator identities are unverified.',
  'Exclusions are written proposals, not actual enforced execution boundaries.',
  'No grant, consent, revocation, assessment, scan, retest or release is conferred.'];
 if(d.requested_mode==='authorized_assessment')notes.push('Proposed authorized assessment is NOT actually authorized.');
 if(d.requested_risk===4)notes.push('Proposed risk 4 requires separate authentic approval.');
 if(window.status!=='resolved')notes.push('UTC planning window is unresolved or unscheduled.');
 if(warnings.some(x=>x.level==='warning'))notes.push('Original Studio identified further manual scope warnings.');
 const summary=Object.freeze({
  kind:'lightup.client_brief_scope_draft_review',source_revision_sha256:fingerprint,
  requested_mode:d.requested_mode,requested_risk:d.requested_risk,
  requested_assets_count:d.requested_assets.length,excluded_assets_count:d.excluded_assets.length,
  requested_types:requested,excluded_types:excluded,
  effective_ipv4_address_count:effective.total.ipv4,
  effective_ipv6_address_count:effective.total.ipv6,
  effective_hostnames_count:Number(effective.total.hostnames),
  effective_truncated:effective.truncated,
  proposed_activities:ACTIVITIES.filter(k=>activity[k]),
  proposed_window_status:window.status,proposed_window_utc:window.status==='resolved'?{
   start:window.start,end:window.end}:null,
  original_human_warning_count:warnings.filter(x=>x.level==='warning').length,
  notes,authenticated:false,tenant_verified:false,authorization:false,client_consent:false,
  operator_consent:false,grant:false,execution:false,scan:false,release:false
 });
 sources.set(summary,{assets:[...d.requested_assets],exclusions:[...d.excluded_assets]});
 return summary;
}
function compareOriginals(earlier,current){
 const a=sources.get(earlier),b=sources.get(current);
 if(!a||!b)throw Error('Both proposal revisions must be original validated Studio imports.');
 const net=global.LightUpScopeNetwork;
 const before=net.effectiveCoverage(a.assets,a.exclusions),after=net.effectiveCoverage(b.assets,b.exclusions);
 if(!before||!after)throw Error('Invalid original effective proposal coverage.');
 const diff=net.coverageDifference(before,after);
 if(!diff)throw Error('No valid canonical scope difference.');
 const elevatedRisk=current.requested_risk>earlier.requested_risk;
 const modeEscalated=earlier.requested_mode==='analysis_only'&&current.requested_mode==='authorized_assessment';
 const addedActivities=current.proposed_activities.filter(v=>!earlier.proposed_activities.includes(v));
 const windowChanged=JSON.stringify(earlier.proposed_window_utc)!==JSON.stringify(current.proposed_window_utc);
 const scopeExpanded=diff.added.length>0;
 return Object.freeze({kind:'lightup.client_brief_scope_revision_review',earlier_revision:earlier.source_revision_sha256,
  current_revision:current.source_revision_sha256,scope_expanded:scopeExpanded,
  scope_narrowed:diff.removed.length>0,
  added_coverage_fragments:diff.added.length,removed_coverage_fragments:diff.removed.length,
  coverage_truncated:diff.truncated,elevated_risk:elevatedRisk,mode_escalated:modeEscalated,
  new_activities:addedActivities,window_changed:windowChanged,
  changes_require_human_review:scopeExpanded||elevatedRisk||modeEscalated||addedActivities.length>0||windowChanged||diff.truncated,
  warning:'Proposal changes are unsigned local comparisons, not approvals. Any widened scope or risk must undergo fresh real client/operator authorization. Absent assets are not revoked target permissions.',
  authenticated:false,authorization:false,client_consent:false,operator_consent:false,grant:false,execution:false,scan:false,release:false});
}
global.LightUpBriefStudio=Object.freeze({importOriginal,compareOriginals});
})(window);
