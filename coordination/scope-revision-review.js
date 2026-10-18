/* LightUp local revision drift reviewer: NO authority or execution. Studio owner sources untouched. */
(function(global){
'use strict';
const ACTIVITIES=['passive_analysis','configuration_review','private_lab_network_checks'];
const STAGES=['client_evidence','scope_boundary','client_consent','operator_review','window_stop','privacy_handoff'];
const FOLLOWUPS=Object.freeze({
 client_evidence:'Re-request authentic client and asset ownership evidence for the changed scope through a separately authenticated channel.',
 scope_boundary:'Review complete requested and excluded scope using the authoritative policy engine; do not infer permission from literal comparison.',
 client_consent:'Request fresh explicit client consent bound to the precise revised proposal in the authenticated workflow.',
 operator_review:'Arrange independent operator re-review against the precise updated scope; do not treat prepared paperwork as approval.',
 window_stop:'Reconfirm risk escalation, approved UTC window, STOP route and action-time revocation in the authorized system.',
 privacy_handoff:'Review evidence minimization, privacy handling and incident/rollback instructions for the revised activities.'
});
function compare(original,updated){
 if(!original||!updated||original.kind!=='lightup.scope_proposal_draft'||
  updated.kind!==original.kind||original.schema_version!==1||updated.schema_version!==1||
  original.state!=='DRAFT_ONLY'||updated.state!=='DRAFT_ONLY')throw Error('Two locally validated Studio v1 DRAFT_ONLY files are required.');
 for(const draft of [original,updated]){
  if(!Array.isArray(draft.requested_assets)||!Array.isArray(draft.excluded_assets)||
   !draft.proposed_activities||typeof draft.proposed_activities!=='object'||
   !draft.proposed_window_local||typeof draft.proposed_window_local!=='object')throw Error('Incomplete source draft.');
 }
 const changes=[];
 const record=(key,label,detail,stages,scopeConcern=false)=>{
  changes.push({key,label,detail,stages,scopeConcern});
 };
 const setDiff=(field,label,stages)=>{
  const before=new Set(original[field].map(x=>x.toLowerCase()));
  const after=new Set(updated[field].map(x=>x.toLowerCase()));
  const added=[...after].filter(x=>!before.has(x)).length;
  const removed=[...before].filter(x=>!after.has(x)).length;
  if(added||removed)record(field,label,
   added+' new declaration(s), '+removed+' removed declaration(s). Literal labels only: changed CIDR notation can conceal net membership changes.',
   stages,true);
 };
 setDiff('requested_assets','Proposed in-scope declarations changed',
  ['client_evidence','scope_boundary','client_consent','operator_review']);
 setDiff('excluded_assets','Explicit exclusions changed',
  ['scope_boundary','client_consent','operator_review','window_stop']);
 if(original.requested_risk!==updated.requested_risk)
  record('requested_risk','Requested risk changed',
   'Requested level '+original.requested_risk+' to '+updated.requested_risk+
   '. A decrease never proves prior risk approval; any increase requires independent escalation review.',
   ['client_consent','operator_review','window_stop']);
 if(original.requested_mode!==updated.requested_mode)
  record('requested_mode','Assessment mode changed','Proposed mode changed. Fresh human policy and no-execution review is required.',
   ['scope_boundary','client_consent','operator_review','window_stop','privacy_handoff']);
 const gained=ACTIVITIES.filter(k=>!original.proposed_activities[k]&&updated.proposed_activities[k]);
 const lost=ACTIVITIES.filter(k=>original.proposed_activities[k]&&!updated.proposed_activities[k]);
 if(gained.length||lost.length)
  record('activities','Proposed activity classes changed',
   gained.length+' newly proposed, '+lost.length+' withdrawn. Re-review intended activities; never assume permission from a checkbox.',
   ['scope_boundary','client_consent','operator_review','window_stop','privacy_handoff']);
 const utc=w=>w&&w.status==='resolved'?
   [w.status,w.timezone,w.start,w.end,w.start_offset_minutes,w.end_offset_minutes].join('|'):
   [w?.status??'no_utc',w?.timezone??'',w?.start??'',w?.end??''].join('|');
 const wall=w=>[w?.start??'',w?.end??''].join('|');
 if(utc(original.proposed_window_utc)!==utc(updated.proposed_window_utc)||
  wall(original.proposed_window_local)!==wall(updated.proposed_window_local))
  record('time_window','Proposed time window or timezone provenance changed',
   'Any newly proposed UTC or local window remains tentative, not booked or operator-approved.',
   ['client_consent','operator_review','window_stop']);
 if(original.notes!==updated.notes)
  record('safety_notes','Purpose or STOP/safety notes changed',
   'Read full originals in an approved private review channel; source free text is never reproduced in this summary.',
   ['client_consent','operator_review','window_stop','privacy_handoff']);
 if(original.client_label!==updated.client_label)
  record('client_label','Unverified client label changed',
   'Client labels do not identify a tenant or authenticate a client.',
   ['client_evidence','client_consent','operator_review']);
 if(original.proposal_name!==updated.proposal_name)
  record('proposal_name','Proposal display name changed',
   'Display-name change only; any substantive authorization must still be performed in the separate authenticated system.',[]);
 const affected=STAGES.filter(key=>changes.some(c=>c.stages.includes(key)));
 const scopeConcern=changes.some(c=>c.scopeConcern);
 return {
  disposition:'REVIEW_ONLY',authorization:false,client_consent:false,operator_consent:false,
  risk_approved:false,grant:false,revocation_checked:false,execution:false,scan:false,release:false,
  summary:changes,affectedStages:affected,
  scopeMembershipUnverified:scopeConcern,
  followups:affected.map(stage=>({stage,action:FOLLOWUPS[stage]})),
  message:!changes.length?'No listed Studio proposal fields differ. Matching drafts still do not prove identity, consent or approval.':
   'Changes require independent human review. Literal asset comparisons are NOT CIDR coverage or DNS membership decisions.'
 };
}
global.LightUpRevisionReview=Object.freeze({compare});
})(window);
