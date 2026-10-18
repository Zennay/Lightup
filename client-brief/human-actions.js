/* Offline human follow-up queue: summarizes review sources, never assigns or runs work. */
(function(global){
'use strict';
function count(n){return Number.isSafeInteger(n)&&n>=0?n:0;}
const ORDER={urgent:0,attention:1,planning:2,context:3};
function fromState(state,{includeOperator=false}={}){
 if(!state||!state.fresh||!Array.isArray(state.fresh.rows))throw Error('Open real source findings first.');
 const out=[];
 const add=(level,origin,title,amount,message)=>{
  if(!count(amount))return;
  out.push(Object.freeze({level,origin,title,source_count:amount,next_human_step:message,
   verified:false,authorized:false,execution:false,release:false}));
 };
 const rows=state.fresh.rows;
 add('urgent','original_findings','Critical/high findings awaiting human triage',
  rows.filter(x=>['critical','high'].includes(x.severity)).length,
  'Discuss ownership and remediation priorities with the authorized client team; do not scan from this report.');
 add('urgent','original_findings','Source-reported regression needs investigation',
  rows.filter(x=>x.retest_status==='regression').length,
  'Ask an authorized reviewer to inspect the original evidence. No independently verified retest is implied.');
 if(state.changes){
  add('attention','historical_findings','Findings now absent from latest source',
   state.changes.missing.length,
   'Reconcile missing rows without presuming they were fixed, revoked or remediated.');
  add('attention','historical_findings','Finding source payload changed',
   state.changes.changed.length,
   'Re-read changed source data and reassess the human plan; changed does not mean fixed.');
 }
 if(Array.isArray(state.history)&&state.history.length){
  const prior=state.history[state.history.length-1];
  const urgent=rows.filter(x=>['critical','high'].includes(x.severity)).length;
  const regressions=rows.filter(x=>x.retest_status==='regression').length;
  if(urgent>prior.critical_high)add('urgent','historical_aggregate','Source-reported critical/high count increased',urgent-prior.critical_high,
   'Human reviewer must compare the underlying original authorized sources; reported count changes are not a verified new scan or proof of worsened security.');
  if(regressions>prior.retest.regression)add('urgent','historical_aggregate','Reported regression count increased',regressions-prior.retest.regression,
   'Escalate original evidence review and obtain independent authorization before any retest.');
  if(prior.proposed_scope&&!state.studio)
   add('attention','historical_aggregate','Previously proposed scope is absent from current review',1,
    'Reconcile the original proposal with its real client/operator owners. A missing proposal is not revocation, a narrowed grant or permission to scan.');
  if(state.studio&&prior.proposed_scope){
   if(state.studio.requested_risk>prior.proposed_scope.risk)
    add('urgent','historical_aggregate','Proposed risk increased since earlier briefing',1,
     'Review proposed risk in the original authenticated request path; a draft cannot expand actual authorization.');
   if(state.studio.source_revision_sha256!==prior.proposed_scope.revision)
    add('attention','historical_aggregate','Original proposal revision differs from earlier briefing',1,
     'Reconcile original Studio revisions with real client/operator owners; no scope approval inferred.');
  }
 }
 if(state.casework){
  add('urgent','private_casework_draft','Local critical/high work marked blocked',
   state.casework.urgentBlocked,'Follow up on self-reported blocking dependencies; this is not confirmed vulnerability remediation.');
  add('attention','private_casework_draft','Local planned follow-up date elapsed',
   state.casework.overdue,'Contact the human owner before assuming the action was performed.');
  add('planning','private_casework_draft','Draft items ready for separately approved retest',
   count(state.casework.counts.ready_for_retest),'Arrange real approval and an independently authorized retest if still needed. No retest is scheduled here.');
 }
 if(state.studio){
  add('attention','studio_proposal','Original Studio proposal still unapproved',1,
   'Reconcile exact client, asset ownership, exclusions, proposed risk and proposed UTC window in the real authenticated process.');
  if(state.studio.requested_risk===4)add('urgent','studio_proposal','Elevated proposed risk requires human approval',1,
   'Request explicit separate risk review through the official authenticated channel.');
  if(state.studio.proposed_window_status!=='resolved')
   add('attention','studio_proposal','Proposed UTC planning window unresolved',1,
    'Agree a real valid window with both parties independently; no existing permission or calendar slot.');
 }
 if(state.studioChange){
  const d=state.studioChange;
  if(d.scope_expanded)add('urgent','studio_revision','Proposed effective asset scope expanded',1,
   'Stop treating the earlier proposal as applicable: seek a fresh separately authenticated client/operator scope decision.');
  if(d.elevated_risk||d.mode_escalated||d.new_activities.length)
   add('urgent','studio_revision','Proposed authority or activity envelope widened',1,
    'Re-review increased risk, mode and new activity declarations with the actual authorization owners.');
  if(d.window_changed)add('attention','studio_revision','Proposed scheduling window changed',1,
   'Reconfirm proposed UTC times independently before any separately authorized work.');
  if(d.coverage_truncated)add('attention','studio_revision','Effective coverage comparison was truncated',1,
   'Use the original Studio detailed review; never assume the summarized scope changes are exhaustive.');
 }
 if(includeOperator&&state.readiness){
  for(const g of state.readiness.risk_groups){
   add('urgent','internal_operator_readiness',g.name,count(g.count),
    'Private operator must review original authenticated database source and repair with the owning domain team. Snapshot is not a grant.');
  }
 }
 const ordered=out.sort((a,b)=>ORDER[a.level]-ORDER[b.level]||a.origin.localeCompare(b.origin)||a.title.localeCompare(b.title));
 return Object.freeze({kind:'lightup.client_brief_human_followup_review',disposition:'REVIEW_ONLY_DRAFT_HOLD',
  authority:{authenticated:false,client_consent:false,operator_consent:false,grant:false,execution:false,scan:false,retest_verified:false,release:false},
  actions:ordered,scope_identity_authenticated:false,actions_performed:false,
  warning:'All rows are proposed human discussion steps from unsigned source snapshots; not actual authorization, assignments, approvals, repair or verified retest.'});
}
function csvEscape(value){
 const raw=String(value??'');
 const safe=/^[\s\x00-\x1f]*[=+@-]/.test(raw)?"'"+raw:raw;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function toCSV(plan){
 if(!plan||plan.kind!=='lightup.client_brief_human_followup_review'||!Array.isArray(plan.actions))throw Error('Invalid offline human register.');
 const header=['urgency','source_type','human_action','source_count','next_human_step','source_verified','authorization_granted'];
 const rows=plan.actions.map(x=>[x.level,x.origin,x.title,x.source_count,x.next_human_step,'FALSE','FALSE']);
 return '\ufeff'+[header,...rows].map(row=>row.map(csvEscape).join(',')).join('\r\n')+'\r\n';
}
global.LightUpBriefActions=Object.freeze({fromState,toCSV});
})(window);
