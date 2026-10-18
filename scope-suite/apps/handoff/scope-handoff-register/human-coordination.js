/* Non-authorizing local coordination agenda. Pure metadata transformation, no network or identities. */
(function(global){
"use strict";
const TASKS=new Set(["owner","assets","risk","schedule","stops","privacy","client","operator"]);
const PAIR_STATES=new Set(["open","discussion_started","needs_followup","discussion_recorded"]);
const ACTION_ROLES=Object.freeze({
 owner:"joint",assets:"joint",risk:"operator",schedule:"joint",
 stops:"joint",privacy:"joint",client:"client",operator:"operator"
});
const PAIR_ROLE="joint";
const LIMIT=16,MAX=700;
const isSHA=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
function build(input,pairs) {
 if(!Array.isArray(input)||input.length>LIMIT||!Array.isArray(pairs)||pairs.length>120)
   throw Error("Unsafe coordination input");
 const rows=[],known=new Map();
 const references=new Map(input.map(r=>[r.sha,r]));
 const ancestral=(child,parent)=>{
   const seen=new Set();let cursor=child.replaces;
   while(cursor&&!seen.has(cursor)){
     if(cursor===parent.sha)return true;
     seen.add(cursor);cursor=references.get(cursor)?.replaces??null;
   }
   return false;
 };
 const related=(a,b)=>ancestral(a,b)||ancestral(b,a);
 for(let i=0;i<input.length;i++){
   const r=input[i];
   if(!r||!isSHA(r.sha)||known.has(r.sha)||typeof r.reference!=="string")
     throw Error("Duplicate or invalid dossier input");
   const dossier="D"+String(i+1).padStart(2,"0");
   known.set(r.sha,dossier);
   const risk=r.source.risk;
   if(!Number.isInteger(risk)||risk<1||risk>4)throw Error("Invalid proposal risk");
   if(!r.withdrawal) {
     const stopLineage=input.filter(other=>other!==r&&other.withdrawal&&related(r,other));
     if(stopLineage.length) rows.push({
       dossier,source_sha256:r.sha,kind:"historical_withdrawal_context",
       code:"related_revision_stop_request",role:"joint",
       priority:stopLineage.some(x=>x.withdrawal.urgency==="urgent")?0:1,
       reason:"Unverified STOP/scope change reported for self-linked source revision",
       state:"needs_independent_review",action:"confirm_scope_version_with_authenticated_operator",
       due_day:null,authority:"REVIEW_ONLY_HOLD"
     });
   }
   if(r.withdrawal){
     const w=r.withdrawal;
     // Human step status 'requested_unverified' still needs independent confirmation.
     const steps=["client_channel","operator_channel","active_work","grant_revoke",
       "scope_schedule","evidence_privacy","human_ack","incident_log"];
     for(const code of steps){
       const status=w.statuses[code];
       rows.push({dossier,source_sha256:r.sha,kind:"withdrawal_human_followup",code,
         role:code==="client_channel"?"client":code==="grant_revoke"||code==="active_work"||code==="operator_channel"?"operator":"joint",
         priority:w.urgency==="urgent"?0:1,reason:"Self-reported "+w.intent,
         state:status,action:status==="requested_unverified"?"independently_verify_stop_receipt":"contact_authenticated_channel",
         due_day:null,authority:"REVIEW_ONLY_HOLD"});
     }
   }
   if(r.permission){
     for(const q of r.permission.questions){
       if(q.status==="answered_unverified"||q.status==="question_sent"||q.status==="unanswered"||q.status==="not_reported")
         rows.push({dossier,source_sha256:r.sha,kind:"permission_question",code:q.code,role:q.role,
           priority:r.withdrawal?.urgency==="urgent"?1:2,reason:"Unverified role-labelled reply",
           state:q.status,action:q.status==="answered_unverified"?"independently_verify_identity_and_scope":
             q.status==="question_sent"?"follow_up_authenticated_channel":
             q.status==="unanswered"?"ask_authenticated_channel":"await_authenticated_reply",
           due_day:null,authority:"REVIEW_ONLY_HOLD"});
     }
   }
   for(const code of TASKS) {
     const status=r.tasks[code];
     if(status==="prepared")continue;
     const due=r.dueDates[code]||null;
     rows.push({dossier,source_sha256:r.sha,kind:"local_preparation",code,
       role:ACTION_ROLES[code],
       priority:r.withdrawal?.urgency==="urgent"?0:status==="needs_revision"?1:risk===4?2:3,
       reason:status==="needs_revision"?"Earlier local preparation requires human reassessment":"Local human preparation",
       state:status,action:status==="needs_revision"?"reassess_revised_proposal":"prepare_offline_handoff",
       due_day:due,authority:"REVIEW_ONLY_HOLD"});
   }
 }
 const seen=new Set();
 for(const p of pairs) {
   if(!known.has(p.left)||!known.has(p.right)||p.left===p.right||
     !PAIR_STATES.has(p.human_status))throw Error("Invalid source-bound pair");
   const key=[p.left,p.right].sort().join(":");
   if(seen.has(key))throw Error("Duplicate review pair");seen.add(key);
   if(p.human_status==="discussion_recorded")continue;
   rows.push({dossier:known.get(p.left)+"-"+known.get(p.right),
     source_sha256:p.left+";"+p.right,kind:"cross_proposal_discussion",
     code:p.revision_related?"historical_revision":p.scope_overlap&&p.utc_overlap?"scope_and_schedule_overlap":
       p.scope_overlap?"effective_scope_overlap":"utc_window_overlap",
     role:PAIR_ROLE,priority:p.revision_related?3:p.scope_overlap&&p.utc_overlap?1:2,
     reason:p.revision_related?"Self-reported revision, not a separate client":"Independent human review of potential collision",
     state:p.human_status,action:"independent_human_coordination",due_day:null,authority:"REVIEW_ONLY_HOLD"});
 }
 if(rows.length>MAX)throw Error("Agenda too large");
 const day=new Date(),today=[day.getFullYear(),String(day.getMonth()+1).padStart(2,"0"),String(day.getDate()).padStart(2,"0")].join("-");
 rows.sort((a,b)=>a.priority-b.priority ||
   ((a.due_day&&a.due_day<today)?0:1)-((b.due_day&&b.due_day<today)?0:1) ||
   (a.due_day||"9999").localeCompare(b.due_day||"9999") ||
   a.dossier.localeCompare(b.dossier) || a.code.localeCompare(b.code));
 return {
   kind:"lightup.scope_handoff_coordination_agenda",schema_version:1,
   disposition:"REVIEW_ONLY_HOLD",authority:{
     authenticated:false,consent:false,authorized:false,grant:false,execution:false,
     scan:false,dispatch:false,deploy:false,release:false
   },
   warning:"Every status is a local unverified human preparation state. No execution rights or real revocation.",
   entries:rows
 };
}
global.LightUpHumanCoordination=Object.freeze({build});
})(window);
