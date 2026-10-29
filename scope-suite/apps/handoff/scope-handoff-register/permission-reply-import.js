/* Strict, offline-only import of Permission Brief reconciliation exports. Never consent or identity proof. */
(function(global){
"use strict";
const FLAGS=["authenticated","client_consent","operator_consent","scope_approved","risk_approved",
"authorization","grant","revocation_checked","execution","scan","deploy","release"];
const QUESTIONS={
client:["client_identity","asset_ownership","purpose_limits","client_consent","safety_context","network_activity","revision_client"],
operator:["operator_independence","enforceable_scope","risk_approval","stop_revocation","mandatory_gates","high_risk","lab_provenance","no_exclusions","open_window","revision_operator"]
};
const STATES=["not_reported","unanswered","question_sent","answered_unverified"];
const NEXT={
not_reported:r=>"await_"+r+"_response",
unanswered:r=>"ask_"+r,
question_sent:r=>"follow_up_"+r,
answered_unverified:()=>"independently_verify"
};
function exact(value,fields) {
 return value!==null && typeof value==="object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value)===Object.prototype &&
  Object.keys(value).length===fields.length && fields.every(k=>Object.hasOwn(value,k));
}
function check(ok,description){if(!ok)throw Error("Permission Brief HOLD: "+description);}
function expectedQuestions(source) {
 const codes=["client_identity","asset_ownership","purpose_limits","client_consent",
   "operator_independence","enforceable_scope","risk_approval","stop_revocation","mandatory_gates"];
 if(source.risk===4)codes.push("high_risk");
 if(source.wantsNetwork===true)codes.push("lab_provenance","network_activity");
 if(source.excluded.length===0)codes.push("no_exclusions");
 if(source.hasWindow!==true)codes.push("open_window");
 if(source.hasSafetyNotes!==true)codes.push("safety_context");
 codes.push("revision_client","revision_operator");
 return codes;
}
function verify(packet,sourceBySha){
 const fields=["kind","schema_version","disposition","source_kind","source_sha256",
  "client_note_present","operator_note_present","requested_mode","requested_risk",
  "proposed_assets_count","excluded_assets_count","window_status","questions",
  "attention_count","flags","notice"];
 check(exact(packet,fields),"noncanonical envelope");
 check(packet.kind==="lightup.scope_permission_reply_reconciliation" &&
       packet.schema_version===1 && packet.disposition==="REVIEW_ONLY_HOLD" &&
       packet.source_kind==="lightup.scope_proposal_draft" &&
       typeof packet.source_sha256==="string" && /^[a-f0-9]{64}$/.test(packet.source_sha256),"kind or source");
 check(sourceBySha instanceof Map && sourceBySha.has(packet.source_sha256),"original Studio draft bytes not loaded");
 const source=sourceBySha.get(packet.source_sha256);
 check(packet.requested_mode===source.mode && packet.requested_risk===source.risk &&
   packet.proposed_assets_count===source.assets.length &&
   packet.excluded_assets_count===source.excluded.length,"risk, mode or asset count mismatch");
 check(typeof packet.window_status==="string" && packet.window_status.length<=64 &&
   packet.window_status===(source.utcWindow?.status==="resolved"?"resolved_unapproved":
     source.utcWindow?.status==="incomplete"?"incomplete":"unscheduled"),"window planning status mismatch");
 check(exact(packet.flags,FLAGS)&&FLAGS.every(k=>packet.flags[k]===false),"authority flag not literally FALSE");
 check(typeof packet.client_note_present==="boolean"&&typeof packet.operator_note_present==="boolean","note presences");
 check(typeof packet.notice==="string" && packet.notice.length<=500 &&
   /not verified identity|not verified|not verified|NOT verified/i.test(packet.notice),
   "missing unverified disclaimer");
 const expected=expectedQuestions(source);
 check(Array.isArray(packet.questions)&&packet.questions.length===expected.length,
   "conditional role question set does not match original Studio draft");
 const seen=new Set(),items=[],roleCounts={client:0,operator:0},roleReplied={client:0,operator:0};
 for(const [index,q] of packet.questions.entries()) {
  check(exact(q,["code","assigned_role","reported_status","next_action"]),"question envelope");
  check(["client","operator"].includes(q.assigned_role) &&
    QUESTIONS[q.assigned_role].includes(q.code) && q.code===expected[index] && !seen.has(q.code),
    "question role/order/conditional identity does not match original draft");
  check(STATES.includes(q.reported_status) &&
    q.next_action===NEXT[q.reported_status](q.assigned_role),"question progress or action inconsistent");
  seen.add(q.code);roleCounts[q.assigned_role]++;
  if(q.reported_status!=="not_reported")roleReplied[q.assigned_role]++;
  items.push({code:q.code,role:q.assigned_role,status:q.reported_status});
 }
 for(const role of ["client","operator"]){
  const required=["client_identity","asset_ownership","purpose_limits","client_consent",
    "operator_independence","enforceable_scope","risk_approval","stop_revocation","mandatory_gates"];
  check(required.filter(code=>QUESTIONS[role].includes(code)).every(code=>seen.has(code)),
    "essential "+role+" questions missing");
  check((role==="client"?packet.client_note_present:packet.operator_note_present)===
    (roleReplied[role]>0),"role report presence inconsistent");
 }
 check(Number.isInteger(packet.attention_count) &&
   packet.attention_count===items.filter(q=>q.status!=="answered_unverified").length,
   "attention count inconsistent");
 return {
   sourceSha:packet.source_sha256,
   clientNoted:packet.client_note_present,operatorNoted:packet.operator_note_present,
   total:items.length,needsAttention:packet.attention_count,
   questions:items,sourceKind:packet.source_kind
 };
}
function saved(value,source){
 if(!source || !Array.isArray(source.excluded) ||
    !exact(value,["clientNoted","operatorNoted","total","needsAttention","questions","sourceKind"]) ||
    value.sourceKind!=="lightup.scope_proposal_draft" ||
    typeof value.clientNoted!=="boolean"||typeof value.operatorNoted!=="boolean" ||
    !Number.isInteger(value.total)||value.total!==expectedQuestions(source).length ||
    !Array.isArray(value.questions)||value.questions.length!==value.total)return false;
 const seen=new Set(),counts={client:0,operator:0};
 for(const [idx,q] of value.questions.entries()){
   if(!exact(q,["code","role","status"])||!QUESTIONS[q.role]?.includes(q.code)||
      q.code!==expectedQuestions(source)[idx] ||
      !STATES.includes(q.status)||seen.has(q.code))return false;
   seen.add(q.code);if(q.status!=="not_reported")counts[q.role]++;
 }
 const required=["client_identity","asset_ownership","purpose_limits","client_consent",
   "operator_independence","enforceable_scope","risk_approval","stop_revocation","mandatory_gates"];
 return required.every(x=>seen.has(x)) &&
   value.clientNoted===(counts.client>0) && value.operatorNoted===(counts.operator>0) &&
   value.needsAttention===value.questions.filter(q=>q.status!=="answered_unverified").length;
}
global.LightUpPermissionReplyImport=Object.freeze({verify,saved});
})(window);
