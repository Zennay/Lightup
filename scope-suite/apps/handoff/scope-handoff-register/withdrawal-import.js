/* Import only source-bound, review-only Withdrawal Desk exports. Never a revocation, consent or stop actuator. */
(function(global){
"use strict";
const DENIAL_KEYS=["authenticated_client","authenticated_operator","approved","consent",
  "authorization","grant","revoked","handler_stopped","dispatch","scan","deploy","release"];
const INTENTS=["stop_all","narrow_scope","postpone","withdraw_share"];
const URGENCY=["urgent","normal"];
const ACTIONS=["client_channel","operator_channel","active_work","grant_revoke",
  "scope_schedule","evidence_privacy","human_ack","incident_log"];
const STATES=["todo","drafted_local","requested_unverified"];
const validSHA=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
function exact(o,keys){
  return o!==null&&typeof o==="object"&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype &&
    Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
}
function deny(o){
  return exact(o,DENIAL_KEYS)&&DENIAL_KEYS.every(k=>o[k]===false);
}
function demand(ok,why){if(!ok)throw Error("HOLD · withdrawal-import: "+why);}
function parse(packet,knownSources){
  demand(exact(packet,["kind","schema_version","disposition","flags","generated_at_utc","cases"]),
    "unexpected envelope shape");
  demand(packet.kind==="lightup.scope_withdrawal_review_only" && packet.schema_version===1 &&
    packet.disposition==="REVIEW_ONLY" && deny(packet.flags),"not a literal non-authorizing withdrawal export");
  demand(typeof packet.generated_at_utc==="string"&&packet.generated_at_utc.length<=40 &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(packet.generated_at_utc) &&
    Number.isFinite(Date.parse(packet.generated_at_utc)),"invalid generated UTC timestamp");
  demand(knownSources instanceof Map && Array.isArray(packet.cases) &&
    packet.cases.length>=1 && packet.cases.length<=16,"case count");
  const base=["source_sha256","risk","intent","urgency","requested_effective_utc",
    "proposed_asset_count","proposed_exclusion_count","paperwork_prepared","human_work_items"];
  const all=[...base,...DENIAL_KEYS];
  const seen=new Set(),accepted=[];
  for(const item of packet.cases){
    demand(exact(item,all)&&DENIAL_KEYS.every(k=>item[k]===false),"case has an unexpected or elevated field");
    demand(validSHA(item.source_sha256)&&!seen.has(item.source_sha256),"duplicate or invalid source hash");
    const source=knownSources.get(item.source_sha256);
    demand(source!==undefined,"source bytes have not been re-imported locally");
    demand(item.risk===source.risk &&
      item.proposed_asset_count===source.assets.length &&
      item.proposed_exclusion_count===source.excluded.length,"source metadata mismatch");
    demand(INTENTS.includes(item.intent)&&URGENCY.includes(item.urgency),"unknown intent or urgency");
    demand(typeof item.paperwork_prepared==="boolean","invalid preparation label");
    const effective=item.requested_effective_utc;
    demand(effective===null||(
      typeof effective==="string"&& /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(effective)&&
      Number.isFinite(Date.parse(effective))
    ),"invalid self-reported effective time");
    demand(Array.isArray(item.human_work_items)&&item.human_work_items.length===ACTIONS.length,"incomplete human work items");
    const states={};
    for(const action of item.human_work_items){
      demand(exact(action,["code","status"])&&ACTIONS.includes(action.code)&&
        !Object.hasOwn(states,action.code)&&STATES.includes(action.status),"invalid or repeated human action");
      states[action.code]=action.status;
    }
    demand(ACTIONS.every(k=>Object.hasOwn(states,k)),"missing human action");
    accepted.push(Object.freeze({
      sha:item.source_sha256,intent:item.intent,urgency:item.urgency,effective,
      paperwork:item.paperwork_prepared,
      outstanding:ACTIONS.filter(k=>states[k]!=="requested_unverified").length,
      // Only non-authorizing statuses, never a proof of revocation/acknowledgment.
      statuses:Object.freeze(states)
    }));
    seen.add(item.source_sha256);
  }
  return accepted;
}
function safeSaved(o,source) {
  if(!exact(o,["intent","urgency","effective","paperwork","outstanding","statuses"]) ||
    !INTENTS.includes(o.intent)||!URGENCY.includes(o.urgency)||
    typeof o.paperwork!=="boolean" || !Number.isInteger(o.outstanding) ||
    o.outstanding<0||o.outstanding>ACTIONS.length)return false;
  if(o.effective!==null && (typeof o.effective!=="string" ||
     !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(o.effective) ||
     !Number.isFinite(Date.parse(o.effective))))return false;
  if(!exact(o.statuses,ACTIONS)||!ACTIONS.every(k=>STATES.includes(o.statuses[k])))return false;
  return ACTIONS.filter(k=>o.statuses[k]!=="requested_unverified").length===o.outstanding &&
    !!source;
}
global.LightUpWithdrawalImport=Object.freeze({parse,safeSaved});
})(window);
