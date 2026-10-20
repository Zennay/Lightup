"use strict";
(() => {
  // Private human planning companion to the existing offline assessment Studio.
  const api=globalThis.LightUpHumanPlanAPI;
  const $=id=>document.getElementById(id);
  const sources=JSON.parse($("lightupSource").textContent).sources;
  const date=$("reference").value;
  const roles=["unassigned","source_owner","reviewer","privacy","operator"];
  const flags=["authorized","consent_verified","dispatch_allowed","release_allowed"];
  const shape=["schema","reference_date","source_count","sources",
    "hypothetical_weeks","role_capacities",...flags].sort().join("|");
  const sameKeys=(obj,keys)=>obj && typeof obj==="object" && !Array.isArray(obj)
    && Object.keys(obj).sort().join("|")===keys;
  const fail=text=>{$("planMessage").textContent=text;};
  function documentValue() {
    const state=api.view();
    if (!Number.isInteger(state.weeks) || state.weeks<1 || state.weeks>12 ||
      roles.some(role=>!Number.isInteger(state.capacities[role]) ||
        state.capacities[role]<0 || state.capacities[role]>100)) return null;
    return {schema:"lightup.assessment_portfolio_capacity_plan.v1",
      reference_date:date,source_count:sources.length,
      sources:sources.map(s=>({slot:s.slot,source_sha256:s.source_sha256,
        claimed_status:s.claimed_status})),
      hypothetical_weeks:state.weeks,
      role_capacities:state.capacities,
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false};
  }
  $("savePlan").addEventListener("click",()=>{
    const value=documentValue();
    if (!value) {fail("HOLD: invalid hypothetical role capacity or weeks.");return;}
    const blob=new Blob([JSON.stringify(value,null,2)+"\n"],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download="lightup-PRIVATE-source-bound-review-capacity.json";
    document.body.appendChild(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),0);
    fail("PRIVATE source-bound plan saved locally. No reviews assigned or executed.");
  });
  $("restorePlan").addEventListener("change",async()=>{
    const file=$("restorePlan").files[0];
    try {
      if (!file || file.size<1 || file.size>65536) throw Error("invalid size");
      const plan=JSON.parse(await file.text());
      if (!sameKeys(plan,shape) ||
          plan.schema!=="lightup.assessment_portfolio_capacity_plan.v1" ||
          plan.reference_date!==date ||
          !Number.isInteger(plan.source_count) || plan.source_count!==sources.length ||
          !Number.isInteger(plan.hypothetical_weeks) ||
          plan.hypothetical_weeks<1 || plan.hypothetical_weeks>12 ||
          !Array.isArray(plan.sources) || plan.sources.length!==sources.length ||
          !sameKeys(plan.role_capacities,roles.slice().sort().join("|")) ||
          roles.some(role=>!Number.isInteger(plan.role_capacities[role]) ||
            plan.role_capacities[role]<0 || plan.role_capacities[role]>100) ||
          flags.some(flag=>plan[flag]!==false)) throw Error("invalid private plan");
      const sourceKeys=["slot","source_sha256","claimed_status"].sort().join("|");
      for (let n=0;n<sources.length;n++) {
        const old=sources[n],candidate=plan.sources[n];
        if (!sameKeys(candidate,sourceKeys) ||
            old.slot!==candidate.slot ||
            old.source_sha256!==candidate.source_sha256 ||
            old.claimed_status!==candidate.claimed_status) throw Error("source drift");
      }
      // Atomic in-memory role planning update after all original source digests admitted.
      api.restore(plan.hypothetical_weeks,plan.role_capacities);
      fail("Source-bound PRIVATE human review assumptions restored. No real task scheduled.");
    } catch(_) {
      fail("HOLD: private assumptions are invalid or an original agenda has changed. No planning fields updated.");
    } finally {
      $("restorePlan").value="";
    }
  });
})();
