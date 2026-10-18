"use strict";
/* Offline recipient-only human review desk; no targets, grants, consent or network. */
(() => {
  const $ = id => document.getElementById(id);
  const status = $("status");
  const cards = $("cards");
  const phases = ["unassigned","investigating","waiting_on_client",
    "waiting_on_operator","needs_source_review","human_followup_complete"];
  const allowedStages = new Set(phases);
  const flags = ["source_authenticated","client_consent_verified",
    "operator_consent_verified","authorization_granted",
    "execution_allowed","release_approved"];
  const baseKeys = ["schema","status","authority","source_sha256",
    "source_as_of","client_id","reviewer","packet_id","rows",...flags];
  const humanKeys = ["owner","due","stage","next"];
  const exact = (obj, keys) => !!obj && typeof obj === "object" &&
    !Array.isArray(obj) && Object.keys(obj).length === keys.length &&
    keys.every(key=>Object.prototype.hasOwnProperty.call(obj,key));
  const clean = (value, max) => typeof value === "string" &&
    value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
  const date = value => {
    if (value === "") return true;
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const parsed = Date.parse(value + "T00:00:00Z");
    if (!Number.isFinite(parsed)) return false;
    const dt = new Date(parsed);
    return Number.isFinite(dt.getTime()) && dt.toISOString().slice(0,10) === value;
  };
  const human = obj => exact(obj,humanKeys) &&
    clean(obj.owner,80) && clean(obj.next,500) && date(obj.due) &&
    allowedStages.has(obj.stage);
  function notify(message, hold=false) {
    status.textContent = (hold?"HOLD · ":"") + message;
    status.dataset.hold=hold?"true":"false";
  }
  function validate(doc) {
    if (!exact(doc,baseKeys) ||
        doc.schema !== "lightup.scope_escalation_reviewer_handoff.v1" ||
        doc.status !== "REVIEW_ONLY" || doc.authority !== false ||
        flags.some(flag=>doc[flag]!==false) ||
        !/^[a-f0-9]{64}$/.test(doc.source_sha256) ||
        !/^[a-f0-9]{32}$/.test(doc.packet_id) ||
        !clean(doc.source_as_of,80) ||
        !clean(doc.client_id,180) || doc.client_id.trim()!==doc.client_id ||
        !clean(doc.reviewer,80) || !doc.reviewer.trim() ||
        !Array.isArray(doc.rows) || doc.rows.length<1 || doc.rows.length>200) {
      throw Error("invalid original-bound human packet");
    }
    const ids = new Set();
    for (const row of doc.rows) {
      if (!exact(row,["key","tier","attention","action","observations","baseline"]) ||
          !clean(row.key,200) || !/^(request|engagement):/.test(row.key) ||
          !["HOLD","PENDING","REVIEW"].includes(row.tier) ||
          !clean(row.attention,120) || !clean(row.action,200) ||
          !Array.isArray(row.observations) || row.observations.length>400 ||
          !row.observations.every(x=>clean(x,230)) ||
          !human(row.baseline) || row.baseline.owner!==doc.reviewer ||
          ids.has(row.key)) throw Error("invalid or duplicated source identity");
      ids.add(row.key);
    }
    return doc;
  }
  let packet=null, edited=false;
  const textarea = (value,max) => {
    const el=document.createElement("textarea");
    el.maxLength=max; el.value=value;
    return el;
  };
  function labeled(title,field) {
    const el=document.createElement("label");
    const name=document.createElement("span"); name.textContent=title;
    el.append(name,field);
    return el;
  }
  function formRow(row,idx) {
    const article=document.createElement("article");
    article.className="row";
    article.dataset.key=row.key;
    article.dataset.tier=row.tier;
    const heading=document.createElement("h2");
    heading.textContent=(idx+1)+". "+row.key;
    const hint=document.createElement("p");
    hint.className="muted";
    hint.textContent=row.tier+" · "+row.attention+" · original source observation, NOT an approval";
    const recommendation=document.createElement("p");
    recommendation.textContent="Original proposed HUMAN action: "+row.action;
    const detail=document.createElement("details"),summary=document.createElement("summary");
    summary.textContent="Historical source observations ("+row.observations.length+")";
    detail.append(summary);
    const listing=document.createElement("ul");
    row.observations.forEach(value=>{
      const item=document.createElement("li");item.textContent=value;listing.append(item);
    });
    detail.append(listing);
    const previous=document.createElement("p");
    previous.textContent="Original human stage: "+row.baseline.stage+
      " · proposed due: "+(row.baseline.due||"unset");
    const stage=document.createElement("select");
    stage.dataset.field="stage";
    phases.forEach(value=>{
      const option=document.createElement("option");
      option.value=value; option.textContent=value.replaceAll("_"," ");
      stage.append(option);
    });
    stage.value=row.baseline.stage;
    const due=document.createElement("input");
    due.type="date"; due.dataset.field="due"; due.value=row.baseline.due;
    const next=textarea(row.baseline.next,500);
    next.dataset.field="next";
    const form=document.createElement("div");
    form.className="form";
    form.append(labeled("Human stage",stage),
      labeled("Proposed UTC follow-up day",due),
      labeled("Private human next action / question",next));
    article.append(heading,hint,recommendation,detail,previous,form);
    article.addEventListener("change",()=>{
      edited=true;refreshSummary();notify("Local human-only draft changed; use PRIVATE reply export.");
    });
    article.addEventListener("input",()=>{
      edited=true;notify("Local human-only draft changed; use PRIVATE reply export.");
    });
    return article;
  }
  async function canonicalFile(file) {
    if (!file || file.size<2 || file.size>262144)
      throw Error("private packet exceeds bounded size");
    const bytes=await file.arrayBuffer();
    const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    if (source.charCodeAt(0)===0xfeff) throw Error("BOM");
    const object=JSON.parse(source);
    if (JSON.stringify(object)!==source) throw Error("noncanonical JSON or repeated keys");
    return object;
  }
  function refreshSummary() {
    if (!packet) {
      $("summary").textContent="No private reviewer handoff has been admitted.";
      return;
    }
    const search=$("search").value.toLocaleLowerCase();
    const filter=$("focus").value;
    let visible=0,changed=0,unfinished=0;
    [...cards.children].forEach((card,index)=>{
      const sourceRow=packet.rows[index];
      const proposed=getHuman(card,sourceRow.baseline);
      const changedRow=["due","stage","next"].some(k=>
        proposed[k]!==sourceRow.baseline[k]);
      if (changedRow)changed++;
      if (proposed.stage!=="human_followup_complete")unfinished++;
      const show=card.dataset.key.toLocaleLowerCase().includes(search) &&
        (filter==="ALL" || filter===card.dataset.tier ||
          (filter==="CHANGED" && changedRow) ||
          (filter==="UNFINISHED" && proposed.stage!=="human_followup_complete"));
      card.hidden=!show;
      if (show)visible++;
    });
    $("summary").textContent=visible+" visible · "+changed+
      " human notes changed · "+unfinished+
      " human follow-ups not marked complete. "+
      "Completeness is a self-declared human stage, NEVER remediation/consent.";
  }
  $("focus").addEventListener("change",refreshSummary);
  $("search").addEventListener("input",refreshSummary);
  $("import").addEventListener("change",async event=>{
    const file=event.target.files[0];event.target.value="";
    if (!file) return;
    try {
      const original=validate(await canonicalFile(file));
      if (packet && edited &&
          !confirm("Discard current UNSAVED private human review edits?")) return;
      // Fully validated first; one DOM replacement (no partial imports).
      const nodes=original.rows.map((row,i)=>formRow(row,i));
      cards.replaceChildren(...nodes);
      packet=original;edited=false;
      $("identity").textContent="Recipient reviewer label: "+original.reviewer+
        " · "+original.rows.length+" source-bound human follow-ups.";
      $("export").disabled=false;
      refreshSummary();
      notify("Original-bound PRIVATE handoff loaded locally. Reviewer label is unverified.");
    } catch (_) {notify("Private handoff refused; current human notes preserved.",true);}
  });
  const getHuman=(card,baseline)=>({
    owner:baseline.owner,
    due:card.querySelector('[data-field="due"]').value,
    stage:card.querySelector('[data-field="stage"]').value,
    next:card.querySelector('[data-field="next"]').value
  });
  $("export").addEventListener("click",()=>{
    if (!packet || cards.children.length!==packet.rows.length) {
      notify("No complete private source handoff",true);return;
    }
    const rows=[...cards.children].map((card,i)=>{
      const r=packet.rows[i];
      return {key:r.key,tier:r.tier,attention:r.attention,
        action:r.action,observations:r.observations,
        baseline:r.baseline,proposed:getHuman(card,r.baseline)};
    });
    if (rows.some(r=>!human(r.proposed)||r.proposed.owner!==packet.reviewer)) {
      notify("Invalid local human reviewer, stage, proposed date or action",true);return;
    }
    const differences=rows.filter(r=>
      ["owner","due","stage","next"].some(k=>r.baseline[k]!==r.proposed[k]));
    if (!confirm("PRIVATE reply will expose original IDs, tenant, source SHA and "+
        "human actions to the verified recipient. "+differences.length+
        " human-only changes. This is NOT client/operator consent or grant. Export?"))return;
    const object={...packet,schema:"lightup.scope_escalation_reviewer_reply.v1",rows};
    const blob=new Blob([JSON.stringify(object)],{type:"application/json;charset=utf-8"});
    const url=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=url;a.download="PRIVATE-scope-reviewer-reply.json";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),5000);
    edited=false;
    refreshSummary();
    notify("PRIVATE human reply exported. It requires exact-source coordinator acceptance.");
  });
  addEventListener("beforeunload",event=>{
    if (!edited)return;
    event.preventDefault();event.returnValue="";
  });
})();