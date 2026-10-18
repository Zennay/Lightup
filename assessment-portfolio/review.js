"use strict";
(() => {
  const input = JSON.parse(document.getElementById("lightupSource").textContent);
  const sourceSelect = document.getElementById("source");
  const filter = document.getElementById("filter");
  const rowsNode = document.getElementById("rows");
  const get = name => document.getElementById(name);
  const stageChoices = ["PENDING_ORIGINAL","NEEDS_ORIGINAL_EVIDENCE","NEEDS_SOURCE_OWNER",
                        "NEEDS_PRIVACY_REVIEW","AWAITING_INPUT","HUMAN_DISCUSSION"];
  const roles = ["unassigned","source_owner","reviewer","privacy","operator"];
  const buffer = new Map(); // Human draft edits in memory only; no persistence.
  const text = (el, value) => { el.textContent = String(value); return el; };
  const el = (tag, parent, value) => {
    const e = document.createElement(tag);
    if (value !== undefined) text(e,value);
    if (parent) parent.appendChild(e);
    return e;
  };
  function buildSelect(parent, choices, selected, changed) {
    const node = el("select",parent);
    for (const choice of choices) {
      const opt = el("option",node,choice);
      opt.value = choice;
    }
    node.value = selected;
    node.addEventListener("change", () => changed(node.value));
    return node;
  }
  for (const st of stageChoices) {
    const opt = el("option",filter,st); opt.value = st;
  }
  input.sources.forEach(src => {
    const opt = el("option",sourceSelect,"Agenda "+src.slot+" · "+src.claimed_status);
    opt.value = String(src.slot);
  });
  const oldFields = row => ({slot:row.source_slot,
    prior_stage:row.stage,prior_next_role:row.next_role,prior_review_date:row.review_date});
  const editedFields = row => ({stage:row.stage,
    next_role:row.next_role,review_date:row.review_date});
  function draftFor(source) {
    if (!buffer.has(source.slot)) {
      buffer.set(source.slot,source.rows.map(row => ({
        ...oldFields(row),...editedFields(row)
      })));
    }
    return buffer.get(source.slot);
  }
  function currentSource() {
    return input.sources.find(src => src.slot === Number(sourceSelect.value));
  }
  function changed(item) {
    return item.stage !== item.prior_stage ||
      item.next_role !== item.prior_next_role ||
      item.review_date !== item.prior_review_date;
  }
  function humanDate(value) {
    if (value === "") return null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const parsed = new Date(value+"T00:00:00Z");
    const year = Number(value.slice(0,4));
    return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0,10)===value &&
      year>=2020 && year<=2100 ? value : false;
  }
  function paint() {
    const source = currentSource();
    if (!source) return;
    const draft = draftFor(source);
    get("total").textContent = draft.length;
    get("sourceState").textContent = source.claimed_status;
    get("modified").textContent = draft.filter(changed).length;
    rowsNode.replaceChildren();
    for (const item of draft) {
      if (filter.value!=="all" && item.stage!==filter.value) continue;
      const original = source.rows.find(x => x.source_slot===item.slot);
      const tr = el("tr",rowsNode);
      if (changed(item)) tr.classList.add("changed");
      for (const value of [item.slot,original.source_kind,item.prior_stage]) el("td",tr,value);
      buildSelect(el("td",tr),stageChoices,item.stage,value => {
        item.stage=value;paint();
      });
      buildSelect(el("td",tr),roles,item.next_role,value => {
        item.next_role=value;paint();
      });
      const td=el("td",tr);
      const dateInput=el("input",td);
      dateInput.type="date";
      dateInput.min="2020-01-01";dateInput.max="2100-12-31";
      dateInput.value=item.review_date || "";
      dateInput.setAttribute("aria-label","Human proposed date for original source slot "+item.slot);
      dateInput.addEventListener("change", () => {
        const parsed=humanDate(dateInput.value);
        if (parsed===false) {
          dateInput.setCustomValidity("Select a valid date in 2020–2100");
          get("status").textContent="Invalid proposed date. No source updated.";
          return;
        }
        dateInput.setCustomValidity("");
        item.review_date=parsed;
        get("status").textContent="Human proposal only. No original state changed.";
        paint();
      });
      el("td",tr,changed(item)?"LOCAL CHANGE":"Original");
    }
  }
  sourceSelect.addEventListener("change", () => {
    get("confirm").checked=false;
    paint();
  });
  filter.addEventListener("change",paint);
  get("reset").addEventListener("click", () => {
    const source=currentSource();
    buffer.delete(source.slot);
    get("confirm").checked=false;
    get("status").textContent="In-memory edits for this agenda reset; original files untouched.";
    paint();
  });
  get("download").addEventListener("click", () => {
    const src=currentSource(), edits=draftFor(src);
    if (!get("confirm").checked) {
      get("status").textContent="Confirm private human-only proposal scope before exporting.";
      return;
    }
    const normalized=edits.map(x => ({
      slot:x.slot,
      prior_stage:x.prior_stage,
      prior_next_role:x.prior_next_role,
      prior_review_date:x.prior_review_date,
      stage:x.stage,
      next_role:x.next_role,
      review_date:x.review_date
    }));
    if (normalized.some(x => humanDate(x.review_date||"")===false)) {
      get("status").textContent="Invalid date: private proposal not exported.";
      return;
    }
    const packet={
      schema:"lightup.assessment_portfolio_human_proposal.v1",
      source_agenda_sha256:src.source_sha256,
      reference_date:input.reference_date,
      source_count:normalized.length,
      items:normalized,
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false
    };
    const object=new Blob([JSON.stringify(packet,null,2)+"\n"],{type:"application/json"});
    const uri=URL.createObjectURL(object);
    const link=el("a",document.body);
    link.href=uri;
    link.download="lightup-PRIVATE-human-proposal-agenda-"+src.slot+".json";
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(uri),0);
    get("status").textContent="Private human proposal exported. Revalidate with original manifest, choices and agenda in original-schema return CLI.";
    get("confirm").checked=false;
  });
  paint();
})();
