"use strict";
(() => {
  const input = JSON.parse(document.getElementById("lightupSource").textContent);
  const get = id => document.getElementById(id);
  const sourceSelect = get("source");
  const filter = get("filter");
  const stageChoices = ["PENDING_ORIGINAL","NEEDS_ORIGINAL_EVIDENCE","NEEDS_SOURCE_OWNER",
                        "NEEDS_PRIVACY_REVIEW","AWAITING_INPUT","HUMAN_DISCUSSION"];
  const roles = ["unassigned","source_owner","reviewer","privacy","operator"];
  const keys = obj => Object.keys(obj).sort().join("|");
  const packetKeys = ["schema","source_agenda_sha256","reference_date","source_count",
                      "items","authorized","consent_verified","dispatch_allowed","release_allowed"].sort().join("|");
  const itemKeys = ["slot","prior_stage","prior_next_role","prior_review_date",
                    "stage","next_role","review_date"].sort().join("|");
  const state = new Map(), selected = new Set();
  const node = (tag,parent,value) => {
    const x=document.createElement(tag);
    if (value !== undefined) x.textContent=String(value);
    if (parent) parent.appendChild(x);
    return x;
  };
  function choices(parent,values,current,onChange,blank=false) {
    const s=node("select",parent);
    if (blank) {
      const o=node("option",s,"Leave unchanged");
      o.value="";
    }
    for (const value of values) {
      const opt=node("option",s,value);
      opt.value=value;
    }
    s.value=current;
    if (onChange) s.addEventListener("change",()=>onChange(s.value));
    return s;
  }
  function message(text) { get("status").textContent=text; }
  for (const step of stageChoices) {
    const opt=node("option",filter,step);
    opt.value=step;
  }
  choices(get("bulkStage"),stageChoices,"",null,true);
  choices(get("bulkRole"),roles,"",null,true);
  for (const src of input.sources) {
    const opt=node("option",sourceSelect,"Agenda "+src.slot+" · "+src.claimed_status);
    opt.value=String(src.slot);
  }
  function originalItem(row) {
    return {slot:row.source_slot,prior_stage:row.stage,
      prior_next_role:row.next_role,prior_review_date:row.review_date,
      stage:row.stage,next_role:row.next_role,review_date:row.review_date};
  }
  function source() {
    return input.sources.find(item=>item.slot===Number(sourceSelect.value));
  }
  function currentRows(src) {
    if (!state.has(src.slot)) state.set(src.slot,src.rows.map(originalItem));
    return state.get(src.slot);
  }
  function modified(item) {
    return ["stage","next_role","review_date"].some(field =>
      item[field]!==item["prior_"+field]);
  }
  function dateValue(value) {
    if (value === "" || value === null) return null;
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const d = new Date(value+"T00:00:00Z");
    const year=Number(value.slice(0,4));
    if (!Number.isFinite(d.getTime()) || year<2020 || year>2100
        || d.toISOString().slice(0,10)!==value) return false;
    return value;
  }
  function changes(item) {
    const output=[];
    for (const key of ["stage","next_role","review_date"]) {
      const older=item["prior_"+key], later=item[key];
      if (older!==later) output.push([key,older || "—",later || "—"]);
    }
    return output;
  }
  function view() {
    const src=source();
    if (!src) return;
    const drafts=currentRows(src);
    get("total").textContent=drafts.length;
    get("modified").textContent=drafts.filter(modified).length;
    get("sourceState").textContent=src.claimed_status;
    const tbody=get("rows"), diff=get("diffRows");
    tbody.replaceChildren(); diff.replaceChildren();
    for (const item of drafts) {
      for (const entry of changes(item)) {
        const tr=node("tr",diff);
        [item.slot,...entry].forEach(value=>node("td",tr,value));
      }
      if (filter.value!=="all" && item.stage!==filter.value) continue;
      const original=src.rows.find(row=>row.source_slot===item.slot);
      const tr=node("tr",tbody);
      if (modified(item)) tr.classList.add("changed");
      const selector=node("input",node("td",tr));
      selector.type="checkbox";
      selector.checked=selected.has(item.slot);
      selector.setAttribute("aria-label","Select human source slot "+item.slot);
      selector.addEventListener("change",()=>{
        if (selector.checked) selected.add(item.slot);
        else selected.delete(item.slot);
      });
      [item.slot,original.source_kind,item.prior_stage].forEach(value=>node("td",tr,value));
      choices(node("td",tr),stageChoices,item.stage,value=>{
        item.stage=value;
        view();
      });
      choices(node("td",tr),roles,item.next_role,value=>{
        item.next_role=value;
        view();
      });
      const date=node("input",node("td",tr));
      date.type="date";date.min="2020-01-01";date.max="2100-12-31";
      date.value=item.review_date || "";
      date.setAttribute("aria-label","Proposed human date for slot "+item.slot);
      date.addEventListener("change",()=>{
        const value=dateValue(date.value);
        if (value===false) {
          date.setCustomValidity("Invalid date, enter 2020–2100");
          message("Invalid date. No original human source modified.");
          return;
        }
        item.review_date=value;
        date.setCustomValidity("");
        view();
      });
      node("td",tr,modified(item)?"LOCALLY EDITED":"Original");
    }
    if (!diff.children.length) {
      const tr=node("tr",diff);
      node("td",tr,"No local human changes");
      for(let i=0;i<3;i++) node("td",tr,"—");
    }
  }
  sourceSelect.addEventListener("change",()=>{
    selected.clear();get("confirm").checked=false;get("confirmAll").checked=false;
    get("restore").value="";
    message("Switched private source. No original data changed.");
    view();
  });
  filter.addEventListener("change",()=>{
    selected.clear();
    view();
  });
  get("selectVisible").addEventListener("click",()=>{
    selected.clear();
    currentRows(source()).filter(item=>filter.value==="all" || item.stage===filter.value)
      .forEach(item=>selected.add(item.slot));
    message(selected.size+" human rows selected for possible local bulk edit.");
    view();
  });
  get("clearSelected").addEventListener("click",()=>{
    selected.clear();
    message("No human rows selected.");
    view();
  });
  get("applySelected").addEventListener("click",()=>{
    const stage=get("bulkStage").value,role=get("bulkRole").value;
    const date=get("bulkDate").value,clear=get("bulkClearDate").checked;
    if (!selected.size) {message("Select specific source slots first.");return;}
    if (clear && date) {message("Choose either a new proposed date OR clear it.");return;}
    const parsed=dateValue(date);
    if (parsed===false) {message("Invalid proposed date, no changes applied.");return;}
    if (!stage && !role && !date && !clear) {
      message("Choose at least one human-only field to modify.");return;
    }
    let changed=0;
    for (const item of currentRows(source())) {
      if (!selected.has(item.slot)) continue;
      if (stage) item.stage=stage;
      if (role) item.next_role=role;
      if (date || clear) item.review_date=clear?null:parsed;
      changed++;
    }
    selected.clear();
    get("confirm").checked=false;get("confirmAll").checked=false;
    message(changed+" selected human rows edited locally; original source unchanged.");
    view();
  });
  get("reset").addEventListener("click",()=>{
    state.delete(source().slot);
    selected.clear();
    get("confirm").checked=false;
    message("All local edits for the selected original agenda reset; source unchanged.");
    view();
  });
  async function restore(file) {
    if (!file || file.size<1 || file.size>262144) throw Error("private proposal size");
    const doc=JSON.parse(await file.text());
    const src=source();
    if (!doc || Array.isArray(doc) || keys(doc)!==packetKeys ||
        doc.schema!=="lightup.assessment_portfolio_human_proposal.v1" ||
        doc.source_agenda_sha256!==src.source_sha256 ||
        doc.reference_date!==input.reference_date ||
        !Number.isInteger(doc.source_count) || doc.source_count!==src.rows.length ||
        !Array.isArray(doc.items) || doc.items.length!==src.rows.length ||
        doc.authorized!==false || doc.consent_verified!==false ||
        doc.dispatch_allowed!==false || doc.release_allowed!==false) {
      throw Error("incompatible private human proposal");
    }
    const replacement=[];
    for (let n=0;n<src.rows.length;n++) {
      const old=originalItem(src.rows[n]);
      const row=doc.items[n];
      if (!row || Array.isArray(row) || keys(row)!==itemKeys ||
          !Number.isInteger(row.slot) || row.slot!==old.slot ||
          row.prior_stage!==old.prior_stage ||
          row.prior_next_role!==old.prior_next_role ||
          row.prior_review_date!==old.prior_review_date ||
          !stageChoices.includes(row.stage) || !roles.includes(row.next_role) ||
          dateValue(row.review_date)===false) {
        throw Error("proposal changes original identity or prior human record");
      }
      replacement.push({...old,
        stage:row.stage,next_role:row.next_role,review_date:dateValue(row.review_date)});
    }
    // Atomic local import. Never modify the previous workspace on error.
    state.set(src.slot,replacement);
    selected.clear();
    get("confirm").checked=false;
    message("Original-bound human proposal resumed locally; original choices remain unchanged.");
    view();
  }
  get("restore").addEventListener("change",async()=>{
    const file=get("restore").files[0];
    try { await restore(file); }
    catch(e) { message("HOLD: private proposal does not match original source/prior human values."); }
    finally { get("restore").value=""; }
  });
  get("download").addEventListener("click",()=>{
    const src=source(),items=currentRows(src);
    if (!get("confirm").checked) {
      message("Confirm PRIVATE human-only scope before creating proposal.");
      return;
    }
    if (items.some(row=>dateValue(row.review_date)===false)) {
      message("HOLD: invalid date. No proposal exported.");return;
    }
    const payload={
      schema:"lightup.assessment_portfolio_human_proposal.v1",
      source_agenda_sha256:src.source_sha256,
      reference_date:input.reference_date,
      source_count:items.length,
      items:items.map(row=>({
        slot:row.slot,prior_stage:row.prior_stage,
        prior_next_role:row.prior_next_role,prior_review_date:row.prior_review_date,
        stage:row.stage,next_role:row.next_role,review_date:row.review_date
      })),
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false
    };
    const blob=new Blob([JSON.stringify(payload,null,2)+"\n"],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const a=node("a",document.body);
    a.href=url;a.download="lightup-PRIVATE-human-proposal-agenda-"+src.slot+".json";
    a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),0);
    get("confirm").checked=false;
    message("Private human-only proposal downloaded. Explicit original-schema receive is mandatory.");
  });
  // A single explicitly confirmed human-only proposal bundle for all original agendas.
  get("downloadAll").addEventListener("click",()=>{
    if (!get("confirmAll").checked) {
      message("Confirm private human-only proposals for ALL original agendas first.");
      return;
    }
    try {
      const sources=input.sources.map(src=>{
        const items=currentRows(src);
        if (items.some(item=>dateValue(item.review_date)===false)) {
          throw Error("invalid original human proposed date");
        }
        const proposal={
          schema:"lightup.assessment_portfolio_human_proposal.v1",
          source_agenda_sha256:src.source_sha256,
          reference_date:input.reference_date,
          source_count:items.length,
          items:items.map(item=>({
            slot:item.slot,prior_stage:item.prior_stage,
            prior_next_role:item.prior_next_role,
            prior_review_date:item.prior_review_date,
            stage:item.stage,next_role:item.next_role,
            review_date:item.review_date
          })),
          authorized:false,consent_verified:false,
          dispatch_allowed:false,release_allowed:false
        };
        return {slot:src.slot,source_agenda_sha256:src.source_sha256,proposal};
      });
      const document={
        schema:"lightup.assessment_portfolio_human_proposal_bundle.v1",
        reference_date:input.reference_date,
        source_count:sources.length,sources,
        planning_not_permission:true,
        authorized:false,consent_verified:false,
        dispatch_allowed:false,release_allowed:false
      };
      const content=JSON.stringify(document,null,2)+"\n";
      if (new TextEncoder().encode(content).length>4194304) {
        throw Error("private proposal bundle size exceeded");
      }
      const blob=new Blob([content],{type:"application/json"});
      const url=URL.createObjectURL(blob);
      const link=node("a",document.body);
      link.href=url;link.download="lightup-PRIVATE-all-human-proposals.json";
      link.click();link.remove();
      setTimeout(()=>URL.revokeObjectURL(url),0);
      get("confirmAll").checked=false;
      message("All private original human proposals downloaded. No source was changed.");
    } catch(e) {
      message("HOLD: invalid proposal in at least one agenda. Nothing exported.");
    }
  });
  view();
})();
