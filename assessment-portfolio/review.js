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
  // Keep the complete portfolio attention board current after individual edits.
  const originalView=view;
  view=()=>{originalView();renderPortfolio();};
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
    const doc=LightUpStrictJSON.parse(await file.text(),262144);
    const src=source();
    const replacement=admitRestoredProposal(src,doc);
    state.set(src.slot,replacement);
    selected.clear();
    get("confirm").checked=false;get("confirmAll").checked=false;
    get("confirmRestoreAll").checked=false;
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
  const portfolioSelected=new Set();
  const crossId=(src,row)=>src.slot+":"+row.slot;
  function dayClass(date) {
    if (date===null) return "unscheduled";
    if (date<input.reference_date) return "past";
    if (date>input.reference_date) return "future";
    return "today";
  }
  for(const stage of stageChoices) {
    for(const id of ["pStage","pApplyStage"]) {
      const opt=node("option",get(id),stage);opt.value=stage;
    }
  }
  for(const role of roles) {
    for(const id of ["pRole","pApplyRole"]) {
      const opt=node("option",get(id),role);opt.value=role;
    }
  }
  function portfolioMatches(row) {
    return (!get("pStage").value || row.stage===get("pStage").value)
      && (!get("pRole").value || row.next_role===get("pRole").value)
      && (!get("pDateBucket").value || dayClass(row.review_date)===get("pDateBucket").value);
  }
  function allPortfolio() {
    const all=[];
    for(const src of input.sources) {
      for(const row of currentRows(src)) {
        const original=src.rows.find(item=>item.source_slot===row.slot);
        if (!original) throw Error("Missing source-local original human row");
        all.push({src,row,kind:original.source_kind});
      }
    }
    return all;
  }
  function renderPortfolio() {
    const all=allPortfolio();
    const filtered=all.filter(item=>portfolioMatches(item.row));
    get("pTotal").textContent=String(all.length);
    get("pVisible").textContent=String(filtered.length);
    get("pSelected").textContent=String(portfolioSelected.size);
    get("pModified").textContent=String(all.filter(item=>modified(item.row)).length);
    const rows=get("pRows");rows.replaceChildren();
    for(const {src,row,kind} of filtered) {
      const tr=node("tr",rows);
      if(modified(row)) tr.classList.add("changed");
      const checkbox=node("input",node("td",tr));
      checkbox.type="checkbox";
      checkbox.checked=portfolioSelected.has(crossId(src,row));
      checkbox.setAttribute("aria-label","Select human agenda "+src.slot+" slot "+row.slot);
      checkbox.addEventListener("change",()=>{
        if(checkbox.checked) portfolioSelected.add(crossId(src,row));
        else portfolioSelected.delete(crossId(src,row));
        get("pSelected").textContent=String(portfolioSelected.size);
      });
      for(const value of [src.slot,row.slot,kind,row.stage,row.next_role,
                           row.review_date || "—",src.claimed_status,
                           modified(row) ? "Locally edited" : "Original"]) {
        node("td",tr,value);
      }
    }
    if(!filtered.length){
      const tr=node("tr",rows);
      const cell=node("td",tr,"No original human items match these filters.");
      cell.colSpan=9;
    }
  }
  for(const id of ["pStage","pRole","pDateBucket"]) {
    get(id).addEventListener("change",()=>{
      portfolioSelected.clear();
      get("pConfirm").checked=false;
      renderPortfolio();
    });
  }
  get("pSelectVisible").addEventListener("click",()=>{
    portfolioSelected.clear();
    for(const item of allPortfolio()){
      if(portfolioMatches(item.row))portfolioSelected.add(crossId(item.src,item.row));
    }
    get("pConfirm").checked=false;
    message(portfolioSelected.size+" human-only slots selected across original agendas.");
    renderPortfolio();
  });
  get("pClear").addEventListener("click",()=>{
    portfolioSelected.clear();
    get("pConfirm").checked=false;
    message("Cross-agenda selection cleared; original sources unchanged.");
    renderPortfolio();
  });
  get("pApply").addEventListener("click",()=>{
    if(!portfolioSelected.size){
      message("Select visible original human slots before applying cross-agenda changes.");
      return;
    }
    if(!get("pConfirm").checked){
      message("Explicitly confirm human-only cross-agenda changes first.");
      return;
    }
    const stage=get("pApplyStage").value,role=get("pApplyRole").value;
    const day=get("pApplyDate").value,clear=get("pClearDate").checked;
    if((day&&clear)||(!stage&&!role&&!day&&!clear)){
      message("Choose a new human field; a date cannot be set and cleared simultaneously.");
      return;
    }
    const date=dateValue(day);
    if(date===false || (stage&&!stageChoices.includes(stage))
       ||(role&&!roles.includes(role))){
      message("HOLD: invalid original human stage, role or date. No changes applied.");
      return;
    }
    const all=allPortfolio();
    const targets=all.filter(item=>portfolioSelected.has(crossId(item.src,item.row)));
    if(targets.length!==portfolioSelected.size) {
      message("HOLD: stale cross-agenda human selection. No changes applied.");
      return;
    }
    // All admission checks finish before a single human-only in-memory mutation.
    for(const item of targets) {
      if(stage)item.row.stage=stage;
      if(role)item.row.next_role=role;
      if(day||clear)item.row.review_date=clear?null:date;
    }
    portfolioSelected.clear();selected.clear();
    get("pConfirm").checked=false;get("confirmAll").checked=false;
    get("confirm").checked=false;
    message(targets.length+" original human slots edited locally across agendas. Export a new PRIVATE all-agenda proposal bundle; original inputs remain unchanged.");
    view();
  });
  const bundleKeys=["schema","reference_date","source_count","sources",
                    "planning_not_permission","authorized","consent_verified",
                    "dispatch_allowed","release_allowed"].sort().join("|");
  const bundleSourceKeys=["slot","source_agenda_sha256","proposal"].sort().join("|");
  function admitRestoredProposal(src,doc) {
    if (!doc || Array.isArray(doc) || typeof doc!=="object" ||
        keys(doc)!==packetKeys ||
        doc.schema!=="lightup.assessment_portfolio_human_proposal.v1" ||
        doc.source_agenda_sha256!==src.source_sha256 ||
        doc.reference_date!==input.reference_date ||
        !Number.isInteger(doc.source_count) || doc.source_count!==src.rows.length ||
        !Array.isArray(doc.items) || doc.items.length!==src.rows.length ||
        doc.authorized!==false || doc.consent_verified!==false ||
        doc.dispatch_allowed!==false || doc.release_allowed!==false) {
      throw Error("complete bundle original source/proposal mismatch");
    }
    return doc.items.map((row,index)=>{
      const old=originalItem(src.rows[index]);
      if (!row || Array.isArray(row) || typeof row!=="object" ||
          keys(row)!==itemKeys || !Number.isInteger(row.slot) ||
          row.slot!==old.slot || row.prior_stage!==old.prior_stage ||
          row.prior_next_role!==old.prior_next_role ||
          row.prior_review_date!==old.prior_review_date ||
          !stageChoices.includes(row.stage) || !roles.includes(row.next_role) ||
          (row.review_date!==null && (typeof row.review_date!=="string" ||
             row.review_date==="" || dateValue(row.review_date)===false))) {
        throw Error("complete bundle changes original human prior source membership");
      }
      return {...old,stage:row.stage,next_role:row.next_role,
              review_date:row.review_date};
    });
  }
  async function restoreCompleteBundle(file) {
    if (!get("confirmRestoreAll").checked)
      throw Error("explicit private replacement acknowledgement required");
    if (!file || file.size<1 || file.size>4194304)
      throw Error("complete private bundle must be a regular bounded local file");
    const doc=LightUpStrictJSON.parse(await file.text(),4194304);
    if (!doc || Array.isArray(doc) || typeof doc!=="object" ||
        keys(doc)!==bundleKeys ||
        doc.schema!=="lightup.assessment_portfolio_human_proposal_bundle.v1" ||
        doc.reference_date!==input.reference_date ||
        !Number.isInteger(doc.source_count) ||
        doc.source_count!==input.sources.length ||
        !Array.isArray(doc.sources) ||
        doc.sources.length!==input.sources.length ||
        doc.planning_not_permission!==true ||
        doc.authorized!==false || doc.consent_verified!==false ||
        doc.dispatch_allowed!==false || doc.release_allowed!==false) {
      throw Error("complete private human bundle has invalid source metadata");
    }
    const next=new Map();
    for(let index=0; index<input.sources.length; index++){
      const src=input.sources[index], record=doc.sources[index];
      if (!record || Array.isArray(record) || typeof record!=="object" ||
          keys(record)!==bundleSourceKeys ||
          !Number.isInteger(record.slot) || record.slot!==src.slot ||
          record.source_agenda_sha256!==src.source_sha256) {
        throw Error("incomplete/ambiguous original human source sequence");
      }
      next.set(src.slot,admitRestoredProposal(src,record.proposal));
    }
    // Commit only after every original agenda and every prior human slot matches.
    state.clear();
    for(const [slot,rows] of next) state.set(slot,rows);
    selected.clear();portfolioSelected.clear();
    for(const id of ["confirm","confirmAll","confirmRestoreAll","pConfirm"])
      get(id).checked=false;
    const changed=allPortfolio().filter(item=>modified(item.row)).length;
    message("Restored "+doc.source_count+" private original agendas and "+
            changed+" locally edited human slots in one step. Nothing was written to original sources.");
    view();
  }
  get("restoreAll").addEventListener("change",async()=>{
    try {await restoreCompleteBundle(get("restoreAll").files[0]);}
    catch(e){message("HOLD: all-agenda private bundle does not match ALL original sources/prior human choices. No local draft was replaced.");}
    finally {get("restoreAll").value="";}
  });
  view();
})();
