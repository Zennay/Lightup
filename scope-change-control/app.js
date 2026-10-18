/* LightUp Casebook Change Control — entirely offline advisory tool.
   Original source files are never changed. No identity/consent/permission inference. */
"use strict";
(function () {
  const EXPECTED = "lightup.auth_casebook.v1";
  const LIMIT = 524288;
  const CATEGORIES = [
    ["requests", "request_id", 200],
    ["engagements", "engagement_id", 200],
    ["grants", "grant_id", 200],
    ["risk_approvals", "approval_id", 200],
    ["case_overview", "engagement_id", 200]
  ];
  const FLAGS = [
    "source_authenticated", "client_consent_verified", "operator_consent_verified",
    "authorization_granted", "execution_allowed", "release_approved"
  ];
  const STAGES = ["unreviewed", "owner-follow-up", "source-recheck", "human-acknowledged"];
  const $ = id => document.getElementById(id);
  const text = (id, value) => { $(id).textContent = String(value); };
  const state = { snapshots: [], changes: [], sha: [], notes: new Map(), details: new Map(), editKey: null };
  function hold(message) { throw Error(message); }
  function isObject(x) { return x !== null && typeof x === "object" && !Array.isArray(x); }
  function literal(x, n) {
    return typeof x === "string" && x.length > 0 && x.length <= n &&
      x === x.trim() && !/[\u0000-\u001f\u007f]/.test(x);
  }
  function nonnegative(x, n) { return Number.isSafeInteger(x) && x >= 0 && x <= n; }
  function exactIso(s) {
    if (typeof s !== "string" || s.length > 80 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(s)) hold("Snapshot time missing timezone");
    const value = Date.parse(s);
    if (!Number.isFinite(value)) hold("Snapshot timestamp invalid");
    return value;
  }
  function canonical(x) {
    if (Array.isArray(x)) return "[" + x.map(canonical).join(",") + "]";
    if (isObject(x)) return "{" + Object.keys(x).sort().map(k => JSON.stringify(k) + ":" + canonical(x[k])).join(",") + "}";
    return JSON.stringify(x);
  }
  // Exact recursive JSON decoder, unlike JSON.parse it refuses duplicate object keys.
  function strictJSON(source) {
    let i = 0, tokens = 0;
    const ws = () => { while (i < source.length && /\s/.test(source[i])) i++; };
    function string() {
      const start = i++;
      while (i < source.length) {
        let ch = source[i++];
        if (ch === '"') return JSON.parse(source.slice(start, i));
        if (ch === "\\") {
          if (i >= source.length) hold("Truncated JSON escape");
          let esc = source[i++];
          if (esc === "u") {
            if (!/^[0-9a-fA-F]{4}$/.test(source.slice(i, i + 4))) hold("Bad Unicode escape");
            i += 4;
          } else if (!'"\\/bfnrt'.includes(esc)) hold("Unknown JSON escape");
        } else if (ch.charCodeAt(0) < 32) hold("Unescaped JSON control");
      }
      hold("Unterminated JSON string");
    }
    function value(depth) {
      if (++tokens > 100000 || depth > 25) hold("Overlarge nested JSON");
      ws();
      const ch = source[i];
      if (ch === '"') return string();
      if (ch === "{") {
        i++; ws();
        const obj = Object.create(null);
        if (source[i] === "}") { i++; return obj; }
        while (true) {
          ws(); if (source[i] !== '"') hold("JSON object key required");
          const k = string(); ws();
          if (Object.hasOwn(obj, k)) hold("Duplicate JSON key");
          if (source[i++] !== ":") hold("JSON colon required");
          obj[k] = value(depth + 1); ws();
          const close = source[i++];
          if (close === "}") return obj;
          if (close !== ",") hold("JSON object comma required");
        }
      }
      if (ch === "[") {
        i++; ws();
        const arr = [];
        if (source[i] === "]") { i++; return arr; }
        while (true) {
          arr.push(value(depth + 1)); ws();
          const close = source[i++];
          if (close === "]") return arr;
          if (close !== ",") hold("JSON array comma required");
        }
      }
      const tail = source.slice(i);
      const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(tail);
      if (!m) hold("Malformed JSON scalar");
      i += m[0].length;
      const parsed = JSON.parse(m[0]);
      if (typeof parsed === "number" && !Number.isFinite(parsed)) hold("Nonfinite JSON number");
      return parsed;
    }
    const result = value(0);
    ws();
    if (i !== source.length) hold("Trailing JSON content");
    return result;
  }
  function rowsFor(doc, category, idField, max) {
    const data = doc[category];
    if (!Array.isArray(data) || data.length > max) hold("Invalid or excessive " + category);
    const seen = new Set();
    for (const row of data) {
      if (!isObject(row) || !literal(row[idField], 180) || seen.has(row[idField])) hold("Duplicate/invalid " + category + " identity");
      seen.add(row[idField]);
    }
    return data;
  }
  function admit(doc) {
    if (!isObject(doc) || doc.schema !== EXPECTED || doc.status !== "REVIEW_ONLY" ||
      doc.source !== "original_persisted_domain_unverified" || !literal(doc.client_id, 180))
      hold("Not an original held Casebook source");
    FLAGS.forEach(k => { if (doc[k] !== false) hold("Unauthorized source assertion: " + k); });
    const when = exactIso(doc.as_of);
    if (!isObject(doc.declared_counts)) hold("Missing original count declarations");
    const maps = Object.create(null);
    for (const [cat, id, cap] of CATEGORIES) {
      const rows = rowsFor(doc, cat, id, cap);
      maps[cat] = new Map(rows.map(row => [row[id], row]));
      if (cat !== "case_overview" && doc.declared_counts[cat] !== rows.length) hold("Original count mismatch " + cat);
    }
    if (maps.engagements.size !== maps.case_overview.size) hold("Casebook engagement coverage mismatch");
    for (const [id, entry] of maps.case_overview) {
      if (!maps.engagements.has(id) || !literal(entry.status, 80) ||
        !literal(entry.attention, 180) || !literal(entry.next_review_action, 180) ||
        !nonnegative(entry.grant_count, 200) || !nonnegative(entry.risk_record_count, 200) ||
        entry.status !== maps.engagements.get(id).status)
        hold("Original case row inconsistent");
      const count = [...maps.grants.values()].filter(g => g.engagement_id === id).length;
      const risk = [...maps.risk_approvals.values()].filter(r => r.engagement_id === id).length;
      if (count !== entry.grant_count || risk !== entry.risk_record_count) hold("Casebook lineage counts disagree");
    }
    for (const g of maps.grants.values()) {
      if (g.engagement_id !== null && !maps.engagements.has(g.engagement_id)) hold("Unknown grant engagement");
      if (!literal(g.request_link_observation, 180) || !literal(g.validity_observation, 180) ||
        !nonnegative(g.max_risk, 5)) hold("Unrecognized recorded grant");
      if (g.approved_request_id !== null && !literal(g.approved_request_id, 180)) hold("Bad grant request link");
    }
    for (const r of maps.risk_approvals.values()) {
      if (r.engagement_id !== null && !maps.engagements.has(r.engagement_id)) hold("Unknown risk engagement");
      if (typeof r.source_tenant_matches !== "boolean" ||
          !literal(r.decision_provenance_observation, 180)) hold("Bad risk lineage observation");
    }
    for (const r of maps.requests.values()) {
      if (!["submitted", "under_review", "approved", "rejected"].includes(r.status) ||
        !nonnegative(r.requested_risk, 5) || typeof r.decision_recorded !== "boolean") hold("Bad request record");
    }
    for (const n of ["foreign_tenant_row_count","case_attention_hold","grant_link_hold","pending_risk_review"]) {
      if (!nonnegative(doc.declared_counts[n], 1000)) hold("Original aggregate missing " + n);
    }
    if (doc.declared_counts.case_attention_hold !== [...maps.case_overview.values()].filter(x => x.attention.startsWith("HOLD_")).length) hold("Case HOLD count mismatch");
    if (doc.declared_counts.grant_link_hold !== [...maps.grants.values()].filter(x => x.request_link_observation.startsWith("HOLD_")).length) hold("Grant HOLD count mismatch");
    return {doc, maps, when};
  }
  function changed(before, after) {
    const output = [];
    for (const [category] of CATEGORIES) {
      const a = before.maps[category], b = after.maps[category];
      const ids = [...new Set([...a.keys(), ...b.keys()])].sort();
      for (const id of ids) {
        const old = a.get(id), newer = b.get(id);
        if (old && newer && canonical(old) === canonical(newer)) continue;
        const kind = !old ? "added" : !newer ? "missing-source" : "changed";
        let priority = kind === "missing-source" ? "urgent" : "review";
        if (category === "grants" || category === "case_overview") priority = "urgent";
        if ([old,newer].some(row => row && (row.status === "approved" || Object.values(row).some(x => typeof x === "string" && x.startsWith("HOLD_"))))) priority = "urgent";
        const fieldNames = old && newer ? [...new Set([...Object.keys(old), ...Object.keys(newer)])]
          .filter(k => canonical(old[k]) !== canonical(newer[k])).sort() : [];
        output.push({category, id, kind, priority, fieldNames, before: old || null, after: newer || null});
      }
    }
    return output;
  }
  const td = (tr, val) => { const cell = document.createElement("td"); cell.textContent = String(val); tr.appendChild(cell); return cell; };

  function field(value,max,label) {
    if (typeof value!=="string" || value.length>max || /[\u0000-\u001f\u007f]/.test(value))
      hold("Invalid human-only "+label);
    return value;
  }
  function humanDetails(value) {
    if (!isObject(value)) hold("Human-only private case notes must be an object");
    const reviewer=field(value.reviewer,80,"reviewer alias");
    const action=field(value.next_action,240,"next action");
    const note=field(value.note,1200,"human note");
    const due=field(value.due_utc,24,"human due date");
    if (due!=="" && (!/^\d{4}-\d\d-\d\d$/.test(due) || !Number.isFinite(Date.parse(due+"T00:00:00Z"))))
      hold("Invalid optional UTC human due date");
    return {reviewer,next_action:action,note,due_utc:due};
  }
  function editHuman(key) {
    if (state.snapshots.length!==2 || !state.changes.some(c=>c.category+":"+c.id===key)) return;
    state.editKey=key;
    const entry=state.details.get(key)||{reviewer:"",next_action:"",note:"",due_utc:""};
    text("detailIdentity",key);
    $("reviewerAlias").value=entry.reviewer;
    $("nextHumanAction").value=entry.next_action;
    $("humanNote").value=entry.note;
    $("humanDue").value=entry.due_utc;
    $("humanDialog").showModal();
  }
  function saveHumanDetail() {
    if (!state.editKey || !state.changes.some(c=>c.category+":"+c.id===state.editKey))
      return;
    try {
      const item=humanDetails({
        reviewer:$("reviewerAlias").value,
        next_action:$("nextHumanAction").value,
        note:$("humanNote").value,
        due_utc:$("humanDue").value,
      });
      state.details.set(state.editKey,item);
      state.editKey=null;
      $("humanDialog").close();
      render();
    } catch(e) { text("dialogError","HOLD: "+e.message); }
  }

  function observedSignals(record) {
    if (!record) return "not recorded in selected source";
    const labels = ["status", "attention", "request_link_observation", "validity_observation", "decision_provenance_observation"];
    const visible = labels.filter(k => typeof record[k] === "string").map(k => k + ": " + record[k]);
    return visible.join(" · ") || "original record present (no status assertion)";
  }
  function impactEngagements() {
    if (state.snapshots.length !== 2) return;
    const older=state.snapshots[0].maps, newer=state.snapshots[1].maps;
    const known=new Set([...older.engagements.keys(),...newer.engagements.keys()]);
    const byEngagement=new Map();
    for(const change of state.changes) {
      let ids=[];
      if(change.category==="engagements" || change.category==="case_overview"){
        ids=[change.id];
      } else if(change.category==="grants" || change.category==="risk_approvals") {
        // Link only from actual original source engagement identities.
        // A request has no engagement identity here; never infer one.
        ids=[change.before?.engagement_id,change.after?.engagement_id]
          .filter(x=>typeof x==="string" && known.has(x));
      }
      for(const id of new Set(ids)){
        if(!byEngagement.has(id)) byEngagement.set(id,[]);
        byEngagement.get(id).push(change);
      }
    }
    const rows=[...byEngagement].map(([id,changes])=>({
      id,changes, urgent:changes.filter(c=>c.priority==="urgent").length,
      before:older.case_overview.get(id), after:newer.case_overview.get(id),
      category:[...new Set(changes.map(c=>c.category))].sort().join(", "),
      humanOutstanding:changes.filter(c=>(state.notes.get(c.category+":"+c.id)||"unreviewed")!=="human-acknowledged").length,
    })).sort((a,b)=>b.urgent-a.urgent || a.id.localeCompare(b.id));
    const body=$("impactRows");
    body.replaceChildren();
    for(const impact of rows){
      const tr=document.createElement("tr");
      td(tr,impact.id);
      td(tr,impact.before ? impact.before.attention : "not recorded");
      td(tr,impact.after ? impact.after.attention : "not recorded");
      td(tr,impact.category);
      td(tr,impact.changes.length);
      td(tr,impact.urgent);
      td(tr,impact.humanOutstanding);
      body.appendChild(tr);
    }
    const tenantRequestChanges=state.changes.filter(c=>c.category==="requests").length;
    const uncertainLinks=state.changes.filter(c=>
      (c.category==="grants" || c.category==="risk_approvals") &&
      [c.before,c.after].some(x=>x && !known.has(x.engagement_id))).length;
    text("impactSummary",rows.length+" recorded engagements affected; "+
      tenantRequestChanges+" tenant-level request changes (not falsely linked to an engagement); "+
      uncertainLinks+" unassigned/malformed recorded grant or risk links requiring separate source review.");
  }
  function render() {
    const tbody = $("changes");
    tbody.replaceChildren();
    const filtered = state.changes.filter(x => $("kind").value === "all" || x.priority === $("kind").value);
    for (const c of filtered) {
      const tr = document.createElement("tr");
      td(tr,c.priority.toUpperCase());
      td(tr,c.category);
      td(tr,c.kind);
      td(tr,c.id);
      td(tr,c.fieldNames.join(", ") || "membership changed");
      td(tr,observedSignals(c.before) + "  →  " + observedSignals(c.after));
      const container = document.createElement("td");
      const select = document.createElement("select");
      select.setAttribute("aria-label","Human follow-up for " + c.category + " " + c.id);
      for (const option of STAGES) { const el = document.createElement("option"); el.value=option; el.textContent=option; select.appendChild(el); }
      const key = c.category + ":" + c.id;
      select.value = state.notes.get(key) || "unreviewed";
      select.addEventListener("change",() => {state.notes.set(key,select.value); impactEngagements();});
      container.appendChild(select); tr.appendChild(container);
      const humanCell=document.createElement("td");
      const open=document.createElement("button");
      open.type="button";open.className="outline compact";
      open.textContent=state.details.has(key)?"Edit local notes":"Add follow-up";
      open.addEventListener("click",()=>editHuman(key));
      humanCell.appendChild(open);tr.appendChild(humanCell);
      tbody.appendChild(tr);
    }
    const urgent = state.changes.filter(x=>x.priority==="urgent").length;
    text("summary",state.changes.length + " changed source records / " + urgent +
      " urgent human reviews. Missing rows never imply withdrawal, repair or revocation.");
    text("tenant",state.snapshots[0].doc.client_id);
    text("provenance","Old " + state.snapshots[0].doc.as_of + " · SHA-256 " + state.sha[0] +
      " | New " + state.snapshots[1].doc.as_of + " · SHA-256 " + state.sha[1]);
    impactEngagements();
    $("results").hidden = false;
  }
  async function readSnapshot(file) {
    if (!file || file.size < 2 || file.size > LIMIT) hold("Original source file is missing or >512 KiB");
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let source;
    try { source = new TextDecoder("utf-8",{fatal:true}).decode(bytes); }
    catch(_) { hold("Source is not UTF-8"); }
    const parsed = admit(strictJSON(source));
    if (!window.crypto || !crypto.subtle) hold("Local secure-context SHA-256 is required; no unsigned handoff");
    const digest = await crypto.subtle.digest("SHA-256",buffer);
    const sha = [...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,"0")).join("");
    return {parsed,sha};
  }
  async function load() {
    text("error","");
    $("results").hidden = true;
    state.snapshots=[];state.changes=[];state.sha=[];state.notes.clear();state.details.clear();state.editKey=null;
    try {
      const files = [$("older").files[0],$("newer").files[0]];
      if (!files[0] || !files[1]) hold("Select two private original Casebook JSON exports");
      const a = await readSnapshot(files[0]);
      const b = await readSnapshot(files[1]);
      if (a.parsed.doc.client_id !== b.parsed.doc.client_id) hold("Different original tenants: refuse comparison");
      if (!(a.parsed.when < b.parsed.when)) hold("Select two strictly ordered historical source timestamps");
      if (a.sha === b.sha) hold("Same source bytes: no historical comparison");
      state.snapshots = [a.parsed,b.parsed];state.sha=[a.sha,b.sha];
      state.changes = changed(a.parsed,b.parsed);
      render();
    } catch (e) {
      state.snapshots=[];state.changes=[];state.sha=[];state.notes.clear();
      text("error","HOLD: " + (e && e.message ? e.message : "invalid source"));
    }
  }
  function save(blob,name) {
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download=name;a.click();
    setTimeout(()=>URL.revokeObjectURL(url),5000);
  }
  function exportSummary() {
    if (state.snapshots.length !== 2) return;
    const groups = Object.create(null);
    for (const c of state.changes) {
      const key=c.category+"/"+c.kind+"/"+c.priority;
      groups[key]=(groups[key]||0)+1;
    }
    const data={
      schema:"lightup.casebook_change_aggregate.v1",disposition:"HOLD_HUMAN_REVIEW",
      original_source_verified:false,client_consent_verified:false,operator_consent_verified:false,
      authorization_granted:false,execution_allowed:false,release_approved:false,
      action_time_revocation_verified:false,snapshot_count:2,
      changed_record_count:state.changes.length,
      urgent_review_count:state.changes.filter(c=>c.priority==="urgent").length,
      human_stage_counts:Object.fromEntries(STAGES.map(s=>[s,state.changes.filter(c=>(state.notes.get(c.category+":"+c.id)||"unreviewed")===s).length])),
      categories:groups
    };
    save(new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"}),"lightup-casebook-change-aggregate.json");
  }
  function exportPrivate() {
    if (state.snapshots.length !== 2) return;
    if (!$("confirm").checked) {
      text("error","HOLD: personally confirm the authorized private recipient before exporting IDs");
      return;
    }
    const data={
      schema:"lightup.casebook_change_private_review.v1",
      disposition:"HOLD_HUMAN_REVIEW",original_source_verified:false,
      client_consent_verified:false,operator_consent_verified:false,
      authorization_granted:false,execution_allowed:false,release_approved:false,
      action_time_revocation_verified:false,
      tenant_original_id:state.snapshots[0].doc.client_id,
      source_sha256_unsigned:state.sha,
      source_times:state.snapshots.map(x=>x.doc.as_of),
      changes:state.changes.map(c=>({
        category:c.category,original_id:c.id,change:c.kind,priority:c.priority,
        changed_source_fields:c.fieldNames,
        local_human_stage:state.notes.get(c.category+":"+c.id)||"unreviewed",
        human_review:state.details.get(c.category+":"+c.id)||{reviewer:"",next_action:"",note:"",due_utc:""}
      }))
    };
    save(new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"}),"lightup-casebook-change-PRIVATE.json");
    $("confirm").checked=false;
  }
  async function restorePrivateReview() {
    text("error","");
    try {
      if (state.snapshots.length !== 2) hold("Load both original snapshots before restoring human stages");
      const file=$("restore-file").files[0];
      if (!file || file.size < 2 || file.size > LIMIT) hold("Private review file missing or too large");
      const bytes=await file.arrayBuffer();
      let doc;
      try { doc=strictJSON(new TextDecoder("utf-8",{fatal:true}).decode(bytes)); }
      catch (_) { hold("Invalid UTF-8 or JSON in private handoff"); }
      if (!isObject(doc) || doc.schema !== "lightup.casebook_change_private_review.v1" ||
          doc.disposition !== "HOLD_HUMAN_REVIEW" ||
          doc.tenant_original_id !== state.snapshots[0].doc.client_id ||
          doc.original_source_verified !== false ||
          doc.action_time_revocation_verified !== false)
        hold("Private handoff is not an original-source-bound human review");
      for(const k of ["client_consent_verified","operator_consent_verified",
                       "authorization_granted","execution_allowed","release_approved"]) {
        if(doc[k] !== false) hold("Private handoff contains unauthorized claims");
      }
      if (!Array.isArray(doc.source_sha256_unsigned) || doc.source_sha256_unsigned.length !== 2 ||
          doc.source_sha256_unsigned.some((s,i)=>s!==state.sha[i]) ||
          !Array.isArray(doc.source_times) || doc.source_times.length !== 2 ||
          doc.source_times.some((t,i)=>t!==state.snapshots[i].doc.as_of))
        hold("Private handoff belongs to different original source bytes");
      if (!Array.isArray(doc.changes) || doc.changes.length !== state.changes.length)
        hold("Private handoff original change membership mismatch");
      const expected=new Map(state.changes.map(c=>[c.category+":"+c.id,c]));
      // The native authenticated CLI emits the same source-bound private schema
      // but a different (non-stage) change-row structure. Never trust its label:
      // convert only after exact source digests and actual original rows match.
      const native=isObject(doc.aggregate_without_original_ids);
      let rows=doc.changes;
      if (native) {
        const aggregate=doc.aggregate_without_original_ids;
        if (aggregate.snapshot_count!==2 ||
            aggregate.changed_record_count!==state.changes.length ||
            aggregate.urgent_review_count!==state.changes.filter(c=>c.priority==="urgent").length ||
            !isObject(aggregate.source_delta_counts))
          hold("Native source-review aggregate inconsistent");
        const counts=Object.create(null);
        rows=doc.changes.map(row=>{
          if(!isObject(row) || !CATEGORIES.some(a=>a[0]===row.family) ||
             !literal(row.original_id,180) || row.human_follow_up!=="UNREVIEWED")
            hold("Native source-review row not admitted");
          const kinds={NEW_SOURCE_ROW:"added",MISSING_FROM_NEW_SOURCE:"missing-source",
                       SOURCE_FIELDS_CHANGED:"changed"};
          if(!Object.hasOwn(kinds,row.change) ||
             !["URGENT_HUMAN_REVIEW","REVIEW_ONLY"].includes(row.priority))
            hold("Native source-review classification not admitted");
          const group=row.family+"/"+row.change+"/"+row.priority;
          counts[group]=(counts[group]||0)+1;
          return {
            category:row.family,original_id:row.original_id,
            change:kinds[row.change],
            priority:row.priority==="URGENT_HUMAN_REVIEW"?"urgent":"review",
            changed_source_fields:row.changed_fields_only,
            local_human_stage:"unreviewed"
          };
        });
        if (canonical(counts)!==canonical(aggregate.source_delta_counts))
          hold("Native source-review classification totals differ");
      }
      const stages=new Map();
      for(const row of rows){
        if(!isObject(row) || !literal(row.category,100) || !literal(row.original_id,180))
          hold("Private handoff original ID missing");
        const key=row.category+":"+row.original_id;
        const c=expected.get(key);
        if(!c || stages.has(key) ||
           row.change!==c.kind || row.priority!==c.priority ||
           !Array.isArray(row.changed_source_fields) ||
           canonical(row.changed_source_fields)!==canonical(c.fieldNames) ||
           !STAGES.includes(row.local_human_stage))
          hold("Private human return changes original source classification");
        stages.set(key,row.local_human_stage);
      }
      if(stages.size!==expected.size) hold("Private handoff incomplete");
      // Commit the entire restored review only after every source-bound record agrees.
      state.notes=stages;
      render();
      text("restore-status",native ? "Authenticated-CLI source review admitted; all original human stages start unreviewed. No permissions inferred." : "Private local human stages restored against exact original source bytes. No authorization changes.");
    } catch(e){
      text("error","HOLD: "+(e && e.message ? e.message : "private follow-up not admitted"));
      text("restore-status","");
    }
  }
  $("saveHuman").addEventListener("click",saveHumanDetail);
  $("humanDialog").addEventListener("close",()=>{state.editKey=null;text("dialogError","");});
  $("load").addEventListener("click",load);
  $("restore").addEventListener("click",restorePrivateReview);
  $("kind").addEventListener("change",()=>{if(state.snapshots.length)render();});
  $("aggregate").addEventListener("click",exportSummary);
  $("private").addEventListener("click",exportPrivate);
})();