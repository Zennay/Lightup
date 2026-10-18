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
  const state = { snapshots: [], changes: [], sha: [], notes: new Map() };
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
        if (newer && Object.values(newer).some(x => typeof x === "string" && (x.startsWith("HOLD_") || x === "STOP_ACTIVE"))) priority = "urgent";
        const fieldNames = old && newer ? [...new Set([...Object.keys(old), ...Object.keys(newer)])]
          .filter(k => canonical(old[k]) !== canonical(newer[k])).sort() : [];
        output.push({category, id, kind, priority, fieldNames, before: old || null, after: newer || null});
      }
    }
    return output;
  }
  const td = (tr, val) => { const cell = document.createElement("td"); cell.textContent = String(val); tr.appendChild(cell); return cell; };
  function observedSignals(record) {
    if (!record) return "not recorded in selected source";
    const labels = ["status", "attention", "request_link_observation", "validity_observation", "decision_provenance_observation"];
    const visible = labels.filter(k => typeof record[k] === "string").map(k => k + ": " + record[k]);
    return visible.join(" · ") || "original record present (no status assertion)";
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
      select.addEventListener("change",() => state.notes.set(key,select.value));
      container.appendChild(select); tr.appendChild(container); tbody.appendChild(tr);
    }
    const urgent = state.changes.filter(x=>x.priority==="urgent").length;
    text("summary",state.changes.length + " changed source records / " + urgent +
      " urgent human reviews. Missing rows never imply withdrawal, repair or revocation.");
    text("tenant",state.snapshots[0].doc.client_id);
    text("provenance","Old " + state.snapshots[0].doc.as_of + " · SHA-256 " + state.sha[0] +
      " | New " + state.snapshots[1].doc.as_of + " · SHA-256 " + state.sha[1]);
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
    state.snapshots=[];state.changes=[];state.sha=[];state.notes.clear();
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
        local_human_stage:state.notes.get(c.category+":"+c.id)||"unreviewed"
      }))
    };
    save(new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"}),"lightup-casebook-change-PRIVATE.json");
    $("confirm").checked=false;
  }
  $("load").addEventListener("click",load);
  $("kind").addEventListener("change",()=>{if(state.snapshots.length)render();});
  $("aggregate").addEventListener("click",exportSummary);
  $("private").addEventListener("click",exportPrivate);
})();