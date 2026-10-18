"use strict";
/* Offline HUMAN follow-up only: no fetch, storage, consent, grants or execution. */
(() => {
  const source = document.getElementById("source");
  const status = document.getElementById("status");
  const fail = msg => { status.textContent = "HOLD: " + msg; status.setAttribute("data-hold", "true"); };
  const meta = JSON.parse(source.textContent);
  source.textContent = "";
  const cards = [...document.querySelectorAll("article.task")];
  const fields = ["owner", "due", "stage", "next"];
  const stages = new Set([
    "unassigned", "investigating", "waiting_on_client", "waiting_on_operator",
    "needs_source_review", "human_followup_complete"
  ]);
  const exactKeys = (v, ks) => v !== null && typeof v === "object" &&
    !Array.isArray(v) && Object.keys(v).length === ks.length &&
    ks.every(k => Object.prototype.hasOwnProperty.call(v, k));
  const textOk = (s, limit) => typeof s === "string" && s.length <= limit &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(s);
  const dayOk = s => s === "" || (
    /^\d{4}-\d{2}-\d{2}$/.test(s) &&
    !Number.isNaN(Date.parse(s + "T00:00:00Z")) &&
    new Date(s + "T00:00:00Z").toISOString().slice(0, 10) === s
  );
  if (!Array.isArray(meta.tasks) || meta.tasks.length !== cards.length ||
      cards.some((card, i) => meta.tasks[i].key !== card.dataset.key ||
        meta.tasks[i].tier !== card.dataset.tier) ||
      new Set(meta.tasks.map(t => t.key)).size !== meta.tasks.length) {
    fail("inconsistent embedded source");
    return;
  }
  const entry = card => Object.fromEntries(fields.map(field =>
    [field, card.querySelector('[data-field="' + field + '"]').value]));
  const all = () => cards.map((card, i) => ({
    key: meta.tasks[i].key,
    tier: meta.tasks[i].tier,
    attention: meta.tasks[i].attention,
    human: entry(card)
  }));
  const validateHuman = h => exactKeys(h, fields) &&
    textOk(h.owner, 80) && textOk(h.next, 500) &&
    stages.has(h.stage) && dayOk(h.due);
  const validateAll = rows => rows.every(row => validateHuman(row.human));
  let touched = false;
  cards.forEach(card => card.addEventListener("input", () => {
    touched = true;
    status.textContent = "Local human edits only — export PRIVATE handoff to preserve them.";
  }));
  cards.forEach(card => card.addEventListener("change", () => {
    touched = true;
    status.textContent = "Local human edits only — export PRIVATE handoff to preserve them.";
  }));
  function download(name, object) {
    const blob = new Blob([JSON.stringify(object)], {type:"application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function refreshWorkload() {
    const assigned = new Map();
    let unfinished = 0;
    let selected = 0;
    for (const card of cards) {
      if (card.querySelector('[data-pick="1"]').checked) selected++;
      const h = entry(card);
      if (h.owner.trim()) assigned.set(h.owner.trim(), (assigned.get(h.owner.trim()) || 0) + 1);
      if (h.stage !== "human_followup_complete") unfinished++;
    }
    const top = [...assigned].sort((a,b) => b[1] - a[1]).slice(0,12);
    const other = Math.max(0, assigned.size - top.length);
    document.getElementById("workload").textContent =
      selected + " selected · " + unfinished + " human follow-ups not marked complete · " +
      (top.length ? top.map(([k,v]) => k + ": " + v).join(" | ") : "No self-declared reviewers yet") +
      (other ? " | " + other + " additional reviewer labels" : "") +
      ". Reviewer labels are self-declared, not authenticated.";
  }
  cards.forEach(card => {
    card.addEventListener("input", refreshWorkload);
    card.addEventListener("change", refreshWorkload);
  });
  document.getElementById("selectVisible").addEventListener("click", () => {
    cards.filter(card => !card.hidden).forEach(card => {
      card.querySelector('[data-pick="1"]').checked = true;
    });
    refreshWorkload();
  });
  document.getElementById("clearSelected").addEventListener("click", () => {
    cards.forEach(card => { card.querySelector('[data-pick="1"]').checked = false; });
    refreshWorkload();
  });
  document.getElementById("applyBulk").addEventListener("click", () => {
    const selected = cards.filter(c => c.querySelector('[data-pick="1"]').checked);
    const owner = document.getElementById("bulkOwner").value.trim();
    const stage = document.getElementById("bulkStage").value;
    const due = document.getElementById("bulkDue").value;
    const preserve = document.getElementById("skipExisting").checked;
    if (!selected.length) { fail("select at least one human review card"); return; }
    if (!textOk(owner,80) || !dayOk(due) || (stage && !stages.has(stage)) ||
        (!owner && !due && !stage)) { fail("select valid HUMAN follow-up changes"); return; }
    const candidates = selected.filter(card => {
      if (!preserve) return true;
      const h = entry(card);
      return !h.owner && !h.due && h.stage === "unassigned" && !h.next;
    });
    if (!candidates.length) { fail("no unedited selected cards (preservation is enabled)"); return; }
    if (!window.confirm("Apply HUMAN-only reviewer / stage / tentative date to " +
        candidates.length + " selected local record(s)? This cannot approve, grant, " +
        "revoke or execute anything.")) return;
    candidates.forEach(card => {
      if (owner) card.querySelector('[data-field="owner"]').value = owner;
      if (due) card.querySelector('[data-field="due"]').value = due;
      if (stage) card.querySelector('[data-field="stage"]').value = stage;
    });
    touched = true;
    refreshWorkload();
    status.textContent = candidates.length + " HUMAN-only changes applied locally. PRIVATE export required.";
  });
  function refresh() {
    const tier = document.getElementById("filter").value;
    const phrase = document.getElementById("search").value.toLocaleLowerCase();
    let visible = 0;
    cards.forEach(card => {
      const show = (tier === "ALL" || card.dataset.tier === tier) &&
        card.dataset.key.toLocaleLowerCase().includes(phrase);
      card.hidden = !show;
      if (show) visible++;
    });
    status.textContent = visible + " human review item(s) shown. No execution authority.";
  }
  document.getElementById("filter").addEventListener("change", refresh);
  document.getElementById("search").addEventListener("input", refresh);
  document.getElementById("private").addEventListener("click", () => {
    const rows = all();
    if (!validateAll(rows)) { fail("invalid human field or UTC date"); return; }
    if (!window.confirm("PRIVATE EXPORT includes original tenant, IDs and human notes. " +
        "Recipient identity and permission must be checked independently. Continue?")) return;
    download("PRIVATE-scope-escalation-review.json", {
      schema:"lightup.scope_escalation_review.v1",
      status:"REVIEW_ONLY", authority:false,
      source_sha256:meta.sha256, source_as_of:meta.as_of,
      client_id:meta.client_id,
      source_authenticated:false, client_consent_verified:false,
      operator_consent_verified:false, authorization_granted:false,
      execution_allowed:false, release_approved:false,
      rows
    });
    touched = false;
    status.textContent = "PRIVATE human handoff saved locally, NOT a grant or consent.";
  });
  document.getElementById("anon").addEventListener("click", () => {
    const rows = all();
    if (!validateAll(rows)) { fail("invalid human follow-up fields"); return; }
    const tiers = {HOLD:0, PENDING:0, REVIEW:0};
    const humanStages = Object.fromEntries([...stages].sort().map(x=>[x,0]));
    rows.forEach(r => { tiers[r.tier]++; humanStages[r.human.stage]++; });
    download("scope-escalation-counts.json", {
      schema:"lightup.scope_escalation_aggregate.v1",
      status:"REVIEW_ONLY", authority:false,
      human_followups:rows.length, tier_counts:tiers,
      human_stage_counts:humanStages
    });
    status.textContent = "ID-free aggregate exported. It cannot approve or release anything.";
  });
  document.getElementById("restore").addEventListener("click", () =>
    document.getElementById("restoreFile").click());
  document.getElementById("restoreFile").addEventListener("change", async event => {
    const file = event.target.files[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 262144 || file.size < 2) {
      fail("private handoff exceeds bounded import size"); return;
    }
    try {
      const raw = new TextDecoder("utf-8", {fatal:true}).decode(await file.arrayBuffer());
      if (raw.charCodeAt(0) === 0xfeff) throw Error("UTF-8 BOM refused");
      const obj = JSON.parse(raw);
      // Accept only byte-for-byte canonical JSON.stringify output from this desk.
      // This also refuses duplicate object keys, unknown whitespace/re-ordered source.
      if (raw !== JSON.stringify(obj)) throw Error("noncanonical or duplicate JSON members");
      const keys = ["schema","status","authority","source_sha256","source_as_of",
        "client_id","source_authenticated","client_consent_verified",
        "operator_consent_verified","authorization_granted","execution_allowed",
        "release_approved","rows"];
      if (!exactKeys(obj, keys) ||
          obj.schema !== "lightup.scope_escalation_review.v1" ||
          obj.status !== "REVIEW_ONLY" || obj.authority !== false ||
          obj.source_sha256 !== meta.sha256 || obj.source_as_of !== meta.as_of ||
          obj.client_id !== meta.client_id ||
          keys.slice(6,12).some(k => obj[k] !== false) ||
          !Array.isArray(obj.rows) || obj.rows.length !== cards.length) {
        throw Error("wrong original source revision or authority claim");
      }
      for (let i=0; i<cards.length; i++) {
        const row = obj.rows[i];
        if (!exactKeys(row, ["key","tier","attention","human"]) ||
            row.key !== meta.tasks[i].key ||
            row.tier !== meta.tasks[i].tier ||
            row.attention !== meta.tasks[i].attention ||
            !validateHuman(row.human)) {
          throw Error("stale, incomplete or invalid human note membership");
        }
      }
      if (touched && !window.confirm("Replace current UNSAVED local edits with this " +
          "exact original revision-bound PRIVATE return?")) return;
      // Apply only after complete atomic admission; original Casebook never changes.
      cards.forEach((card, i) => fields.forEach(field => {
        card.querySelector('[data-field="' + field + '"]').value =
          obj.rows[i].human[field];
      }));
      touched = false;
      refreshWorkload();
      status.textContent = "Exact-source human notes restored. Not client consent or authorization.";
    } catch (_) {
      fail("private handoff refused; current human notes preserved");
    }
  });
  refresh();
  refreshWorkload();
})();
