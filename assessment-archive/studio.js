"use strict";
// LightUp Archive Studio is deliberately browser-only. All decisions remain
// human planning drafts, and original Python admission is mandatory on import.
(() => {
  const raw = document.getElementById("archive-seed");
  const seed = JSON.parse(raw.textContent);
  raw.remove();
  const FLAGS = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
  const STAGES = ["PENDING_ORIGINAL", "NEEDS_ORIGINAL_EVIDENCE", "NEEDS_SOURCE_OWNER",
    "NEEDS_PRIVACY_REVIEW", "AWAITING_INPUT", "HUMAN_DISCUSSION"];
  const ROLES = ["unassigned", "source_owner", "reviewer", "privacy", "operator"];
  const GUIDANCE = {
    completed_lab_case_claim: "Review source-run facts with the original lab scenario and operator.",
    completed_lab_cohort_claim: "Reconcile original cohort membership against the pinned benchmark source.",
    offline_comparison_claim: "Discuss metric changes with the original comparator owner; don't infer fixes.",
    studio_catalog_draft: "Check original author-supplied ground truth and separate lab endpoint bindings.",
    other_lightup_draft: "Confirm original producer schema and privacy before any broader circulation.",
    private_review_zip_claim: "Use the original private Review Desk inspector and source owner."
  };
  if (seed.schema !== "lightup.archive_studio_seed.v1" ||
      seed.entries.length < 2 || seed.entries.length > 64 ||
      !/^[a-f0-9]{64}$/.test(seed.manifest_sha256) ||
      !["REVIEW_ONLY", "HOLD"].includes(seed.status)) {
    document.body.textContent = "LOCAL_ARCHIVE_HOLD"; return;
  }
  let choices = seed.entries.map(row => ({
    slot: row.slot, source_sha256: row.sha256, stage: "PENDING_ORIGINAL",
    next_role: "unassigned", review_date: null
  }));
  let batchBackup = null;
  const byId = id => document.getElementById(id);
  const invalidateUndo = () => {
    batchBackup = null;
    const undoButton = byId("bulk-undo");
    if (undoButton) undoButton.disabled = true;
  };
  const list = byId("cards");
  const status = byId("status");
  const query = byId("search");
  const typeFilter = byId("type-filter");
  const stageFilter = byId("stage-filter");
  const roleFilter = byId("role-filter");
  const historyFilter = byId("history-filter");
  const countFormat = n => new Intl.NumberFormat().format(n);
  const notify = message => { status.textContent = message; };
  const fresh = () => choices.map(x => ({...x}));
  const isValidDate = value => {
    if (value === null) return true;
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(value + "T00:00:00Z");
    return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value &&
      Number(value.slice(0, 4)) >= 2020 && Number(value.slice(0, 4)) <= 2100;
  };
  const make = (tag, cls, text) => {
    const element = document.createElement(tag);
    if (cls) element.className = cls;
    if (text !== undefined) element.textContent = String(text);
    return element;
  };
  const el = (tag, attrs = {}) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  };
  const optionSelect = (options, selected, callback, caption) => {
    const label = make("label", "", caption);
    const control = document.createElement("select");
    for (const text of options) {
      const option = document.createElement("option");
      option.value = text;
      option.textContent = text.replaceAll("_", " ").toLowerCase();
      option.selected = text === selected;
      control.append(option);
    }
    control.addEventListener("change", () => callback(control.value));
    label.append(control);
    return label;
  };
  const matches = (row, selection) => {
    const q = query.value.trim().toLowerCase();
    const terms = [String(row.slot), row.kind, row.review_state, row.sha256.slice(0, 16),
      selection.stage, selection.next_role].join(" ").toLowerCase();
    return (!q || terms.includes(q)) &&
      (!typeFilter.value || typeFilter.value === row.kind) &&
      (!stageFilter.value || stageFilter.value === selection.stage) &&
      (!roleFilter.value || roleFilter.value === selection.next_role) &&
      (!historyFilter.value || historyFilter.value === row.history);
  };
  const visibleEntries = () => seed.entries.filter((row, i) => matches(row, choices[i]));
  const entryItem = (row, selection) => {
    const article = make("article", "item");
    article.setAttribute("data-slot", String(row.slot));
    const head = make("header");
    const titleWrap = make("div");
    titleWrap.append(make("div", "title", "Source slot #" + row.slot));
    titleWrap.append(make("div", "small", row.kind.replaceAll("_", " ")));
    if (row.history) titleWrap.append(make("div", "help",
      row.history === "NEW_SOURCE_BYTES" ? "New source bytes; not a new finding" :
      "Unchanged source bytes; not proven correct"));
    head.append(titleWrap, make("span", "pill", row.review_state));
    const description = make("p", "hint", GUIDANCE[row.kind]);
    const meta = make("div", "small", countFormat(row.size_bytes) + " bytes · " +
      countFormat(row.item_count_claim) + " claimed entries (not verified findings)");
    const fingerprint = make("div", "hash", "Private byte SHA-256: " + row.sha256);
    const form = make("div", "fields");
    form.append(
      optionSelect(STAGES, selection.stage, value => {
        invalidateUndo(); selection.stage = value; updateStats(); if (stageFilter.value) render();
        notify("Human follow-up draft updated in browser memory only.");
      }, "Human follow-up"),
      optionSelect(ROLES, selection.next_role, value => {
        invalidateUndo(); selection.next_role = value; updateStats(); if (roleFilter.value) render();
        notify("Human planning role updated; not approval.");
      }, "Next role"),
    );
    const dateLabel = make("label", "", "Proposed review date");
    const dateInput = el("input", {type:"date", min:"2020-01-01", max:"2100-12-31",
      "aria-label":"Review date, source slot " + row.slot});
    dateInput.value = selection.review_date || "";
    dateInput.addEventListener("change", () => {
      const next = dateInput.value || null;
      if (!isValidDate(next)) {
        dateInput.value = selection.review_date || ""; notify("Invalid planning date; previous draft retained.");
        return;
      }
      invalidateUndo(); selection.review_date = next;
      notify("Human calendar note updated; not an authorization window.");
    });
    dateLabel.append(dateInput); form.append(dateLabel);
    article.append(head, description, meta, fingerprint, form);
    return article;
  };
  const updateStats = () => {
    const sourceCounts = new Map();
    for (const row of seed.entries) sourceCounts.set(row.kind, (sourceCounts.get(row.kind) || 0) + 1);
    const stateCounts = Object.fromEntries(STAGES.map(key => [key, 0]));
    for (const choice of choices) stateCounts[choice.stage]++;
    byId("total-count").textContent = countFormat(seed.entries.length);
    byId("pending-count").textContent = countFormat(stateCounts.PENDING_ORIGINAL);
    byId("attention-count").textContent = countFormat(stateCounts.NEEDS_ORIGINAL_EVIDENCE +
      stateCounts.NEEDS_SOURCE_OWNER + stateCounts.NEEDS_PRIVACY_REVIEW);
    byId("source-class-count").textContent = countFormat(sourceCounts.size);
    const summary = byId("stage-summary");
    summary.replaceChildren();
    for (const [stage, count] of Object.entries(stateCounts)) {
      if (!count) continue;
      const li = make("li", "", stage.replaceAll("_", " ") + " · " + count);
      summary.append(li);
    }
  };
  const render = () => {
    const shown = visibleEntries();
    list.replaceChildren();
    for (const row of shown) {
      const selected = choices[row.slot - 1];
      list.append(entryItem(row, selected));
    }
    byId("shown-count").textContent = shown.length + " of " + choices.length + " source slots shown";
    if (!shown.length) list.append(make("div", "empty", "No source slots match the current filters."));
    updateStats();
  };
  const download = (filename, data, mime) => {
    if (data.length > 200_000) { notify("Export HOLD: local content limit exceeded."); return; }
    const url = URL.createObjectURL(new Blob([data], {type:mime}));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = filename; anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 15000);
    notify("Draft prepared as a browser download. Save it privately; Python CLI must revalidate before use.");
  };
  const exportChoices = () => {
    if (!choices.every((x,i) => x.slot === i+1 && x.source_sha256 === seed.entries[i].sha256 &&
        STAGES.includes(x.stage) && ROLES.includes(x.next_role) && isValidDate(x.review_date))) {
      notify("Export HOLD: invalid local choices. Nothing written."); return;
    }
    const packet = {schema:"lightup.archive_human_followup.v1",
      manifest_sha256:seed.manifest_sha256,items:fresh()};
    for (const name of FLAGS) packet[name] = false;
    download("lightup-private-human-followup.json", JSON.stringify(packet, null, 2) + "\n",
      "application/json");
  };
  const exportSummary = () => {
    const stageCounts = {};
    for (const choice of choices) stageCounts[choice.stage] = (stageCounts[choice.stage] || 0) + 1;
    const packet = {
      schema:"lightup.archive_human_followup_aggregate.v1", source_count:choices.length,
      claimed_status:seed.status, stage_counts:stageCounts
    };
    for (const name of FLAGS) packet[name] = false;
    download("lightup-aggregate-human-followup.json", JSON.stringify(packet, null, 2)+"\n",
      "application/json");
  };
  const importChoices = async file => {
    if (!file || file.size > 128 * 1024 || file.size < 10) {
      notify("Import HOLD: missing or oversized private follow-up form.");return;
    }
    try {
      const packet = JSON.parse(await file.text());
      if (!packet || Array.isArray(packet) || typeof packet !== "object" ||
          Object.keys(packet).length !== 7 || packet.schema !== "lightup.archive_human_followup.v1" ||
          packet.manifest_sha256 !== seed.manifest_sha256 ||
          !FLAGS.every(key => packet[key] === false) || !Array.isArray(packet.items) ||
          packet.items.length !== seed.entries.length) throw Error("private form mismatch");
      const next = packet.items.map((value, i) => {
        if (!value || typeof value !== "object" || Array.isArray(value) ||
            Object.keys(value).length !== 5 || !Number.isInteger(value.slot) ||
            value.slot !== i+1 || value.source_sha256 !== seed.entries[i].sha256 ||
            !STAGES.includes(value.stage) || !ROLES.includes(value.next_role) ||
            !isValidDate(value.review_date)) throw Error("source slot mismatch");
        return {slot:value.slot,source_sha256:value.source_sha256,
          stage:value.stage,next_role:value.next_role,review_date:value.review_date};
      });
      invalidateUndo(); choices = next; render();
      notify("Matching draft imported into memory. Python final source admission remains mandatory.");
    } catch {
      notify("Import HOLD: incompatible, ambiguous or stale private draft. Existing choices preserved.");
    }
  };
  for (const kind of [...new Set(seed.entries.map(row => row.kind))].sort()) {
    const item = el("option", {value:kind});item.textContent = kind.replaceAll("_"," ");
    typeFilter.append(item);
  }
  for (const stage of STAGES) {
    const item = el("option", {value:stage});item.textContent = stage.replaceAll("_", " ");
    stageFilter.append(item);
  }
  for (const role of ROLES) {
    const item = el("option", {value:role});item.textContent = role.replaceAll("_", " ");
    roleFilter.append(item);
  }
  for (const stage of STAGES) {
    const node = el("option", {value:stage});
    node.textContent = stage.replaceAll("_", " ");
    byId("bulk-stage").append(node);
  }
  for (const role of ROLES) {
    const node = el("option", {value:role});
    node.textContent = role.replaceAll("_", " ");
    byId("bulk-role").append(node);
  }
  byId("bulk-apply").addEventListener("click", () => {
    const stage = byId("bulk-stage").value;
    const role = byId("bulk-role").value;
    const date = byId("bulk-date").value || null;
    const visible = visibleEntries();
    if ((!stage && !role && !date) || !visible.length || (date && !isValidDate(date))) {
      notify("Batch HOLD: choose a human planning change and a nonempty filtered source list.");
      return;
    }
    if (!window.confirm("Update human planning fields for " + visible.length +
      " visible source slots? This will NOT approve or change source evidence.")) {
      notify("Batch coordination cancelled. No source selections modified.");return;
    }
    batchBackup = fresh();
    for (const row of visible) {
      const selected = choices[row.slot - 1];
      if (stage) selected.stage = stage;
      if (role) selected.next_role = role;
      if (date) selected.review_date = date;
    }
    byId("bulk-undo").disabled = false;
    render();
    notify("Local human planning updated for " + visible.length +
      " visible source slots. No original data or consent affected.");
  });
  byId("bulk-undo").addEventListener("click", () => {
    if (!batchBackup) return;
    choices = batchBackup;
    invalidateUndo();
    render();
    notify("Last confirmed batch human-plan edit reverted. Original source untouched.");
  });
  if (seed.history) {
    const h = seed.history;
    if (h.new_count + h.retained_count !== seed.entries.length ||
        h.absent_count + h.retained_count !== h.previous_count ||
        !["HOLD","REVIEW_ONLY"].includes(h.previous_status)) {
      document.body.textContent = "HISTORICAL_SOURCE_HOLD"; return;
    }
    byId("history-panel").hidden = false;
    byId("history-filter-wrapper").hidden = false;
    byId("history-new").textContent = String(h.new_count);
    byId("history-absent").textContent = String(h.absent_count);
    byId("history-retained").textContent = String(h.retained_count);
    byId("history-previous-state").textContent = h.previous_status;
  }
  for (const filter of [query,typeFilter,stageFilter,roleFilter,historyFilter]) {
    filter.addEventListener(filter === query ? "input" : "change", render);
  }
  byId("export-draft").addEventListener("click",exportChoices);
  byId("export-summary").addEventListener("click",exportSummary);
  byId("import-choices").addEventListener("change",async event => {
    await importChoices(event.target.files?.[0]); event.target.value="";
  });
  byId("clear-filter").addEventListener("click",() => {
    query.value=typeFilter.value=stageFilter.value=roleFilter.value=historyFilter.value="";render();
  });
  byId("reset-plan").addEventListener("click",() => {
    if (!window.confirm("Discard all local human planning selections? This cannot be undone.")) return;
    invalidateUndo();
    choices = seed.entries.map(r => ({
      slot:r.slot,source_sha256:r.sha256,stage:"PENDING_ORIGINAL",
      next_role:"unassigned",review_date:null
    }));
    render();notify("All local planning choices cleared; original source manifest unchanged.");
  });
  byId("print").addEventListener("click",() => window.print());
  render();
  notify("Private source snapshot loaded locally. No browser storage or network requests.");
})();
