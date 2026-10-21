/* LightUp original offline HUMAN lab workflow desk. No backend, network, persistent storage or source admission. */
"use strict";
(() => {
  const SCHEMA = "lightup.private.human-lab-route.self-report.v1";
  const NO_AUTHORITY = Object.freeze({scan_authorized:false,grant_authorized:false,consent_verified:false,human_go:false});
  const LABELS = Object.freeze({
    NOT_REVIEWED:"Not reviewed", IN_PROGRESS:"Discussing", NEEDS_INPUT:"Needs original input", DISCUSSED:"Discussed only"
  });
  const STAGES = [
    {title:"1 · Offline proposal",intro:"Prepare and compare numeric, isolated lab proposals. These plans never execute targets.",steps:[
      [52,"Prepare isolated-lab proposal"],[53,"Reopen original owner-private proposal"],[54,"Compare two original proposals"],[55,"Review 3–8 original proposals"]]},
    {title:"2 · Source-bound human review",intro:"Only original admitted packets and explicitly recorded HUMAN choices can advance the draft.",steps:[
      [56,"Prepare review Studio"],[57,"Manually finalize original HUMAN proposal choices"],[58,"Reopen original HUMAN choices"],[59,"Compare 2–8 original HUMAN review rounds"]]},
    {title:"3 · Team feedback",intro:"Prepare separate owner-private team rooms; absent replies are NOT approvals.",steps:[
      [60,"Prepare assigned-team workrooms"],[61,"Read one exact source-bound HUMAN reply"],[62,"Assemble 1–4 replies with explicit withholding"],[63,"Reopen a complete original team batch"],[64,"Compare original team batches"]]},
    {title:"4 · Multi-round continuation",intro:"Carry human drafts forward without silently replacing previous choices.",steps:[
      [65,"Prepare explicit next HUMAN review round"],[66,"Reopen complete original continuation chain"],[67,"Inspect source-minimal HUMAN changes"]]},
    {title:"5 · Conflict reconciliation",intro:"A conflict resolution creates a NEW unfinalized candidate; review and explicit human finalization remain separate.",steps:[
      [68,"Prepare per-ordinal HUMAN conflict editor"],[69,"Publish selected HUMAN choices to a NEW draft"],[70,"Reopen published draft against originals"],[71,"Open NEW original HUMAN Review Studio"]]}
  ];
  const ALL = STAGES.flatMap(s => s.steps.map(x => String(x[0])));
  const state = Object.create(null);
  ALL.forEach(id => state[id] = "NOT_REVIEWED");
  const $ = id => document.getElementById(id);
  const node = (tag, label, className) => {
    const el = document.createElement(tag);
    if (label != null) el.textContent = label;
    if (className) el.className = className;
    return el;
  };
  const actionLabel = Object.fromEntries(
    STAGES.flatMap(stage => stage.steps.map(([id, caption]) => [String(id), caption])));
  function matchesFilter(id) {
    const query = $("action-search").value.trim().toLocaleLowerCase();
    const filter = $("status-filter").value;
    return (!query || id.includes(query) ||
            actionLabel[id].toLocaleLowerCase().includes(query)) &&
            (!filter || state[id] === filter);
  }
  function applyFilter() {
    let visible = 0;
    for (const row of document.querySelectorAll("[data-lab-action]")) {
      row.hidden = !matchesFilter(row.dataset.labAction);
      if (!row.hidden) visible++;
    }
    $("visible-count").textContent = visible +
      " of 20 original HUMAN steps visible. Hidden steps are still exported.";
    for (const stage of document.querySelectorAll(".phase")) {
      const count = [...stage.querySelectorAll("[data-lab-action]")]
        .filter(row => !row.hidden).length;
      const note = stage.querySelector(".visible-stage-count");
      if (note) note.textContent = count + " matching actions";
    }
    return visible;
  }
  function bulkHUMAN(marker) {
    if (!["NEEDS_INPUT", "IN_PROGRESS"].includes(marker)) return;
    const ids = ALL.filter(id => matchesFilter(id));
    if (!ids.length) {
      $("result").textContent = "No matching HUMAN actions to change.";
      return;
    }
    if (!window.confirm("Mark " + ids.length + " currently visible HUMAN discussion steps as " +
        LABELS[marker] + "? Only this local plan will change; " +
        "hidden steps remain unchanged. Nothing is approved or validated.")) {
      return;
    }
    ids.forEach(id => state[id] = marker);
    clearComparison();
    render();
    $("result").textContent = ids.length +
      " local self-report markers updated to " + LABELS[marker] +
      ". Nothing was verified, sent or authorized.";
  }
  $("action-search").addEventListener("input", applyFilter);
  $("status-filter").addEventListener("change", applyFilter);
  $("bulk-input").addEventListener("click", () => bulkHUMAN("NEEDS_INPUT"));
  $("bulk-discussing").addEventListener("click", () => bulkHUMAN("IN_PROGRESS"));

  const stageStatus = (stage) => {
    const values = stage.steps.map(([id]) => state[String(id)]);
    return values.filter(v => v === "DISCUSSED").length + "/" + values.length + " discussed · " +
      values.filter(v => v === "NEEDS_INPUT").length + " need input";
  };
  function render() {
    const host = $("stages");
    host.replaceChildren();
    STAGES.forEach((stage, index) => {
      const section = node("section", null, "phase");
      const h = node("h2", stage.title);
      section.append(h, node("p", stage.intro, "hint"));
      const meter = node("p", stageStatus(stage), "stage-metric");
      section.append(meter);
      const list = node("div", null, "actions");
      stage.steps.forEach(([number, caption]) => {
        const id = String(number);
        const row = node("div", null, "action");
        row.dataset.labAction = id;
        const field = node("label", null, "caption");
        field.append(node("strong", number + " · "), document.createTextNode(caption));
        const select = node("select");
        select.setAttribute("aria-label", "Self-reported discussion state, action " + id);
        Object.entries(LABELS).forEach(([value, label]) => {
          const option = node("option", label);
          option.value = value;
          select.append(option);
        });
        select.value = state[id];
        select.addEventListener("change", () => {
          state[id] = select.value;
          clearComparison();
          summary();
          meter.textContent = stageStatus(stage);
          applyFilter();
        });
        row.append(field, select);
        list.append(row);
      });
      section.append(list, node("p", "", "visible-stage-count hint"));
      host.append(section);
    });
    summary();
    applyFilter();
  }
  function summary() {
    const counts = Object.fromEntries(Object.keys(LABELS).map(k => [k, ALL.filter(id => state[id] === k).length]));
    $("progress").textContent = counts.DISCUSSED + "/20 discussed (self-reported), " +
      counts.IN_PROGRESS + " in discussion, " + counts.NEEDS_INPUT + " waiting on original input.";
    $("pending").replaceChildren();
    const items = ALL.filter(id => state[id] !== "DISCUSSED");
    if (!items.length) $("pending").append(node("li","All steps marked discussed. This is NOT approval, validation or completion."));
    else items.forEach(id => {
      const entry = STAGES.flatMap(s => s.steps).find(([num]) => String(num) === id);
      $("pending").append(node("li", id + " · " + entry[1] + " — " + LABELS[state[id]]));
    });
  }
  function report() {
    return {
      schema:SCHEMA,mode:"REVIEW_ONLY",authority:{...NO_AUTHORITY},
      verified_original_source:false, source_files_included:false, private_notes_included:false,
      steps:ALL.map(id => ({action:Number(id),self_reported_state:state[id]}))
    };
  }
  function download(name,text,kind) {
    const blob = new Blob([text],{type:kind});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;a.download = name;document.body.append(a);a.click();a.remove();
    setTimeout(() => URL.revokeObjectURL(url),1000);
    $("result").textContent = "A LOCAL download was requested. Verify the actual file before using it; no upload, verification or release occurred.";
  }
  $("export-json").addEventListener("click", () => download(
    "LightUp-PRIVATE-HUMAN-Lab-Route.json",JSON.stringify(report(),null,2)+"\n","application/json"));
  $("export-csv").addEventListener("click", () => download(
    "LightUp-PRIVATE-HUMAN-Lab-Route.csv",
    "action,self_reported_state,authority\r\n" +
    ALL.map(id => id+","+state[id]+",REVIEW_ONLY").join("\r\n")+"\r\n","text/csv"));
  $("print").addEventListener("click", () => window.print());
  $("reset").addEventListener("click", () => {
    if (!window.confirm("Discard all local unsaved HUMAN discussion markers?")) return;
    ALL.forEach(id => state[id]="NOT_REVIEWED");clearComparison();render();
    $("result").textContent = "In-memory markers cleared. No original files changed.";
  });
  // JSON.parse alone accepts duplicate object properties and silently keeps the
  // last value. Inspect every syntactic string key in a valid JSON document,
  // including escaped names, before trusting an offline imported self-report.
  function parseWithoutDuplicateKeys(raw) {
    const result = JSON.parse(raw);
    const containers = [];
    for (let i = 0; i < raw.length;) {
      const char = raw[i];
      if (char === '"') {
        let end = i + 1;
        while (end < raw.length) {
          if (raw[end] === "\\") { end += 2; continue; }
          if (raw[end] === '"') break;
          end++;
        }
        if (end >= raw.length) throw Error("Malformed JSON string");
        let next = end + 1;
        while (next < raw.length && /\s/.test(raw[next])) next++;
        if (raw[next] === ":") {
          const keys = containers[containers.length - 1];
          if (!(keys instanceof Set)) throw Error("Unexpected JSON key position");
          const key = JSON.parse(raw.slice(i, end + 1));
          if (keys.has(key)) throw Error("Duplicate JSON object property");
          keys.add(key);
        }
        i = end + 1;
      } else if (char === "{") {
        containers.push(new Set());
        if (containers.length > 32) throw Error("JSON nesting limit exceeded");
        i++;
      } else if (char === "[") {
        containers.push(null);
        if (containers.length > 32) throw Error("JSON nesting limit exceeded");
        i++;
      } else if (char === "}" || char === "]") {
        containers.pop();
        i++;
      } else {
        i++;
      }
    }
    if (containers.length) throw Error("Unbalanced JSON");
    return result;
  }

  function admitImportedReport(data) {
    const sameKeys = (value, expected) =>
      value !== null && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === expected.length &&
      expected.every(key => Object.hasOwn(value, key));
    if (!sameKeys(data, ["schema","mode","authority","verified_original_source",
          "source_files_included","private_notes_included","steps"]) ||
        data.schema !== SCHEMA || data.mode !== "REVIEW_ONLY" ||
        data.verified_original_source !== false || data.source_files_included !== false ||
        data.private_notes_included !== false) throw Error("Unknown schema or source claim");
    if (!sameKeys(data.authority, Object.keys(NO_AUTHORITY)) ||
        Object.keys(NO_AUTHORITY).some(key => data.authority[key] !== false)) {
      throw Error("Attempted authorization claim");
    }
    if (!Array.isArray(data.steps) || data.steps.length !== ALL.length) {
      throw Error("Incomplete original HUMAN action order");
    }
    const imported = Object.create(null);
    data.steps.forEach((entry, index) => {
      const id = ALL[index];
      if (!sameKeys(entry, ["action","self_reported_state"]) ||
          entry.action !== Number(id) || !Object.hasOwn(LABELS,entry.self_reported_state)) {
        throw Error("Altered original HUMAN action or marker");
      }
      imported[id] = entry.self_reported_state;
    });
    return imported;
  }

  function describeChanges(incoming) {
    const changes = ALL.filter(id => state[id] !== incoming[id]);
    return {
      changes,
      preview: changes.map(id =>
        id + " · " + LABELS[state[id]] + " → " + LABELS[incoming[id]]).join("\n")
    };
  }

  // Comparison is intentionally not an import. Only fixed local marker
  // tokens are rendered, never original source, paths, private notes or IDs.
  let comparison = null;
  function clearComparison() {
    comparison = null;
    $("compare-rows").replaceChildren();
    $("compare-summary").textContent =
      "No current local comparison. Load another plan to view differences.";
    $("compare-details").open = false;
    $("export-diff").disabled = true;
  }
  function showComparison(incoming) {
    const diff = describeChanges(incoming);
    comparison = diff.changes.map(id => ({
      action: id, old_state: state[id], proposed_state: incoming[id]
    }));
    const table = $("compare-rows");
    table.replaceChildren();
    for (const item of comparison) {
      const tr = node("tr");
      for (const label of [
        item.action,
        LABELS[item.old_state],
        LABELS[item.proposed_state]
      ]) tr.append(node("td", label));
      table.append(tr);
    }
    if (!comparison.length) {
      const row = node("tr");
      const cell = node("td", "No local marker changes. Nothing was verified.");
      cell.colSpan = 3;
      row.append(cell);
      table.append(row);
    }
    $("compare-summary").textContent = diff.changes.length +
      " of 20 self-reported HUMAN markers differ. This is a discussion-only comparison.";
    $("compare-details").open = true;
    $("export-diff").disabled = !comparison.length;
    return diff;
  }
  async function readReport(file) {
    if (file.size < 20 || file.size > 24576) throw Error("Not a bounded HUMAN report");
    return admitImportedReport(parseWithoutDuplicateKeys(await file.text()));
  }
  $("compare-json").addEventListener("change", async ev => {
    const file = ev.target.files && ev.target.files[0];
    ev.target.value = "";
    if (!file) return;
    try {
      const incoming = await readReport(file);
      const diff = showComparison(incoming);
      $("result").textContent = "Compared " + diff.changes.length +
        " HUMAN markers without changing current values. No source authenticated.";
    } catch (_) {
      clearComparison();
      $("result").textContent =
        "HOLD: local HUMAN comparison refused. Current values are unchanged.";
    }
  });
  $("export-diff").addEventListener("click", () => {
    if (!comparison || !comparison.length) return;
    const lines = ["action,previous_self_report,proposed_self_report,authority"];
    for (const change of comparison) {
      lines.push([change.action, change.old_state, change.proposed_state,
        "REVIEW_ONLY"].join(","));
    }
    download("LightUp-PRIVATE-HUMAN-Lab-Discussion-Changes.csv",
      lines.join("\r\n") + "\r\n", "text/csv");
  });

  $("import-json").addEventListener("change", async ev => {
    const file = ev.target.files && ev.target.files[0];
    ev.target.value = "";
    if (!file) return;
    try {
      const incoming = await readReport(file);
      const diff = showComparison(incoming);
      if (!diff.changes.length) {
        $("result").textContent = "The self-report contains the same 20 local discussion markers. Nothing replaced.";
        return;
      }
      const notice = "PRIVATE HUMAN discussion import: " + diff.changes.length +
        " of 20 self-reported markers would change.\n\n" +
        diff.preview + "\n\nReplace all 20 in-memory markers? " +
        "No original source, review, identity or consent is authenticated.";
      if (!window.confirm(notice)) {
        $("result").textContent = "HUMAN import cancelled. No local markers were changed.";
        return;
      }


      ALL.forEach(id => state[id]=incoming[id]);clearComparison();render();
      $("result").textContent = "Imported " + diff.changes.length + " local HUMAN marker changes. No original source or consent verified.";
    } catch (_) {
      clearComparison();
      $("result").textContent = "HOLD: untrusted route file refused (shape, size, sequence or authority claim). No changes applied.";
    }
  });

  // Separate HUMAN reports form a local, ordered discussion comparison only.
  // There is deliberately no timestamp, identity inference, source ingestion,
  // stored session, network request, or application to active discussion markers.
  let roundHistory = null;
  function clearHistory() {
    roundHistory = null;
    $("history-view").hidden = true;
    $("history-columns").replaceChildren();
    $("history-rows").replaceChildren();
    $("history-stage-summary").replaceChildren();
    $("history-export").disabled = true;
    $("history-clear").disabled = true;
    $("history-result").textContent = "No prior HUMAN rounds selected.";
    $("history-focus").value = "";
    $("history-stage").value = "";
    $("history-visible").textContent = "";
  }
  function transitionCount(id, rounds) {
    let changes = 0;
    for (let index = 1; index < rounds.length; index++) {
      if (rounds[index][id] !== rounds[index - 1][id]) changes++;
    }
    return changes;
  }
  function applyHistoryFilter() {
    if (!roundHistory) return;
    const focus = $("history-focus").value;
    const stageIndex = $("history-stage").value;
    let visible = 0;
    for (const row of $("history-rows").children) {
      const id = row.dataset.historyAction;
      const transitions = transitionCount(id, roundHistory);
      const last = roundHistory[roundHistory.length - 1][id];
      const matchStage = !stageIndex || STAGES[Number(stageIndex)].steps
        .some(([action]) => String(action) === id);
      const matchFocus = !focus ||
        (focus === "changed" && transitions > 0) ||
        (focus === "repeat" && transitions > 1) ||
        (focus === "needs" && last === "NEEDS_INPUT") ||
        (focus === "pending" && last !== "DISCUSSED");
      row.hidden = !(matchStage && matchFocus);
      if (!row.hidden) visible++;
    }
    $("history-visible").textContent = visible +
      " of 20 original HUMAN actions shown. All 20 remain in complete CSV export.";
  }
  $("history-focus").addEventListener("change", applyHistoryFilter);
  $("history-stage").addEventListener("change", applyHistoryFilter);
  function renderHistory(rounds) {
    roundHistory = rounds;
    const header = node("tr");
    header.append(node("th", "Original action"));
    rounds.forEach((_, index) => header.append(node("th", "Selected round " + (index + 1))));
    header.append(node("th", "Marker transitions"));
    $("history-columns").replaceChildren(header);
    const tbody = $("history-rows");
    tbody.replaceChildren();
    for (const id of ALL) {
      const tr = node("tr");
      tr.dataset.historyAction = id;
      const transitions = transitionCount(id, rounds);
      if (transitions) tr.className = "changed";
      tr.append(node("td", id + " · " + actionLabel[id]));
      for (const report of rounds) tr.append(node("td", LABELS[report[id]]));
      tr.append(node("td", String(transitions)));
      tbody.append(tr);
    }
    const stages = $("history-stage-summary");
    stages.replaceChildren();
    for (const stage of STAGES) {
      const ids = stage.steps.map(step => String(step[0]));
      const changed = ids.filter(id => transitionCount(id, rounds) > 0).length;
      const waiting = ids.filter(id => rounds[rounds.length - 1][id] === "NEEDS_INPUT").length;
      const line = node("p", null, "history-stage");
      line.append(node("strong", stage.title));
      line.append(node("span", changed + "/" + ids.length + " actions with marker changes"));
      line.append(node("span", waiting + " last-round needs-input markers"));
      stages.append(line);
    }
    const changed = ALL.filter(id => transitionCount(id, rounds) > 0).length;
    const transitions = ALL.reduce((n, id) => n + transitionCount(id, rounds), 0);
    $("history-result").textContent = rounds.length + " explicitly ordered local HUMAN reports; " +
      changed + "/20 original actions changed at least once, " + transitions +
      " marker transitions. This is not authenticated chronology or assessment progress.";
    $("history-view").hidden = false;
    $("history-export").disabled = false;
    $("history-clear").disabled = false;
    applyHistoryFilter();
  }
  $("history-json").addEventListener("change", async ev => {
    const files = Array.from(ev.target.files || []);
    ev.target.value = "";
    // Never leave an old source-free comparison on screen after an invalid
    // replacement selection; no partial imports or round order inference.
    clearHistory();
    if (!files.length) return;
    if (files.length < 2 || files.length > 8) {
      $("history-result").textContent = "HOLD: select 2–8 exact HUMAN discussion reports.";
      return;
    }
    try {
      const reports = [];
      const signatures = new Set();
      for (const file of files) {
        const report = await readReport(file);
        const signature = ALL.map(id => report[id]).join("|");
        if (signatures.has(signature)) throw Error("Repeated identical HUMAN markers");
        signatures.add(signature);
        reports.push(report);
      }
      renderHistory(reports);
    } catch (_) {
      clearHistory();
      $("history-result").textContent =
        "HOLD: one or more original HUMAN self-reports were rejected. Nothing imported or changed.";
    }
  });
  $("history-clear").addEventListener("click", () => {
    clearHistory();
    $("history-result").textContent = "Compared HUMAN reports cleared from memory.";
  });
  $("history-export").addEventListener("click", () => {
    if (!roundHistory) return;
    const heading = ["action", ...roundHistory.map((_, index) =>
      "self_report_round_" + (index + 1)), "marker_transitions", "authority"];
    const rows = [heading.join(",")];
    for (const id of ALL) {
      rows.push([id, ...roundHistory.map(report => report[id]),
        String(transitionCount(id, roundHistory)), "REVIEW_ONLY"].join(","));
    }
    download("LightUp-PRIVATE-HUMAN-Lab-Rounds.csv",
      rows.join("\r\n") + "\r\n", "text/csv");
  });
  render();
})();
