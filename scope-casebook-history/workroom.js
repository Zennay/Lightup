"use strict";
/* LightUp HUMAN Casebook Workroom — local-only, no network, no saved browser state.
 * Original case IDs/actions are source declarations, NOT account approvals,
 * authorization, verified revocation, security verdicts or risk rankings.
 */
(() => {
  const FIELDS = [
    "original_engagement_id", "original_next_action", "original_attention",
    "human_stage", "human_followup_route", "human_blocker"
  ];
  const STAGES = ["unreviewed", "investigating", "awaiting-owner", "documented"];
  const ROUTES = [
    "unassigned", "original-scope-owner", "client-clarification",
    "independent-security-review", "operator-followup"
  ];
  const BLOCKERS = [
    "none", "missing-source", "missing-owner", "needs-independent-consent",
    "requires-revocation-review", "unresolved-tenant-lineage"
  ];
  const table = document.getElementById("cases");
  const rows = Array.from(table.querySelectorAll("tr[data-case]"));
  const status = document.getElementById("status");
  const search = document.getElementById("search");
  const stageFilter = document.getElementById("stage-filter");
  const sourceFilter = document.getElementById("source-filter");
  const panel = document.getElementById("totals");
  const pick = document.getElementById("import-file");
  const btnImport = document.getElementById("import");
  const btnExport = document.getElementById("export");
  const btnSummary = document.getElementById("export-summary");
  const btnReset = document.getElementById("reset");

  // The private source columns in the HTML are always read-only.
  // A separate workspace edits only three HUMAN workflow enumerations.
  function original(row) {
    return [
      row.dataset.case, row.dataset.action, row.dataset.attention,
    ];
  }
  function selections(row) {
    return [
      row.querySelector(".stage").value,
      row.querySelector(".route").value,
      row.querySelector(".blocker").value
    ];
  }
  function csvEscape(value) {
    // Source IDs start with ASCII letters/digits/underscore at admission and
    // all editable values are tightly enumerated, not free text.
    const s = String(value);
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  function csv(rowsData) {
    return rowsData.map(row => row.map(csvEscape).join(",")).join("\r\n") + "\r\n";
  }
  function showStatus(message, invalid = false) {
    status.textContent = message;
    status.dataset.invalid = String(invalid);
  }
  function update() {
    const term = search.value.trim().toLowerCase();
    const stage = stageFilter.value;
    const flag = sourceFilter.value;
    const counts = Object.fromEntries(STAGES.map(k => [k, 0]));
    const blockers = Object.fromEntries(BLOCKERS.map(k => [k, 0]));
    let shown = 0;
    for (const row of rows) {
      const [id, action, attention] = original(row);
      const [s, , b] = selections(row);
      counts[s] += 1;
      blockers[b] += 1;
      const visible =
        (id.toLowerCase().includes(term) ||
         action.toLowerCase().includes(term) ||
         attention.toLowerCase().includes(term)) &&
        (!stage || s === stage) &&
        (!flag || (flag === "hold" && attention.startsWith("HOLD_")) ||
                    (flag === "not-hold" && !attention.startsWith("HOLD_")));
      row.hidden = !visible;
      if (visible) shown += 1;
    }
    panel.replaceChildren();
    const boxes = [
      ["Cases shown", shown + " / " + rows.length],
      ["Investigating", counts.investigating],
      ["Awaiting owner", counts["awaiting-owner"]],
      ["Documented (HUMAN only)", counts.documented],
      ["Human blockers", rows.length - blockers.none]
    ];
    for (const [label, value] of boxes) {
      const box = document.createElement("div");
      box.className = "metric";
      const name = document.createElement("span");
      name.textContent = label;
      const number = document.createElement("strong");
      number.textContent = String(value);
      box.append(name, number);
      panel.append(box);
    }
  }
  function download(text, filename) {
    const url = URL.createObjectURL(new Blob([text], {
      type: "text/csv;charset=utf-8"
    }));
    const link = document.createElement("a");
    link.download = filename;
    link.href = url;
    link.style.display = "none";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function exportCurrent() {
    const records = [FIELDS, ...rows.map(row => [
      ...original(row), ...selections(row)
    ])];
    download(csv(records), "lightup-PRIVATE-human-case-followup.csv");
    showStatus("PRIVATE HUMAN CSV saved locally. This cannot authorize work or prove consent.");
  }
  function exportSummary() {
    const source = [["dimension", "human_label", "count", "authority"]];
    const dimensions = [
      ["human_stage", STAGES, 0],
      ["human_followup_route", ROUTES, 1],
      ["human_blocker", BLOCKERS, 2]
    ];
    for (const [field, labels, fieldIndex] of dimensions) {
      for (const label of labels) {
        const count = rows.filter(row => selections(row)[fieldIndex] === label).length;
        source.push([field, label, count, "HUMAN_REVIEW_ONLY_HOLD"]);
      }
    }
    download(csv(source), "lightup-PRIVATE-id-free-human-workload.csv");
    showStatus("ID-free HUMAN counts exported; SMALL GROUP COUNTS MAY STILL BE SENSITIVE. No approval.");
  }

  // Strict RFC-4180-style CSV reader, rejecting malformed framing.
  // Parses before applying any edits; a failed import leaves every row intact.
  function parseCsv(data) {
    if (data.startsWith("\uFEFF")) data = data.slice(1);
    const output = [];
    let row = [], part = "", state = 0;
    // states: 0 unquoted, 1 quoted, 2 after closing quote
    for (let i = 0; i < data.length; i++) {
      const ch = data[i];
      if (state === 1) {
        if (ch === '"') {
          if (data[i + 1] === '"') { part += '"'; i += 1; }
          else state = 2;
        } else {
          part += ch;
        }
        continue;
      }
      if (ch === '"' && state === 0 && part === "") {
        state = 1;
      } else if (ch === "," && state !== 1) {
        row.push(part); part = ""; state = 0;
      } else if (ch === "\r" || ch === "\n") {
        if (ch === "\r" && data[i + 1] === "\n") i++;
        row.push(part); output.push(row); row = []; part = ""; state = 0;
      } else {
        if (state === 2 || ch === '"') throw new Error("Invalid CSV framing.");
        part += ch;
      }
      if (output.length > rows.length + 1) {
        throw new Error("CSV exceeds original case count.");
      }
    }
    if (state === 1) throw new Error("Unclosed quoted CSV cell.");
    if (row.length || part !== "") { row.push(part); output.push(row); }
    return output;
  }
  function admitImport(text) {
    if (text.length > 131072) throw new Error("PRIVATE CSV exceeds 128 KiB.");
    const data = parseCsv(text);
    if (data.length !== rows.length + 1) {
      throw new Error("PRIVATE CSV case count does not match the original report.");
    }
    if (!FIELDS.every((field, i) => data[0][i] === field) ||
        data[0].length !== FIELDS.length) {
      throw new Error("CSV field names/order differ from the original template.");
    }
    const staged = [];
    for (let i = 0; i < rows.length; i++) {
      const line = data[i + 1];
      if (!line || line.length !== FIELDS.length ||
          !original(rows[i]).every((value, j) => line[j] === value)) {
        throw new Error("An original case ID, action, attention or position changed.");
      }
      if (!STAGES.includes(line[3]) ||
          !ROUTES.includes(line[4]) ||
          !BLOCKERS.includes(line[5])) {
        throw new Error("Unknown HUMAN stage, route or blocker.");
      }
      staged.push(line.slice(3));
    }
    return staged;
  }
  async function importSelected() {
    const file = pick.files && pick.files[0];
    if (!file) { showStatus("Select one PRIVATE CSV to resume.", true); return; }
    if (file.size > 131072) {
      showStatus("HOLD: selected PRIVATE CSV exceeds 128 KiB.", true);
      return;
    }
    try {
      const contents = await file.text();
      const pending = admitImport(contents);
      if (!window.confirm(
        "Restore these HUMAN-only stages? Original source fields remain locked."
      )) {
        showStatus("Restore cancelled; existing HUMAN state unchanged.");
        return;
      }
      rows.forEach((row, i) => {
        row.querySelector(".stage").value = pending[i][0];
        row.querySelector(".route").value = pending[i][1];
        row.querySelector(".blocker").value = pending[i][2];
      });
      update();
      showStatus("Restored PRIVATE HUMAN stages locally. Never a source approval.");
    } catch (e) {
      showStatus("HOLD: " + (e instanceof Error ? e.message : "Invalid PRIVATE CSV.") +
                 " No HUMAN stages were changed.", true);
    } finally {
      pick.value = "";
    }
  }
  rows.forEach(row => row.querySelectorAll("select").forEach(select => {
    select.addEventListener("change", () => {
      update();
      showStatus("Unsaved HUMAN-only changes in this tab. Export PRIVATE CSV to retain.");
    });
  }));
  [search, stageFilter, sourceFilter].forEach(el => {
    el.addEventListener("input", update);
  });
  btnImport.addEventListener("click", importSelected);
  btnExport.addEventListener("click", exportCurrent);
  btnSummary.addEventListener("click", exportSummary);
  btnReset.addEventListener("click", () => {
    if (!window.confirm("Clear local HUMAN stages? Original source rows stay unchanged.")) return;
    rows.forEach(row => {
      row.querySelector(".stage").value = "unreviewed";
      row.querySelector(".route").value = "unassigned";
      row.querySelector(".blocker").value = "none";
    });
    update();
    showStatus("HUMAN stages cleared in this tab; original source untouched.");
  });
  update();
  showStatus("Local-only. HUMAN review, not authorization. Changes stay in this tab until CSV export.");
})();
