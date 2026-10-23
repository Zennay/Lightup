/* Private original HUMAN decision editor. No network, storage or authority. */
(() => {
  "use strict";
  const one = id => document.getElementById(id);
  const node = one("original-choices");
  const board = one("choices");
  const feedback = one("feedback");
  const exportButton = one("export");
  const teamFilter = one("filter-team");
  const stageFilter = one("filter-stage");
  const noteFilter = one("filter-question");
  const ordinalFilter = one("filter-ordinal");
  const applyVisible = one("apply-visible");
  const keepVisible = one("keep-visible");
  const undo = one("undo-choice");
  const redo = one("redo-choice");
  if ([node, board, feedback, exportButton, teamFilter, stageFilter,
       noteFilter, ordinalFilter, applyVisible, keepVisible, undo, redo]
       .some(item => !item)) return;

  let rows;
  try {
    rows = JSON.parse(node.textContent);
    if (!Array.isArray(rows) || rows.length < 1 || rows.length > 500) throw Error();
  } catch {
    feedback.textContent = "HOLD: original source-bound choices are not readable.";
    return;
  }
  const columns = [
    "source_snapshot_sha256", "prior_candidate_sha256",
    "proposal_slot", "human_team", "prior_stage", "proposed_stage",
    "human_question_changed", "human_choice"
  ];
  const valid = rows.every(row =>
    Object.keys(row).length === columns.length &&
    columns.every(key => Object.prototype.hasOwnProperty.call(row, key)) &&
    columns.slice(0, -1).every(key => typeof row[key] === "string") &&
    row.human_choice === "KEEP_PREVIOUS" &&
    /^[a-f0-9]{64}$/.test(row.source_snapshot_sha256) &&
    /^[a-f0-9]{64}$/.test(row.prior_candidate_sha256) &&
    /^\d{1,10}$/.test(row.proposal_slot) &&
    ["YES", "NO"].includes(row.human_question_changed));
  if (!valid || new Set(rows.map(row => row.proposal_slot)).size !== rows.length) {
    feedback.textContent = "HOLD: the original source-bound choice sheet is malformed.";
    return;
  }
  const esc = value => String(value).replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
  const fragment = document.createDocumentFragment();
  const table = [];
  rows.forEach((row, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = "<th scope='row'>" + esc(row.proposal_slot) +
      "</th><td>" + esc(row.human_team) +
      "</td><td>" + esc(row.prior_stage) +
      "</td><td>" + esc(row.proposed_stage) +
      "</td><td>" + esc(row.human_question_changed) + "</td>";
    const action = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = "c" + String(i);
    checkbox.setAttribute("aria-label", "Apply ORIGINAL HUMAN proposal " + row.proposal_slot);
    checkbox.addEventListener("change", () => {
      row.human_choice = checkbox.checked ? "APPLY_RETURN" : "KEEP_PREVIOUS";
      saveHistory();
      refresh();
    });
    action.append(checkbox);
    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    label.textContent = " APPLY_RETURN";
    action.append(label);
    tr.append(action);
    table.push({tr, checkbox, row});
    fragment.append(tr);
  });
  board.append(fragment);

  function addOptions(element, values) {
    values.forEach(value => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      element.append(option);
    });
  }
  addOptions(teamFilter, [...new Set(rows.map(row => row.human_team))].sort());
  addOptions(stageFilter, [...new Set(rows.flatMap(
    row => [row.prior_stage, row.proposed_stage]))].sort());

  const snapshots = [rows.map(row => row.human_choice)];
  let cursor = 0;
  function saveHistory() {
    const current = rows.map(row => row.human_choice);
    if (snapshots[cursor].every((value, index) => value === current[index])) return;
    snapshots.splice(cursor + 1);
    snapshots.push(current);
    if (snapshots.length > 26) snapshots.shift();
    cursor = snapshots.length - 1;
  }
  function restore(index) {
    cursor = index;
    snapshots[cursor].forEach((choice, i) => {
      rows[i].human_choice = choice;
      table[i].checkbox.checked = choice === "APPLY_RETURN";
    });
    refresh();
  }
  undo.addEventListener("click", () => { if (cursor > 0) restore(cursor - 1); });
  redo.addEventListener("click", () => {
    if (cursor < snapshots.length - 1) restore(cursor + 1);
  });
  const filters = [teamFilter, stageFilter, noteFilter, ordinalFilter];
  filters.forEach(item => item.addEventListener("input", refresh));

  function refresh() {
    let visible = 0;
    table.forEach(({tr, row}) => {
      const matches = (!teamFilter.value || teamFilter.value === row.human_team) &&
        (!stageFilter.value || stageFilter.value === row.prior_stage ||
         stageFilter.value === row.proposed_stage) &&
        (!noteFilter.value || noteFilter.value === row.human_question_changed) &&
        (!ordinalFilter.value.trim() ||
         row.proposal_slot.includes(ordinalFilter.value.trim()));
      tr.hidden = !matches;
      if (matches) visible += 1;
    });
    const chosen = rows.filter(row => row.human_choice === "APPLY_RETURN").length;
    feedback.textContent = chosen + " of " + rows.length +
      " original HUMAN proposals selected; " + visible + " currently visible. " +
      "All unseen original rows remain included in the final CSV as chosen.";
    exportButton.disabled = chosen === 0;
    applyVisible.disabled = visible === 0;
    keepVisible.disabled = visible === 0;
    undo.disabled = cursor === 0;
    redo.disabled = cursor === snapshots.length - 1;
  }
  function setVisible(shouldApply) {
    const filtered = table.filter(entry => !entry.tr.hidden);
    if (filtered.length === 0) return;
    if (shouldApply && !window.confirm(
      "Mark " + filtered.length + " VISIBLE original HUMAN proposals as APPLY_RETURN? " +
      "This only edits this offline draft, and no native FINALIZE occurs.")) return;
    filtered.forEach(({row, checkbox}) => {
      row.human_choice = shouldApply ? "APPLY_RETURN" : "KEEP_PREVIOUS";
      checkbox.checked = shouldApply;
    });
    saveHistory();
    refresh();
  }
  applyVisible.addEventListener("click", () => setVisible(true));
  keepVisible.addEventListener("click", () => setVisible(false));

  function cell(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  exportButton.addEventListener("click", () => {
    if (!rows.some(row => row.human_choice === "APPLY_RETURN")) return;
    const csv = [columns.map(cell).join(","),
      ...rows.map(row => columns.map(key => cell(row[key])).join(","))].join("\r\n") + "\r\n";
    const blob = new Blob([csv], {type: "text/csv;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "PRIVATE-HUMAN-COMPLETED-CHOICES.csv";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    feedback.textContent = "PRIVATE CSV download requested. Store in a trusted " +
      "owner-only 0700 directory with 0600 file mode; browsers do not apply " +
      "PRIVATE custody. Native console action 69 re-admits ALL source-bound rows.";
  });
  refresh();
})();