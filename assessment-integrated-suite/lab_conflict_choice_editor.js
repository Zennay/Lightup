/* Private local HUMAN choice editor. No networking, storage, or automatic decisions. */
(() => {
  "use strict";
  const node = document.getElementById("original-choices");
  const board = document.getElementById("choices");
  const feedback = document.getElementById("feedback");
  const exportButton = document.getElementById("export");
  if (!node || !board || !feedback || !exportButton) return;
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
  if (!valid) {
    feedback.textContent = "HOLD: the original choice sheet is malformed.";
    return;
  }
  const esc = value => String(value).replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
  const fragment = document.createDocumentFragment();
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
    checkbox.setAttribute("aria-label", "Explicitly include original proposal " + row.proposal_slot);
    checkbox.addEventListener("change", () => {
      row.human_choice = checkbox.checked ? "APPLY_RETURN" : "KEEP_PREVIOUS";
      summary();
    });
    action.append(checkbox);
    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    label.textContent = " APPLY_RETURN";
    action.append(label);
    tr.append(action);
    fragment.append(tr);
  });
  board.append(fragment);
  function summary() {
    const selected = rows.filter(row => row.human_choice === "APPLY_RETURN").length;
    feedback.textContent = selected + " of " + rows.length +
      " original HUMAN proposals explicitly selected; all others KEEP_PREVIOUS.";
    exportButton.disabled = selected === 0;
  }
  function cell(value) {
    const str = String(value);
    return '"' + str.replaceAll('"', '""') + '"';
  }
  exportButton.addEventListener("click", () => {
    if (!rows.some(row => row.human_choice === "APPLY_RETURN")) return;
    const csv = [columns.map(cell).join(","),
      ...rows.map(row => columns.map(key => cell(row[key])).join(","))].join("\r\n") + "\r\n";
    const blob = new Blob([csv], {type: "text/csv;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "PRIVATE-HUMAN-COMPLETED-CHOICES.csv";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    feedback.textContent = "PRIVATE CSV download requested. Save under a trusted owner-only 0700 folder and chmod 0600; browser downloads are NOT automatically private. Re-admit in native console option 69.";
  });
  summary();
})();