"""PRIVATE, offline, source-minimal HUMAN next-action desk.

HUMAN status suggestions only; no endpoint URLs, notes, identities, execution.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json

from launchpad import Hold
from review_desk import ROLES, STAGES

NAME = "lightup-lab-human-next-actions-private.html"
NEXT = ("REQUEST_HUMAN_ROLE_REPLY", "COLLECT_MISSING_HUMAN_INPUT",
        "SCHEDULE_HUMAN_REVIEW", "FOLLOW_UP_WITH_HUMAN_OWNER")
STATUSES = ("ROLE_REPLY_RECEIVED", "AWAITING_HUMAN_ROLE_REPLY")
NOTES = ("YES", "NO", "NOT_RETURNED")
STYLE = (
    "*{box-sizing:border-box}body{margin:0;background:#f3f6fb;"
    "font:15px/1.55 system-ui,sans-serif;color:#162b41}"
    "header,main,footer{max-width:1100px;margin:0 auto;padding:1.2rem}"
    "h1{font-size:clamp(1.7rem,4vw,2.6rem);margin:.2rem 0}"
    ".hold{background:#fff1df;border-left:6px solid #9b5811;padding:1rem;font-weight:750}"
    ".panel{background:white;border:1px solid #cedbe8;border-radius:.7rem;"
    "padding:1rem;margin:1rem 0}"
    ".filters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem}"
    "label{display:block;font-weight:700}select{font:inherit;width:100%;padding:.55rem;"
    "border:1px solid #7d91a8;border-radius:.3rem;background:white}"
    "select:focus-visible,button:focus-visible{outline:3px solid #e0a940;outline-offset:2px}"
    "button{font:inherit;background:#1a426d;color:white;border:0;border-radius:.4rem;"
    "padding:.65rem 1rem;font-weight:700;cursor:pointer;margin:.3rem .4rem .3rem 0}"
    "button:disabled{opacity:.5;cursor:not-allowed}#printScope{font-size:.9rem}"
    "table{width:100%;border-collapse:collapse}th,td{border:1px solid #c1d0de;"
    "padding:.65rem;text-align:left}th{background:#e8f0fa}"
    "tr[hidden]{display:none}small{color:#435970}"
    ".slotselect{display:flex;align-items:center;gap:.45rem;white-space:nowrap}"
    ".slotselect input{width:1.1rem;height:1.1rem}"
    ".selectionpreview{margin:.8rem 0}.selectionpreview summary{cursor:pointer;font-weight:750;padding:.5rem 0}"
    ".selectionpreview table{min-width:760px}"
    ".importpanel{border:1px dashed #7d91a8;border-radius:.5rem;padding:.9rem;margin:.8rem 0}"
    ".importpanel input{font:inherit;max-width:100%;display:block;margin:.5rem 0}"
    "@media(max-width:690px){.filters{grid-template-columns:1fr}"
    ".tablewrap{overflow-x:auto}table{min-width:800px}}"
    "@media print{.filters,button,.slotselect input,#selectionSummary,.selectionpreview,.importpanel{display:none}header,main{max-width:none}"
    "tr[hidden]{display:none}#printScope{display:block;font-weight:700}}"
)
SCRIPT = r'''(() => {
"use strict";
const source = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(
  Uint8Array.from(atob(__ROWS64__),x=>x.charCodeAt(0))));
const root = document.getElementById("actionRows");
const roleFilter = document.getElementById("role");
const replyFilter = document.getElementById("reply");
const nextFilter = document.getElementById("next");
const stageFilter = document.getElementById("stage");
const noteFilter = document.getElementById("note");
const resetButton = document.getElementById("reset");
const progress = document.getElementById("progress");
const printButton = document.getElementById("print");
const saveButton = document.getElementById("saveSelected");
const saveVisibleSelected = document.getElementById("saveVisibleSelected");
const selectVisibleButton = document.getElementById("selectVisible");
const deselectVisibleButton = document.getElementById("deselectVisible");
const clearSelectionButton = document.getElementById("clearSelection");
const selectionSummary = document.getElementById("selectionSummary");
const selectionPreview = document.getElementById("selectionPreview");
const importFile = document.getElementById("importSelection");
const importStatus = document.getElementById("importStatus");
const importPreview = document.getElementById("importPreview");
const addImported = document.getElementById("addImported");
const replaceImported = document.getElementById("replaceImported");
const saveDiff = document.getElementById("saveDiff");
const saveRoleDiff = document.getElementById("saveRoleDiff");
let importSequence = 0, importedSlots = null;
const selectedSlots = new Set();
const printScope = document.getElementById("printScope");
const summary = document.getElementById("summary");
const fieldNames = ["original_slot","latest_suggested_role","private_human_reply_status",
  "latest_self_reported_human_stage","suggested_operator_next_step",
  "private_note_changed"];
if (!Array.isArray(source) || source.length < 1 || source.length > 16) {
  progress.textContent = "No bounded original HUMAN action rows admitted.";
  return;
}
const lookup = [];
function option(select, value, label) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = label;
  select.append(item);
}
option(roleFilter,"ALL","All suggested HUMAN roles");
option(replyFilter,"ALL","All recipient return statuses");
option(nextFilter,"ALL","All HUMAN next steps");
option(stageFilter,"ALL","All self-reported HUMAN stages");
option(noteFilter,"ALL","All private note change flags");
for (const value of [...new Set(source.map(r=>r[1]))].sort()) {
  option(roleFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[2]))].sort()) {
  option(replyFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[4]))].sort()) {
  option(nextFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[3]))].sort()) {
  option(stageFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[5]))].sort()) {
  option(noteFilter,value,value.replaceAll("_"," "));
}
for (const row of source) {
  if (!Array.isArray(row) || row.length !== 6) {
    progress.textContent = "Invalid bounded local HUMAN action row.";
    root.replaceChildren();
    return;
  }
  const tr = document.createElement("tr");
  const slotCell = document.createElement("td");
  const label = document.createElement("label");
  label.className = "slotselect";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label","Select original slot " + row[0]);
  checkbox.addEventListener("change",()=>{
    if (checkbox.checked) selectedSlots.add(row[0]);
    else selectedSlots.delete(row[0]);
    apply();
  });
  label.append(checkbox,document.createTextNode(String(row[0])));
  slotCell.append(label); tr.append(slotCell);
  for (const value of row.slice(1)) {
    const td = document.createElement("td");
    td.textContent = String(value).replaceAll("_"," "); tr.append(td);
  }
  root.append(tr);
  lookup.push({values:row,element:tr,checkbox});
}
function renderImportPreview() {
  importPreview.replaceChildren();
  saveDiff.disabled = !importedSlots;
  saveRoleDiff.disabled = !importedSlots || roleFilter.value === "ALL" ||
    !lookup.some(({values})=>values[1] === roleFilter.value &&
      (selectedSlots.has(values[0]) || importedSlots.has(values[0])));
  if (!importedSlots) return;
  const sourceOnly = [...selectedSlots].filter(slot => !importedSlots.has(slot));
  const importedOnly = [...importedSlots].filter(slot => !selectedSlots.has(slot));
  const shared = [...importedSlots].filter(slot => selectedSlots.has(slot));
  const summary = document.createElement("p");
  summary.textContent = "Source-matched PRIVATE draft · " + importedSlots.size +
    " imported · " + shared.length + " already selected · " +
    importedOnly.length + " import-only · " + sourceOnly.length + " current-only.";
  importPreview.append(summary);
  for (const [label,items] of [["Imported only",importedOnly],
                                ["Current only",sourceOnly],["Both",shared]]) {
    const line = document.createElement("p");
    line.textContent = label + " original slot ordinals: " +
      (items.length ? items.sort((a,b)=>a-b).join(", ") : "none");
    importPreview.append(line);
  }
  if (roleFilter.value !== "ALL") {
    const role = roleFilter.value;
    const roleCurrent = [...selectedSlots].filter(slot => lookup.some(({values}) =>
      values[0] === slot && values[1] === role));
    const roleImported = [...importedSlots].filter(slot => lookup.some(({values}) =>
      values[0] === slot && values[1] === role));
    const roleUnion = lookup.filter(({values}) => values[1] === role &&
      (selectedSlots.has(values[0]) || importedSlots.has(values[0]))).map(({values}) => values[0]);
    const detail = document.createElement("p");
    detail.textContent = "Proposed role-only export · " + role.replaceAll("_", " ") +
      " · " + roleCurrent.length + " current · " + roleImported.length +
      " imported · " + roleUnion.length + " rows. Recipient identity is not verified.";
    importPreview.append(detail);
    for (const [label,items] of [["Role-only imported",roleImported.filter(slot=>!selectedSlots.has(slot))],
      ["Role-only current",roleCurrent.filter(slot=>!importedSlots.has(slot))],
      ["Role-only in both",roleUnion.filter(slot=>selectedSlots.has(slot)&&importedSlots.has(slot))]]) {
      const line = document.createElement("p");
      line.textContent = label + " original slot ordinals: " +
        (items.length ? items.sort((a,b)=>a-b).join(", ") : "none");
      importPreview.append(line);
    }
  }
  addImported.disabled = importedOnly.length === 0;
  replaceImported.disabled = sourceOnly.length !== 0 || importedOnly.length !== 0 ? false : true;
}
function apply() {
  let visible = 0, awaiting = 0, visibleSelected = 0;
  const byAction = new Map();
  for (const {values,element,checkbox} of lookup) {
    const keep = (roleFilter.value === "ALL" || roleFilter.value === values[1]) &&
      (replyFilter.value === "ALL" || replyFilter.value === values[2]) &&
      (nextFilter.value === "ALL" || nextFilter.value === values[4]) &&
      (stageFilter.value === "ALL" || stageFilter.value === values[3]) &&
      (noteFilter.value === "ALL" || noteFilter.value === values[5]);
    element.hidden = !keep;
    const checked = selectedSlots.has(values[0]);
    checkbox.checked = checked;
    if (keep) {
      if (checked) visibleSelected++;
      visible++;
      byAction.set(values[4], (byAction.get(values[4]) || 0) + 1);
      if (values[2] === "AWAITING_HUMAN_ROLE_REPLY") awaiting++;
    }
  }
  progress.textContent = visible + " of " + lookup.length +
    " original local HUMAN slots displayed · " + awaiting +
    " awaiting an original role reply in the selected view.";
  selectionSummary.textContent = selectedSlots.size + " explicitly selected original slots · " +
    visibleSelected + " selected in the current view. Selection stays in memory only.";
  const selectedRows = lookup.filter(({values})=>selectedSlots.has(values[0])).map(({values})=>values);
  selectionPreview.replaceChildren();
  if (!selectedRows.length) selectionPreview.textContent = "No original slots selected yet.";
  else {
    const table = document.createElement("table");
    const labels = ["Original slot","Suggested role","Reply status","Self-reported stage",
      "Suggested next action","PRIVATE note changed?"];
    const head = document.createElement("tr");
    for (const value of labels) { const th=document.createElement("th");th.textContent=value;head.append(th); }
    const thead=document.createElement("thead");thead.append(head);table.append(thead);
    const tbody=document.createElement("tbody");
    for (const row of selectedRows) {
      const tr=document.createElement("tr");
      for (const value of row) { const td=document.createElement("td");td.textContent=String(value).replaceAll("_"," ");tr.append(td); }
      tbody.append(tr);
    }
    table.append(tbody);selectionPreview.append(table);
  }
  const filters = [roleFilter, replyFilter, nextFilter, stageFilter, noteFilter].map(item =>
    item.options[item.selectedIndex].textContent);
  printScope.textContent = "PRIVATE selected view · " + filters.join(" · ") +
    " · " + visible + " / " + lookup.length + " original local slots";
  summary.textContent = [...byAction.entries()].sort().map(([key,count]) =>
    key.replaceAll("_"," ") + ": " + count).join(" · ") || "No matching HUMAN actions.";
  saveButton.disabled = selectedSlots.size === 0;
  saveVisibleSelected.disabled = visibleSelected === 0;
  selectVisibleButton.disabled = visible === 0;
  deselectVisibleButton.disabled = visibleSelected === 0;
  clearSelectionButton.disabled = selectedSlots.size === 0;
  printButton.disabled = visible === 0;
  renderImportPreview();
}
const allFilters = [roleFilter,replyFilter,nextFilter,stageFilter,noteFilter];
for (const item of allFilters) item.addEventListener("change",apply);
resetButton.addEventListener("click",()=>{
  for (const item of allFilters) item.value = "ALL";
  apply();
});
function loadImported(raw) {
  if (typeof raw !== "string" || !raw.endsWith("\r\n") ||
      raw.includes("\uFEFF") || raw.includes("\u0000")) throw Error("Noncanonical PRIVATE CSV");
  const lines = raw.slice(0,-2).split("\r\n");
  if (lines.length < 2 || lines.length > source.length + 1 ||
      lines[0] !== fieldNames.join(",")) throw Error("Wrong original-source CSV schema");
  const originals = new Map(lookup.map(({values},i)=>[String(values[0]),
    {line:values.map(csvCell).join(","),index:i}]));
  const staged = new Set();
  let previous = -1;
  for (const line of lines.slice(1)) {
    const fields = line.split(",");
    if (fields.length !== 6) throw Error("Invalid fixed HUMAN CSV row");
    const sourceRow = originals.get(fields[0]);
    if (!sourceRow || sourceRow.line !== line || sourceRow.index <= previous)
      throw Error("PRIVATE selected rows differ from original source or order");
    previous = sourceRow.index;
    staged.add(Number(fields[0]));
  }
  if (staged.size !== lines.length - 1) throw Error("Duplicate original slot");
  return staged;
}
importFile.addEventListener("change",async()=>{
  const ticket = ++importSequence;
  importedSlots = null;
  addImported.disabled = replaceImported.disabled = saveDiff.disabled = true;
  importStatus.textContent = "Checking selected PRIVATE CSV against original local HUMAN source…";
  importPreview.replaceChildren();
  const file = importFile.files && importFile.files[0];
  if (!file) { importStatus.textContent = "No PRIVATE CSV selected.";return; }
  try {
    if (!file.size || file.size > 8192) throw Error("PRIVATE CSV size outside bound");
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (ticket !== importSequence) return;
    const raw = new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    importedSlots = loadImported(raw);
    importStatus.textContent = "Source-matched unsigned PRIVATE selection. Review differences before applying.";
  } catch (_) {
    if (ticket !== importSequence) return;
    importedSlots = null;
    importStatus.textContent = "HOLD: selected CSV rejected. Current selection unchanged.";
  } finally {
    if (ticket === importSequence) { importFile.value="";renderImportPreview(); }
  }
});
addImported.addEventListener("click",()=>{
  if (!importedSlots) return;
  for (const slot of importedSlots) selectedSlots.add(slot);
  apply();
});
replaceImported.addEventListener("click",()=>{
  if (!importedSlots) return;
  selectedSlots.clear();
  for (const slot of importedSlots) selectedSlots.add(slot);
  apply();
});
function downloadSelectionDiff(roleOnly) {
  if (!importedSlots) return;
  const role = roleOnly ? roleFilter.value : null;
  if (roleOnly && (!role || role === "ALL")) return;
  // Unsigned operator order is not chronology; emit fixed labels, never source text.
  const headings = [fieldNames[0],"selection_change",...fieldNames.slice(1)];
  const rows = lookup.filter(({values})=>(!role || values[1] === role) &&
    (selectedSlots.has(values[0]) || importedSlots.has(values[0]))).map(({values})=>{
      const before = selectedSlots.has(values[0]), after = importedSlots.has(values[0]);
      const change = before && after ? "UNCHANGED_SELECTION" :
        after ? "NEWLY_SELECTED" : "NO_LONGER_SELECTED";
      return [values[0],change,...values.slice(1)].map(csvCell).join(",");
    });
  if (!rows.length) return;
  const raw = [headings.join(","),...rows].join("\r\n") + "\r\n";
  const url = URL.createObjectURL(new Blob([raw],{type:"text/csv;charset=utf-8"}));
  const link=document.createElement("a");link.href=url;
  link.download = role ? "lightup-PRIVATE-human-selection-changes-" +
    role.toLowerCase().replaceAll("_","-") + ".csv" :
    "lightup-PRIVATE-human-selection-changes.csv";
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
saveDiff.addEventListener("click",()=>downloadSelectionDiff(false));
saveRoleDiff.addEventListener("click",()=>downloadSelectionDiff(true));
selectVisibleButton.addEventListener("click",()=>{
  for (const {values,element} of lookup) if (!element.hidden) selectedSlots.add(values[0]);
  apply();
});
deselectVisibleButton.addEventListener("click",()=>{
  for (const {values,element} of lookup) if (!element.hidden) selectedSlots.delete(values[0]);
  apply();
});
clearSelectionButton.addEventListener("click",()=>{selectedSlots.clear();apply();});
printButton.addEventListener("click",()=>window.print());
// Fixed-enum, ordinal-only CSV: no endpoint, reviewer, note or local source path.
// Explicit user action only. Never send data to a server or browser storage.
function csvCell(value) {
  const item = String(value);
  if (!/^[A-Z_0-9]+$/.test(item)) throw Error("Noncanonical HUMAN export cell");
  return item;
}
function downloadSourceSelected(rows, filename) {
  if (!rows.length) return;
  const data = [fieldNames.join(","),
    ...rows.map(row => row.map(csvCell).join(","))].join("\r\n") + "\r\n";
  const objectUrl = URL.createObjectURL(new Blob([data],{type:"text/csv;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = objectUrl; link.download = filename;
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(objectUrl),1000);
}
saveButton.addEventListener("click",()=>{
  const rows = lookup.filter(({values})=>selectedSlots.has(values[0])).map(({values})=>values);
  downloadSourceSelected(rows,"lightup-PRIVATE-human-actions-selected.csv");
});
saveVisibleSelected.addEventListener("click",()=>{
  const rows = lookup.filter(({values,element})=>
    selectedSlots.has(values[0]) && !element.hidden).map(({values})=>values);
  downloadSourceSelected(rows,"lightup-PRIVATE-human-actions-selected-visible.csv");
});
apply();
})();'''


def render(work):
    if not 1 <= len(work) <= 16:
        raise Hold("HUMAN next-action browser accepts 1-16 original local slots")
    seen = set()
    source_slots = []
    for row in work:
        if (not isinstance(row, tuple) or len(row) != 6 or
                type(row[0]) is not int or row[0] < 1 or row[0] > 16 or
                row[0] in seen or row[1] not in ROLES or
                row[2] not in STATUSES or row[3] not in STAGES or
                row[4] not in NEXT or row[5] not in NOTES):
            raise Hold("HUMAN action browser source is not fixed original metadata")
        seen.add(row[0])
        source_slots.append(row[0])
    if source_slots != sorted(source_slots):
        raise Hold("HUMAN action browser must preserve original source slot order")
    encoded = base64.b64encode(json.dumps(work, ensure_ascii=True,
                                          separators=(",", ":")).encode("utf-8")).decode("ascii")
    script = SCRIPT.replace("__ROWS64__", json.dumps(encoded))
    css_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    js_hash = base64.b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + css_hash + "'; script-src 'sha256-" +
        js_hash + "'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " frame-src 'none'; worker-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN next-action desk</title><style>" + STYLE +
        "</style></head><body><header><p>LIGHTUP / OFFLINE HUMAN-ONLY</p>"
        "<h1>PRIVATE HUMAN next-action desk</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD ·"
        " REVIEW_ONLY · NO AUTHORIZATION</p></header>"
        "<main><p>All original local HUMAN slots; filter proposed actions by "
        "voluntarily suggested role, received source-bound packet, suggested "
        "next action, self-reported stage and private-note-change marker. "
        "Priority is operator-selected, not authenticated time."
        " No endpoint URLs, note text or reviewer identities are loaded."
        " Browser filters and explicit slot selections exist in memory only. "
        "Printed pages contain displayed rows; CSV downloads contain only "
        "explicitly selected original slots, including selected rows hidden "
        "by current filters. The role-only difference export excludes all other roles; other display filters do not narrow it. The full "
        "original CSV in the PRIVATE source directory remains unchanged. "
        "CSV downloads are unencrypted PRIVATE files.</p>"
        "<section class='panel filters'>"
        "<label for='role'>Suggested HUMAN role<select id='role'></select></label>"
        "<label for='reply'>Role return<select id='reply'></select></label>"
        "<label for='next'>Suggested HUMAN action<select id='next'></select></label>"
        "<label for='stage'>Self-reported HUMAN stage<select id='stage'></select></label>"
        "<label for='note'>PRIVATE note changed?<select id='note'></select></label>"
        "</section><section class='panel'>"
        "<button type='button' id='reset'>Clear all HUMAN filters</button>"
        "<p id='progress' role='status' aria-live='polite'></p>"
        "<p id='summary' role='status' aria-live='polite'></p>"
        "<p id='printScope'>PRIVATE selected HUMAN view</p>"
        "<button type='button' id='selectVisible'>Select displayed slots</button> "
        "<button type='button' id='deselectVisible'>Deselect displayed slots</button> "
        "<button type='button' id='clearSelection'>Clear all selections</button> "
        "<button type='button' id='print'>Print only displayed PRIVATE rows</button> "
        "<button type='button' id='saveSelected' disabled>Download all selected PRIVATE rows</button> "
        "<button type='button' id='saveVisibleSelected' disabled>Download selected-and-visible PRIVATE rows</button>"
        "<p id='selectionSummary' role='status' aria-live='polite'>0 explicitly selected slots.</p>"
        "<div class='importpanel'><h3>Reopen earlier PRIVATE selected HUMAN CSV</h3>"
        "<p>Read the exact original-bound CSV locally; no selection is changed until "
        "you explicitly choose Add or Replace. Manual source order is not chronology.</p>"
        "<label for='importSelection'>Previously downloaded PRIVATE CSV"
        "<input type='file' id='importSelection' accept='.csv,text/csv'></label>"
        "<p id='importStatus' role='status' aria-live='polite'>No previous selection loaded.</p>"
        "<div id='importPreview' aria-live='polite'></div>"
        "<button type='button' id='addImported' disabled>Add imported selection</button> "
        "<button type='button' id='replaceImported' disabled>Replace current selection</button> "
        "<button type='button' id='saveDiff' disabled>Download all-role PRIVATE selection differences CSV</button>"
        "<button type='button' id='saveRoleDiff' disabled>Download selected-role-only differences CSV</button>"
        "<small>Selected-role-only export requires one suggested role and excludes every other role, even if its rows are selected. "
        "This is not verified role assignment, reviewer authentication, consent or HUMAN GO.</small></div>"
        "<details class='selectionpreview'><summary>Review selected rows before CSV download</summary>"
        "<div id='selectionPreview' class='tablewrap' aria-live='polite'>No original slots selected yet.</div></details>"
        "<div class='tablewrap'><table><thead><tr><th>Select / original slot</th>"
        "<th>Suggested role</th><th>Returned packet</th><th>Last HUMAN stage</th>"
        "<th>Suggested next HUMAN action</th><th>PRIVATE note changed?</th>"
        "</tr></thead><tbody id='actionRows'></tbody></table></div></section>"
        "<small>These are self-reported HUMAN planning labels, NOT verified "
        "security findings, reviewer authentication, remediation proof,"
        " client/operator consent, scope grant, or HUMAN GO. Do not host or"
        " forward this PRIVATE report publicly.</small></main>"
        "<footer>No browser storage, network access, scanning or target execution.</footer>"
        "<script>" + script + "</script></body></html>"
    ).encode("utf-8")
