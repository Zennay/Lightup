#!/usr/bin/env python3
"""Offline HUMAN-only cross-agenda worksheet and private source-bound return.

Never validates consent, starts assessments, contacts targets or authenticates reviewers.
"""
from __future__ import annotations

import base64
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
import stat
import unicodedata

SCHEMA = "lightup.assessment_portfolio_human_worksheet.v1"
STATUS = ("PENDING_HUMAN", "DISCUSSING", "AWAITING_ORIGINAL", "DOCUMENTED_DISCUSSION")
ROLES = ("unassigned", "source_owner", "reviewer", "privacy", "operator")
AUTHORITY_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
MAX_ROWS = 768
MAX_WORKSHEET_BYTES = 256 * 1024
MAX_NOTE = 160
JS = r'''"use strict";
const boot = document.getElementById("worksheet-seed");
const data = JSON.parse(boot.textContent);
const original = JSON.parse(JSON.stringify(data));
boot.remove();
const rows = document.querySelector("#humanRows");
const stages = ["PENDING_HUMAN", "DISCUSSING", "AWAITING_ORIGINAL", "DOCUMENTED_DISCUSSION"];
const roles = ["unassigned", "source_owner", "reviewer", "privacy", "operator"];
const selectedRows = new Set();
const rowNodes = [];
let batchUndo = null;
const state = document.getElementById("savedState");
const progress = document.getElementById("humanProgress");
const batchSummary = document.getElementById("batchSummary");
const plain = (label, value) => {
  const cell = document.createElement("td"); cell.textContent = String(value); return cell;
};
const clearSelection = () => {
  selectedRows.clear();
  for (const row of rowNodes) {
    const checkbox = row.querySelector("input[type=checkbox]");
    if (checkbox) checkbox.checked = false;
  }
  syncSelectionUi();
  updateBatchControls();
};
const syncSelectionUi = () => {
  const visible = rowNodes.map((row, index) => ({row, index})).filter(item => !item.row.hidden);
  const count = visible.filter(item => selectedRows.has(item.index)).length;
  const master = document.getElementById("selectVisibleRows");
  master.checked = visible.length > 0 && count === visible.length;
  master.indeterminate = count > 0 && count < visible.length;
  document.getElementById("clearSelectedRows").disabled = selectedRows.size === 0;
};
for (const [index, entry] of data.entries.entries()) {
  const tr = document.createElement("tr");
  tr.dataset.rowIndex = String(index);
  const chooseCell = document.createElement("td");
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label", "Select HUMAN row agenda " + entry.agenda_slot +
    " source slot " + entry.source_slot);
  checkbox.addEventListener("change", () => {
    if (checkbox.checked && !tr.hidden) selectedRows.add(index);
    else selectedRows.delete(index);
    syncSelectionUi(); updateBatchControls();
  });
  chooseCell.append(checkbox); tr.append(chooseCell);
  tr.append(plain("slot", "A" + String(entry.agenda_slot).padStart(2, "0") + "/S" +
    String(entry.source_slot).padStart(2, "0")));
  tr.append(plain("date", entry.proposed_review_date || "unscheduled"));
  tr.append(plain("role", entry.source_next_role));
  tr.append(plain("status", entry.source_stage));
  for (const [key, options] of [["human_status", stages], ["proposed_role", roles]]) {
    const td = document.createElement("td");
    const select = document.createElement("select");
    select.setAttribute("aria-label", key + " for agenda " + entry.agenda_slot +
      " source slot " + entry.source_slot);
    for (const value of options) {
      const option = document.createElement("option"); option.value = value;
      option.textContent = value; select.append(option);
    }
    select.value = entry[key];
    select.addEventListener("change", () => {
      entry[key] = select.value; batchUndo = null; filterRows();
      state.textContent = "Individual HUMAN edit made. Previous batch Undo is no longer available.";
      reportProgress(); updateBatchControls();
    });
    td.append(select); tr.append(td);
  }
  const noteCell = document.createElement("td");
  const note = document.createElement("input"); note.type = "text"; note.maxLength = 160;
  note.placeholder = "PRIVATE HUMAN note; never enter secrets"; note.value = entry.note;
  note.setAttribute("aria-label", "Private non-authorizing HUMAN note for agenda " +
    entry.agenda_slot + " source slot " + entry.source_slot);
  note.addEventListener("input", () => {
    entry.note = note.value; batchUndo = null; filterRows();
    state.textContent = "Individual HUMAN edit made. Previous batch Undo is no longer available.";
    reportProgress(); updateBatchControls();
  });
  noteCell.append(note); tr.append(noteCell);
  rows.append(tr); rowNodes.push(tr);
}
const reportProgress = () => {
  const changes = data.entries.filter((entry, index) =>
    entry.human_status !== original.entries[index].human_status ||
    entry.proposed_role !== original.entries[index].proposed_role ||
    entry.note !== original.entries[index].note
  ).length;
  const nonempty = data.entries.filter(entry => entry.note.length > 0).length;
  progress.textContent = changes + " of " + data.entries.length +
    " local HUMAN discussions changed; " + nonempty +
    " PRIVATE notes. Unverified and unsaved until explicit download.";
};
const exactKeys = (one, two) => JSON.stringify(Object.keys(one).sort()) ===
  JSON.stringify(Object.keys(two).sort());
const filterRows = () => {
  const statusFilter = document.getElementById("filterHumanStatus").value;
  const roleFilter = document.getElementById("filterProposedRole").value;
  const query = document.getElementById("filterHumanSearch").value.trim().toLocaleLowerCase();
  clearSelection();
  for (const [index, row] of rowNodes.entries()) {
    const entry = data.entries[index];
    const haystack = [entry.agenda_slot, entry.source_slot, entry.source_kind,
      entry.source_stage, entry.source_next_role, entry.proposed_review_date || "",
      entry.date_bucket, entry.human_status, entry.proposed_role].join(" ").toLocaleLowerCase();
    row.hidden = !!((statusFilter && entry.human_status !== statusFilter) ||
      (roleFilter && entry.proposed_role !== roleFilter) ||
      (query && !haystack.includes(query)));
  }
  syncSelectionUi(); updateBatchControls();
  document.getElementById("visibleHumanRows").textContent =
    rowNodes.filter(row => !row.hidden).length + " of " + rowNodes.length +
    " HUMAN rows visible. Filtering is local and does not change source rows.";
};
const updateBatchControls = () => {
  const selected = [...selectedRows].filter(index => rowNodes[index] && !rowNodes[index].hidden);
  const targetStage = document.getElementById("batchHumanStatus").value;
  const targetRole = document.getElementById("batchProposedRole").value;
  const changes = selected.filter(index => {
    const entry = data.entries[index];
    return (targetStage && entry.human_status !== targetStage) ||
      (targetRole && entry.proposed_role !== targetRole);
  });
  const stageChanges = changes.filter(index => targetStage &&
    data.entries[index].human_status !== targetStage).length;
  const roleChanges = changes.filter(index => targetRole &&
    data.entries[index].proposed_role !== targetRole).length;
  document.getElementById("applyHumanBatch").disabled =
    !selected.length || !changes.length || (!targetStage && !targetRole);
  const canUndo = !!batchUndo && batchUndo.binding === original.source_row_binding &&
    batchUndo.changes.every(change => data.entries[change.index].human_status === change.afterStatus &&
      data.entries[change.index].proposed_role === change.afterRole);
  document.getElementById("undoHumanBatch").disabled = !canUndo;
  if (batchUndo && !canUndo) batchUndo = null;
  batchSummary.textContent = selected.length
    ? changes.length + " of " + selected.length + " selected visible rows would change" +
      (targetStage ? "; " + stageChanges + " HUMAN stage change(s)" : "") +
      (targetRole ? "; " + roleChanges + " proposed-role change(s)" : "") +
      ". Nothing changes until you confirm. Unselected rows, notes and original source fields are excluded."
    : "Select individual visible rows or use the table header checkbox. Choose a target HUMAN stage and/or role to preview.";
};
const applyHumanBatch = () => {
  const selected = [...selectedRows].filter(index => rowNodes[index] && !rowNodes[index].hidden);
  const targetStage = document.getElementById("batchHumanStatus").value;
  const targetRole = document.getElementById("batchProposedRole").value;
  if (!selected.length || (!targetStage && !targetRole)) return;
  const changes = selected.filter(index => {
    const entry = data.entries[index];
    return (targetStage && entry.human_status !== targetStage) ||
      (targetRole && entry.proposed_role !== targetRole);
  }).map(index => {
    const entry = data.entries[index];
    return {index, beforeStatus: entry.human_status, beforeRole: entry.proposed_role,
      afterStatus: targetStage || entry.human_status, afterRole: targetRole || entry.proposed_role};
  });
  if (!changes.length) return;
  const stageCount = changes.filter(change => change.beforeStatus !== change.afterStatus).length;
  const roleCount = changes.filter(change => change.beforeRole !== change.afterRole).length;
  if (!window.confirm("Apply HUMAN-only changes to " + changes.length + " of " + selected.length +
    " selected visible rows? This changes " + stageCount + " stage(s) and " + roleCount +
    " proposed role(s). Notes and original source fields stay unchanged. This is not approval, evidence or authorization.")) return;
  for (const change of changes) {
    const entry = data.entries[change.index]; entry.human_status = change.afterStatus;
    entry.proposed_role = change.afterRole;
    const selects = rowNodes[change.index].querySelectorAll("select");
    selects[0].value = entry.human_status; selects[1].value = entry.proposed_role;
  }
  batchUndo = {binding: original.source_row_binding, changes};
  filterRows(); reportProgress(); updateBatchControls();
  state.textContent = "Applied " + changes.length +
    " explicitly selected HUMAN row(s). One-step Undo is available until another HUMAN edit or source restore.";
};
const undoHumanBatch = () => {
  if (!batchUndo || batchUndo.binding !== original.source_row_binding) return;
  if (!batchUndo.changes.every(change =>
    data.entries[change.index].human_status === change.afterStatus &&
    data.entries[change.index].proposed_role === change.afterRole)) {
    batchUndo = null; updateBatchControls();
    state.textContent = "Undo expired because HUMAN values changed after the batch.";
    return;
  }
  for (const change of batchUndo.changes) {
    const entry = data.entries[change.index]; entry.human_status = change.beforeStatus;
    entry.proposed_role = change.beforeRole;
    const selects = rowNodes[change.index].querySelectorAll("select");
    selects[0].value = entry.human_status; selects[1].value = entry.proposed_role;
  }
  batchUndo = null; filterRows(); reportProgress(); updateBatchControls();
  state.textContent = "Last HUMAN batch reverted in memory. Original source fields and notes were never changed.";
};
document.getElementById("selectVisibleRows").addEventListener("change", () => {
  for (const [index, row] of rowNodes.entries()) {
    if (row.hidden) continue;
    const checkbox = row.querySelector("input[type=checkbox]");
    if (document.getElementById("selectVisibleRows").checked) {
      selectedRows.add(index); checkbox.checked = true;
    } else { selectedRows.delete(index); checkbox.checked = false; }
  }
  syncSelectionUi(); updateBatchControls();
});
document.getElementById("clearSelectedRows").addEventListener("click", clearSelection);
for (const id of ["filterHumanStatus", "filterProposedRole", "filterHumanSearch"])
  document.getElementById(id).addEventListener(id === "filterHumanSearch" ? "input" : "change", filterRows);
for (const id of ["batchHumanStatus", "batchProposedRole"])
  document.getElementById(id).addEventListener("change", updateBatchControls);
document.getElementById("applyHumanBatch").addEventListener("click", applyHumanBatch);
document.getElementById("undoHumanBatch").addEventListener("click", undoHumanBatch);
const restore = document.getElementById("restoreWorksheet");
restore.addEventListener("change", async event => {
  const file = event.target.files && event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (file.size < 1 || file.size > 262144) {
    state.textContent = "HOLD: PRIVATE worksheet file exceeds accepted byte limits."; return;
  }
  let imported;
  try { imported = JSON.parse(await file.text()); }
  catch (_) { state.textContent = "HOLD: PRIVATE HUMAN JSON cannot be read."; return; }
  if (!imported || typeof imported !== "object" || Array.isArray(imported) ||
      !exactKeys(imported, original) || !Array.isArray(imported.entries) ||
      imported.entries.length !== original.entries.length ||
      !Object.keys(original).filter(key => key !== "entries").every(key =>
        JSON.stringify(imported[key]) === JSON.stringify(original[key]))) {
    state.textContent = "HOLD: original source binding or HUMAN worksheet envelope changed."; return;
  }
  const immutable = ["agenda_slot", "source_slot", "source_kind", "source_stage",
    "source_next_role", "proposed_review_date", "date_bucket"];
  const safeNote = note => typeof note === "string" && note.length <= 160 &&
    !/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069]/u.test(note);
  const valid = imported.entries.every((entry, index) => entry &&
    typeof entry === "object" && !Array.isArray(entry) &&
    exactKeys(entry, original.entries[index]) &&
    immutable.every(key => entry[key] === original.entries[index][key]) &&
    stages.includes(entry.human_status) && roles.includes(entry.proposed_role) &&
    safeNote(entry.note));
  if (!valid) {
    state.textContent = "HOLD: row values or HUMAN-only fields are invalid."; return;
  }
  // Whole document accepted atomically; never apply an invalid partial import.
  imported.entries.forEach((entry, index) => {
    Object.assign(data.entries[index], {
      human_status: entry.human_status, proposed_role: entry.proposed_role, note: entry.note
    });
    const tr = rows.children[index];
    const selects = tr.querySelectorAll("select");
    selects[0].value = entry.human_status;
    selects[1].value = entry.proposed_role;
    tr.querySelector("input[type=text]").value = entry.note;
  });
  batchUndo = null; clearSelection(); filterRows(); reportProgress();
  state.textContent = "PRIVATE HUMAN worksheet reopened locally. Native source/JSON admission is still required before a new bundle.";
});
reportProgress(); filterRows();
document.getElementById("saveWorksheet").addEventListener("click", () => {
  for (const entry of data.entries) {
    if (entry.note.length > 160 || /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]/u.test(entry.note)) {
      state.textContent = "HOLD: remove control characters or overlong notes before private export."; return;
    }
  }
  const output = JSON.stringify(data, null, 2) + "\n";
  if (new TextEncoder().encode(output).length > 262144) {
    state.textContent = "HOLD: private worksheet would exceed the native size bound."; return;
  }
  const blob = new Blob([output], {type:"application/json;charset=utf-8"});
  const uri = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = uri;
  link.download = "lightup-PRIVATE-HUMAN-worksheet.json"; link.rel = "noopener";
  link.click(); setTimeout(() => URL.revokeObjectURL(uri), 5000);
  state.textContent = "PRIVATE HUMAN worksheet downloaded locally. Original agenda unchanged; return requires native strict readmission.";
});'''.strip()
CSS = """body{background:#f3f5f8;color:#1b2837;font:16px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1200px;padding:1.5rem}h1{margin:.25rem 0}header,section{background:#fff;border:1px solid #ccd5df;border-radius:8px;padding:1rem;margin-bottom:1rem}.hold{border-left:5px solid #9b5012;padding:.8rem;background:#fff8ea;font-weight:700}.table{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.84rem}th,td{border:1px solid #dbe2e9;text-align:left;vertical-align:top;padding:.5rem}th{background:#e8edf4}input[type=text]{min-width:190px;max-width:250px}select,input[type=text],button{font:inherit;padding:.4rem;border-radius:4px;border:1px solid #9eabb9}button{cursor:pointer;background:#e2f0ff}p small{color:#566477}@media print{button,input[type=text]{display:none}}"""
CSS += """ .human-batch-tools{background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:.8rem;margin:.8rem 0}.human-batch-row{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center;margin:.45rem 0}.human-batch-row label{font-weight:650}.human-batch-tools input[type=search]{min-width:190px;max-width:300px}.human-batch-tools button:disabled{opacity:.5;cursor:not-allowed}#batchSummary,#visibleHumanRows{font-size:.9rem;color:#334155;margin:.45rem 0}[hidden]{display:none!important}@media print{.human-batch-tools,#selectVisibleRows,tbody input[type=checkbox]{display:none!important}}"""


class Hold(ValueError):
    pass


def _json_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Hold("duplicate key")
        out[key] = value
    return out


def _bad_constant(_):
    raise Hold("invalid JSON numeric constant")


def _bad_float(_):
    raise Hold("unexpected numeric field")


def _clean_note(value):
    if type(value) is not str or len(value) > MAX_NOTE:
        raise Hold("invalid HUMAN note")
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in value):
        raise Hold("unsafe HUMAN note")
    return value


def _snapshot(rows):
    # Reconstruct exclusively from already-admitted fixed-vocabulary canonical rows.
    return [
        {
            "agenda_slot": row["agenda_slot"],
            "source_slot": row["source_slot"],
            "source_kind": row["source_kind"],
            "source_stage": row["stage"],
            "source_next_role": row["next_role"],
            "proposed_review_date": row["review_date"],
            "date_bucket": row["date_bucket"],
        }
        for row in sorted(rows, key=lambda r: (r["agenda_slot"], r["source_slot"]))
    ]


def _binding(items, reference_date):
    canonical = json.dumps(
        {"reference_date": reference_date, "rows": items}, sort_keys=True,
        ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    return sha256(canonical).hexdigest()


def worksheet_seed(rows, reference_date):
    source = _snapshot(rows)
    if len(source) > MAX_ROWS:
        raise Hold("too many original HUMAN rows")
    result = {
        "schema": SCHEMA,
        "status": "PRIVATE_HUMAN_DRAFT_ONLY",
        "reference_date": reference_date,
        "source_row_binding": _binding(source, reference_date),
        "rows_from_original": len(source),
        "planning_not_permission": True,
        **{key: False for key in AUTHORITY_FLAGS},
        "entries": [
            {**item, "human_status": STATUS[0], "proposed_role": item["source_next_role"], "note": ""}
            for item in source
        ],
    }
    return result


def render_worksheet(rows, reference_date):
    seed = worksheet_seed(rows, reference_date)
    encoded = json.dumps(seed, ensure_ascii=True, separators=(",", ":"))
    # Never parse JSON through active HTML; the template is inert and literal text.
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    css_hash = base64.b64encode(sha256(CSS.encode()).digest()).decode()
    js_hash = base64.b64encode(sha256(JS.encode()).digest()).decode()
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'sha256-" + js_hash + "'; style-src 'sha256-" + css_hash +
        "'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN worksheet</title><style>" + CSS + "</style></head><body>"
        "<header><h1>PRIVATE HUMAN follow-up worksheet</h1>"
        "<p class='hold'>INCUBATE / PLAN-LAB ONLY / REVIEW_ONLY / NO AUTHORIZATION / NO SCAN</p>"
        "<p>Edit suggested human roles, discussion stages and short private HUMAN notes only."
        " Neither this worksheet nor its JSON export authenticates a person, source, finding, consent or completion."
        " Do not enter secrets, original targets or customer identifiers.</p></header>"
        "<section><p>Local reference day: " + escape(reference_date) + " · rows " +
        str(len(seed["entries"])) + " · original ordinal order only, not chronology.</p>"
        "<div class='human-batch-tools'><h2>Filter and batch HUMAN discussion</h2>"
        "<div class='human-batch-row'><label for='filterHumanStatus'>Current HUMAN state</label>"
        "<select id='filterHumanStatus'><option value=''>All states</option>"
        "<option>PENDING_HUMAN</option><option>DISCUSSING</option><option>AWAITING_ORIGINAL</option>"
        "<option>DOCUMENTED_DISCUSSION</option></select>"
        "<label for='filterProposedRole'>Proposed role</label><select id='filterProposedRole'>"
        "<option value=''>All roles</option><option>unassigned</option><option>source_owner</option>"
        "<option>reviewer</option><option>privacy</option><option>operator</option></select>"
        "<label for='filterHumanSearch'>Search fixed row fields</label>"
        "<input id='filterHumanSearch' type='search' maxlength='100' autocomplete='off' "
        "placeholder='Agenda/source ordinal, kind or stage'></div>"
        "<div class='human-batch-row'><label for='batchHumanStatus'>Set HUMAN state</label>"
        "<select id='batchHumanStatus'><option value=''>Leave unchanged</option>"
        "<option>PENDING_HUMAN</option><option>DISCUSSING</option><option>AWAITING_ORIGINAL</option>"
        "<option>DOCUMENTED_DISCUSSION</option></select>"
        "<label for='batchProposedRole'>Set proposed role</label><select id='batchProposedRole'>"
        "<option value=''>Leave unchanged</option><option>unassigned</option><option>source_owner</option>"
        "<option>reviewer</option><option>privacy</option><option>operator</option></select>"
        "<button type='button' id='applyHumanBatch' disabled>Preview &amp; confirm selected changes</button>"
        "<button type='button' id='undoHumanBatch' disabled>Undo last batch</button>"
        "<button type='button' id='clearSelectedRows' disabled>Clear selection</button></div>"
        "<p id='visibleHumanRows' role='status' aria-live='polite'></p>"
        "<p id='batchSummary' role='status' aria-live='polite'>Select visible rows and choose a proposed HUMAN change.</p></div>"
        "<div class='table'><table><thead><tr><th><input id='selectVisibleRows' type='checkbox' "
        "aria-label='Select all visible HUMAN rows'></th><th>Source ordinal</th><th>Proposed day</th>"
        "<th>Original role suggestion</th><th>Original HUMAN stage</th>"
        "<th>New HUMAN discussion state</th><th>Proposed role</th><th>PRIVATE note (max 160)</th>"
        "</tr></thead><tbody id='humanRows'></tbody></table></div>"
        "<p id='humanProgress' role='status' aria-live='polite'></p>"
        "<label for='restoreWorksheet'>Reopen earlier PRIVATE HUMAN draft (source-bound, no upload)</label> "
        "<input id='restoreWorksheet' type='file' accept='.json,application/json'> "
        "<button type='button' id='saveWorksheet'>Download private HUMAN response JSON</button>"
        "<p id='savedState' role='status' aria-live='polite'></p></section>"
        "<footer>No network, cookies, local storage, actual assignment, scan, grant or release.</footer>"
        "<template id='worksheet-seed'>" + encoded + "</template>"
        "<script>" + JS + "</script></body></html>"
    )
    return html.encode("utf-8")


def read_private_response(path, parent_opener):
    # Exact original file mode, owner, path and hardlink protection.
    directory, name = parent_opener(os.path.dirname(os.path.abspath(path)))
    try:
        fd = os.open(
            os.path.basename(os.path.abspath(path)),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_WORKSHEET_BYTES
        ):
            raise Hold("unsafe private HUMAN worksheet source")
        raw = stream.read(MAX_WORKSHEET_BYTES + 1)
        after = os.fstat(stream.fileno())
        signature = lambda st: (
            st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns
        )
        if signature(before) != signature(after) or len(raw) != before.st_size:
            raise Hold("changed private HUMAN worksheet source")
    try:
        obj = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_json_object,
            parse_constant=_bad_constant, parse_float=_bad_float
        )
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise Hold("invalid HUMAN JSON") from exc
    return raw, obj


def validate_response(doc, rows, reference_date):
    expected = worksheet_seed(rows, reference_date)
    keys = set(expected)
    if type(doc) is not dict or set(doc) != keys:
        raise Hold("unknown HUMAN worksheet fields")
    for key in keys - {"entries"}:
        if doc[key] != expected[key] or type(doc[key]) is not type(expected[key]):
            raise Hold("HUMAN worksheet source binding changed")
    entries = doc["entries"]
    if type(entries) is not list or len(entries) != len(expected["entries"]):
        raise Hold("wrong HUMAN rows count")
    for item, initial in zip(entries, expected["entries"]):
        if type(item) is not dict or set(item) != set(initial):
            raise Hold("unknown HUMAN row field")
        for key in set(initial) - {"human_status", "proposed_role", "note"}:
            if item[key] != initial[key] or type(item[key]) is not type(initial[key]):
                raise Hold("HUMAN source row was modified")
        if type(item["human_status"]) is not str or item["human_status"] not in STATUS:
            raise Hold("unrecognized HUMAN-only stage")
        if type(item["proposed_role"]) is not str or item["proposed_role"] not in ROLES:
            raise Hold("unrecognized proposed role")
        _clean_note(item["note"])
    return entries


def human_summary(entries, reference_date):
    """Small-cell-sensitive PRIVATE HUMAN-only counts, never a public benchmark."""
    by_status = {key: 0 for key in STATUS}
    by_role = {key: 0 for key in ROLES}
    by_status_role = {status: {role: 0 for role in ROLES} for status in STATUS}
    notes = 0
    for item in entries:
        by_status[item["human_status"]] += 1
        by_role[item["proposed_role"]] += 1
        by_status_role[item["human_status"]][item["proposed_role"]] += 1
        notes += bool(item["note"])
    return {
        "schema": "lightup.assessment_portfolio_human_summary.v1",
        "status": "PRIVATE_HUMAN_DISCUSSION_ONLY",
        "reference_date": reference_date,
        "row_count": len(entries),
        "human_notes_recorded": notes,
        "human_status_counts": by_status,
        "proposed_role_counts": by_role,
        "status_by_proposed_role": by_status_role,
        "private_not_anonymous": True,
        "planning_not_permission": True,
        **{flag: False for flag in AUTHORITY_FLAGS},
    }


def render_private_summary_json(entries, reference_date):
    return (json.dumps(
        human_summary(entries, reference_date), ensure_ascii=False, indent=2
    ) + "\n").encode("utf-8")


def render_private_return(entries, reference_date):
    table = []
    for item in entries:
        values = (
            "A" + str(item["agenda_slot"]).zfill(2) + " / S" + str(item["source_slot"]).zfill(2),
            item["source_stage"], item["human_status"], item["source_next_role"],
            item["proposed_role"], item["proposed_review_date"] or "unscheduled",
            item["note"] or "(no HUMAN note recorded)"
        )
        table.append("<tr>" + "".join("<td>" + escape(value) + "</td>" for value in values) + "</tr>")
    summary = human_summary(entries, reference_date)
    dashboard = (
        "<h2>Private HUMAN discussion state</h2><table border='1'>"
        "<thead><tr><th>HUMAN status</th>" +
        "".join("<th>" + escape(role) + "</th>" for role in ROLES) +
        "<th>Total</th></tr></thead><tbody>" +
        "".join(
            "<tr><th>" + escape(stage) + "</th>" +
            "".join("<td>" + str(summary["status_by_proposed_role"][stage][role]) +
                    "</td>" for role in ROLES) +
            "<td>" + str(summary["human_status_counts"][stage]) + "</td></tr>"
            for stage in STATUS
        ) + "</tbody></table>"
        "<p>PRIVATE local HUMAN notes: " + str(summary["human_notes_recorded"]) +
        "; total rows: " + str(summary["row_count"]) +
        ". Small-cell counts may reveal private planning context. Never publish as anonymous.</p>"
    )
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'none'; script-src 'none'; "
        "connect-src 'none'; form-action 'none'; base-uri 'none'\"><title>PRIVATE HUMAN response</title></head><body>"
        "<h1>Private HUMAN discussion return</h1>"
        "<p>INCUBATE / HOLD / HUMAN ONLY / NOT AUTHORIZED / NO TARGET / NO SCAN</p>"
        "<p>Reference day: " + escape(reference_date) + ". Ordinals are not authenticated chronology."
        " Fields are manually entered; none authenticates reviewer, consent or remediation.</p>"
        + dashboard +
        "<table border='1'><thead><tr><th>Original ordinal</th><th>Original stage</th><th>HUMAN status</th>"
        "<th>Original role</th><th>Proposed role</th><th>Proposed date</th><th>PRIVATE HUMAN note</th>"
        "</tr></thead><tbody>" + "".join(table) + "</tbody></table>"
        "<p>Source originals remain unchanged. PRIVATE non-authorizing local output only.</p></body></html>"
    )
    return body.encode("utf-8")


def human_comparison(previous, current, reference_date):
    """Order-only HUMAN discussion comparison. No verified chronology or remediation."""
    if len(previous) != len(current):
        raise Hold("HUMAN comparison rows do not match")
    transitions = {stage: {next_stage: 0 for next_stage in STATUS} for stage in STATUS}
    role_changes = 0
    note_changes = 0
    status_changes = 0
    changed = []
    for old, new in zip(previous, current):
        before = old["human_status"]
        after = new["human_status"]
        transitions[before][after] += 1
        role_changed = old["proposed_role"] != new["proposed_role"]
        note_changed = old["note"] != new["note"]
        stage_changed = before != after
        role_changes += role_changed
        note_changes += note_changed
        status_changes += stage_changed
        if stage_changed or role_changed or note_changed:
            changed.append({
                "agenda_slot": new["agenda_slot"],
                "source_slot": new["source_slot"],
                "old_status": before,
                "new_status": after,
                "old_role": old["proposed_role"],
                "new_role": new["proposed_role"],
                "note_changed": bool(note_changed),
            })
    return {
        "schema": "lightup.assessment_portfolio_human_delta.v1",
        "status": "PRIVATE_HUMAN_DISCUSSION_ONLY",
        "reference_date": reference_date,
        "row_count": len(current),
        "changed_human_rows": len(changed),
        "human_status_changes": status_changes,
        "proposed_role_changes": role_changes,
        "private_note_changes": note_changes,
        "human_status_transition_counts": transitions,
        "changed": changed,
        "private_not_anonymous": True,
        "operator_order_not_chronology": True,
        **{key: False for key in AUTHORITY_FLAGS},
    }


def render_private_comparison_json(previous, current, reference_date):
    # PRIVATE ordinal-level comparison, never a public/anonymous rollup.
    return (json.dumps(
        human_comparison(previous, current, reference_date),
        indent=2, ensure_ascii=False
    ) + "\n").encode("utf-8")


def render_private_comparison_html(previous, current, reference_date):
    summary = human_comparison(previous, current, reference_date)
    rows = []
    for change in summary["changed"]:
        values = (
            "A" + str(change["agenda_slot"]).zfill(2) + " / S" +
            str(change["source_slot"]).zfill(2),
            change["old_status"], change["new_status"],
            change["old_role"], change["new_role"],
            "YES — PRIVATE note bytes differed" if change["note_changed"] else "NO"
        )
        rows.append("<tr>" + "".join("<td>" + escape(v) + "</td>" for v in values) +
                    "</tr>")
    if not rows:
        rows.append("<tr><td colspan='6'>No changed HUMAN fields were found in the selected local pair."
                    " This does not prove completion or remediation.</td></tr>")
    content = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        "script-src 'none'; style-src 'none'; connect-src 'none'; base-uri 'none'\">"
        "<title>PRIVATE HUMAN discussion comparison</title></head><body>"
        "<h1>PRIVATE HUMAN discussion changes</h1>"
        "<p>INCUBATE / PLAN-LAB ONLY / HUMAN ONLY / HOLD / NO AUTHORIZATION</p>"
        "<p>Local reference day: " + escape(reference_date) +
        ". The source order is a HUMAN-selected comparison, never proven chronological."
        " No source identifiers, targets or note contents are shown.</p>"
        "<p>Changed row ordinals: " + str(summary["changed_human_rows"]) +
        "; status changes: " + str(summary["human_status_changes"]) +
        "; proposed-role changes: " + str(summary["proposed_role_changes"]) +
        "; private-note changes: " + str(summary["private_note_changes"]) + ".</p>"
        "<table border='1'><thead><tr><th>Original ordinal</th>"
        "<th>Earlier supplied HUMAN status</th><th>Later supplied HUMAN status</th>"
        "<th>Earlier proposed role</th><th>Later proposed role</th>"
        "<th>PRIVATE note changed?</th></tr></thead><tbody>" +
        "".join(rows) + "</tbody></table>"
        "<p>A documented discussion is not permission, an authenticated sign-off,"
        " a verified finding, or evidence of remediation. No network or active work.</p>"
        "</body></html>"
    )
    return content.encode("utf-8")


def human_timeline(rounds, reference_date):
    """Summarize 2–8 operator-ordered PRIVATE HUMAN rounds without claiming chronology."""
    if not isinstance(rounds, list) or not 2 <= len(rounds) <= 8:
        raise Hold("HUMAN timeline requires 2–8 separately admitted rounds")
    first = rounds[0]
    expected = [
        (item["agenda_slot"], item["source_slot"], item["source_stage"])
        for item in first
    ]
    for entries in rounds:
        if len(entries) != len(first):
            raise Hold("HUMAN timeline rounds do not have the same admitted rows")
        observed = [
            (item["agenda_slot"], item["source_slot"], item["source_stage"])
            for item in entries
        ]
        if observed != expected:
            raise Hold("HUMAN timeline source ordinals or original stages differ")

    row_views = []
    for row_index, base in enumerate(first):
        round_views = []
        for round_index, entries in enumerate(rounds):
            item = entries[row_index]
            previous = rounds[round_index - 1][row_index] if round_index else None
            status_changed = bool(previous is not None and
                                  previous["human_status"] != item["human_status"])
            role_changed = bool(previous is not None and
                                previous["proposed_role"] != item["proposed_role"])
            note_changed = bool(previous is not None and previous["note"] != item["note"])
            round_views.append({
                "round_ordinal": round_index + 1,
                "human_status": item["human_status"],
                "proposed_role": item["proposed_role"],
                "changed_since_previous": status_changed or role_changed or note_changed,
                "status_changed": status_changed,
                "role_changed": role_changed,
                "private_note_changed": note_changed,
            })
        row_views.append({
            "agenda_slot": base["agenda_slot"],
            "source_slot": base["source_slot"],
            "original_stage": base["source_stage"],
            "rounds": round_views,
        })

    round_summaries = []
    transitions = []
    for round_index, entries in enumerate(rounds):
        status_counts = {value: 0 for value in STATUS}
        role_counts = {value: 0 for value in ROLES}
        for item in entries:
            status_counts[item["human_status"]] += 1
            role_counts[item["proposed_role"]] += 1
        changed_rows = status_changes = role_changes = note_changes = 0
        if round_index:
            previous_entries = rounds[round_index - 1]
            status_transitions = {
                old_status: {new_status: 0 for new_status in STATUS}
                for old_status in STATUS
            }
            for old, new in zip(previous_entries, entries):
                status_changed = old["human_status"] != new["human_status"]
                role_changed = old["proposed_role"] != new["proposed_role"]
                note_changed = old["note"] != new["note"]
                status_changes += status_changed
                role_changes += role_changed
                note_changes += note_changed
                changed_rows += bool(status_changed or role_changed or note_changed)
                status_transitions[old["human_status"]][new["human_status"]] += 1
            transitions.append({
                "from_round": round_index,
                "to_round": round_index + 1,
                "changed_human_rows": changed_rows,
                "human_status_changes": status_changes,
                "proposed_role_changes": role_changes,
                "private_note_changes": note_changes,
                "human_status_transition_counts": status_transitions,
            })
        round_summaries.append({
            "round_ordinal": round_index + 1,
            "row_count": len(entries),
            "human_status_counts": status_counts,
            "proposed_role_counts": role_counts,
            "changed_human_rows_since_previous": changed_rows,
        })

    return {
        "schema": "lightup.assessment_portfolio_human_timeline.v1",
        "status": "PRIVATE_HUMAN_DISCUSSION_ONLY",
        "reference_date": reference_date,
        "row_count": len(first),
        "round_count": len(rounds),
        "round_order_is_operator_supplied_not_chronology": True,
        "round_summaries": round_summaries,
        "transitions": transitions,
        "rows": row_views,
        "private_not_anonymous": True,
        "planning_not_permission": True,
        **{key: False for key in AUTHORITY_FLAGS},
    }


def render_private_timeline_json(rounds, reference_date):
    """PRIVATE ordinal-level multi-round timeline; no notes or source identifiers."""
    return (json.dumps(
        human_timeline(rounds, reference_date), indent=2, ensure_ascii=False
    ) + "\n").encode("utf-8")


def render_private_timeline_csv(rounds, reference_date):
    summary = human_timeline(rounds, reference_date)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow((
        "agenda_slot", "source_slot", "original_stage", "round_ordinal",
        "human_status", "proposed_role", "changed_since_previous",
        "status_changed", "role_changed", "private_note_changed",
        "authority_status",
    ))
    for row in summary["rows"]:
        for item in row["rounds"]:
            writer.writerow((
                row["agenda_slot"], row["source_slot"], row["original_stage"],
                item["round_ordinal"], item["human_status"], item["proposed_role"],
                str(item["changed_since_previous"]).lower(),
                str(item["status_changed"]).lower(), str(item["role_changed"]).lower(),
                str(item["private_note_changed"]).lower(), "REVIEW_ONLY",
            ))
    return output.getvalue().encode("utf-8")


def render_private_timeline_html(rounds, reference_date):
    summary = human_timeline(rounds, reference_date)
    header = "".join("<th>Round " + str(index + 1) + "</th>"
                     for index in range(summary["round_count"]))
    table_rows = []
    for row in summary["rows"]:
        cells = [
            "<td>A" + str(row["agenda_slot"]).zfill(2) + " / S" +
            str(row["source_slot"]).zfill(2) + "</td>",
            "<td>" + escape(row["original_stage"]) + "</td>",
        ]
        for item in row["rounds"]:
            flags = []
            if item["status_changed"]:
                flags.append("stage changed")
            if item["role_changed"]:
                flags.append("role changed")
            if item["private_note_changed"]:
                flags.append("private note changed")
            detail = " · " + ", ".join(flags) if flags else ""
            cells.append(
                "<td>" + escape(item["human_status"]) + "<br>Role: " +
                escape(item["proposed_role"]) + detail + "</td>"
            )
        table_rows.append("<tr>" + "".join(cells) + "</tr>")
    transition_rows = []
    for item in summary["transitions"]:
        transition_rows.append(
            "<tr><td>Round " + str(item["from_round"]) + " → " +
            str(item["to_round"]) + "</td><td>" +
            str(item["changed_human_rows"]) + "</td><td>" +
            str(item["human_status_changes"]) + "</td><td>" +
            str(item["proposed_role_changes"]) + "</td><td>" +
            str(item["private_note_changes"]) + "</td></tr>"
        )
    if not transition_rows:
        transition_rows.append("<tr><td colspan='5'>No round transitions.</td></tr>")
    content = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'none'; style-src 'none'; connect-src 'none'; img-src 'none'; "
        "form-action 'none'; base-uri 'none'\">"
        "<title>PRIVATE HUMAN multi-round timeline</title></head><body>"
        "<header><h1>PRIVATE HUMAN multi-round timeline</h1>"
        "<p><strong>INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD / NO AUTHORIZATION / NO SCAN</strong></p>"
        "<p>Reference day: " + escape(reference_date) + ". " +
        str(summary["round_count"]) + " rounds in manually supplied order across " +
        str(summary["row_count"]) + " admitted rows. "
        "This order is not authenticated chronology; no note contents, source identifiers "
        "or targets are included. Small-cell counts and ordinals remain PRIVATE. "
        "An empty selection is not evidence that work is complete.</p></header>"
        "<section><h2>Adjacent-round changes</h2><table border='1'><thead><tr>"
        "<th>Operator-supplied transition</th><th>Rows with any HUMAN field change</th>"
        "<th>Status changes</th><th>Proposed-role changes</th><th>Private-note changes</th>"
        "</tr></thead><tbody>" + "".join(transition_rows) + "</tbody></table></section>"
        "<section><h2>Source-ordinal timeline</h2><div><table border='1'><thead><tr>"
        "<th>Original ordinal</th><th>Original stage</th>" + header +
        "</tr></thead><tbody>" + "".join(table_rows) + "</tbody></table></div></section>"
        "<footer><p>PRIVATE local planning only. A status, role, or note change does not "
        "prove identity, consent, finding remediation, completion, chronology or permission. "
        "No network, scan, grant, dispatch or release operation occurs.</p></footer>"
        "</body></html>"
    )
    return content.encode("utf-8")


PRIVATE_LABELS = {
    "assessment-portfolio-private.html": "Original PRIVATE cross-agenda human planning",
    "assessment-portfolio-private-routing.csv": "Original PRIVATE ordinal routing CSV",
    "assessment-portfolio-anonymous.json": "Original counts-only JSON (may be sensitive in small cohorts)",
    "assessment-portfolio-anonymous.csv": "Original counts-only CSV (may be sensitive in small cohorts)",
    "assessment-portfolio-private-explorer.html": "Interactive PRIVATE planning explorer",
    "assessment-portfolio-private-proposals.ics": "PRIVATE tentative calendar (external import may disclose planning)",
    "assessment-portfolio-private-role-day.ics": "PRIVATE grouped tentative role/day calendar; import may disclose planning",
    "assessment-portfolio-private-day-brief.html": "PRIVATE printable source-ordinal role/day attention brief",
    "assessment-portfolio-private-role-day.csv": "PRIVATE proposed role/day spreadsheet with source ordinals",
    "assessment-portfolio-private-capacity.html": "PRIVATE HUMAN workload vs operator-assumed daily role limits",
    "assessment-portfolio-private-capacity.csv": "PRIVATE role/day capacity comparison CSV with source ordinals",
    "assessment-portfolio-private-capacity-comparison.html": "PRIVATE two-scenario HUMAN proposed role/day capacity desk",
    "assessment-portfolio-private-capacity-comparison.csv": "PRIVATE source-ordinal comparison of two manual capacity assumptions",
    "assessment-portfolio-private-capacity-studio.html": "Memory-only PRIVATE HUMAN capacity scenario editing desk",
    "assessment-portfolio-human-workbook.html": "Edit and download PRIVATE HUMAN discussion worksheet",
    "assessment-portfolio-private-HUMAN-return.html": "PRIVATE HUMAN response and status-by-role dashboard",
    "assessment-portfolio-private-HUMAN-return.csv": "PRIVATE HUMAN detailed response CSV",
    "assessment-portfolio-private-HUMAN-summary.json": "PRIVATE HUMAN status/role rollup",
    "assessment-portfolio-private-HUMAN-delta.html": "PRIVATE comparison of two human-selected discussion rounds",
    "assessment-portfolio-private-HUMAN-delta.json": "PRIVATE ordinal-level discussion change details",
    "assessment-portfolio-private-HUMAN-timeline.html": "PRIVATE multi-round HUMAN discussion timeline",
    "assessment-portfolio-private-HUMAN-timeline.json": "PRIVATE source-ordinal multi-round HUMAN history",
    "assessment-portfolio-private-HUMAN-timeline.csv": "PRIVATE source-ordinal per-round HUMAN spreadsheet",
}


def render_private_home(names, reference_date):
    """Standalone scriptless local navigation over a fixed closed artifact vocabulary."""
    if len(set(names)) != len(names) or any(name not in PRIVATE_LABELS for name in names):
        raise Hold("unexpected PRIVATE workspace file inventory")
    items = "".join(
        "<li><a href='" + escape(name, quote=True) + "'>" +
        escape(PRIVATE_LABELS[name]) + "</a></li>"
        for name in names
    )
    css = ("body{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;"
           "padding:1rem;color:#192334;background:#f3f5f8}header,section{background:white;"
           "border:1px solid #d0d9e5;border-radius:10px;padding:1.4rem;margin:.8rem 0}"
           ".hold{font-weight:750;background:#fff4e2;padding:.8rem;border-left:4px solid #99601a}"
           "li{margin:.6rem 0}a{color:#07549d}")
    css_hash = base64.b64encode(sha256(css.encode()).digest()).decode()
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        "style-src 'sha256-" + css_hash + "'; script-src 'none'; connect-src 'none';"
        "form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN workroom</title><style>" + css + "</style></head><body>"
        "<header><h1>LightUp PRIVATE HUMAN workroom</h1>"
        "<p class='hold'>INCUBATE / M3-M7 PLAN-LAB ONLY / HUMAN DISCUSSION / HOLD."
        " No consent, grant, active target, verification or release.</p>"
        "<p>Operator-selected reference day " + escape(reference_date) +
        ". File names are fixed product artifacts; original input files remain separate.</p></header>"
        "<section><h2>Open this local PRIVATE packet</h2><ul>" + items + "</ul>"
        "<p>Use local original source inputs and strict native gates to return any downloaded HUMAN JSON."
        " These files alone do not prove human identity, approved scope, completed work or chronology.</p>"
        "<p>Exporting, printing, calendar-importing or sharing PRIVATE files may disclose sensitive"
        " human-planning information. Never distribute without independent authorization.</p>"
        "</section></body></html>"
    )
    return document.encode("utf-8")


def render_private_csv(entries):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow((
        "agenda_slot", "source_slot", "human_status", "proposed_role",
        "proposed_date", "private_human_note", "authority_status"
    ))
    for item in entries:
        # Notes must never be treated as spreadsheet formulas, even with Unicode whitespace.
        note = item["note"]
        if "".join(ch for ch in note if not unicodedata.category(ch).startswith("Z")).lstrip().startswith(("=", "+", "-", "@")):
            note = "'" + note
        writer.writerow((
            item["agenda_slot"], item["source_slot"], item["human_status"],
            item["proposed_role"], item["proposed_review_date"] or "",
            note, "REVIEW_ONLY"
        ))
    return output.getvalue().encode("utf-8")
