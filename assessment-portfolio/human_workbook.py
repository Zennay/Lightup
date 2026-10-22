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
const plain = (label, value) => {
  const cell = document.createElement("td"); cell.textContent = String(value); return cell;
};
for (const entry of data.entries) {
  const tr = document.createElement("tr");
  tr.append(plain("slot", "A" + String(entry.agenda_slot).padStart(2, "0") + "/S" +
    String(entry.source_slot).padStart(2, "0")));
  tr.append(plain("date", entry.proposed_review_date || "unscheduled"));
  tr.append(plain("role", entry.source_next_role));
  tr.append(plain("status", entry.source_stage));
  for (const [key, options] of [["human_status", stages], ["proposed_role", roles]]) {
    const td = document.createElement("td");
    const select = document.createElement("select"); select.setAttribute("aria-label", key);
    for (const value of options) {
      const option = document.createElement("option"); option.value = value;
      option.textContent = value; select.append(option);
    }
    select.value = entry[key]; select.addEventListener("change", () => entry[key] = select.value);
    td.append(select); tr.append(td);
  }
  const noteCell = document.createElement("td");
  const note = document.createElement("textarea"); note.maxLength = 160; note.rows = 2;
  note.placeholder = "PRIVATE HUMAN note; never enter secrets"; note.value = entry.note;
  note.setAttribute("aria-label", "Private non-authorizing human note");
  note.addEventListener("input", () => {entry.note = note.value;});
  noteCell.append(note); tr.append(noteCell);
  rows.append(tr);
}
const state = document.getElementById("savedState");
const progress = document.getElementById("humanProgress");
const reportProgress = () => {
  const changes = data.entries.filter((entry, index) =>
    entry.human_status !== original.entries[index].human_status ||
    entry.proposed_role !== original.entries[index].proposed_role || entry.note.length > 0
  ).length;
  const nonempty = data.entries.filter(entry => entry.note.length > 0).length;
  progress.textContent = changes + " of " + data.entries.length +
    " local HUMAN discussions changed; " + nonempty + " PRIVATE notes. Unverified and unsaved until explicit download.";
};
rows.addEventListener("input", reportProgress);
rows.addEventListener("change", reportProgress);
const exactKeys = (one, two) => JSON.stringify(Object.keys(one).sort()) ===
  JSON.stringify(Object.keys(two).sort());
document.getElementById("restoreWorksheet").addEventListener("change", async event => {
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
    !/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]/u.test(note);
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
    tr.querySelector("textarea").value = entry.note;
  });
  reportProgress();
  state.textContent = "PRIVATE HUMAN worksheet reopened locally. Native source/JSON admission is still required before a new bundle.";
});
reportProgress();
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
});
'''.strip()
CSS = """body{background:#f3f5f8;color:#1b2837;font:16px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1200px;padding:1.5rem}h1{margin:.25rem 0}header,section{background:#fff;border:1px solid #ccd5df;border-radius:8px;padding:1rem;margin-bottom:1rem}.hold{border-left:5px solid #9b5012;padding:.8rem;background:#fff8ea;font-weight:700}.table{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.84rem}th,td{border:1px solid #dbe2e9;text-align:left;vertical-align:top;padding:.5rem}th{background:#e8edf4}textarea{min-width:190px;max-width:250px}select,textarea,button{font:inherit;padding:.4rem;border-radius:4px;border:1px solid #9eabb9}button{cursor:pointer;background:#e2f0ff}p small{color:#566477}@media print{button,textarea{display:none}}"""


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
        "<div class='table'><table><thead><tr><th>Source ordinal</th><th>Proposed day</th>"
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
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'none'; script-src 'none'; "
        "connect-src 'none'; form-action 'none'; base-uri 'none'\"><title>PRIVATE HUMAN response</title></head><body>"
        "<h1>Private HUMAN discussion return</h1>"
        "<p>INCUBATE / HOLD / HUMAN ONLY / NOT AUTHORIZED / NO TARGET / NO SCAN</p>"
        "<p>Reference day: " + escape(reference_date) + ". Ordinals are not authenticated chronology."
        " Fields are manually entered; none authenticates reviewer, consent or remediation.</p>"
        "<table border='1'><thead><tr><th>Original ordinal</th><th>Original stage</th><th>HUMAN status</th>"
        "<th>Original role</th><th>Proposed role</th><th>Proposed date</th><th>PRIVATE HUMAN note</th>"
        "</tr></thead><tbody>" + "".join(table) + "</tbody></table>"
        "<p>Source originals remain unchanged. PRIVATE non-authorizing local output only.</p></body></html>"
    )
    return body.encode("utf-8")


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
