"""Offline, role-minimal PRIVATE browser editor for native HUMAN role-return CSV.

All dynamic values are base64-encoded into a CSP hash-pinned local script.
No endpoint URLs, prior notes, target I/O, role authentication or storage.
"""
from __future__ import annotations

import base64
import csv
from hashlib import sha256
import io
import json
from pathlib import Path

NAME = "lightup-lab-human-role-return-editor.html"

STYLE = """*{box-sizing:border-box}body{background:#f3f6fb;color:#152235;font:16px/1.5 system-ui,sans-serif;margin:0}
main,header,footer{max-width:950px;margin:auto;padding:1.2rem}h1{font-size:2rem}
.hold{background:#fff0d9;border-left:6px solid #985318;padding:1rem;font-weight:bold}
.card{background:white;border:1px solid #cfdbe8;border-radius:.6rem;padding:1.1rem;margin:1rem 0}
label{display:block;font-weight:700;margin:.7rem 0}textarea,select{font:inherit;display:block;width:100%;padding:.5rem;
border:1px solid #8995a8;border-radius:.35rem}textarea{min-height:6rem}
button{background:#183c62;color:white;border:0;border-radius:.4rem;padding:.8rem 1.2rem;font:inherit;font-weight:750;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #edb64e}
small{color:#405168}#message{font-weight:700;min-height:2rem}"""

SCRIPT = r'''(() => {
"use strict";
const decoded = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(
 Uint8Array.from(atob(__DATA__), x => x.charCodeAt(0))));
const stages = ["NEEDS_INPUT","HUMAN_REVIEW","FOLLOW_UP"];
const message = document.getElementById("message");
const root = document.getElementById("rows");
const button = document.getElementById("download");
const rows = decoded.rows;
if (!Array.isArray(rows) || rows.length < 1 || rows.length > 16 ||
    typeof decoded.fingerprint !== "string" ||
    !/^[0-9a-f]{64}$/.test(decoded.fingerprint) ||
    typeof decoded.role !== "string" || !Array.isArray(decoded.header) ||
    decoded.header.length !== 6) {
  message.textContent = "Invalid local template. Re-create using the native CLI.";
  return;
}
__RESUME_JS__
let previousSlot = 0;
for (const row of rows) {
  if (!Number.isSafeInteger(row.slot) || row.slot <= previousSlot ||
      row.slot > 16 || !stages.includes(row.prior)) {
    message.textContent = "Unadmitted selected role template.";
    root.replaceChildren();
    return;
  }
  previousSlot = row.slot;
  row.proposed = row.prior;
  row.note = "";
  const card = document.createElement("section");
  card.className = "card";
  const heading = document.createElement("h2");
  heading.textContent = "Original local slot " + String(row.slot).padStart(2,"0");
  card.append(heading);
  const label = document.createElement("label");
  label.textContent = "Proposed HUMAN stage (no authority)";
  const select = document.createElement("select");
  for (const stage of stages) {
    const option = document.createElement("option");
    option.value = stage;
    option.textContent = stage.replaceAll("_"," ");
    select.append(option);
  }
  select.value = row.prior;
  select.addEventListener("change", () => {row.proposed = select.value; statusSummary();});
  label.append(select);
  card.append(label);
  const noteLabel = document.createElement("label");
  noteLabel.textContent = "New PRIVATE note (blank = retain existing, '-' = clear; max 400 characters)";
  const note = document.createElement("textarea");
  note.maxLength = 400;
  note.autocomplete = "off";
  note.setAttribute("aria-label","PRIVATE note for slot " + row.slot);
  note.addEventListener("input", () => {row.note = note.value; statusSummary();});
  noteLabel.append(note);
  card.append(noteLabel);
  root.append(card);
  editors.push({stage:select,note});
}
statusSummary();
button.disabled = false;
function csvCell(value) {
  return '"' + String(value).replaceAll('"','""') + '"';
}
button.addEventListener("click", () => {
  if (rows.some(row => restrictedNote(row.note))) {
    message.textContent = "A PRIVATE note has unsafe controls, formula-like prefix, or exceeds 400 characters.";
    return;
  }
  const lines = [decoded.header.map(csvCell).join(",")];
  for (const row of rows) {
    lines.push([decoded.fingerprint,row.slot,decoded.role,row.prior,
                row.proposed,row.note].map(csvCell).join(","));
  }
  const raw = lines.join("\n") + "\n";
  const blob = new Blob([raw],{type:"text/csv;charset=utf-8"});
  if (blob.size > 32768) {
    message.textContent = "Role return exceeded native bounded CSV size.";
    return;
  }
  const uri = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = uri;
  a.download = "lightup-lab-human-role-return.edited.csv";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(uri),2500);
  message.textContent = "Downloaded PRIVATE CSV. Store only in an owner-private 0700 folder as a 0600 file; native role_return.py --reply-file MUST re-admit it.";
});
})();'''


def render_editor(csv_template: bytes) -> bytes:
    # Native producer generated the bounded template. Parse, then embed only
    # selected fixed fields; notes are ALWAYS empty and no URLs are emitted.
    decoded = csv_template.decode("utf-8")
    records = list(csv.reader(io.StringIO(decoded, newline=""), strict=True))
    if len(records) < 2:
        raise ValueError("missing selected HUMAN role records")
    expected = ("handoff_sha256", "original_slot", "selected_role",
                "latest_human_stage", "proposed_human_stage", "proposed_private_note")
    if tuple(records[0]) != expected:
        raise ValueError("wrong private role-return template")
    raw_rows = records[1:]
    if any(len(record) != len(expected) for record in raw_rows):
        raise ValueError("malformed native role-return CSV")
    if any(record[2] != raw_rows[0][2] or record[0] != raw_rows[0][0]
           or record[5] for record in raw_rows):
        raise ValueError("mixed role or nonblank original template notes")
    data = {"header": expected, "fingerprint": raw_rows[0][0],
            "role": raw_rows[0][2],
            "rows": [{"slot": int(record[1]), "prior": record[3]}
                     for record in raw_rows]}
    encoded = base64.b64encode(json.dumps(
        data, ensure_ascii=True, separators=(",", ":")).encode("utf-8")).decode("ascii")
    resume_js = Path(__file__).with_name("role_return_resume.js").read_text(encoding="utf-8")
    script = (SCRIPT.replace("__DATA__", json.dumps(encoded))
                    .replace("__RESUME_JS__", resume_js))
    css_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    js_hash = base64.b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\';'
        " script-src 'sha256-" + js_hash + "'; style-src 'sha256-" + css_hash +
        "'; connect-src 'none'; img-src 'none'; frame-src 'none'; object-src 'none';"
        ' worker-src \'none\'; form-action \'none\'; base-uri \'none\'">'
        "<title>LightUp PRIVATE selected-role HUMAN return</title><style>" +
        STYLE + "</style></head><body><header><p>LIGHTUP / OFFLINE HUMAN-ONLY</p>"
        "<h1>PRIVATE role-filtered HUMAN response</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO AUTHORIZATION</p>"
        "</header><main><p>This isolated, owner-private browser file contains "
        "ONLY selected ordinals, a self-reported HUMAN role, stages and a source "
        "fingerprint. No endpoint URLs, previous PRIVATE notes or other roles "
        "are included. This is not reviewer authentication, client consent, "
        "security clearance, or HUMAN GO.</p>"
        "<label for='resume'>Resume an earlier PRIVATE CSV draft</label>"
        "<input type='file' id='resume' accept='.csv,text/csv'>"
        "<p id='progress' role='status' aria-live='polite'></p>"
        "<div id='rows'></div><button type='button' id='download' disabled>"
        "Download PRIVATE role-return CSV</button>"
        "<p id='message' role='status' aria-live='polite'></p>"
        "<small>No network, browser storage, target interaction or scanning. "
        "Native owner-side import validates the original source and full role "
        "handoff before any next HUMAN round. This local file is not a permission "
        "grant. Browser download permissions are NOT owner-only by default.</small>"
        "</main><footer>REVIEW_ONLY · source-bounded but UNSIGNED</footer>"
        "<script>" + script + "</script></body></html>"
    )
    return html.encode("utf-8")
