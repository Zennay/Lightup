"""Browser-only PRIVATE HUMAN overlap selection with source-bound CSV export.

Never contains source endpoint URLs or PRIVATE note text and never approves work.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path

NAME = "lightup-lab-human-conflict-editor-private.html"
STYLE = (
    "*{box-sizing:border-box}body{font:16px/1.5 system-ui,sans-serif;"
    "margin:0;background:#f2f5fb;color:#14253a}"
    "header,main,footer{max-width:1050px;margin:auto;padding:1.1rem}"
    "h1{font-size:clamp(1.6rem,4vw,2.5rem)}"
    ".hold{border-left:6px solid #9b5810;background:#fff1dd;padding:1rem;font-weight:800}"
    ".card{background:#fff;border:1px solid #cad6e5;border-radius:.6rem;"
    "padding:1rem;margin:1rem 0}"
    "label{display:block;font-weight:700;margin:.6rem 0}"
    "select{display:block;padding:.6rem;border:1px solid #8498ae;"
    "border-radius:.4rem;font:inherit;width:100%;max-width:680px}"
    "button{background:#16456c;color:#fff;padding:.8rem 1.2rem;border:0;"
    "border-radius:.4rem;font:inherit;font-weight:800;cursor:pointer}"
    "button:focus-visible,select:focus-visible{outline:3px solid #dea43d}"
    "small{color:#536078}#progress,#message{font-weight:700}"
)
SCRIPT = r'''(() => {
"use strict";
const decoded = new TextDecoder("utf-8",{fatal:true}).decode(
 Uint8Array.from(atob(__SOURCE64__),value=>value.charCodeAt(0)));
const state = JSON.parse(decoded);
const container = document.getElementById("choices");
const progress = document.getElementById("progress");
const message = document.getElementById("message");
const button = document.getElementById("save");
const rows = state.rows;
if (!Array.isArray(rows) || rows.length < 1 || rows.length > 16 ||
    !/^[0-9a-f]{64}$/.test(state.fingerprint)) {
  message.textContent = "PRIVATE source-bound HUMAN conflict template rejected.";
  return;
}
const chosen = new Map();
const selectors = new Map();
let previousSlot = 0;
for (const row of rows) {
  if (!Number.isSafeInteger(row.slot) || row.slot <= previousSlot ||
      !Array.isArray(row.options) || row.options.length < 2 ||
      row.options.length > 5 || row.options.some(o =>
       !Number.isSafeInteger(o.packet) || o.packet < 1 || o.packet > 5)) {
    message.textContent = "Malformed original HUMAN overlap inventory.";
    container.replaceChildren();
    return;
  }
  previousSlot = row.slot;
  const section = document.createElement("section");
  section.className = "card";
  const title = document.createElement("h2");
  title.textContent = "Original local HUMAN slot " + row.slot;
  section.append(title);
  const label = document.createElement("label");
  label.textContent = "Human selection: one original return packet (required)";
  const select = document.createElement("select");
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "— No decision made —";
  select.append(blank);
  for (const option of row.options) {
    const el = document.createElement("option");
    el.value = String(option.packet);
    el.textContent = "Original return packet " + option.packet +
      " · suggested role: " + option.role +
      " · HUMAN stage: " + option.stage +
      " · PRIVATE note changed: " + (option.noteChanged ? "YES" : "NO");
    select.append(el);
  }
  select.addEventListener("change",()=> {
    if (select.value) chosen.set(row.slot,Number(select.value));
    else chosen.delete(row.slot);
    updateProgress();
  });
  label.append(select);
  section.append(label);
  container.append(section);
  selectors.set(row.slot, select);
}
function updateProgress() {
  progress.textContent = chosen.size + " of " + rows.length +
    " overlapping source slots explicitly chosen.";
  button.disabled = chosen.size !== rows.length;
}
updateProgress();
button.addEventListener("click",()=> {
  if (chosen.size !== rows.length) {
    message.textContent = "Every overlap needs an explicit HUMAN source choice.";
    return;
  }
  const lines = [["source_set_sha256","original_slot","eligible_packet_numbers",
                  "chosen_packet_number"].join(",")];
  for (const row of rows) {
    const eligible = row.options.map(o=>o.packet);
    const choice = chosen.get(row.slot);
    if (!eligible.includes(choice)) {
      message.textContent = "Selected packet no longer belongs to original slot.";
      return;
    }
    lines.push([state.fingerprint,row.slot,eligible.join("|"),choice].join(","));
  }
  const blob = new Blob([lines.join("\n")+"\n"],{type:"text/csv;charset=utf-8"});
  if (blob.size > 32768) {
    message.textContent = "Original HUMAN choices exceeded bounded CSV size.";
    return;
  }
  const uri = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = uri;
  link.download = "lightup-lab-human-conflict-choices-private.csv";
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(uri),2500);
  message.textContent = "PRIVATE HUMAN CSV saved locally. Store as a 0600 file "
    + "inside a 0700 owner-only directory, then re-admit using "
    + "role_return_conflicts.py --decision-file. Browser values grant no authority.";
});
__RESUME_JS__
})();'''


def render(rows, fingerprint):
    # rows are admitted, fixed-vocabulary original local packet choices only.
    encoded = base64.b64encode(json.dumps(
        {"fingerprint": fingerprint, "rows": rows},
        sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")).decode("ascii")
    resume_js = Path(__file__).with_name("role_return_conflict_resume.js").read_text(
        encoding="utf-8")
    js = (SCRIPT.replace("__SOURCE64__", json.dumps(encoded))
                .replace("__RESUME_JS__", resume_js))
    css_digest = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    js_digest = base64.b64encode(sha256(js.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "script-src 'sha256-" + js_digest + "'; style-src 'sha256-" +
        css_digest + "'; connect-src 'none'; img-src 'none';"
        " worker-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN conflict choices</title><style>" +
        STYLE + "</style></head><body><header><h1>PRIVATE HUMAN source choices</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "NO AUTHORIZATION</p></header><main>"
        "<p>Make one conscious owner-local choice for every overlapping HUMAN "
        "source slot. The only choices are the ORIGINAL independently admitted "
        "role-return packet numbers, in the same order provided on the native "
        "command line. No endpoint URLs or old PRIVATE note text are included. "
        "No automatic precedence, browser storage, network or models.</p>"
        "<label for='resume'>Resume earlier PRIVATE conflict-choice CSV</label>"
        "<input id='resume' type='file' accept='.csv,text/csv'>"
        "<p id='progress' role='status' aria-live='polite'></p>"
        "<div id='choices'></div><button id='save' disabled type='button'>"
        "Download PRIVATE explicit decisions CSV</button>"
        "<p id='message' role='status' aria-live='polite'></p>"
        "<small>The downloaded file is not guaranteed 0600 by the browser. "
        "Only the owner-private native source-bound input gate can admit it. "
        "This tool cannot establish reviewer identity, consent, remediation, "
        "scope authorization or HUMAN GO.</small></main>"
        "<footer>REVIEW_ONLY · UNSIGNED original HUMAN reports</footer>"
        "<script>" + js + "</script></body></html>"
    ).encode("utf-8")
