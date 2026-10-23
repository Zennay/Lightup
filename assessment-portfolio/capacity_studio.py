#!/usr/bin/env python3
"""Single-file memory-only HUMAN capacity comparison studio; no target/authorization."""
from __future__ import annotations

import base64
from hashlib import sha256
from html import escape
import json

import capacity

CSS = (
    "*{box-sizing:border-box}body{margin:0 auto;max-width:1280px;padding:1.5rem;"
    "font:16px/1.5 system-ui,sans-serif;background:#f2f5f9;color:#19283b}"
    "header,section{background:#fff;border:1px solid #ccd7e5;border-radius:12px;"
    "padding:1.1rem;margin:.8rem 0}h1{line-height:1.15;margin:.4rem 0}"
    ".hold{background:#fff1dc;border-left:5px solid #a16207;padding:.8rem;font-weight:750}"
    ".controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem}"
    ".role{border:1px solid #cbd5e1;border-radius:8px;padding:.7rem}"
    "label{display:block;font-size:.9rem}input{width:100%;max-width:110px;padding:.45rem;"
    "font:inherit;border:1px solid #9ba8b8;border-radius:5px}"
    "button{padding:.55rem .8rem;font:inherit;border-radius:6px;"
    "border:1px solid #8ca2bd;background:#e4efff;cursor:pointer;margin:.25rem}"
    ".table{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.84rem}"
    "th,td{border:1px solid #d9e1ea;padding:.5rem;text-align:left;vertical-align:top}"
    "th{background:#edf3fa}.excess{background:#fff3e6}"
    ".hint{font-size:.91rem;color:#42566e}.metrics{font-size:1.15rem;font-weight:700}"
    "[hidden]{display:none!important}@media print{button{display:none!important}"
    "body{background:white;padding:.3rem}section{break-inside:avoid}}"
)

JS = r'''"use strict";
const payload = JSON.parse(document.getElementById("source-data").textContent);
document.getElementById("source-data").remove();
const fields = document.getElementById("capacity-fields");
const table = document.getElementById("scenario-rows");
const message = document.getElementById("message");
const summary = document.getElementById("summary");
const download = document.getElementById("download-current");
const downloadJSON = document.getElementById("download-json");
const printButton = document.getElementById("print-studio");
const undatedList = document.getElementById("undated-list");
const settings = {};
let assumptionsRevision = 0;
let currentRows = [];
let currentJson = null;
const make = (tag, value) => {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = String(value);
  return node;
};
for (const role of payload.roles) {
  const item = make("div"); item.className = "role";
  item.append(make("strong", role));
  settings[role] = [];
  for (const [index, name] of ["First declared limit", "Alternative declared limit"].entries()) {
    const label = make("label", name);
    const input = document.createElement("input");
    input.type = "number"; input.min = "1"; input.max = "128";
    input.step = "1"; input.required = true; input.inputMode = "numeric";
    input.value = String((index ? payload.alternative : payload.first)[role]);
    input.setAttribute("aria-label", name + " for proposed neutral role " + role);
    input.addEventListener("input", () => { assumptionsRevision++; refresh(); });
    settings[role].push(input);
    label.append(input); item.append(label);
  }
  fields.append(item);
}
const limits = (position) => {
  const result = {};
  for (const role of payload.roles) {
    const input = settings[role][position];
    const raw = input.value;
    if (!/^[0-9]{1,3}$/.test(raw)) return null;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1 || value > 128) return null;
    result[role] = value;
  }
  return result;
};
const link = (source) => {
  const anchor = document.createElement("a");
  anchor.textContent = "A" + String(source[0]).padStart(2, "0") +
    "/S" + String(source[1]).padStart(2, "0");
  anchor.href = "assessment-portfolio-private.html#agenda-" +
    source[0] + "-slot-" + source[1];
  return anchor;
};
for (const group of payload.undated_rows) {
  const item = make("p", group.role + ": " + group.ordinals.length +
    " original undated HUMAN proposals — ");
  for (const [index, original] of group.ordinals.entries()) {
    if (index) item.append(document.createTextNode(", "));
    item.append(link(original));
  }
  undatedList.append(item);
}
if (!payload.undated_rows.length)
  undatedList.append(make("p", "No undated items visible in this selected view. Not completion."));
function refresh() {
  const first = limits(0), alternate = limits(1);
  if (!first || !alternate) {
    message.textContent = "HOLD: Enter integer limits 1–128 for every neutral role. " +
      "No preview or export is available until inputs are corrected.";
    table.replaceChildren();
    summary.textContent = "INVALID ASSUMPTIONS · no scenario counts displayed.";
    currentRows = [];
    currentJson = null;
    printButton.disabled = true;
    download.disabled = true;
    downloadJSON.disabled = true;
    return;
  }
  const fragment = document.createDocumentFragment();
  const exportRows = [];
  const jsonRows = [];
  let firstExcess = 0, alternateExcess = 0;
  for (const entry of payload.groups) {
    const a = Math.max(0, entry.count - first[entry.role]);
    const b = Math.max(0, entry.count - alternate[entry.role]);
    firstExcess += a; alternateExcess += b;
    const tr = make("tr");
    if (a || b) tr.className = "excess";
    const cells = [entry.date, entry.role, entry.count,
      first[entry.role], a, alternate[entry.role], b, b - a];
    for (const cell of cells) tr.append(make("td", cell));
    const refs = make("td");
    for (const [i, original] of entry.ordinals.entries()) {
      if (i) refs.append(document.createTextNode(", "));
      refs.append(link(original));
    }
    tr.append(refs); fragment.append(tr);
    const ids = entry.ordinals.map(original =>
      "A" + String(original[0]).padStart(2,"0") +
      "/S" + String(original[1]).padStart(2,"0")).join(";");
    exportRows.push([...cells, ids, "REVIEW_ONLY"]);
    jsonRows.push({
      proposed_day: entry.date,
      suggested_neutral_role: entry.role,
      human_items: entry.count,
      first_declared_daily_limit: first[entry.role],
      first_items_above_assumption: a,
      alternative_declared_daily_limit: alternate[entry.role],
      alternative_items_above_assumption: b,
      alternative_minus_first_excess: b - a,
      source_agenda_count: new Set(entry.ordinals.map(original => original[0])).size,
      original_source_ordinals: entry.ordinals.map(original => ({
        agenda_slot: original[0], source_slot: original[1]
      })),
      status: "REVIEW_ONLY"
    });
  }
  for (const group of payload.undated_rows) {
    const source = group.ordinals.map(original =>
      "A" + String(original[0]).padStart(2, "0") +
      "/S" + String(original[1]).padStart(2, "0")).join(";");
    exportRows.push(["", group.role, group.ordinals.length,
      "", "", "", "", "", source, "REVIEW_ONLY"]);
    jsonRows.push({
      proposed_day: null,
      suggested_neutral_role: group.role,
      human_items: group.ordinals.length,
      first_declared_daily_limit: null,
      first_items_above_assumption: null,
      alternative_declared_daily_limit: null,
      alternative_items_above_assumption: null,
      alternative_minus_first_excess: null,
      source_agenda_count: new Set(group.ordinals.map(original => original[0])).size,
      original_source_ordinals: group.ordinals.map(original => ({
        agenda_slot: original[0], source_slot: original[1]
      })),
      status: "REVIEW_ONLY"
    });
  }
  table.replaceChildren(fragment);
  currentRows = exportRows;
  currentJson = {
    schema: "lightup.human_capacity_scenario_private.v2",
    source_payload_sha256: payload.payload_sha256,
    posture: "INCUBATE_M3_M7_PLAN_LAB_ONLY_DRAFT_HOLD",
    status: "REVIEW_ONLY",
    reference_date: payload.reference_date,
    roles: payload.roles.slice(),
    first_declared_daily_limit_by_role: {...first},
    alternative_declared_daily_limit_by_role: {...alternate},
    summary: {
      first_items_above_declared_limits: firstExcess,
      alternative_items_above_declared_limits: alternateExcess,
      arithmetic_difference: alternateExcess - firstExcess,
      undated_items: payload.undated_count
    },
    rows: jsonRows,
    original_source_ordinals_included: true,
    source_filenames_included: false,
    source_hashes_included: false,
    original_case_ids_included: false,
    human_notes_included: false,
    planning_not_permission: true,
    authorized: false,
    consent_verified: false,
    dispatch_allowed: false,
    release_allowed: false,
    disclaimer: "PRIVATE HUMAN-only hypothetical capacity arithmetic. Ordinals are source-local pointers, not identities. This is not a booking, staffing verdict, verified finding, consent or permission."
  };
  summary.textContent = "First scenario: " + firstExcess +
    " proposed HUMAN items above declared limits; alternative: " + alternateExcess +
    "; arithmetic difference: " + (alternateExcess - firstExcess) +
    ". Unscheduled original items: " + payload.undated_count +
    " (never charged to either daily limit).";
  message.textContent = "PREVIEW ONLY · local hypothetical arithmetic, not a booking, " +
    "staffing verdict, consent or permission. Changes are not saved.";
  download.disabled = false;
  downloadJSON.disabled = false;
  printButton.disabled = false;
}
document.getElementById("reset-studio").addEventListener("click", () => {
  assumptionsRevision++;
  for (const role of payload.roles) {
    settings[role][0].value = String(payload.first[role]);
    settings[role][1].value = String(payload.alternative[role]);
  }
  refresh();
});
document.getElementById("print-studio").addEventListener("click", () => window.print());
const csvValue = value => '"' + String(value).replace(/"/g, '""') + '"';
download.addEventListener("click", () => {
  if (download.disabled) return;
  const rows = [[
    "original_proposed_day", "suggested_neutral_role", "human_items",
    "first_declared_daily_limit", "first_items_above_assumption",
    "alternative_declared_daily_limit", "alternative_items_above_assumption",
    "alternative_minus_first_excess", "original_source_ordinals", "authority_status"
  ], ...currentRows];
  const data = rows.map(line => line.map(csvValue).join(",")).join("\r\n") + "\r\n";
  if (new TextEncoder().encode(data).length > 1048576) {
    message.textContent = "HOLD: selected PRIVATE CSV exceeds 1 MiB."; return;
  }
  const object = URL.createObjectURL(new Blob([data], {type: "text/csv;charset=utf-8"}));
  const anchor = document.createElement("a");
  anchor.href = object; anchor.download = "lightup-PRIVATE-HUMAN-capacity-scenarios.csv";
  anchor.rel = "noopener"; anchor.click();
  setTimeout(() => URL.revokeObjectURL(object), 5000);
  message.textContent = "PRIVATE CSV downloaded locally. No source file, " +
    "calendar entry, identity, consent or permission was changed.";
});
const importButton = document.getElementById("open-scenario-json");
const importFile = document.getElementById("scenario-json-file");
const exactKeys = (obj, keys) => obj && typeof obj === "object" && !Array.isArray(obj) &&
  Object.keys(obj).length === keys.length &&
  keys.every(key => Object.prototype.hasOwnProperty.call(obj, key));
const admittedLimits = obj => exactKeys(obj, payload.roles) &&
  payload.roles.every(role => Number.isInteger(obj[role]) &&
    obj[role] >= 1 && obj[role] <= 128);
importButton.addEventListener("click", () => importFile.click());
importFile.addEventListener("change", async () => {
  const file = importFile.files && importFile.files[0];
  importFile.value = "";
  if (!file) return;
  if (file.size > 1048576 || file.size === 0) {
    message.textContent = "HOLD: PRIVATE capacity scenario must be 1 byte to 1 MiB.";
    return;
  }
  const revisionAtStart = assumptionsRevision;
  let text;
  try {
    text = await file.text();
    if (assumptionsRevision !== revisionAtStart) {
      message.textContent = "HOLD: current HUMAN capacity assumptions changed while reading. Nothing imported.";
      return;
    }
    const candidate = JSON.parse(text);
    if (JSON.stringify(candidate, null, 2) + "\n" !== text ||
        candidate.schema !== "lightup.human_capacity_scenario_private.v2" ||
        candidate.source_payload_sha256 !== payload.payload_sha256 ||
        candidate.reference_date !== payload.reference_date ||
        !admittedLimits(candidate.first_declared_daily_limit_by_role) ||
        !admittedLimits(candidate.alternative_declared_daily_limit_by_role)) {
      throw new Error("different source, schema or noncanonical capacity file");
    }
    // A strict full native regenerated export comparison rejects duplicate keys,
    // altered false-authority flags, unknown fields and differing source rows.
    const before = payload.roles.map(role => settings[role].map(input => input.value));
    let matches = false;
    try {
      payload.roles.forEach((role, index) => {
        settings[role][0].value = String(candidate.first_declared_daily_limit_by_role[role]);
        settings[role][1].value = String(candidate.alternative_declared_daily_limit_by_role[role]);
      });
      refresh();
      matches = JSON.stringify(currentJson, null, 2) + "\n" === text;
    } finally {
      payload.roles.forEach((role, index) => {
        settings[role][0].value = before[index][0];
        settings[role][1].value = before[index][1];
      });
      refresh();
    }
    if (!matches) throw new Error("source grouping, private rows or authority fields changed");
    if (!window.confirm("Restore these two HUMAN-only hypothetical capacity plans? The exact current original source rows were rechecked. This is NOT an authorization.")) {
      message.textContent = "Import canceled. Existing HUMAN assumptions kept.";
      return;
    }
    if (assumptionsRevision !== revisionAtStart) {
      message.textContent = "HOLD: assumptions changed. Nothing imported.";
      return;
    }
    payload.roles.forEach(role => {
      settings[role][0].value = String(candidate.first_declared_daily_limit_by_role[role]);
      settings[role][1].value = String(candidate.alternative_declared_daily_limit_by_role[role]);
    });
    assumptionsRevision++;
    refresh();
    message.textContent = "PRIVATE hypothetical capacity plans reopened against exact source-bound rows. No identity, consent, real staffing, booking, permission or dispatch verified.";
  } catch (_) {
    message.textContent = "HOLD: not an exact original PRIVATE v2 export from these unchanged source rows. Existing plans kept.";
  }
});
downloadJSON.addEventListener("click", () => {
  if (downloadJSON.disabled || !currentJson) return;
  const data = JSON.stringify(currentJson, null, 2) + "\n";
  if (new TextEncoder().encode(data).length > 1048576) {
    message.textContent = "HOLD: selected PRIVATE JSON exceeds 1 MiB."; return;
  }
  const object = URL.createObjectURL(new Blob([data], {type: "application/json;charset=utf-8"}));
  const anchor = document.createElement("a");
  anchor.href = object; anchor.download = "lightup-PRIVATE-HUMAN-capacity-scenarios.json";
  anchor.rel = "noopener"; anchor.click();
  setTimeout(() => URL.revokeObjectURL(object), 5000);
  message.textContent = "PRIVATE JSON downloaded locally. It includes proposed assumptions and source-local ordinals only; no filenames, source hashes, identities or HUMAN notes.";
});
refresh();
'''.strip()


def render(rows, reference_day, first_limits, alternative_limits, roles):
    """Embed only already-admitted ordinals, dates and fixed vocabulary."""
    records, undated = capacity.collect(rows, first_limits, roles)
    if alternative_limits is None:
        alternative_limits = dict(first_limits)
    grouped = [
        {
            "date": record["day"],
            "role": record["role"],
            "count": record["items"],
            "ordinals": [[row["agenda_slot"], row["source_slot"]]
                         for row in record["members"]],
        }
        for record in records
    ]
    seed = {
        "schema": "lightup.human_capacity_studio_private.v1",
        "reference_date": reference_day.isoformat(),
        "roles": list(roles),
        "first": first_limits,
        "alternative": alternative_limits,
        "groups": grouped,
        "undated_count": sum(map(len, undated.values())),
        "undated_rows": [
            {"role": role, "ordinals": [[item["agenda_slot"], item["source_slot"]]
                                      for item in sorted(undated.get(role, []),
                                      key=lambda row: (row["agenda_slot"], row["source_slot"]))]}
            for role in roles if undated.get(role)
        ],
        "planning_not_permission": True,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    seed["payload_sha256"] = sha256(json.dumps(
        seed, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    seed_text = json.dumps(seed, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    # Prevent an HTML delimiter or attribute breakout regardless of future schema.
    seed_text = (seed_text.replace("&", "\\u0026").replace("<", "\\u003c")
                          .replace(">", "\\u003e"))
    style_hash = base64.b64encode(sha256(CSS.encode()).digest()).decode("ascii")
    script_hash = base64.b64encode(sha256(JS.encode()).digest()).decode("ascii")
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'sha256-" + script_hash + "'; style-src 'sha256-" + style_hash +
        "'; connect-src 'none'; img-src 'none'; object-src 'none'; "
        "form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN capacity scenario studio</title>"
        "<style>" + CSS + "</style></head><body>"
        "<header><p>LIGHTUP / ASSESSMENT RUNTIME / LOCAL ONLY</p>"
        "<h1>Private HUMAN capacity scenario studio</h1>"
        "<div class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "NOT AUTHORIZED</div>"
        "<p>Reference day " + escape(reference_day.isoformat()) +
        ". All row counts came from strictly admitted original source agendas "
        "and current CLI filters; no source filenames, endpoints, recipients "
        "or HUMAN notes are embedded.</p>"
        "<p class='hint'>Adjust two HYPOTHETICAL maximum HUMAN discussion "
        "items per neutral role/day. This page does not know real staffing, "
        "authenticate identity, book time, contact a target or approve work."
        " Browser-memory changes disappear when the page closes.</p></header>"
        "<section><h2>Manual per-role assumptions</h2>"
        "<div id='capacity-fields' class='controls'></div>"
        "<p><button type='button' id='reset-studio'>Restore original assumptions</button>"
        "<button type='button' id='print-studio'>Print PRIVATE scenario</button>"
        "<button type='button' id='download-current'>Download PRIVATE scenario CSV</button>"
        "<button type='button' id='download-json'>Download PRIVATE scenario JSON</button>"
        "<button type='button' id='open-scenario-json'>Reopen PRIVATE scenario JSON</button>"
        "<input id='scenario-json-file' type='file' accept='.json,application/json' hidden></p>"
        "<p id='message' role='status' aria-live='polite'></p>"
        "<p id='summary' class='metrics' aria-live='polite'></p></section>"
        "<section><h2>Original proposed date and role groups</h2>"
        "<div class='table'><table><thead><tr><th>Proposed day</th>"
        "<th>Role</th><th>Items</th><th>First limit</th><th>First above</th>"
        "<th>Alternative limit</th><th>Alternative above</th>"
        "<th>Alternative minus first</th><th>Original ordinal links</th>"
        "</tr></thead><tbody id='scenario-rows'></tbody></table></div>"
        "<p class='hint'>A smaller arithmetic excess does not prove real "
        "staffing availability, security risk, completed remediation or "
        "authorization. Undated proposals are never allocated to a date.</p></section>"
        "<section><h2>Original HUMAN items without proposed date</h2>"
        "<div id='undated-list'></div><p class='hint'>Undated original records "
        "are excluded from both daily capacity assumptions, but remain visible "
        "and included in the optional PRIVATE CSV export.</p></section>"
        "<script id='source-data' type='application/json'>" + seed_text + "</script>"
        "<script>" + JS + "</script></body></html>"
    )
    return ("assessment-portfolio-private-capacity-studio.html", document.encode("utf-8"))
