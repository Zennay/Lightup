#!/usr/bin/env python3
"""Original Lab Launchpad -> source-bound private HUMAN review, NO authority.

Uses original lab-scope + immutable local source-owner packet reopening. This
never invokes lab-assess, a scanner, model, network, grant or recipient.
"""
from __future__ import annotations

from base64 import b64encode
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil

import lab_plan_portfolio
import lab_plans
import private_session as privacy
import route_queue
import workpack_progress

SCHEMA = "lightup.private.original-lab-human-review.v1"
COLUMNS = ("source_snapshot_sha256", "proposal_slot", "human_stage",
           "human_team", "human_question")
NOTE_MAX = 180


def _source_rows(packets: list[str]) -> tuple[list[dict], str]:
    if type(packets) is not list or not 3 <= len(packets) <= 8:
        raise privacy.Hold("HOLD: 3–8 original source-owned Lab Launchpad packets required")
    if any(type(x) is not str for x in packets):
        raise privacy.Hold("HOLD: original packets must be absolute paths")
    originals = [lab_plans._packet(name) for name in packets]
    if len(set(originals)) != len(originals):
        raise privacy.Hold("HOLD: duplicate original private packet")
    source = lab_plan_portfolio._load(packets)
    payload = [{
        "slot": index, "manifest_sha256": row["manifest_sha256"],
        "studio_sha256": row["studio_catalog_sha256"],
        "studio_scenario": row["studio_scenario_id"],
        "endpoint_count": len(row["endpoints"]),
    } for index, row in enumerate(source, 1)]
    digest = sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":")).encode("ascii")).hexdigest()
    rows = [{
        "source_snapshot_sha256": digest,
        "proposal_slot": str(item["slot"]),
        "human_stage": "UNASSESSED",
        "human_team": "",
        "human_question": "",
    } for item in payload]
    return rows, digest


def _csv(rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([row[k] for k in COLUMNS])
    return output.getvalue().encode("utf-8")


def _html_editor(rows: list[dict]) -> bytes:
    esc = lambda x: html.escape(str(x), quote=True)
    items = []
    for row in rows:
        slot = row["proposal_slot"]
        items.append(
            '<tr data-review-row data-source="' + row["source_snapshot_sha256"] +
            '" data-slot="' + slot + '"><th scope="row">Original packet #' +
            slot + '</th><td><select aria-label="HUMAN stage packet ' + slot +
            '">' + "".join('<option value="' + esc(stage) + '"' +
                           (' selected' if row["human_stage"] == stage else '') + '>' +
                           esc(stage.replace("_", " ")) + '</option>'
                           for stage in route_queue.STAGES) +
            '</select></td><td><select aria-label="HUMAN team packet ' + slot +
            '">' + "".join('<option value="' + esc(team) + '"' +
                           (' selected' if row["human_team"] == team else '') + '>' +
                           esc(team or "Unassigned") + '</option>'
                           for team in route_queue.TEAMS) +
            '</select></td><td><input maxlength="' + str(NOTE_MAX) +
            '" aria-label="Private HUMAN question for packet ' + slot +
            '" value="' + esc(row["human_question"]) +
            '" placeholder="Optional HUMAN review question"></td></tr>'
        )
    js = r"""'use strict';
(() => {
  const rows = [...document.querySelectorAll('[data-review-row]')];
  const status = document.querySelector('#message');
  const slotSearch = document.querySelector('#packet-search');
  const stageFilter = document.querySelector('#stage-filter');
  const summary = document.querySelector('#review-summary');
  function refresh() {
    const counts = {UNASSESSED:0,HOLD:0,NEEDS_INPUT:0,HUMAN_REVIEW:0,HUMAN_FOLLOWUP:0};
    let visible = 0;
    for (const tr of rows) {
      const stage = tr.querySelector('select').value;
      counts[stage] += 1;
      const matchesSlot = !slotSearch.value.trim() ||
        tr.dataset.slot.includes(slotSearch.value.trim());
      const matchesStage = !stageFilter.value || stage === stageFilter.value;
      tr.hidden = !(matchesSlot && matchesStage);
      if (!tr.hidden) visible += 1;
    }
    summary.textContent = visible + '/' + rows.length +
      ' HUMAN proposals visible · Unassessed ' + counts.UNASSESSED +
      ' · HOLD ' + counts.HOLD + ' · Needs input ' + counts.NEEDS_INPUT +
      ' · Review ' + counts.HUMAN_REVIEW +
      ' · Follow-up ' + counts.HUMAN_FOLLOWUP +
      '. All rows remain in the complete native CSV export.';
  }
  slotSearch.addEventListener('input', refresh);
  stageFilter.addEventListener('change', refresh);
  for (const tr of rows) {
    for (const select of tr.querySelectorAll('select')) {
      select.addEventListener('change', refresh);
    }
  }
  refresh();
  const header = ['source_snapshot_sha256','proposal_slot','human_stage',
                  'human_team','human_question'];
  function quote(s) { return '"' + String(s).replaceAll('"','""') + '"'; }
  document.querySelector('#download').addEventListener('click', () => {
    const output = [header.map(quote).join(',')];
    for (const tr of rows) {
      const stage = tr.querySelectorAll('select')[0].value;
      const team = tr.querySelectorAll('select')[1].value;
      const note = tr.querySelector('input').value;
      if (note.length > 180 || /[\x00-\x1f\x7f]/.test(note) ||
          /^[\s]*[=+\-@]/.test(note) ||
          (stage === 'UNASSESSED' && (team !== '' || note !== ''))) {
        status.textContent = 'HOLD: a HUMAN row is invalid or incomplete; nothing downloaded.';
        return;
      }
      output.push([tr.dataset.source,tr.dataset.slot,stage,team,note].map(quote).join(','));
    }
    const blob = new Blob([output.join('\r\n') + '\r\n'],
                          {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'PRIVATE-LAB-HUMAN-DECISIONS.csv';
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = 'Download requested (not proven). Move into 0700/0600 custody, then use native FINALIZE.';
  });
})();
"""
    hash_js = b64encode(sha256(js.encode("utf-8")).digest()).decode("ascii")
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; script-src \'sha256-' + hash_js +
        '\'; connect-src \'none\'; img-src \'none\'; form-action \'none\'; base-uri \'none\'">'
        "<title>LightUp PRIVATE HUMAN Lab Plan Review</title>"
        "<style>:root{color-scheme:dark;background:#101c2d;color:#edf6fd;font:16px/1.5 system-ui}"
        "body{max-width:1100px;margin:auto;padding:25px}header,main,footer{padding:25px;margin:14px 0;"
        "border-radius:16px;background:#20364c;border:1px solid #52738b}"
        ".warn{font-weight:700;color:#ffe2a6}.wrap{overflow-x:auto}"
        "table{border-collapse:collapse;width:100%;min-width:760px}th,td{text-align:left;padding:14px;"
        "border-bottom:1px solid #456278}select,input,button{padding:9px;font:inherit;border-radius:7px;"
        "background:#10253a;border:1px solid #8fb0c9;color:#f0fbff}input{width:100%}"
        "button{margin:15px 0}a{color:#bfe9ff}</style></head><body>"
        "<header><p class='warn'>PRIVATE / SOURCE-BOUND / HUMAN REVIEW ONLY</p>"
        "<h1>Lab Proposal HUMAN Review Studio</h1><p>" + str(len(rows)) +
        " re-admitted original private lab proposals. Review scope and planning "
        "questions only; do not add client identifiers, passwords, credentials, "
        "finding claims or assessment approvals.</p></header>"
        "<main><h2>Draft HUMAN decisions</h2><p>Every row starts UNASSESSED. "
        "First-use rows start UNASSESSED; native source-revalidated HUMAN choices can be reopened.</p>"
        "<label>Filter packet number <input id='packet-search' type='search' inputmode='numeric' "
        "autocomplete='off' placeholder='Packet slot'></label> "
        "<label>Filter HUMAN stage <select id='stage-filter'><option value=''>All stages</option>" +
        "".join("<option value='" + esc(stage) + "'>" + esc(stage) + "</option>"
                for stage in route_queue.STAGES) +
        "</select></label><p id='review-summary' role='status' aria-live='polite'></p>"
        "<div class='wrap'><table><thead><tr><th>Original packet</th>"
        "<th>HUMAN stage</th><th>Proposed team</th><th>PRIVATE question</th></tr></thead><tbody>" +
        "".join(items) + "</tbody></table></div>"
        "<button id='download' type='button'>Download complete PRIVATE HUMAN decisions CSV</button>"
        "<p id='message' role='status' aria-live='polite'>No browser changes persisted. "
        "Browser download permission is NOT automatically 0600.</p></main>"
        "<footer><p class='warn'>DRAFT/HOLD · NO AUTHORIZATION</p><p>Move the "
        "downloaded PRIVATE CSV to an owner-only 0700 parent and set mode 0600 "
        "before native finalize. The original source-owning validator must "
        "re-open all original packets and match the exact unsigned source "
        "snapshot again. The browser cannot authenticate reviewer identity "
        "or prove permission. No scan, grant, network, model or dispatch.</p>"
        "</footer><script>" + js + "</script></body></html>"
    )
    # Pin the exact generated inline CSS as well as the inline JS.
    # Offline browser output never needs generic unsafe-inline styling.
    start = page.index("<style>") + len("<style>")
    end = page.index("</style>", start)
    style_pin = b64encode(sha256(page[start:end].encode("utf-8")).digest()).decode("ascii")
    page = page.replace("style-src 'unsafe-inline'",
                        "style-src 'sha256-" + style_pin + "'")
    return page.encode("utf-8")


def _rows_admit(original: list[dict], source: str) -> list[dict]:
    raw = route_queue.read_owner_csv(source)
    try:
        reader = csv.reader(io.StringIO(raw.decode("utf-8", "strict"), newline=""),
                            strict=True)
        head = next(reader)
        if tuple(head) != COLUMNS:
            raise privacy.Hold("HOLD: original HUMAN Lab Plan CSV columns changed")
        records = list(reader)
        if len(records) != len(original):
            raise privacy.Hold("HOLD: original Lab Plan CSV row count changed")
        result = []
        for base, fields in zip(original, records):
            if len(fields) != len(COLUMNS):
                raise privacy.Hold("HOLD: original lab HUMAN row malformed")
            row = dict(zip(COLUMNS, fields))
            if (row["source_snapshot_sha256"] != base["source_snapshot_sha256"]
                    or row["proposal_slot"] != base["proposal_slot"]):
                raise privacy.Hold("HOLD: original lab HUMAN source binding changed")
            stage, team, note = (row["human_stage"], row["human_team"],
                                 row["human_question"])
            if stage not in route_queue.STAGES or team not in route_queue.TEAMS:
                raise privacy.Hold("HOLD: unsupported HUMAN stage/team")
            if (len(note) > NOTE_MAX or any(ord(c) < 32 or ord(c) == 127 for c in note)
                    or note.lstrip().startswith(("=", "+", "-", "@"))):
                raise privacy.Hold("HOLD: unsafe PRIVATE HUMAN question")
            if stage == "UNASSESSED" and (team or note):
                raise privacy.Hold("HOLD: UNASSESSED cannot carry a HUMAN decision")
            result.append(row)
        return result
    except (UnicodeError, csv.Error, StopIteration):
        raise privacy.Hold("HOLD: unreadable PRIVATE HUMAN Lab Plan CSV") from None


def _admit_existing_review_room(room: str, fingerprint: str,
                                expected_count: int) -> Path:
    """Admit the unchanged ORIGINAL private review receipt, not an approval."""
    source = lab_plans._packet(room)
    receipt = workpack_progress._private_receipt(source / "PRIVATE-LAB-HUMAN-RECEIPT.json")
    if (set(receipt) != {
            "schema", "status", "source_snapshot_sha256_unsigned",
            "source_count", "source_bytes_included", "verified_source",
            "verified_consent", "authority"}
            or receipt["schema"] != SCHEMA or receipt["status"] != "DRAFT_HOLD"
            or receipt["source_snapshot_sha256_unsigned"] != fingerprint
            or type(receipt["source_count"]) is not int
            or receipt["source_count"] != expected_count
            or receipt["source_bytes_included"] is not False
            or receipt["verified_source"] is not False
            or receipt["verified_consent"] is not False
            or type(receipt["authority"]) is not dict
            or set(receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(receipt["authority"][key]) is not bool
                   or receipt["authority"][key] is not False
                   for key in privacy.AUTHORITY)):
        raise privacy.Hold("HOLD: original HUMAN review receipt/session changed")
    return source


def prepare(packets: list[str], parent: str, folder: str,
            *, prior_room: str = "", prior_csv: str = "") -> Path:
    output = lab_plans._new_path(parent, folder)
    rows, fingerprint = _source_rows(packets)
    if bool(prior_room) != bool(prior_csv):
        raise privacy.Hold("HOLD: original review room and HUMAN CSV must be paired")
    if prior_room:
        source = _admit_existing_review_room(prior_room, fingerprint, len(rows))
        if source == output or source in output.parents:
            raise privacy.Hold("HOLD: continued HUMAN room cannot be inside original")
        # Re-admit the SAME original source identity and all prior HUMAN rows
        # before opening any new output folder.
        rows = _rows_admit(rows, prior_csv)
    receipt = {
        "schema": SCHEMA, "status": "DRAFT_HOLD",
        "source_snapshot_sha256_unsigned": fingerprint,
        "source_count": len(rows),
        "source_bytes_included": False,
        "verified_source": False, "verified_consent": False,
        "authority": privacy.AUTHORITY,
    }
    docs = (
        ("OPEN-PRIVATE.html", _html_editor(rows)),
        ("PRIVATE-LAB-HUMAN-TEMPLATE.csv", _csv(rows)),
        ("PRIVATE-LAB-HUMAN-RECEIPT.json",
         (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    )
    output.mkdir(mode=0o700)
    try:
        if not privacy.private(output, True):
            raise privacy.Hold("HOLD: original PRIVATE HUMAN Lab Plan room not owner-owned")
        for file, contents in docs:
            privacy.private_write(output, file, contents)
        fd = os.open(output, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(output)
        raise privacy.Hold("HOLD: original HUMAN Lab Plan Studio not published") from None
    return output / "OPEN-PRIVATE.html"


def finalize(packets: list[str], room: str, edited_csv: str, parent: str,
             folder: str) -> Path:
    output = lab_plans._new_path(parent, folder)
    original, fingerprint = _source_rows(packets)
    source = _admit_existing_review_room(room, fingerprint, len(original))
    if source == output or source in output.parents:
        raise privacy.Hold("HOLD: final review cannot be inside original room")
    rows = _rows_admit(original, edited_csv)
    summary = {
        "schema": SCHEMA, "status": "REVIEW_ONLY",
        "source_snapshot_sha256_unsigned": fingerprint,
        "verified_source": False, "verified_consent": False,
        "authority": privacy.AUTHORITY,
        "human_stages": {stage: sum(r["human_stage"] == stage for r in rows)
                         for stage in route_queue.STAGES},
        "human_teams": {team: sum(r["human_team"] == team for r in rows)
                        for team in route_queue.TEAMS if team},
        "no_approval_or_execution": True,
        "original_urls_included": False, "human_question_text_included": False,
    }
    fragments = "".join(
        "<li><strong>Original packet #" + html.escape(row["proposal_slot"]) +
        "</strong> · " + html.escape(row["human_stage"]) + " · " +
        html.escape(row["human_team"] or "No team") +
        "<br>HUMAN question: " + html.escape(row["human_question"] or "None") + "</li>"
        for row in rows
    )
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp / Private original Lab Proposal HUMAN Review</title>
<style>:root{color-scheme:dark;background:#101d30;color:#edf6fd;font:16px/1.5 system-ui}
body{max-width:950px;margin:auto;padding:24px}header,main,footer{padding:25px;margin:18px 0;background:#1c364c;border:1px solid #476881;border-radius:16px}
.warn{color:#ffdfa7;font-weight:bold}li{padding:14px 0;border-bottom:1px solid #49657a}</style>
<header><p class="warn">PRIVATE HUMAN / DRAFT-HOLD / NO AUTHORITY</p>
<h1>Original Lab Proposal HUMAN Review</h1><p>""" + str(len(rows)) + """
strict original-source-bound PRIVATE proposals. All statuses are
HUMAN drafts; no security target contact, scan, finding, grant or
customer identity/consent has been verified.</p></header><main><ol>""" +
            fragments + """</ol></main><footer>Free HUMAN questions are confidential.
Keep this file 0600 within owner-only 0700 custody. An unchanged unsigned
source SHA is not authentication, approval or current permission. No
model, network, real deployment or automatic dispatch. Existing exact-head CI,
source-owner, independent privacy/security/browser review, authentic separate
client and operator consent incl. action-time revocation, explicit HUMAN GO
still required. INCUBATE M3/M7 · PLAN/LAB ONLY.</footer></html>""").encode("utf-8")
    private_csv = _csv(rows)
    docs = (
        ("OPEN-PRIVATE.html", page),
        ("PRIVATE-HUMAN-FINAL.csv", private_csv),
        ("PRIVATE-HUMAN-SUMMARY.json",
         (json.dumps(summary, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":")) + "\n").encode("ascii")),
    )
    output.mkdir(mode=0o700)
    try:
        if not privacy.private(output, True):
            raise privacy.Hold("HOLD: final original HUMAN Lab Plan room not private")
        for name, content in docs:
            privacy.private_write(output, name, content)
        fd = os.open(output, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(output)
        raise privacy.Hold("HOLD: original PRIVATE Lab HUMAN review not published") from None
    return output / "OPEN-PRIVATE.html"
