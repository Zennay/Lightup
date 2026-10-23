#!/usr/bin/env python3
"""Owner-private offline HUMAN discussion team routing, not real assignment.

Every original review, received discussion and manually ordered completed
HUMAN action round is re-admitted. Team labels are suggestions only: there
is no authenticated team member, sender, broker, consent or scope grant.
"""
from __future__ import annotations

from private_csv_formula import unsafe_private_csv_note

from base64 import b64encode
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import tempfile

from notes import Hold, private_directory, private_input, file_new, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_discussion_history import source_state, reopen_history
from privacy_triage_discussion_focus import focus_rows

SCHEMA = "lightup.private_human_action_team_routing.v1"
FIELDS = ("original_ordinal", "human_proposed_team", "private_followup_note")
TEAMS = ("UNASSIGNED", "SECURITY", "PRIVACY", "CLIENT_OPERATIONS", "PLATFORM")


def write_csv(rows: list[dict]) -> bytes:
    result = io.StringIO(newline="")
    result.write(",".join(FIELDS) + "\r\n")
    writer = csv.writer(result, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    for row in rows:
        writer.writerow([row[key] for key in FIELDS])
    return result.getvalue().encode("utf-8")


def blank(original_ordinals: list[int]) -> list[dict]:
    return [
        {"original_ordinal": str(ordinal), "human_proposed_team": "UNASSIGNED",
         "private_followup_note": ""}
        for ordinal in original_ordinals
    ]


def read_complete(raw: bytes, original_ordinals: list[int]) -> list[dict]:
    if not raw or len(raw) > 65536 or b"\x00" in raw:
        raise Hold("HOLD: invalid PRIVATE HUMAN team CSV size")
    try:
        value = raw.decode("utf-8", "strict")
        if value.startswith("\ufeff") or not value.endswith("\r\n"):
            raise ValueError("noncanonical")
        lines = list(csv.reader(io.StringIO(value, newline=""), strict=True))
        if (not lines or lines[0] != list(FIELDS)
                or len(lines) - 1 != len(original_ordinals)):
            raise ValueError("source roster")
        rows = []
        for raw_row, ordinal in zip(lines[1:], original_ordinals):
            if len(raw_row) != 3 or raw_row[0] != str(ordinal) or raw_row[1] not in TEAMS:
                raise ValueError("original ordinal/team mismatch")
            note = raw_row[2]
            if (len(note) > 160 or note.lstrip().startswith(("=", "-", "+", "@"))
                    or unsafe_private_csv_note(note, 160)
                    or any(ord(c) < 32 or ord(c) == 127 for c in note)):
                raise ValueError("invalid private routing note")
            rows.append({"original_ordinal": str(ordinal),
                         "human_proposed_team": raw_row[1],
                         "private_followup_note": note})
        if raw != write_csv(rows):
            raise ValueError("not canonical original HUMAN export")
        return rows
    except (ValueError, UnicodeError, csv.Error):
        raise Hold("HOLD: invalid or unbound PRIVATE HUMAN proposed-team CSV") from None


def original_state(original: str, reviews: list[str], received: str,
                   finals: list[str], history: str):
    reopen_history(original, reviews, received, finals, history)
    sources, manifest, decisions, packets, received_csv, selected, rounds, records, shas, copies, export = source_state(
        original, reviews, received, finals)
    latest = focus_rows(records, [x[0] for x in selected], len(rounds))
    by_ordinal = {row["original_ordinal"]: row for row in latest}
    original_ordinals = [x[0] for x in selected]
    return (sources, manifest, decisions, packets, received_csv, rounds,
            shas, latest, by_ordinal, original_ordinals)


def bindings(source) -> dict:
    sources, manifest, decisions, packets, received_csv, rounds, shas, latest, by_ordinal, original_ordinals = source
    return {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "private_human_team_proposals_only": True,
        "actual_team_owners_not_authenticated": True,
        "original_count": len(sources),
        "selected_original_ordinals": original_ordinals,
        "human_rounds": len(rounds),
        "original_manifest_sha256_unsigned": manifest,
        "original_human_csv_sha256_unsigned": decisions,
        "original_reviewer_csv_sha256_unsigned": [
            x["csv_sha256_unsigned"] for x in packets],
        "original_received_selected_csv_sha256_unsigned": sha256(received_csv).hexdigest(),
        "original_human_round_csv_sha256_unsigned": shas,
        **{flag: False for flag in FALSE_FLAGS},
    }


def editor(source) -> bytes:
    _, _, _, _, _, _, _, _, by_ordinal, original_ordinals = source
    info = [
        {"ordinal": ordinal, "latest": by_ordinal[ordinal]["latest_human_step"]}
        for ordinal in original_ordinals
    ]
    encoded = json.dumps(info, ensure_ascii=True, separators=(",", ":")).replace("<", r"\u003c")
    js = r"""'use strict';
const originals = """ + encoded + r""";
const teams = ['UNASSIGNED','SECURITY','PRIVACY','CLIENT_OPERATIONS','PLATFORM'];
const list = document.getElementById('sources');
const message = document.getElementById('message');
const fields = new Map();
for(const row of originals){
 const section=document.createElement('section');
 const title=document.createElement('h2');
 title.textContent='Original #'+row.ordinal+' · latest declared HUMAN action: '+row.latest.replaceAll('_',' ');
 section.append(title);
 const label=document.createElement('label');
 label.textContent='Proposed internal HUMAN discussion team (NOT assigned) ';
 const team=document.createElement('select');
 team.setAttribute('aria-label','Proposed team for original '+row.ordinal);
 for(const code of teams){
  const option=document.createElement('option');
  option.textContent=code.replaceAll('_',' ');option.value=code;team.append(option);
 }
 label.append(team);section.append(label);
 const noteLabel=document.createElement('label');
 noteLabel.textContent='Optional PRIVATE human-only follow-up note (max 160; no secrets) ';
 const note=document.createElement('input');note.type='text';note.maxLength=160;
 note.setAttribute('aria-label','Private proposed team note for original '+row.ordinal);
 noteLabel.append(note);section.append(noteLabel);
 fields.set(row.ordinal,{team,note});list.append(section);
}
const bad=s=>s.length>160||/^[\s]*[=+@-]/.test(s)||/[\x00-\x1f\x7f]/.test(s);
const quote=s=>'"'+String(s).replaceAll('"','""')+'"';
function download(rows){
 const text=['original_ordinal,human_proposed_team,private_followup_note',
  ...rows.map(row=>row.map(quote).join(','))].join('\r\n')+'\r\n';
 const url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'}));
 const a=document.createElement('a');a.href=url;
 a.download='PRIVATE-HUMAN-team-proposals.csv';
 document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),15000);
}
document.getElementById('export').addEventListener('click',()=>{
 const records=[];
 for(const row of originals){
  const input=fields.get(row.ordinal);
  if(!teams.includes(input.team.value)||bad(input.note.value)){
   message.textContent='HOLD: invalid PRIVATE team or human note. No export.';
   return;
  }
  records.push([row.ordinal,input.team.value,input.note.value]);
 }
 if(!window.confirm('Export ALL original-source HUMAN team proposals locally? No real team assignment or sharing permission.'))return;
 download(records);
 message.textContent='Downloaded PRIVATE source-complete HUMAN proposed-team CSV. Place in 0600 owner-only file and finalize natively. HOLD.';
});
"""
    # Static CSP pin is derived from the exact embedded byte source.
    pin = b64encode(sha256(js.encode("utf-8")).digest()).decode("ascii")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'sha256-""" + pin +
            """';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN proposed discussion teams</title>
<style>body{max-width:950px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#243749}
aside{background:#fff0e8;border-left:5px solid #ae4b28;padding:1rem}
section{border:1px solid #ccd;border-radius:12px;padding:13px;margin:1rem 0}
label{display:block;padding:.4rem}input{width:90%;max-width:650px}
button{padding:13px} :focus-visible{outline:3px solid #bd7a25}</style>
<h1>PRIVATE HUMAN proposed team routing</h1>
<aside><b>INCUBATE / PLAN/LAB ONLY / DRAFT/HOLD.</b>
These are NOT team assignments, real responsible persons, authenticated owner
identities, scope grants, client consent, privacy clearance, findings or fixes.
The local human owner must still decide actual follow-up separately.
No external communications, server access, scheduling, model or tool calls.
Keep PRIVATE notes and CSV on owner-only storage.</aside>
<p>Every selected original source remains in the export even if not assigned.
All choices start UNASSIGNED; no stage or team is automatically adopted.</p>
<main id="sources"></main>
<button id="export" type="button">Save complete PRIVATE HUMAN proposed-team CSV</button>
<p id="message" role="status" aria-live="polite">No real team permissions are created.</p>
<script>""" + js + """</script></html>""").encode("utf-8")


def meeting_page(rows: list[dict], latest: dict[int, dict]) -> bytes:
    fragments = []
    for team in TEAMS:
        assigned = [row for row in rows if row["human_proposed_team"] == team]
        if not assigned:
            continue
        lines = []
        for row in assigned:
            ordinal = int(row["original_ordinal"])
            status = latest[ordinal]["latest_human_step"]
            lines.append("<li>Original #" + str(ordinal) + " · latest HUMAN step " +
                         html.escape(status) + " · PRIVATE follow-up note " +
                         ("present; text withheld" if row["private_followup_note"]
                          else "blank") + "</li>")
        fragments.append("<section><h2>" + html.escape(team.replace("_", " ")) +
                         " · proposed HUMAN discussion only</h2><ol>" +
                         "".join(lines) + "</ol></section>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>LightUp PRIVATE HUMAN proposed-team briefing</title>
<style>body{font:16px/1.6 system-ui;max-width:900px;margin:2rem auto;padding:1rem}
aside{background:#fff0e8;border-left:5px solid #a94325;padding:1rem}
section{border:1px solid #ccc;padding:12px;margin:1rem 0}li{margin:.6rem}</style>
<h1>PRIVATE HUMAN proposed-team conversation, not delivery</h1>
<aside><b>HOLD · NO REAL TEAM ASSIGNMENT OR PRIVACY CLEARANCE.</b>
Teams below are locally proposed labels only. No person, recipient, operator
or client is authenticated; no action is dispatched, no actual issue ownership
granted, no scan, model, consent, confirmed fix or public disclosure allowed.
Notes remain PRIVATE in a separate owner-only CSV; text is withheld here.</aside>
""" + "".join(fragments) + """<footer>Original complete HUMAN packets and
all authority/identity/revocation gates remain independent, unchanged and
mandatory. Never treat this as a task assignment or recipient approval.
</footer></html>""").encode("utf-8")


def prepare(original: str, reviews: list[str], received: str, finals: list[str],
            history: str, parent_name: str) -> int:
    source = original_state(original, reviews, received, finals, history)
    parent = private_directory(parent_name)
    folder = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-team-draft-", dir=parent))
    os.chmod(folder, 0o700)
    complete = False
    try:
        save_json(folder / "PRIVATE-HUMAN-team-bindings.json", bindings(source))
        file_new(folder / "PRIVATE-HUMAN-team-template.csv",
                 write_csv(blank(source[-1])))
        file_new(folder / "PRIVATE-HUMAN-team-editor.html", editor(source))
        complete = True
        print("REVIEW_ONLY: PRIVATE original-source-bound proposed-team Studio prepared")
        print("OPEN LOCALLY: " + str(folder / "PRIVATE-HUMAN-team-editor.html"))
        return 2
    finally:
        if not complete:
            shutil.rmtree(folder)


def completed_receipt(source, raw: bytes, rows: list[dict]) -> dict:
    return {
        **bindings(source),
        "completed_human_team_csv_sha256_unsigned": sha256(raw).hexdigest(),
        "manual_team_counts": {
            team: sum(row["human_proposed_team"] == team for row in rows)
            for team in TEAMS},
        "real_team_members_or_consent_authenticated": False,
    }


def finalize(original: str, reviews: list[str], received: str,
             finals: list[str], history: str, draft_room: str,
             completed_csv: str, parent_name: str) -> int:
    source = original_state(original, reviews, received, finals, history)
    draft = private_directory(draft_room)
    expected = (json.dumps(bindings(source), indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n").encode("utf-8")
    if private_input(str(draft / "PRIVATE-HUMAN-team-bindings.json"), 65536) != expected:
        raise Hold("HOLD: original PRIVATE HUMAN proposed-team source binding changed")
    if (private_input(str(draft / "PRIVATE-HUMAN-team-editor.html"), 65536)
            != editor(source)):
        raise Hold("HOLD: original PRIVATE HUMAN team Studio changed")
    if (private_input(str(draft / "PRIVATE-HUMAN-team-template.csv"), 65536)
            != write_csv(blank(source[-1]))):
        raise Hold("HOLD: original PRIVATE HUMAN team source roster changed")
    raw = private_input(completed_csv, 65536)
    rows = read_complete(raw, source[-1])
    parent = private_directory(parent_name)
    out = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-team-proposals-", dir=parent))
    os.chmod(out, 0o700)
    complete = False
    try:
        save_json(out / "PRIVATE-HUMAN-team-receipt.json",
                  completed_receipt(source, raw, rows))
        file_new(out / "PRIVATE-HUMAN-team-proposals.csv", raw)
        file_new(out / "PRIVATE-HUMAN-team-briefing.html",
                 meeting_page(rows, source[-2]))
        complete = True
        print("HOLD: PRIVATE HUMAN proposed-team packet created; NO real assignment")
        print("OPEN LOCALLY: " + str(out / "PRIVATE-HUMAN-team-briefing.html"))
        return 3
    finally:
        if not complete:
            shutil.rmtree(out)



def reopen_team(original: str, reviews: list[str], received: str,
                finals: list[str], history: str, team_room: str) -> int:
    """Read-only original source/round/team receipt admission, no assignment."""
    source = original_state(original, reviews, received, finals, history)
    folder = private_directory(team_room)
    csv_raw = private_input(
        str(folder / "PRIVATE-HUMAN-team-proposals.csv"), 65536)
    rows = read_complete(csv_raw, source[-1])
    expected = completed_receipt(source, csv_raw, rows)
    canonical = (json.dumps(expected, indent=2, sort_keys=True,
                            ensure_ascii=False) + "\n").encode("utf-8")
    if (private_input(str(folder / "PRIVATE-HUMAN-team-receipt.json"), 65536)
            != canonical):
        raise Hold("HOLD: original-bound HUMAN team receipt altered")
    if (private_input(str(folder / "PRIVATE-HUMAN-team-briefing.html"), 65536)
            != meeting_page(rows, source[-2])):
        raise Hold("HOLD: original-bound HUMAN team briefing altered")
    print("HOLD: original-bound PRIVATE HUMAN team packet reopened read-only")
    print("OPEN LOCALLY: " + str(folder / "PRIVATE-HUMAN-team-briefing.html"))
    return 3
