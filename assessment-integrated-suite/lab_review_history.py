#!/usr/bin/env python3
"""Original-source-bound PRIVATE HUMAN Lab Review history; no scan or grants."""
from __future__ import annotations
import argparse
import csv
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys
import lab_plans
import lab_plan_review
import private_session as privacy
import route_queue
import workpack_progress

SCHEMA = "lightup.private.lab-human-review-history.v1"
MAX_ROUNDS = 8
SUMMARY_KEYS = frozenset((
    "schema","status","source_snapshot_sha256_unsigned","verified_source",
    "verified_consent","authority","human_stages","human_teams",
    "no_approval_or_execution","original_urls_included","human_question_text_included"
))

def _admit_final(folder: str, originals: list[dict], fingerprint: str) -> list[dict]:
    source = lab_plans._packet(folder)
    receipt = workpack_progress._private_receipt(source / "PRIVATE-HUMAN-SUMMARY.json")
    if (set(receipt) != SUMMARY_KEYS
        or receipt["schema"] != lab_plan_review.SCHEMA
        or receipt["status"] != "REVIEW_ONLY"
        or receipt["source_snapshot_sha256_unsigned"] != fingerprint
        or receipt["no_approval_or_execution"] is not True
        or any(receipt[k] is not False for k in
               ("verified_source","verified_consent","original_urls_included",
                "human_question_text_included"))
        or type(receipt["authority"]) is not dict
        or set(receipt["authority"]) != set(privacy.AUTHORITY)
        or any(type(receipt["authority"][k]) is not bool or
               receipt["authority"][k] is not False for k in privacy.AUTHORITY)):
        raise privacy.Hold("HOLD: native PRIVATE HUMAN result receipt has changed")
    # Reapply ORIGINAL source, schema, exact per-slot identity and CSV constraints.
    rows = lab_plan_review._rows_admit(originals, str(source / "PRIVATE-HUMAN-FINAL.csv"))
    stages = {s:sum(r["human_stage"]==s for r in rows) for s in route_queue.STAGES}
    teams = {t:sum(r["human_team"]==t for r in rows)
             for t in route_queue.TEAMS if t}
    if receipt["human_stages"] != stages or receipt["human_teams"] != teams:
        raise privacy.Hold("HOLD: original PRIVATE HUMAN result counts differ")
    return rows

def movements(rounds: list[list[dict]]) -> tuple[list[dict], list[dict]]:
    events=[]
    for i in range(1,len(rounds)):
        for a,b in zip(rounds[i-1],rounds[i]):
            if any(a[k]!=b[k] for k in ("human_stage","human_team","human_question")):
                events.append({
                    "from_position":i,"to_position":i+1,
                    "proposal_slot":int(b["proposal_slot"]),
                    "previous_human_stage":a["human_stage"],
                    "current_human_stage":b["human_stage"],
                    "previous_team":a["human_team"],
                    "current_team":b["human_team"],
                    "private_question_changed":a["human_question"]!=b["human_question"]})
    attention=[]
    for i,current in enumerate(rounds[-1]):
        if current["human_stage"] not in ("HOLD","NEEDS_INPUT"):
            continue
        streak=0
        for older in reversed(rounds):
            if older[i]["human_stage"] not in ("HOLD","NEEDS_INPUT"):
                break
            streak+=1
        attention.append({
            "proposal_slot":int(current["proposal_slot"]),
            "declared_stage":current["human_stage"],
            "declared_team":current["human_team"],
            "consecutive_operator_declared_rounds":streak,
            "first_continuous_position":len(rounds)-streak+1})
    return events,attention

def _page(rounds: list[list[dict]], events: list[dict], attention: list[dict]) -> bytes:
    esc=lambda s:html.escape(str(s),quote=True)
    rows=[]
    for i,round_ in enumerate(rounds,1):
        rows.append("<tr><th scope='row'>#"+str(i)+"</th>"+
            "".join("<td>"+str(sum(x["human_stage"]==stage for x in round_))+"</td>"
                    for stage in route_queue.STAGES)+"</tr>")
    changes=[
        "<li>Packet #"+str(e["proposal_slot"])+" · #"+str(e["from_position"])+
        " → #"+str(e["to_position"])+"<br>Stage: "+esc(e["previous_human_stage"])+
        " → "+esc(e["current_human_stage"])+" · Team: "+
        esc(e["previous_team"] or "None")+" → "+esc(e["current_team"] or "None")+
        " · Private question changed: "+("YES" if e["private_question_changed"] else "NO")+"</li>"
        for e in events]
    pending=[
        "<li>Packet #"+str(a["proposal_slot"])+" · "+esc(a["declared_stage"])+
        " · team "+esc(a["declared_team"] or "unassigned")+
        " · "+str(a["consecutive_operator_declared_rounds"])+
        " consecutive declared rounds since #"+str(a["first_continuous_position"])+"</li>"
        for a in attention]
    document=("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Lab Review History</title>
<style>:root{color-scheme:dark;background:#101c30;color:#eef6ff;font:16px/1.5 system-ui}
body{max-width:1050px;margin:auto;padding:24px}header,section,footer{background:#21354b;border:1px solid #5a788e;padding:24px;border-radius:15px;margin:16px 0}
h1{font-size:2rem}.warn{color:#ffe1a0;font-weight:bold}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px;border-bottom:1px solid #536b7d}
li{margin:13px 0}div{overflow-x:auto}</style>
<header><p class="warn">ORIGINAL LAB SOURCE · PRIVATE HUMAN · REVIEW_ONLY</p>
<h1>Lab Proposal HUMAN History</h1><p>""" +str(len(rounds))+""" operator-ordered original finalized PRIVATE HUMAN rounds.
No real chronology or authenticated identity is inferred.</p></header>
<section><h2>Human stage distribution</h2><div><table><thead><tr><th>Round</th>"""+ "".join("<th>"+esc(s)+"</th>" for s in route_queue.STAGES)+"""</tr></thead>
<tbody>"""+"".join(rows)+"""</tbody></table></div></section>
<section><h2>Latest declared HUMAN attention</h2><p>These are operator choices, never incident severity.</p><ol>"""+
("".join(pending) or "<li>No latest HUMAN HOLD or NEEDS_INPUT.</li>")+"""</ol></section>
<section><h2>Manually declared changes</h2><ol>"""+
("".join(changes) or "<li>No changed HUMAN entries.</li>")+"""</ol></section>
<footer><p class="warn">DRAFT/HOLD · NO SCAN, GRANT OR AUTHORITY</p>
<p>Every original owner-only packet was independently re-admitted against
the same original source-bound fingerprint. This page excludes original
URLs, paths, SHA values and HUMAN free-text questions. Original source
authentication, current client/operator consent, action-time revocation,
security/privacy/browser approvals, exact-head CI and HUMAN GO still
require independent verification. No provider, model, network or scheduling.</p></footer></html>""")
    return document.encode("utf-8")

def build(packets: list[str], rooms: list[str], parent: str, name: str) -> Path:
    if (type(rooms) is not list or not 2<=len(rooms)<=MAX_ROUNDS or
        any(type(x) is not str for x in rooms)):
        raise privacy.Hold("HOLD: 2–8 original finalized HUMAN review rooms required")
    dest=lab_plans._new_path(parent,name)
    original,fingerprint=lab_plan_review._source_rows(packets)
    paths=[lab_plans._packet(x) for x in rooms]
    if len(set(paths))!=len(paths) or any(x==dest or x in dest.parents for x in paths):
        raise privacy.Hold("HOLD: repeated or nested original PRIVATE HUMAN review room")
    rounds=[_admit_final(str(x),original,fingerprint) for x in paths]
    if len({_bytes_key(rows) for rows in rounds}) != len(rounds):
        raise privacy.Hold("HOLD: exact duplicate HUMAN decisions are not new review rounds")
    events,attention=movements(rounds)
    result={
        "schema":SCHEMA,"status":"REVIEW_ONLY","authority":privacy.AUTHORITY,
        "verified_source":False,"verified_consent":False,"automated_actions":False,
        "real_chronology_verified":False,"source_paths_or_sha_included":False,
        "private_question_text_included":False,
        "rounds":[{"position":i,"human_stages":{s:sum(r["human_stage"]==s for r in rows)
                   for s in route_queue.STAGES}}
                  for i,rows in enumerate(rounds,1)],
        "declared_movements":events,"latest_attention":attention}
    out_csv=io.StringIO(newline="")
    fields=("from_position","to_position","proposal_slot","previous_human_stage",
            "current_human_stage","previous_team","current_team","private_question_changed")
    writer=csv.writer(out_csv,lineterminator="\r\n")
    writer.writerow(fields)
    for event in events:writer.writerow([event[k] for k in fields])
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest,True):
            raise privacy.Hold("HOLD: output HUMAN history room is not private")
        privacy.private_write(dest,"OPEN-PRIVATE.html",_page(rounds,events,attention))
        privacy.private_write(dest,"PRIVATE-HUMAN-HISTORY.json",
            (json.dumps(result,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"))
        privacy.private_write(dest,"PRIVATE-HUMAN-CHANGES.csv",out_csv.getvalue().encode("utf-8"))
        fd=os.open(dest,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    except (OSError,ValueError):
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: original PRIVATE HUMAN history could not be published") from None
    return dest/"OPEN-PRIVATE.html"

def _bytes_key(rows: list[dict]) -> bytes:
    return lab_plan_review._csv(rows)

def main(argv: list[str]|None=None) -> int:
    cli=argparse.ArgumentParser(description="Review 2–8 original source-bound HUMAN lab rounds offline")
    cli.add_argument("--packet",action="append",required=True)
    cli.add_argument("--final-room",action="append",required=True)
    cli.add_argument("--private-parent",required=True)
    cli.add_argument("--folder",required=True)
    cli.add_argument("--human-confirm",required=True)
    args=cli.parse_args(argv)
    try:
        if args.human_confirm!="BUILD PRIVATE LAB HUMAN HISTORY":
            raise privacy.Hold("HOLD: exact manual HUMAN history confirmation required")
        page=build(args.packet,args.final_room,args.private_parent,args.folder)
        print("PRIVATE REVIEW_ONLY: original lab HUMAN history prepared")
        print("OPEN LOCALLY: "+str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc,privacy.Hold) else
              "HOLD: original HUMAN source or PRIVATE history invalid",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
