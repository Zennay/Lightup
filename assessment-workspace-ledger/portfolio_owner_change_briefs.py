#!/usr/bin/env python3
"""PRIVATE offline HUMAN proposed change-briefs from one original reply inbox.

Original source-bound owner reply → operator follow-up proposal comparison;
human coordination only, never an actual finding, task, consent, grant or scan.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import json
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    literal_false_authority, new_private, object_unique, private_parent,
    read_owner_file, reject, safe_human, write_private,
)
from portfolio_focus import local_path
from portfolio_owner_followup import SCHEMA as FOLLOWUP_SCHEMA, read_inbox, interpret
from portfolio_owner_inbox_viewer import render as browser_viewer

SCHEMA = "lightup.private.workspace-ledger-human-owner-change-briefs.v1"
FOLLOWUP_KEYS = {
    "schema","authority","historical_only","sources_reopened",
    "recipient_authenticated","consent_assumed","actions_dispatched",
    "appointments_booked","verified_remediation","original_owner_inbox_sha256",
    "original_history_sha256","original_human_operator_csv_sha256",
    "human_only_operator_followup_rows",
}
MAX_OWNERS = 8
STAGES = ("needs_discussion", "proposed_followup", "hold")


def admit(args):
    paths=[args.history,args.inbox,args.followup,args.operator_csv,args.private_parent]
    if any(not local_path(p) for p in paths) or len(paths)!=len(set(paths)):
        reject("PRIVATE HOLD: original sources/output parent must be distinct absolute paths")
    private_parent(args.private_parent)
    inbox_raw, history_raw, rows = read_inbox(args.inbox,args.history)
    edited=read_owner_file(args.operator_csv,MAX_MANIFEST)
    actual=interpret(edited,rows,digest(inbox_raw))
    received=read_owner_file(args.followup,MAX_MANIFEST)
    try:
        doc=json.loads(received.decode("utf-8"),object_pairs_hook=object_unique,
                       parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite original HUMAN follow-up"))
    except (UnicodeError,ValueError,TypeError) as exc:
        raise Hold("PRIVATE HOLD: original HUMAN operator response unreadable") from exc
    if (type(doc) is not dict or set(doc)!=FOLLOWUP_KEYS or
        received!=canonical(doc) or doc["schema"]!=FOLLOWUP_SCHEMA or
        not literal_false_authority(doc["authority"],FLAGS) or
        doc["historical_only"] is not True or
        any(doc[x] is not False for x in (
          "sources_reopened","recipient_authenticated","consent_assumed",
          "actions_dispatched","appointments_booked","verified_remediation")) or
        doc["original_owner_inbox_sha256"]!=digest(inbox_raw) or
        doc["original_history_sha256"]!=digest(history_raw) or
        doc["original_human_operator_csv_sha256"]!=digest(edited) or
        doc["human_only_operator_followup_rows"]!=actual):
        reject("PRIVATE HOLD: original HUMAN operator follow-up not exact source-bound")
    grouped={}
    for item in actual:
        proposed=item["original_proposed_human_owner_label"]
        safe_human(proposed,80)
        grouped.setdefault(proposed,[]).append(item)
    if len(grouped)>MAX_OWNERS:
        reject("PRIVATE HOLD: too many distinct original HUMAN proposed owner labels")
    return inbox_raw,history_raw,received,edited,grouped


def selected(rows, changed_only):
    return [r for r in rows if not changed_only or
            r["original_owner_human_reply_stage"]!=r["human_operator_followup_stage"] or
            bool(r["private_human_followup_note"])]


def anonymous(rows, groups):
    tally=Counter(r["human_operator_followup_stage"] for r in rows)
    changes=sum(r["original_owner_human_reply_stage"]!=r["human_operator_followup_stage"] for r in rows)
    notes=sum(bool(r["private_human_followup_note"]) for r in rows)
    return html_page("LightUp PRIVATE HUMAN proposal change counts",
        "<p><strong>Owner-private HUMAN coordination only.</strong> No labels, source "
        "identifiers, SHA hashes or note texts here. NOT verified remediation, "
        "actual security finding, authenticated identity, consent, assigned "
        "task, approved scope or a scan.</p><p>Original proposed HUMAN owner "
        "groups: "+str(groups)+"; selected HUMAN proposals: "+str(len(rows))+
        "; HUMAN proposed-stage changes: "+str(changes)+
        "; HUMAN private-note-present slots: "+str(notes)+".</p><table><tbody>"+
        "".join("<tr><td>"+html.escape(k)+"</td><td>"+str(tally[k])+
                "</td></tr>" for k in STAGES)+"</tbody></table>")


def details(owner, rows, original_count):
    parts=[
      "<p><strong>PRIVATE source-bound original HUMAN proposed-owner brief.</strong> "
      "This proposed label is NOT an authenticated recipient. Owner label: "+
      html.escape(owner,quote=True)+". Original owner slots: "+str(original_count)+
      ". Selected HUMAN discussion rows: "+str(len(rows))+
      ". Zero rows does NOT mean a fix was completed. No automatic sending, "
      "actual assignment, scan, grant, approval or security verdict.</p>",
      "<table><thead><tr><th>Historical source slot</th><th>Received original "
      "HUMAN proposal</th><th>Operator HUMAN proposal</th><th>PRIVATE HUMAN "
      "follow-up note</th></tr></thead><tbody>",
    ]
    for r in rows:
        def esc(x):return html.escape(str(x),quote=True)
        parts.append("<tr><td>"+esc(r["local_case"])+" / "+
            esc(r["historical_transition"])+" / "+esc(r["original_kit"])+
            "</td><td>"+esc(r["original_owner_human_reply_stage"])+
            "</td><td>"+esc(r["human_operator_followup_stage"])+
            "</td><td>"+esc(r["private_human_followup_note"])+
            "</td></tr>")
    parts.append("</tbody></table><p>Manual confidentiality, identity, consent "
                 "and custody review are required before anyone can share this document.</p>")
    return html_page("LightUp PRIVATE original HUMAN owner change brief","".join(parts))


def as_csv(rows):
    stream=io.StringIO(newline="")
    writer=csv.writer(stream,lineterminator="\n")
    cols=("local_case","historical_transition","original_kit",
          "original_round_human_stage","original_owner_human_reply_stage",
          "human_operator_followup_stage","private_human_followup_note")
    writer.writerow(cols)
    for r in rows:writer.writerow([r[k] for k in cols])
    return stream.getvalue()


def run(args):
    inbox,history,followup,edited,groups=admit(args)
    # Repeat exact original native admission immediately before output.
    current=admit(args)
    if current[:4]!=(inbox,history,followup,edited) or current[4]!=groups:
        reject("PRIVATE HOLD: original source-bound HUMAN replies drifted")
    # All output rooms are newly created 0700; source files never changed.
    root=new_private(args.private_parent)
    try:
        records=[]
        for ordinal,(owner,raw_rows) in enumerate(groups.items(),1):
            chosen=selected(raw_rows,args.changed_only)
            room=new_private(root)
            fields={
                "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
                "sources_reopened":False,"recipient_authenticated":False,
                "consent_assumed":False,"actions_dispatched":False,
                "appointments_booked":False,"verified_remediation":False,
                "original_history_sha256":digest(history),
                "original_owner_inbox_sha256":digest(inbox),
                "original_operator_followup_sha256":digest(followup),
                "original_proposed_human_owner_label":owner,
                "changed_only":args.changed_only,
                "original_owner_slot_count":len(raw_rows),
                "human_proposed_owner_rows":chosen,
            }
            outputs={
                "OPEN-PRIVATE.html":anonymous(chosen,1),
                "PRIVATE-HUMAN-owner-change-brief.html":details(owner,chosen,len(raw_rows)),
                "PRIVATE-HUMAN-owner-change-brief.csv":as_csv(chosen),
                "PRIVATE-HUMAN-owner-change-brief.json":canonical(fields),
            }
            if any(len(x if isinstance(x,bytes) else x.encode("utf-8"))>MAX_MANIFEST
                   for x in outputs.values()):
                reject("PRIVATE HOLD: original owner-private HUMAN change packet too large")
            for name,data in outputs.items():write_private(room,name,data)
            records.append({
                "packet":ordinal,"private_room":Path(room).name,
                "original_proposed_human_owner_label":owner,
                "original_owner_slot_count":len(raw_rows),
                "human_selected_rows":len(chosen),
            })
        count=sum(x["human_selected_rows"] for x in records)
        source_minimal=html_page("LightUp PRIVATE HUMAN proposed owner coordination",
            "<p><strong>PRIVATE index; HUMAN proposal only.</strong> No owner labels, "
            "case identities, source paths, free-text notes, grants, consent or "
            "auth.</p><p>Original owner groups: "+str(len(records))+
            "; selected HUMAN proposals: "+str(count)+
            ".</p><table><thead><tr><th>Private owner packet</th><th>Human "
            "proposals</th><th>View</th></tr></thead><tbody>"+
            "".join("<tr><td>"+str(x["packet"])+"</td><td>"+
                    str(x["human_selected_rows"])+"</td><td><a href=\""+
                    html.escape(x["private_room"]+"/PRIVATE-HUMAN-owner-change-brief.html",quote=True)+
                    "\">Open private owner packet</a></td></tr>" for x in records)+
            "</tbody></table>")
        manifest={
            "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_history_sha256":digest(history),
            "original_owner_inbox_sha256":digest(inbox),
            "original_operator_followup_sha256":digest(followup),
            "changed_only":args.changed_only,
            "owner_private_packets_in_explicit_order":records,
        }
        private_board={
            "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_history_sha256":digest(history),
            "original_owner_inbox_sha256":digest(inbox),
            "original_operator_followup_sha256":digest(followup),
            "changed_only":args.changed_only,
            "human_only_proposed_owner_rows":[{
                "original_proposed_human_owner_label":owner,
                "original_owner_slot_count":len(raw_rows),
                "human_proposed_owner_rows":selected(raw_rows,args.changed_only),
            } for owner,raw_rows in groups.items()],
        }
        from portfolio_owner_change_board import render as render_board
        private_browser=render_board()
        if any(len(data if isinstance(data,bytes) else data.encode("utf-8"))>
               MAX_MANIFEST for data in (
            source_minimal,canonical(manifest),canonical(private_board),private_browser
        )):
            reject("PRIVATE HOLD: operator source-bound board exceeds private output limit")
        write_private(root,"OPEN-PRIVATE.html",source_minimal)
        write_private(root,"PRIVATE-HUMAN-operator-change-manifest.json",canonical(manifest))
        write_private(root,"PRIVATE-HUMAN-operator-change-board.json",canonical(private_board))
        write_private(root,"PRIVATE-HUMAN-operator-change-board.html",private_browser)
    except BaseException:
        shutil.rmtree(root)
        raise
    print("PRIVATE HOLD: separate human-only source-bound change briefs; no actual assignment")
    print(str(Path(root)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description=
        "Prepare original source-exact owner-private HUMAN proposal changes offline")
    p.add_argument("--history",required=True,help="Original PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--inbox",required=True,help="Original PRIVATE-HUMAN-owner-inbox.json")
    p.add_argument("--followup",required=True,help="Native PRIVATE-HUMAN-operator-followup.json")
    p.add_argument("--operator-csv",required=True,help="Original PRIVATE-HUMAN-original-operator-followup.csv")
    p.add_argument("--private-parent",required=True,help="Existing 0700 operator-private parent")
    p.add_argument("--changed-only",action="store_true",help="Only proposed changes or human notes")
    args=p.parse_args()
    try:return run(args)
    except (Hold,OSError,ValueError,UnicodeError,TypeError,csv.Error):
        print("PRIVATE HOLD: original HUMAN owner change brief refused",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
