#!/usr/bin/env python3
"""Compare original PRIVATE HUMAN operator follow-up revisions offline.

Two to eight explicitly ordered original operator receipts, paired with
matching original full HUMAN CSVs, against ONE original owner inbox/history.
Never infers real task status, approved scope, consent, verification or scan.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, write_private,
)
from portfolio_focus import local_path
from portfolio_owner_change_briefs import admit as native_change_admit

SCHEMA="lightup.private.workspace-ledger-human-operator-change-history.v1"
MAX_ROUNDS=8
CSV_COLS=(
    "original_proposed_human_owner_label","local_case",
    "historical_transition","original_kit",
    "original_owner_human_reply_stage","first_human_operator_stage",
    "latest_human_operator_stage","human_stage_changed_in_rounds",
    "private_human_note_changed_in_rounds",
)


def admit(args):
    if (type(args.followup) is not list or type(args.operator_csv) is not list or
        not 2<=len(args.followup)==len(args.operator_csv)<=MAX_ROUNDS):
        reject("PRIVATE HOLD: require 2–8 independently finalized original HUMAN operator rounds")
    paths=[args.history,args.inbox,args.private_parent,*args.followup,*args.operator_csv]
    if any(not local_path(path) for path in paths) or len(set(paths))!=len(paths):
        reject("PRIVATE HOLD: original HUMAN history paths must be distinct absolute paths")
    private_parent(args.private_parent)
    stored=[]
    originals=None
    signatures=set()
    first=None
    for followup,csv_path in zip(args.followup,args.operator_csv):
        single=argparse.Namespace(
            history=args.history,inbox=args.inbox,followup=followup,
            operator_csv=csv_path,private_parent=args.private_parent,
        )
        inbox,hist,returned,source,groups=native_change_admit(single)
        if originals is None:originals=(inbox,hist)
        elif originals!=(inbox,hist):
            reject("PRIVATE HOLD: original HISTORY/owner inbox bytes changed between rounds")
        fingerprint=digest(returned)
        if fingerprint in signatures:
            reject("PRIVATE HOLD: repeated byte-identical HUMAN operator version")
        signatures.add(fingerprint)
        flat=[]
        for owner,rows in groups.items():
            for row in rows:flat.append(row)
        keys=[(r["original_proposed_human_owner_label"],r["local_case"],
              r["historical_transition"],r["original_kit"]) for r in flat]
        if len(set(keys))!=len(keys):
            reject("PRIVATE HOLD: duplicate original HUMAN owner source slot")
        baseline=[(r["original_proposed_human_owner_label"],r["local_case"],
                   r["historical_transition"],r["original_kit"],
                   r["original_round_human_stage"],r["original_owner_human_reply_stage"])
                  for r in flat]
        if first is None:first=baseline
        elif baseline!=first:
            reject("PRIVATE HOLD: original HUMAN owner slot set/order or native stage drifted")
        stored.append({
            "return_path":followup,"csv_path":csv_path,
            "receipt_raw":returned,"csv_raw":source,
            "receipt_sha256":fingerprint,"original_csv_sha256":digest(source),
            "rows":flat,
        })
    return originals,stored


def review(stored):
    cases=[]
    counters=Counter()
    for index,origin in enumerate(stored[0]["rows"]):
        revisions=[item["rows"][index] for item in stored]
        stage_steps=[]
        note_steps=[]
        for step in range(1,len(revisions)):
            if revisions[step-1]["human_operator_followup_stage"]!=revisions[step]["human_operator_followup_stage"]:
                stage_steps.append(step+1)
                counters["stage_changes"]+=1
            if revisions[step-1]["private_human_followup_note"]!=revisions[step]["private_human_followup_note"]:
                note_steps.append(step+1)
                counters["note_changes"]+=1
        if stage_steps or note_steps:counters["changed_rows"]+=1
        if revisions[-1]["human_operator_followup_stage"]=="hold":counters["latest_hold"]+=1
        cases.append({
            "original_proposed_human_owner_label":origin["original_proposed_human_owner_label"],
            "local_case":origin["local_case"],
            "historical_transition":origin["historical_transition"],
            "original_kit":origin["original_kit"],
            "original_owner_human_reply_stage":origin["original_owner_human_reply_stage"],
            "first_human_operator_stage":revisions[0]["human_operator_followup_stage"],
            "latest_human_operator_stage":revisions[-1]["human_operator_followup_stage"],
            "human_stage_changed_in_rounds":stage_steps,
            "private_human_note_changed_in_rounds":note_steps,
            "human_operator_stage_by_round":[r["human_operator_followup_stage"] for r in revisions],
        })
    return cases,counters


def csv_source(rows):
    stream=io.StringIO(newline="")
    writer=csv.writer(stream,lineterminator="\n")
    writer.writerow(CSV_COLS)
    for r in rows:
        writer.writerow([
            ";".join(map(str,r[k])) if isinstance(r[k],list) else r[k]
            for k in CSV_COLS
        ])
    return stream.getvalue()


def owner_html(owner,rows,round_count):
    parts=[
        "<p><strong>Owner-private HUMAN proposal version history, DRAFT/HOLD.</strong>"
        " Proposed owner label (not authenticated): "+html.escape(owner,quote=True)+
        ". Original HUMAN rounds given in operator-selected order: "+str(round_count)+
        ". Neither first/latest stage nor absence of changes proves actual "
        "completion, remediation or security clearance. No PRIVATE human note "
        "contents are copied into this historical summary.</p>",
        "<table><thead><tr><th>Original source slot</th><th>Original HUMAN owner "
        "reply</th><th>Operator HUMAN stage rounds</th><th>Stage changed rounds</th>"
        "<th>PRIVATE note changed rounds (not text)</th></tr></thead><tbody>",
    ]
    for r in rows:
        def esc(k):return html.escape(str(r[k]),quote=True)
        parts.append("<tr><td>"+esc("local_case")+" / "+esc("historical_transition")+
                     " / "+esc("original_kit")+"</td><td>"+
                     esc("original_owner_human_reply_stage")+"</td><td>"+
                     html.escape(" → ".join(r["human_operator_stage_by_round"]))+
                     "</td><td>"+html.escape(",".join(map(str,r["human_stage_changed_in_rounds"])) or "none")+
                     "</td><td>"+html.escape(",".join(map(str,r["private_human_note_changed_in_rounds"])) or "none")+
                     "</td></tr>")
    return html_page("LightUp PRIVATE original HUMAN operator versions",
                     "".join(parts)+"</tbody></table>")


def anonym(rows,round_count):
    changes=sum(bool(r["human_stage_changed_in_rounds"] or
                     r["private_human_note_changed_in_rounds"]) for r in rows)
    return html_page("LightUp PRIVATE HUMAN-only version counts",
        "<p>Original source-bound HUMAN coordination only; source IDs, proposed "
        "HUMAN owner labels, SHA digests and human note text omitted. "
        "No actual work, verified security finding, scope authorization, "
        "consent, recipient authenticity or active scan.</p><p>Explicitly ordered "
        "human proposal versions: "+str(round_count)+
        "; original HUMAN-only slots: "+str(len(rows))+
        "; slots with altered proposals or note text: "+str(changes)+
        ".</p>")



def latest_changes(rows, rounds):
    result=[]
    for r in rows:
        values=r["human_operator_stage_by_round"]
        if len(values)!=rounds:
            reject("PRIVATE HOLD: incomplete original HUMAN historical status progression")
        previous,current=values[-2:]
        note_changed=rounds in r["private_human_note_changed_in_rounds"]
        if previous!=current or note_changed:
            result.append({
                "local_case":r["local_case"],
                "historical_transition":r["historical_transition"],
                "original_kit":r["original_kit"],
                "previous_human_operator_stage":previous,
                "latest_human_operator_stage":current,
                "private_human_note_changed":note_changed,
            })
    return result


def latest_html(owner, rows, total, round_no):
    parts=[
        "<p><strong>PRIVATE original HUMAN-only latest-change briefing, DRAFT/HOLD."
        "</strong> Original proposed owner: "+html.escape(owner,quote=True)+
        " (NOT recipient authentication). Comparing manually supplied versions "+
        str(round_no-1)+" → "+str(round_no)+". Original owner source slots: "+
        str(total)+"; latest-changed proposal slots: "+str(len(rows))+
        ". No changes does NOT prove remediation, an actual task, authorization "
        "or consent. No HUMAN note text is present.</p>",
        "<table><thead><tr><th>Original source slot</th><th>Previous HUMAN "
        "proposal</th><th>Latest HUMAN proposal</th><th>PRIVATE note changed? "
        "(not note content)</th></tr></thead><tbody>",
    ]
    for r in rows:
        def esc(k):return html.escape(str(r[k]),quote=True)
        parts.append("<tr><td>"+esc("local_case")+" / "+esc("historical_transition")+
                     " / "+esc("original_kit")+"</td><td>"+
                     esc("previous_human_operator_stage")+"</td><td>"+
                     esc("latest_human_operator_stage")+"</td><td>"+
                     ("yes" if r["private_human_note_changed"] else "no")+"</td></tr>")
    return html_page("LightUp PRIVATE HUMAN latest-round changes",
                     "".join(parts)+"</tbody></table>")


def latest_csv(rows):
    output=io.StringIO(newline="")
    keys=("local_case","historical_transition","original_kit",
          "previous_human_operator_stage","latest_human_operator_stage",
          "private_human_note_changed")
    writer=csv.writer(output,lineterminator="\n")
    writer.writerow(keys)
    for row in rows:writer.writerow([row[k] for k in keys])
    return output.getvalue()

def run(args):
    original,stored=admit(args)
    rows,metrics=review(stored)
    again,all_reopened=admit(args)
    if (again!=original or
        len(all_reopened)!=len(stored) or
        any(a["receipt_raw"]!=b["receipt_raw"] or
            a["csv_raw"]!=b["csv_raw"] for a,b in zip(stored,all_reopened))):
        reject("PRIVATE HOLD: original HUMAN operator version inputs drifted")
    groups={}
    for r in rows:groups.setdefault(r["original_proposed_human_owner_label"],[]).append(r)
    root=new_private(args.private_parent)
    try:
        operator=[]
        for ordinal,(owner,selected) in enumerate(groups.items(),1):
            directory=new_private(root)
            latest=latest_changes(selected,len(stored))
            data={
                "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
                "sources_reopened":False,"recipient_authenticated":False,
                "consent_assumed":False,"actions_dispatched":False,
                "appointments_booked":False,"verified_remediation":False,
                "original_owner_inbox_sha256":digest(original[0]),
                "original_history_sha256":digest(original[1]),
                "original_proposed_human_owner_label":owner,
                "original_human_operator_rounds":[{
                    "ordinal":i,"receipt_sha256":v["receipt_sha256"],
                    "original_csv_sha256":v["original_csv_sha256"],
                } for i,v in enumerate(stored,1)],
                "human_proposed_history_rows":selected,
            }
            from portfolio_owner_change_history_studio import render as render_history_studio
            outputs={
                "OPEN-PRIVATE.html":anonym(selected,len(stored)),
                "PRIVATE-HUMAN-operator-version-studio.html":render_history_studio(),
                "PRIVATE-HUMAN-operator-version-history.html":owner_html(owner,selected,len(stored)),
                "PRIVATE-HUMAN-operator-version-history.csv":csv_source(selected),
                "PRIVATE-HUMAN-operator-version-history.json":canonical(data),
                "PRIVATE-HUMAN-latest-round-changes.html":latest_html(
                    owner,latest,len(selected),len(stored)),
                "PRIVATE-HUMAN-latest-round-changes.csv":latest_csv(latest),
                "PRIVATE-HUMAN-latest-round-changes.json":canonical({
                    "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
                    "sources_reopened":False,"recipient_authenticated":False,
                    "consent_assumed":False,"actions_dispatched":False,
                    "appointments_booked":False,"verified_remediation":False,
                    "original_owner_inbox_sha256":digest(original[0]),
                    "original_history_sha256":digest(original[1]),
                    "original_proposed_human_owner_label":owner,
                    "previous_original_human_round":len(stored)-1,
                    "latest_original_human_round":len(stored),
                    "latest_human_proposal_changes":latest,
                }),
            }
            if any(len(x if isinstance(x,bytes) else x.encode("utf-8"))>MAX_MANIFEST
                   for x in outputs.values()):
                reject("PRIVATE HOLD: PRIVATE HUMAN historical owner packet too large")
            for name,content in outputs.items():write_private(directory,name,content)
            operator.append({
                "ordinal":ordinal,"owner_private_room":Path(directory).name,
                "original_proposed_human_owner_label":owner,
                "original_human_slots":len(selected),
                "latest_changed_human_slots":len(latest),
                "changed_human_slots":sum(bool(r["human_stage_changed_in_rounds"] or
                    r["private_human_note_changed_in_rounds"]) for r in selected),
            })
        summary={
            "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_owner_inbox_sha256":digest(original[0]),
            "original_history_sha256":digest(original[1]),
            "original_human_operator_rounds":[{
                "ordinal":i,"receipt_sha256":v["receipt_sha256"],
                "original_csv_sha256":v["original_csv_sha256"],
            } for i,v in enumerate(stored,1)],
            "owner_private_rooms_in_explicit_order":operator,
        }
        index=html_page("LightUp PRIVATE operator HUMAN version index",
            "<p>Source-minimal operator-only HUMAN revision history. No owner "
            "names, original case IDs, input hashes or PRIVATE note texts "
            "appear in this index. No real task, remediation, permission, "
            "consent or security PASS.</p><p>Explicit operator HUMAN versions: "+
            str(len(stored))+"; proposed owner groups: "+str(len(groups))+
            "; HUMAN changed slots: "+str(metrics["changed_rows"])+
            "; latest-round changed slots: "+str(sum(x["latest_changed_human_slots"] for x in operator))+
            ".</p><table><tbody>"+
            "".join("<tr><td>Owner packet "+str(x["ordinal"])+"</td><td>"+
                    str(x["original_human_slots"])+" HUMAN slots</td><td><a href=\""+
                    html.escape(x["owner_private_room"]+"/PRIVATE-HUMAN-operator-version-history.html",quote=True)+
                    "\">Open PRIVATE HUMAN history</a></td></tr>" for x in operator)+
            "</tbody></table>")
        if len(index.encode("utf-8"))>MAX_MANIFEST or len(canonical(summary))>MAX_MANIFEST:
            reject("PRIVATE HOLD: original version room count/index too large")
        write_private(root,"OPEN-PRIVATE.html",index)
        write_private(root,"PRIVATE-HUMAN-operator-version-index.json",canonical(summary))
    except BaseException:
        shutil.rmtree(root)
        raise
    print("PRIVATE HOLD: original HUMAN operator versions compared, no work dispatched")
    print(str(Path(root)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description=
        "Compare 2–8 source-exact PRIVATE historical HUMAN operator follow-up versions")
    p.add_argument("--history",required=True)
    p.add_argument("--inbox",required=True)
    p.add_argument("--followup",required=True,action="append",
                   help="ORIGINAL finalized HUMAN operator receipt in manual order")
    p.add_argument("--operator-csv",required=True,action="append",
                   help="Matching ORIGINAL complete HUMAN operator CSV in same order")
    p.add_argument("--private-parent",required=True)
    args=p.parse_args()
    try:return run(args)
    except (Hold,OSError,UnicodeError,ValueError,TypeError,csv.Error):
        print("PRIVATE HOLD: original source-bound HUMAN version comparison refused",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
