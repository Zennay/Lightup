#!/usr/bin/env python3
"""Batch native offline PRIVATE HUMAN timeline owner handoffs.

Builds separate owner-private rooms only after strict all-or-nothing native
selection re-admission against the SAME original owner-private history.
Human labels never authenticate actual recipients or authorize actions.
"""
from __future__ import annotations
import argparse
from collections import Counter
import html
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, safe_human, write_private,
)
from portfolio_focus import local_path
from portfolio_inbox_timeline_selection import (
    source_history, selected_csv, minimal_html, private_html,
    SCHEMA as SINGLE_SCHEMA,
)

SCHEMA = "lightup.private.workspace-ledger-history-human-batch-handoff.v1"
MAX_OWNERS = 8


def admit(args):
    if (type(args.owner) is not list or type(args.selection_csv) is not list or
        not 1 <= len(args.owner) == len(args.selection_csv) <= MAX_OWNERS):
        reject("PRIVATE HOLD: require 1–8 paired original HUMAN owner labels and selection CSV files")
    paths=[args.history, args.private_parent, *args.selection_csv]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: original batch inputs and parent must have distinct absolute paths")
    if len(set(args.owner)) != len(args.owner):
        reject("PRIVATE HOLD: repeated original proposed HUMAN owner label")
    private_parent(args.private_parent)
    original, original_doc, slots = source_history(args.history)
    original_scope=original_doc["selected_original_proposed_human_owner_label"]
    if original_scope is not None and (len(args.owner)!=1 or args.owner[0]!=original_scope):
        reject("PRIVATE HOLD: original PRIVATE owner-scoped source cannot be widened")
    selected=[]
    claimed_slots=set()
    for human, csv_path in zip(args.owner,args.selection_csv):
        if type(human) is not str or not human or human!=human.strip():
            reject("PRIVATE HOLD: exact original proposed HUMAN owner label required")
        safe_human(human,80)
        data=read_owner_file(csv_path,MAX_MANIFEST)
        rows, round_no=selected_csv(
            data,slots,human,len(original_doc["original_human_discussion_rounds"]),digest(original)
        )
        for row in rows:
            identity=(
                row["local_case"],row["historical_transition"],row["original_kit"]
            )
            if identity in claimed_slots:
                reject("PRIVATE HOLD: overlapping original HUMAN source slots")
            claimed_slots.add(identity)
        selected.append({
            "owner_label":human,"csv_path":csv_path,
            "csv_raw":data,"csv_sha":digest(data),
            "selected_original_human_round":round_no,"rows":rows
        })
    return original,original_doc,slots,selected


def source_minimal_index(selected, directories):
    parts=[
        "<p><strong>PRIVATE HUMAN-only multi-owner discussion selection.</strong> "
        "Original owner identities, private notes, original source IDs and "
        "hashes are not present in this count-only operator index. "
        "No authenticated receiving identity, real task assignment, grant, "
        "consent, verified finding, scan or security approval.</p>",
        "<p>Original proposed HUMAN owner packet count: "+str(len(selected))+
        "; selected original HUMAN proposal slots: "+
        str(sum(len(x["rows"]) for x in selected))+".</p>",
        "<table><thead><tr><th>HUMAN packet slot (not identity)</th>"
        "<th>Selected HUMAN round</th><th>Private HUMAN slots</th>"
        "<th>Owner-only view</th></tr></thead><tbody>"
    ]
    for ordinal,(entry,path) in enumerate(zip(selected,directories),1):
        parts.append("<tr><td>"+str(ordinal)+"</td><td>"+
                     str(entry["selected_original_human_round"])+"</td><td>"+
                     str(len(entry["rows"]))+"</td><td><a href=\""+
                     html.escape(path.name+"/PRIVATE-HUMAN-history-selection.html",quote=True)+
                     "\">Open owner-private packet "+str(ordinal)+"</a></td></tr>")
    parts.append("</tbody></table><p>All original selected HUMAN proposals are "
                 "historical concepts. Original inputs are unchanged.</p>")
    return html_page("LightUp PRIVATE HUMAN batch selection overview", "".join(parts))


def run(args):
    original,original_doc,slots,selected=admit(args)
    # Validate all original owner-controlled bytes again BEFORE allocating output.
    if source_history(args.history)[0]!=original:
        reject("PRIVATE HOLD: original canonical PRIVATE HUMAN timeline changed")
    for entry in selected:
        if read_owner_file(entry["csv_path"],MAX_MANIFEST)!=entry["csv_raw"]:
            reject("PRIVATE HOLD: original owner-selected PRIVATE CSV changed")
    root=new_private(args.private_parent)
    try:
        folders=[]
        operator_rows=[]
        for ordinal,entry in enumerate(selected,1):
            private_room=new_private(root)
            folders.append(Path(private_room))
            data={
                "schema":SINGLE_SCHEMA,"authority":FLAGS,
                "historical_only":True,"sources_reopened":False,
                "recipient_authenticated":False,"consent_assumed":False,
                "actions_dispatched":False,"appointments_booked":False,
                "verified_remediation":False,
                "original_history_sha256":digest(original),
                "original_human_browser_selection_csv_sha256":entry["csv_sha"],
                "selected_original_proposed_human_owner_label":entry["owner_label"],
                "selected_original_human_round":entry["selected_original_human_round"],
                "selected_original_human_rows_only":entry["rows"],
            }
            exports={
                "OPEN-PRIVATE.html":minimal_html(entry["rows"],entry["selected_original_human_round"]),
                "PRIVATE-HUMAN-history-selection.html":private_html(
                    entry["owner_label"],entry["rows"],entry["selected_original_human_round"]),
                "PRIVATE-HUMAN-history-selection.json":canonical(data),
                "PRIVATE-HUMAN-original-selection.csv":entry["csv_raw"],
            }
            if any(len(value if isinstance(value,bytes) else value.encode("utf-8"))>
                   MAX_MANIFEST for value in exports.values()):
                reject("PRIVATE HOLD: owner packet exceeds 0600 source size bound")
            for filename,payload in exports.items():
                write_private(private_room,filename,payload)
            operator_rows.append({
                "slot":ordinal,"relative_owner_private_room":Path(private_room).name,
                "original_proposed_human_owner_label":entry["owner_label"],
                "original_selection_csv_sha256":entry["csv_sha"],
                "selected_original_human_round":entry["selected_original_human_round"],
                "selected_original_human_rows":len(entry["rows"]),
            })
        inventory={
            "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_history_sha256":digest(original),
            "original_human_owner_packets_in_explicit_order":operator_rows,
        }
        index=source_minimal_index(selected,folders)
        if len(index.encode("utf-8"))>MAX_MANIFEST or len(canonical(inventory))>MAX_MANIFEST:
            reject("PRIVATE HOLD: original operator batch index over source limit")
        write_private(root,"OPEN-PRIVATE.html",index)
        write_private(root,"PRIVATE-HUMAN-operator-batch-index.json",canonical(inventory))
    except BaseException:
        shutil.rmtree(root)
        raise
    print("PRIVATE HOLD: original HUMAN owner selections separated; no recipient contacted")
    print(str(Path(root)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description=
        "Native source-bound 1–8 owner PRIVATE timeline selection handoffs, offline only")
    p.add_argument("--history",required=True,help="One original native PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--owner",required=True,action="append",help="Exact ORIGINAL proposed HUMAN owner (repeat 1–8)")
    p.add_argument("--selection-csv",required=True,action="append",
                   help="Corresponding original browser private selection CSV (repeat 1–8)")
    p.add_argument("--private-parent",required=True,help="Existing owner-private 0700 output parent")
    a=p.parse_args()
    try:return run(a)
    except (Hold,OSError,TypeError,ValueError,UnicodeError):
        print("PRIVATE HOLD: native HUMAN owner batch refused",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
