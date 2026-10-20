#!/usr/bin/env python3
"""Offline PRIVATE HUMAN multiple-owner reply reconciliation.

Admits 1–8 complete original owner source/selected CSV/native reply/edited CSV
quadruples from the SAME native historical HUMAN inbox. Does not authenticate
owners, act on targets, dispatch work, grant scope or verify remediation.
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
    read_owner_file, reject, write_private,
)
from portfolio_focus import local_path
from portfolio_inbox_owner_return import (
    SCHEMA as RECEIPT_SCHEMA, source_selection, read_reply,
)
from portfolio_inbox_timeline_selection import source_history
from portfolio_owner_inbox_review import STAGES

SCHEMA = "lightup.private.workspace-ledger-human-owner-return-inbox.v1"
RECEIPT_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation",
    "original_selection_sha256", "original_history_sha256",
    "original_selection_csv_sha256", "original_human_owner_reply_csv_sha256",
    "original_proposed_human_owner_label", "selected_original_human_round",
    "human_reply_rows",
}
HEADERS = (
    "original_proposed_human_owner_label","local_case",
    "historical_transition","original_kit","original_round_human_stage",
    "human_reply_stage","private_human_reply_note",
)
MAX_OWNERS = 8


def receipt(path, source_raw, source_doc, history_raw, selection_csv, reply_csv, rows):
    raw=read_owner_file(path,MAX_MANIFEST)
    try:
        doc=json.loads(raw.decode("utf-8"),object_pairs_hook=object_unique,
                       parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN owner return"))
    except (ValueError,TypeError,UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable original private HUMAN reply") from exc
    if (type(doc) is not dict or set(doc)!=RECEIPT_KEYS or
        raw!=canonical(doc) or doc["schema"]!=RECEIPT_SCHEMA or
        not literal_false_authority(doc["authority"],FLAGS) or
        doc["historical_only"] is not True or
        any(doc[k] is not False for k in (
           "sources_reopened","recipient_authenticated","consent_assumed",
           "actions_dispatched","appointments_booked","verified_remediation"
        )) or doc["original_selection_sha256"]!=digest(source_raw) or
        doc["original_history_sha256"]!=digest(history_raw) or
        doc["original_selection_csv_sha256"]!=digest(selection_csv) or
        doc["original_human_owner_reply_csv_sha256"]!=digest(reply_csv) or
        doc["original_proposed_human_owner_label"]!=
          source_doc["selected_original_proposed_human_owner_label"] or
        doc["selected_original_human_round"]!=
          source_doc["selected_original_human_round"]):
        reject("PRIVATE HOLD: original HUMAN owner return lost source-byte identity")
    native=read_reply(reply_csv,digest(source_raw),rows)
    if doc["human_reply_rows"]!=native:
        reject("PRIVATE HOLD: original native HUMAN return rows mismatch")
    return raw,native


def admit(args):
    a,b,c,d=(args.selection,args.selection_csv,args.reply,args.reply_csv)
    if not 1<=len(a)==len(b)==len(c)==len(d)<=MAX_OWNERS:
        reject("PRIVATE HOLD: require 1–8 complete owner source/CSV/return/CSV quadruples")
    paths=[args.history,args.private_parent,*a,*b,*c,*d]
    if any(not local_path(p) for p in paths) or len(paths)!=len(set(paths)):
        reject("PRIVATE HOLD: all original HUMAN private paths must be distinct and absolute")
    private_parent(args.private_parent)
    history_raw,history_doc,original=source_history(args.history)
    seen_owners=set(); seen_slots=set(); reconciled=[]
    for sel_path,csv_path,reply_path,reply_csv_path in zip(a,b,c,d):
        source_raw,source_doc,same_history,sel_csv,rows=source_selection(
            sel_path,args.history,csv_path
        )
        if same_history!=history_raw:
            reject("PRIVATE HOLD: owner returns from different original PRIVATE history")
        owner=source_doc["selected_original_proposed_human_owner_label"]
        if owner in seen_owners:
            reject("PRIVATE HOLD: duplicate proposed HUMAN owner reply")
        seen_owners.add(owner)
        edited=read_owner_file(reply_csv_path,MAX_MANIFEST)
        receipt_raw,chosen=receipt(
            reply_path,source_raw,source_doc,history_raw,sel_csv,edited,rows
        )
        for row in chosen:
            key=(row["local_case"],row["historical_transition"],row["original_kit"])
            if key in seen_slots:
                reject("PRIVATE HOLD: overlapping original HUMAN case from multiple owners")
            seen_slots.add(key)
        reconciled.append({
            "original_proposed_human_owner_label":owner,
            "original_selected_human_round":source_doc["selected_original_human_round"],
            "source_path":sel_path,"selection_csv_path":csv_path,
            "reply_path":reply_path,"reply_csv_path":reply_csv_path,
            "source_raw":source_raw,"selection_csv_raw":sel_csv,
            "reply_raw":receipt_raw,"reply_csv_raw":edited,
            "source_sha":digest(source_raw),"receipt_sha":digest(receipt_raw),
            "rows":chosen,
        })
    return history_raw,history_doc,original,reconciled


def anonymous_html(groups):
    counts=Counter()
    for group in groups:
        for r in group["rows"]:counts[r["human_reply_stage"]]+=1
    parts=[
      "<p><strong>PRIVATE, source-minimal HUMAN reply coordination only.</strong>"
      " This page contains no proposed HUMAN owner labels, original source case "
      "identifiers, source hashes, PRIVATE note text or dates. HUMAN replies are "
      "not authenticated people, verified remediation, approved work orders, "
      "client consent, grants or scan permission.</p>",
      "<p>Complete proposed original HUMAN owner groups: "+str(len(groups))+
      "; original selected HUMAN rows: "+str(sum(len(x["rows"]) for x in groups))+".</p>",
      "<table><thead><tr><th>Historical HUMAN stage</th><th>Count</th></tr>"
      "</thead><tbody>",
    ]
    for stage in STAGES:
        parts.append("<tr><td>"+html.escape(stage)+"</td><td>"+str(counts[stage])+"</td></tr>")
    parts.append("</tbody></table><p>Consult operator-only PRIVATE report for "
                 "context; never treat this document as permission.</p>")
    return html_page("LightUp PRIVATE HUMAN owner reply counts", "".join(parts))


def detailed_html(groups):
    parts=[
      "<p><strong>Operator-private ORIGINAL human-only reply inbox.</strong>"
      " All original owner/row/csv receipts independently source-admitted "
      "against exactly the same private HUMAN history. This is not actual "
      "recipient authentication, a security finding, remediation, actual "
      "task, grant, consent or assessment approval.</p>",
      "<table><thead><tr><th>Proposed HUMAN owner (unauthenticated label)</th>"
      "<th>Original source slot</th><th>Original selected HUMAN round</th>"
      "<th>Previous HUMAN proposal</th><th>New HUMAN reply proposal</th>"
      "<th>PRIVATE HUMAN reply note</th></tr></thead><tbody>",
    ]
    for group in groups:
        for row in group["rows"]:
            def esc(v):return html.escape(str(v),quote=True)
            parts.append("<tr><td>"+esc(group["original_proposed_human_owner_label"])+
                         "</td><td>"+esc(row["local_case"])+" / "+
                         esc(row["historical_transition"])+" / "+esc(row["original_kit"])+
                         "</td><td>"+esc(group["original_selected_human_round"])+
                         "</td><td>"+esc(row["original_round_human_stage"])+
                         "</td><td>"+esc(row["human_reply_stage"])+
                         "</td><td>"+esc(row["private_human_reply_note"])+
                         "</td></tr>")
    parts.append("</tbody></table><p>Source inputs unchanged. No automatic action."
                 " Verify genuine recipient authorizations before any manual sharing.</p>")
    return html_page("LightUp PRIVATE original HUMAN owner inbox", "".join(parts))


def as_csv(groups):
    stream=io.StringIO(newline="")
    writer=csv.writer(stream,lineterminator="\n")
    writer.writerow(HEADERS)
    for group in groups:
        for row in group["rows"]:
            writer.writerow([group["original_proposed_human_owner_label"],*(
                row[k] for k in HEADERS[1:])])
    return stream.getvalue()


def run(args):
    history_raw,doc,original,groups=admit(args)
    if source_history(args.history)[0]!=history_raw:
        reject("PRIVATE HOLD: original HUMAN inbox source changed before output")
    # Every source is independently re-admitted immediately before publication.
    for g in groups:
        source,selected,same,selection_csv,rows=source_selection(
            g["source_path"],args.history,g["selection_csv_path"]
        )
        edited=read_owner_file(g["reply_csv_path"],MAX_MANIFEST)
        native,reply_rows=receipt(
            g["reply_path"],source,selected,same,selection_csv,edited,rows
        )
        if (source!=g["source_raw"] or same!=history_raw or
            selection_csv!=g["selection_csv_raw"] or
            edited!=g["reply_csv_raw"] or native!=g["reply_raw"] or
            reply_rows!=g["rows"]):
            reject("PRIVATE HOLD: private HUMAN owner reply source changed")
    combined=[{
        "original_proposed_human_owner_label":g["original_proposed_human_owner_label"],
        "original_selected_human_round":g["original_selected_human_round"],
        "original_selection_sha256":g["source_sha"],
        "original_human_owner_reply_sha256":g["receipt_sha"],
        "human_reply_rows":g["rows"],
    } for g in groups]
    result={
        "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
        "sources_reopened":False,"recipient_authenticated":False,
        "consent_assumed":False,"actions_dispatched":False,
        "appointments_booked":False,"verified_remediation":False,
        "original_history_sha256":digest(history_raw),
        "original_human_owner_replies_in_explicit_order":combined,
    }
    from portfolio_owner_inbox_viewer import render as render_inbox_viewer
    exports={
        "OPEN-PRIVATE.html":anonymous_html(groups),
        "PRIVATE-HUMAN-owner-inbox-viewer.html":render_inbox_viewer(),
        "PRIVATE-HUMAN-owner-inbox.html":detailed_html(groups),
        "PRIVATE-HUMAN-owner-inbox.csv":as_csv(groups),
        "PRIVATE-HUMAN-owner-inbox.json":canonical(result),
    }
    if any(len(val if isinstance(val,bytes) else val.encode("utf-8"))>MAX_MANIFEST
           for val in exports.values()):
        reject("PRIVATE HOLD: original owner response inbox too large")
    folder=new_private(args.private_parent)
    try:
        for name,data in exports.items():write_private(folder,name,data)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: all original owner HUMAN replies reconciled; no action or grant")
    print(str(Path(folder)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description=
        "Native PRIVATE offline HUMAN owner reply reconciliation against one original history")
    p.add_argument("--history",required=True,help="Original PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--selection",required=True,action="append",help="Owner original selected packet JSON")
    p.add_argument("--selection-csv",required=True,action="append",help="Matching original owner selection CSV")
    p.add_argument("--reply",required=True,action="append",help="Matching native HUMAN owner reply JSON")
    p.add_argument("--reply-csv",required=True,action="append",help="Matching edited complete HUMAN reply CSV")
    p.add_argument("--private-parent",required=True,help="Existing 0700 original PRIVATE operator folder")
    args=p.parse_args()
    try:return run(args)
    except (Hold,OSError,ValueError,UnicodeError,TypeError,csv.Error):
        print("PRIVATE HOLD: original multiple-owner HUMAN reconciliation rejected",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
