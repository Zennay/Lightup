#!/usr/bin/env python3
"""Original PRIVATE HUMAN owner-inbox operator follow-up, no real action.

Prepares and source-admits a complete HUMAN-only response to a native
multi-owner reply inbox. Does not assert owner identity, client consent,
security verdict, work completion, task dispatch, scan or scope grant.
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
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, object_unique,
    literal_false_authority, new_private, private_parent, read_owner_file,
    reject, safe_human, write_private,
)
from portfolio_focus import local_path
from portfolio_inbox_timeline_selection import source_history, hex64
from portfolio_inbox_owner_reconcile import SCHEMA as INBOX_SCHEMA
from portfolio_owner_inbox_review import STAGES

SCHEMA = "lightup.private.workspace-ledger-human-owner-inbox-followup.v1"
INBOX_KEYS = {
    "schema","authority","historical_only","sources_reopened",
    "recipient_authenticated","consent_assumed","actions_dispatched",
    "appointments_booked","verified_remediation",
    "original_history_sha256","original_human_owner_replies_in_explicit_order",
}
GROUP_KEYS = {
    "original_proposed_human_owner_label","original_selected_human_round",
    "original_selection_sha256","original_human_owner_reply_sha256",
    "human_reply_rows",
}
ROW_KEYS = {
    "local_case","historical_transition","original_kit",
    "original_round_human_stage","human_reply_stage",
    "private_human_reply_note",
}
HEADERS = (
    "original_owner_inbox_sha256","original_proposed_human_owner_label",
    "local_case","historical_transition","original_kit",
    "original_round_human_stage","original_owner_human_reply_stage",
    "human_operator_followup_stage","private_human_followup_note",
)
MAX_ROWS = 2048


def read_inbox(path, history_path):
    raw=read_owner_file(path,MAX_MANIFEST)
    hist_raw,_,_=source_history(history_path)
    try:
        doc=json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                       parse_constant=lambda _: reject("PRIVATE HOLD: invalid nonfinite HUMAN inbox"))
    except (UnicodeError,TypeError,ValueError) as exc:
        raise Hold("PRIVATE HOLD: original HUMAN owner inbox unreadable") from exc
    if (type(doc) is not dict or set(doc)!=INBOX_KEYS or
        raw!=canonical(doc) or doc["schema"]!=INBOX_SCHEMA or
        not literal_false_authority(doc["authority"],FLAGS) or
        doc["historical_only"] is not True or
        any(doc[k] is not False for k in (
          "sources_reopened","recipient_authenticated","consent_assumed",
          "actions_dispatched","appointments_booked","verified_remediation"
        )) or doc["original_history_sha256"]!=digest(hist_raw)):
        reject("PRIVATE HOLD: not original canonical source-bound HUMAN reply inbox")
    groups=doc["original_human_owner_replies_in_explicit_order"]
    if type(groups) is not list or not 1<=len(groups)<=8:
        reject("PRIVATE HOLD: missing original HUMAN owner response groups")
    owners=set();ids=set();items=[]
    for group in groups:
        if (type(group) is not dict or set(group)!=GROUP_KEYS or
            not hex64(group["original_selection_sha256"]) or
            not hex64(group["original_human_owner_reply_sha256"]) or
            type(group["original_selected_human_round"]) is not int or
            not 1<=group["original_selected_human_round"]<=8):
            reject("PRIVATE HOLD: original HUMAN response group invalid")
        owner=group["original_proposed_human_owner_label"]
        if (type(owner) is not str or not owner or owner!=owner.strip()
            or owner in owners):
            reject("PRIVATE HOLD: ambiguous original proposed HUMAN owner")
        safe_human(owner,80); owners.add(owner)
        source=group["human_reply_rows"]
        if type(source) is not list or not source:
            reject("PRIVATE HOLD: original HUMAN group empty")
        for row in source:
            if type(row) is not dict or set(row)!=ROW_KEYS:
                reject("PRIVATE HOLD: original HUMAN reply row schema mismatch")
            identity=tuple(row[k] for k in (
                "local_case","historical_transition","original_kit"
            ))
            if (any(type(v) is not int for v in identity) or
                not 1<=identity[0]<=8 or not 1<=identity[1]<=11 or
                not 1<=identity[2]<=12 or identity in ids):
                reject("PRIVATE HOLD: repeated or invalid original HUMAN source slot")
            ids.add(identity)
            if (row["original_round_human_stage"] not in STAGES or
                row["human_reply_stage"] not in STAGES or
                type(row["private_human_reply_note"]) is not str or
                any(c in row["private_human_reply_note"] for c in "\r\n\t")):
                reject("PRIVATE HOLD: invalid original HUMAN reply values")
            safe_human(row["private_human_reply_note"],240)
            items.append({
                "original_proposed_human_owner_label":owner,
                "local_case":row["local_case"],
                "historical_transition":row["historical_transition"],
                "original_kit":row["original_kit"],
                "original_round_human_stage":row["original_round_human_stage"],
                "original_owner_human_reply_stage":row["human_reply_stage"],
            })
            if len(items)>MAX_ROWS:
                reject("PRIVATE HOLD: too many original HUMAN owner reply slots")
    return raw,hist_raw,items


def template(source_sha,items):
    stream=io.StringIO(newline="")
    writer=csv.writer(stream,lineterminator="\n")
    writer.writerow(HEADERS)
    for r in items:
        writer.writerow([
            source_sha,r["original_proposed_human_owner_label"],
            r["local_case"],r["historical_transition"],r["original_kit"],
            r["original_round_human_stage"],r["original_owner_human_reply_stage"],
            "needs_discussion",""
        ])
    return stream.getvalue()


def interpret(data, items, source_sha):
    try:
        reader=csv.DictReader(io.StringIO(data.decode("utf-8"),newline=""),strict=True)
        if reader.fieldnames!=list(HEADERS):
            reject("PRIVATE HOLD: original HUMAN operator follow-up CSV column mismatch")
        entries=list(reader)
    except (UnicodeError,ValueError,csv.Error) as exc:
        raise Hold("PRIVATE HOLD: original HUMAN follow-up CSV unreadable") from exc
    if len(entries)!=len(items):
        reject("PRIVATE HOLD: all original HUMAN owner reply source slots required")
    chosen=[]
    for original,row in zip(items,entries):
        if type(row) is not dict or set(row)!=set(HEADERS) or None in row:
            reject("PRIVATE HOLD: malformed original HUMAN follow-up columns")
        expected={
            "original_owner_inbox_sha256":source_sha,
            "original_proposed_human_owner_label":original["original_proposed_human_owner_label"],
            **{k:str(original[k]) for k in (
                "local_case","historical_transition","original_kit")},
            "original_round_human_stage":original["original_round_human_stage"],
            "original_owner_human_reply_stage":original["original_owner_human_reply_stage"],
        }
        if any(row[k]!=v for k,v in expected.items()):
            reject("PRIVATE HOLD: original owner or slot or historical HUMAN stage changed")
        stage=row["human_operator_followup_stage"]
        note=row["private_human_followup_note"]
        if (stage not in STAGES or type(note) is not str or
            any(c in note for c in "\r\n\t")):
            reject("PRIVATE HOLD: invalid proposed HUMAN operator follow-up")
        safe_human(note,240)
        chosen.append({
            **original,
            "human_operator_followup_stage":stage,
            "private_human_followup_note":note,
        })
    return chosen


def counts_html(rows):
    counts=Counter(r["human_operator_followup_stage"] for r in rows)
    summary="<p>PRIVATE historical HUMAN-only operator response; no owner names, source case IDs, SHA or confidential notes. Not a verified finding, task, incident, grant, recipient identity or consent.</p>"
    summary+="<p>Original HUMAN response slots: "+str(len(rows))+".</p><table><tbody>"
    summary+="".join("<tr><td>"+html.escape(stage)+"</td><td>"+str(counts[stage])+"</td></tr>" for stage in STAGES)
    return html_page("LightUp HUMAN follow-up counts",summary+"</tbody></table>")


def details_html(rows):
    body=["<p><strong>PRIVATE original HUMAN response follow-up only.</strong>"
          " Source bound to original unsigned owner inbox and source history, "
          "not real remediation, permission, grant or security approval.</p>",
          "<table><thead><tr><th>Proposed HUMAN owner</th><th>Original source slot</th>"
          "<th>Original HUMAN stage</th><th>Owner HUMAN reply</th><th>Operator HUMAN proposal</th>"
          "<th>PRIVATE operator note</th></tr></thead><tbody>"]
    for r in rows:
        def val(k):return html.escape(str(r[k]),quote=True)
        body.append("<tr><td>"+val("original_proposed_human_owner_label")+
                    "</td><td>"+val("local_case")+" / "+val("historical_transition")+
                    " / "+val("original_kit")+"</td><td>"+
                    val("original_round_human_stage")+"</td><td>"+
                    val("original_owner_human_reply_stage")+"</td><td>"+
                    val("human_operator_followup_stage")+"</td><td>"+
                    val("private_human_followup_note")+"</td></tr>")
    return html_page("LightUp PRIVATE HUMAN original operator response",
                     "".join(body)+"</tbody></table>")


def run(args):
    paths=[args.inbox,args.history,args.private_parent]
    if args.mode=="receive":paths.append(args.followup_csv)
    if any(not local_path(x) for x in paths) or len(set(paths))!=len(paths):
        reject("PRIVATE HOLD: require distinct absolute PRIVATE source/destination paths")
    private_parent(args.private_parent)
    inbox_raw, history_raw, items=read_inbox(args.inbox,args.history)
    data=None
    if args.mode=="receive":
        data=read_owner_file(args.followup_csv,MAX_MANIFEST)
        rows=interpret(data,items,digest(inbox_raw))
    else:
        rows=[{**r,"human_operator_followup_stage":"needs_discussion",
              "private_human_followup_note":""} for r in items]
    if read_inbox(args.inbox,args.history)[:2]!=(inbox_raw,history_raw):
        reject("PRIVATE HOLD: original HUMAN follow-up source changed")
    if data is not None and read_owner_file(args.followup_csv,MAX_MANIFEST)!=data:
        reject("PRIVATE HOLD: original HUMAN follow-up CSV changed")
    if args.mode=="prepare":
        from portfolio_owner_followup_studio import render as render_operator_studio
        outputs={
            "OPEN-PRIVATE.html":counts_html(rows),
            "PRIVATE-HUMAN-operator-followup-studio.html":render_operator_studio(),
            "HUMAN-operator-followup-template.csv":template(digest(inbox_raw),items),
        }
    else:
        output={
            "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_owner_inbox_sha256":digest(inbox_raw),
            "original_history_sha256":digest(history_raw),
            "original_human_operator_csv_sha256":digest(data),
            "human_only_operator_followup_rows":rows,
        }
        outputs={
            "OPEN-PRIVATE.html":counts_html(rows),
            "PRIVATE-HUMAN-operator-followup.html":details_html(rows),
            "PRIVATE-HUMAN-operator-followup.json":canonical(output),
            "PRIVATE-HUMAN-original-operator-followup.csv":data,
        }
    if any(len(x if isinstance(x,bytes) else x.encode("utf-8"))>MAX_MANIFEST
           for x in outputs.values()):
        reject("PRIVATE HOLD: original PRIVATE HUMAN follow-up too large")
    directory=new_private(args.private_parent)
    try:
        for name,content in outputs.items():write_private(directory,name,content)
    except BaseException:
        shutil.rmtree(directory)
        raise
    print("PRIVATE HOLD: original HUMAN operator follow-up "+args.mode+
          " recorded; no verified security action")
    print(str(Path(directory)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description=
        "Original native human operator follow-up, no real authorization or action")
    p.add_argument("mode",choices=("prepare","receive"))
    p.add_argument("--inbox",required=True,help="Original PRIVATE-HUMAN-owner-inbox.json")
    p.add_argument("--history",required=True,help="Original PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--followup-csv",help="Complete original HUMAN-operator-followup-template.csv on receive")
    p.add_argument("--private-parent",required=True,help="Existing 0700 PRIVATE operator directory")
    args=p.parse_args()
    if (args.mode=="receive") != bool(args.followup_csv):
        p.error("receive requires --followup-csv; prepare must omit it")
    try:return run(args)
    except (Hold,OSError,TypeError,ValueError,UnicodeError,csv.Error):
        print("PRIVATE HOLD: original HUMAN operator follow-up refused",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
