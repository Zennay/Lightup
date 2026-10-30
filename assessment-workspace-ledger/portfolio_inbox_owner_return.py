#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN owner selection reply, never authorization.

Prepare an owner-only complete HUMAN response template, then receive a
human-edited template against the same original native history, selection and
browser selection CSV. No target, network, messaging or verified fix.
"""
from __future__ import annotations

import argparse
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
from portfolio_inbox_timeline_selection import (
    SCHEMA as SELECT_SCHEMA, source_history, selected_csv, hex64,
)
from portfolio_owner_inbox_review import STAGES

SCHEMA = "lightup.private.workspace-ledger-owner-history-human-reply.v1"
SELECT_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_history_sha256",
    "original_human_browser_selection_csv_sha256",
    "selected_original_proposed_human_owner_label",
    "selected_original_human_round", "selected_original_human_rows_only",
}
HEADERS = (
    "original_selection_sha256", "local_case", "historical_transition",
    "original_kit", "original_round_human_stage",
    "human_reply_stage", "private_human_reply_note",
)
MAX_ROWS = 2048


def source_selection(selection, history, original_csv):
    history_raw, history_doc, original = source_history(history)
    csv_raw = read_owner_file(original_csv, MAX_MANIFEST)
    raw = read_owner_file(selection, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN owner packet"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: original private HUMAN owner packet unreadable") from exc
    if (type(doc) is not dict or set(doc) != SELECT_KEYS or
        raw != canonical(doc) or doc["schema"] != SELECT_SCHEMA or
        doc["historical_only"] is not True or
        not literal_false_authority(doc["authority"], FLAGS) or
        any(doc[k] is not False for k in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or not hex64(doc["original_history_sha256"]) or
        not hex64(doc["original_human_browser_selection_csv_sha256"]) or
        doc["original_history_sha256"] != digest(history_raw) or
        doc["original_human_browser_selection_csv_sha256"] != digest(csv_raw)):
        reject("PRIVATE HOLD: source identity of selected original HUMAN owner packet changed")
    owner = doc["selected_original_proposed_human_owner_label"]
    if type(owner) is not str or not owner or owner != owner.strip():
        reject("PRIVATE HOLD: original proposed HUMAN owner absent")
    safe_human(owner, 80)
    if (history_doc["owner_scoped_private_export"] and
        history_doc["selected_original_proposed_human_owner_label"] != owner):
        reject("PRIVATE HOLD: cannot broaden original selected HUMAN owner")
    source_rows, selected_round = selected_csv(
        csv_raw, original, owner, len(history_doc["original_human_discussion_rounds"]),
        digest(history_raw)
    )
    if (type(doc["selected_original_human_round"]) is not int or
        doc["selected_original_human_round"] != selected_round or
        doc["selected_original_human_rows_only"] != source_rows or
        not 1 <= len(source_rows) <= MAX_ROWS):
        reject("PRIVATE HOLD: original owner-selected HUMAN rows do not match native source")
    return raw, doc, history_raw, csv_raw, source_rows


def template(source_sha, rows):
    output=io.StringIO(newline="")
    writer=csv.writer(output,lineterminator="\n")
    writer.writerow(HEADERS)
    for row in rows:
        writer.writerow([
            source_sha,row["local_case"],row["historical_transition"],
            row["original_kit"],row["original_round_human_stage"],
            "needs_discussion",""
        ])
    return output.getvalue()


def read_reply(data, source_sha, rows):
    try:
        reader=csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""),strict=True)
        if reader.fieldnames!=list(HEADERS):
            reject("PRIVATE HOLD: HUMAN owner response CSV has wrong columns/order")
        incoming=list(reader)
    except (UnicodeError,ValueError,csv.Error) as exc:
        raise Hold("PRIVATE HOLD: HUMAN owner response CSV unreadable") from exc
    if len(incoming)!=len(rows):
        reject("PRIVATE HOLD: entire original HUMAN owner response required")
    chosen=[]
    for row,item in zip(rows,incoming):
        if type(item) is not dict or set(item)!=set(HEADERS) or None in item:
            reject("PRIVATE HOLD: missing/foreign HUMAN owner response columns")
        expected={
            "original_selection_sha256":source_sha,
            "local_case":str(row["local_case"]),
            "historical_transition":str(row["historical_transition"]),
            "original_kit":str(row["original_kit"]),
            "original_round_human_stage":row["original_round_human_stage"],
        }
        if any(item[k]!=v for k,v in expected.items()):
            reject("PRIVATE HOLD: original owner selection, stage or row order drifted")
        stage=item["human_reply_stage"]
        note=item["private_human_reply_note"]
        if (type(stage) is not str or stage not in STAGES or
            type(note) is not str or any(c in note for c in "\r\n\t")):
            reject("PRIVATE HOLD: invalid HUMAN-only owner stage or note")
        safe_human(note,240)
        chosen.append({
            "local_case":row["local_case"],
            "historical_transition":row["historical_transition"],
            "original_kit":row["original_kit"],
            "original_round_human_stage":row["original_round_human_stage"],
            "human_reply_stage":stage,
            "private_human_reply_note":note,
        })
    return chosen


def minimal(rows):
    content="<p>PRIVATE HUMAN-only owner proposal; no source identities, HUMAN owner labels or PRIVATE notes included. No real work, remediation, review approval or recipient authentication.</p>"
    content+="<p>Original selected HUMAN rows: "+str(len(rows))+"; locally proposed follow-up: "+str(sum(r["human_reply_stage"]=="proposed_followup" for r in rows))+"; HUMAN hold: "+str(sum(r["human_reply_stage"]=="hold" for r in rows))+".</p>"
    return html_page("LightUp PRIVATE HUMAN-only owner counts",content)


def detail(owner, rows):
    body=["<p><strong>PRIVATE owner HUMAN response, historical proposal only.</strong> "
          "No actual recipient authentication, finding verification, task assignment, "
          "consent or grant. Original proposed owner: "+html.escape(owner,quote=True)+"</p>",
          "<table><thead><tr><th>Original case / transition / kit</th><th>Original HUMAN stage</th><th>New HUMAN reply stage</th><th>PRIVATE HUMAN reply note</th></tr></thead><tbody>"]
    for row in rows:
        def val(key):return html.escape(str(row[key]),quote=True)
        body.append("<tr><td>"+val("local_case")+" / "+val("historical_transition")+" / "+
                    val("original_kit")+"</td><td>"+val("original_round_human_stage")+
                    "</td><td>"+val("human_reply_stage")+"</td><td>"+
                    val("private_human_reply_note")+"</td></tr>")
    body.append("</tbody></table><p>Original sources remain unchanged. This is not a status of actual work.</p>")
    return html_page("LightUp PRIVATE HUMAN owner response", "".join(body))


def run(args):
    paths=[args.selection,args.history,args.selection_csv,args.private_parent]
    if args.mode=="receive":paths.append(args.reply_csv)
    if any(not local_path(p) for p in paths) or len(set(paths))!=len(paths):
        reject("PRIVATE HOLD: use distinct absolute original PRIVATE files and parent")
    private_parent(args.private_parent)
    source,doc,history_raw,csv_raw,rows=source_selection(
        args.selection,args.history,args.selection_csv
    )
    owner=doc["selected_original_proposed_human_owner_label"]
    response_data=None
    if args.mode=="receive":
        response_data=read_owner_file(args.reply_csv,MAX_MANIFEST)
        result=read_reply(response_data,digest(source),rows)
    else:
        result=[{
            "local_case":r["local_case"],
            "historical_transition":r["historical_transition"],
            "original_kit":r["original_kit"],
            "original_round_human_stage":r["original_round_human_stage"],
            "human_reply_stage":"needs_discussion",
            "private_human_reply_note":"",
        } for r in rows]
    if (source_selection(args.selection,args.history,args.selection_csv)[:4] !=
        (source,doc,history_raw,csv_raw)):
        reject("PRIVATE HOLD: original HUMAN owner source changed before publication")
    if response_data is not None and read_owner_file(args.reply_csv,MAX_MANIFEST)!=response_data:
        reject("PRIVATE HOLD: HUMAN owner response changed before publication")
    if args.mode=="prepare":
        from portfolio_inbox_owner_return_studio import render as render_owner_studio
        exports={
            "OPEN-PRIVATE.html":minimal(result),
            "PRIVATE-HUMAN-owner-reply-studio.html":render_owner_studio(),
            "HUMAN-owner-history-reply-template.csv":template(digest(source),rows),
            "PRIVATE-HUMAN-owner-reply-instructions.html":html_page(
                "LightUp original PRIVATE HUMAN owner reply instructions",
                "<p>Complete every original HUMAN source slot in the private CSV. "
                "Only update HUMAN reply stage (needs_discussion, proposed_followup, hold) "
                "and PRIVATE note (max 240 characters, no line breaks or formula). "
                "This is NOT a real task, security fix, source consent or approval. "
                "Use the separate native receive command with original source inputs.</p>"
            ),
        }
    else:
        receipt={
            "schema":SCHEMA, "authority":FLAGS,"historical_only":True,
            "sources_reopened":False,"recipient_authenticated":False,
            "consent_assumed":False,"actions_dispatched":False,
            "appointments_booked":False,"verified_remediation":False,
            "original_selection_sha256":digest(source),
            "original_history_sha256":digest(history_raw),
            "original_selection_csv_sha256":digest(csv_raw),
            "original_human_owner_reply_csv_sha256":digest(response_data),
            "original_proposed_human_owner_label":owner,
            "selected_original_human_round":doc["selected_original_human_round"],
            "human_reply_rows":result,
        }
        exports={
            "OPEN-PRIVATE.html":minimal(result),
            "PRIVATE-HUMAN-owner-history-reply.html":detail(owner,result),
            "PRIVATE-HUMAN-owner-history-reply.json":canonical(receipt),
            "PRIVATE-HUMAN-original-owner-reply.csv":response_data,
        }
    if any(len(v if isinstance(v,bytes) else v.encode("utf-8"))>MAX_MANIFEST for v in exports.values()):
        reject("PRIVATE HOLD: original private HUMAN owner output exceeds size bound")
    folder=new_private(args.private_parent)
    try:
        for name,payload in exports.items():
            write_private(folder,name,payload)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: original source-bound HUMAN owner "+args.mode+" ready; no real recipient, task or action")
    print(str(Path(folder)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(description="Offline original source-bound owner HUMAN reply template/receipt")
    p.add_argument("mode",choices=("prepare","receive"))
    p.add_argument("--selection",required=True,help="PRIVATE-HUMAN-history-selection.json")
    p.add_argument("--history",required=True,help="Original PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--selection-csv",required=True,help="Original PRIVATE-HUMAN-original-selection.csv")
    p.add_argument("--reply-csv",help="Complete editable HUMAN-owner-history-reply-template.csv for receive only")
    p.add_argument("--private-parent",required=True,help="Existing PRIVATE operator 0700 parent")
    a=p.parse_args()
    if (a.mode=="receive") != bool(a.reply_csv):
        p.error("receive requires --reply-csv; prepare must omit it")
    try:return run(a)
    except (Hold,OSError,ValueError,UnicodeError,TypeError,csv.Error):
        print("PRIVATE HOLD: original source-bound HUMAN owner reply not admitted",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
