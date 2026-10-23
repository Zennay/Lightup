#!/usr/bin/env python3
"""Native PRIVATE historical HUMAN owner selection admission.

Consumes the exact canonical native-produced history + browser-selected CSV;
creates one fresh operator-private selection packet, with no action or grant.
Browser exports and unsigned SHA are not identity, consent or security proof.
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
from portfolio_inbox_history import SCHEMA as HISTORY_SCHEMA
from portfolio_owner_inbox_review import STAGES

SCHEMA = "lightup.private.workspace-ledger-history-human-selected-handoff.v1"
HISTORY_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_inbox_sha256",
    "selected_original_proposed_human_owner_label", "owner_scoped_private_export",
    "original_human_discussion_rounds", "private_human_history_slots",
}
ROUND_KEYS = {"round", "original_discussion_sha256", "original_review_csv_sha256"}
SLOT_KEYS = {
    "local_case", "historical_transition", "original_kit",
    "original_proposed_human_owner", "original_human_stage",
    "original_owner_reply_stage", "first_human_triage_stage",
    "latest_human_triage_stage", "stage_changed_rounds",
    "private_note_changed_rounds", "round_stages",
}
HEADERS = (
    "original_history_sha256", "selected_human_round",
    "local_case", "historical_transition", "original_kit",
    "original_proposed_human_owner", "first_human_triage_stage",
    "latest_human_triage_stage", "stage_changed_rounds",
    "private_note_changed_rounds",
)


def hex64(value):
    return type(value) is str and len(value) == 64 and all(
        letter in "0123456789abcdef" for letter in value
    )


def source_history(path):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: invalid nonfinite HUMAN history"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: original HUMAN history cannot be read") from exc
    if (type(doc) is not dict or set(doc) != HISTORY_KEYS or
        raw != canonical(doc) or doc["schema"] != HISTORY_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[k] is not False for k in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or not hex64(doc["original_inbox_sha256"]) or
        type(doc["owner_scoped_private_export"]) is not bool):
        reject("PRIVATE HOLD: not exact original canonical HUMAN history")
    owner = doc["selected_original_proposed_human_owner_label"]
    if (doc["owner_scoped_private_export"] is not (owner is not None) or
        (owner is not None and
         (type(owner) is not str or not owner or owner != owner.strip()))):
        reject("PRIVATE HOLD: original source-owner selection mismatch")
    if owner is not None:
        safe_human(owner, 80)
    rounds = doc["original_human_discussion_rounds"]
    if type(rounds) is not list or not 2 <= len(rounds) <= 8:
        reject("PRIVATE HOLD: original HUMAN history requires 2–8 rounds")
    signatures = set()
    for i, row in enumerate(rounds, 1):
        if (type(row) is not dict or set(row) != ROUND_KEYS or row["round"] != i or
            not hex64(row["original_discussion_sha256"]) or
            not hex64(row["original_review_csv_sha256"]) or
            row["original_discussion_sha256"] in signatures):
            reject("PRIVATE HOLD: original HUMAN round fingerprints invalid")
        signatures.add(row["original_discussion_sha256"])
    slots = doc["private_human_history_slots"]
    if type(slots) is not list or not 1 <= len(slots) <= 2048:
        reject("PRIVATE HOLD: missing original source-bound HUMAN rows")
    original_ids = set()
    for row in slots:
        if type(row) is not dict or set(row) != SLOT_KEYS:
            reject("PRIVATE HOLD: original HUMAN history rows malformed")
        identity = tuple(row[k] for k in ("local_case", "historical_transition", "original_kit"))
        if (any(type(v) is not int for v in identity) or not 1 <= identity[0] <= 8 or
            not 1 <= identity[1] <= 11 or not 1 <= identity[2] <= 12 or
            identity in original_ids):
            reject("PRIVATE HOLD: ambiguous original HUMAN slot identity")
        original_ids.add(identity)
        label = row["original_proposed_human_owner"]
        if (type(label) is not str or not label or label != label.strip() or
            (owner is not None and label != owner)):
            reject("PRIVATE HOLD: invalid or widened original proposed HUMAN owner")
        safe_human(label, 80)
        history = row["round_stages"]
        if (type(history) is not list or len(history) != len(rounds) or
            any(type(v) is not str or v not in STAGES for v in history) or
            any(row[k] not in STAGES for k in (
                "original_human_stage", "original_owner_reply_stage",
                "first_human_triage_stage", "latest_human_triage_stage"
            )) or history[0] != row["first_human_triage_stage"] or
            history[-1] != row["latest_human_triage_stage"]):
            reject("PRIVATE HOLD: original HUMAN stage sequence invalid")
        computed = [i+1 for i in range(1,len(history)) if history[i] != history[i-1]]
        changes = row["stage_changed_rounds"]
        notes = row["private_note_changed_rounds"]
        if (type(changes) is not list or changes != computed or
            type(notes) is not list or
            any(type(v) is not int or v<2 or v>len(rounds) for v in notes) or
            sorted(set(notes)) != notes):
            reject("PRIVATE HOLD: original HUMAN change flags invalid")
    return raw, doc, slots


def selected_csv(raw, slots, owner, count, source_sha):
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
        if reader.fieldnames != list(HEADERS):
            reject("PRIVATE HOLD: native HUMAN owner selection CSV schema mismatch")
        items = list(reader)
    except (UnicodeError, ValueError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: cannot read human-selected PRIVATE source CSV") from exc
    if not 1 <= len(items) <= len(slots):
        reject("PRIVATE HOLD: browser-selected HUMAN row count invalid")
    known = {(
        r["local_case"], r["historical_transition"], r["original_kit"]
    ): (n,r) for n,r in enumerate(slots)}
    prev = -1
    chosen = []
    selected_round = None
    for item in items:
        if type(item) is not dict or set(item) != set(HEADERS) or None in item:
            reject("PRIVATE HOLD: malformed extra/partial HUMAN CSV fields")
        identity = tuple(item[k] for k in (
            "local_case", "historical_transition", "original_kit"
        ))
        try:
            key = tuple(int(v) for v in identity)
            if any(str(a) != b for a,b in zip(key,identity)):
                reject("PRIVATE HOLD: noncanonical original ordinal in HUMAN CSV")
        except (ValueError, TypeError) as exc:
            raise Hold("PRIVATE HOLD: invalid original HUMAN CSV ordinal") from exc
        if key not in known:
            reject("PRIVATE HOLD: selected HUMAN slot absent in original")
        index, orig = known[key]
        if index <= prev or orig["original_proposed_human_owner"] != owner:
            reject("PRIVATE HOLD: HUMAN selection order or owner scope widened")
        prev=index
        try:
            n=int(item["selected_human_round"])
        except (TypeError, ValueError) as exc:
            raise Hold("PRIVATE HOLD: invalid proposed HUMAN round number") from exc
        if (item["selected_human_round"] != str(n) or not 1<=n<=count or
            (selected_round is not None and selected_round != n)):
            reject("PRIVATE HOLD: inconsistent original HUMAN round selection")
        selected_round=n
        expected = {
            "original_history_sha256": source_sha,
            "selected_human_round": str(n),
            "local_case": str(orig["local_case"]),
            "historical_transition": str(orig["historical_transition"]),
            "original_kit": str(orig["original_kit"]),
            "original_proposed_human_owner": owner,
            "first_human_triage_stage": orig["first_human_triage_stage"],
            "latest_human_triage_stage": orig["latest_human_triage_stage"],
            "stage_changed_rounds": ";".join(map(str,orig["stage_changed_rounds"])),
            "private_note_changed_rounds": ";".join(map(str,orig["private_note_changed_rounds"])),
        }
        if item != expected:
            reject("PRIVATE HOLD: browser HUMAN selection not exact-original-history-bound")
        chosen.append({
            "local_case": orig["local_case"],
            "historical_transition": orig["historical_transition"],
            "original_kit": orig["original_kit"],
            "original_proposed_human_owner": owner,
            "original_round_human_stage": orig["round_stages"][n-1],
            "human_stage_changes_at_rounds": orig["stage_changed_rounds"],
            "private_note_changed_at_rounds": orig["private_note_changed_rounds"],
        })
    return chosen, selected_round


def private_html(owner, rows, round_no):
    parts=[
        "<p><strong>PRIVATE source-bound HUMAN selection, DRAFT/HOLD only.</strong> "
        "Proposed original owner: "+html.escape(owner,quote=True)+
        ". Not an authenticated recipient, task, fix, clearance, grant, consent "
        "or verified security finding. Manual round: "+str(round_no)+".</p>",
        "<table><thead><tr><th>Original slot</th><th>Proposed HUMAN stage "
        "in selected round</th><th>Stage changes</th><th>Note-changed rounds "
        "(no note contents)</th></tr></thead><tbody>"
    ]
    for r in rows:
        def val(x):return html.escape(str(x),quote=True)
        parts.append("<tr><td>"+val(r["local_case"])+" / "+val(r["historical_transition"])+
                     " / "+val(r["original_kit"])+"</td><td>"+
                     val(r["original_round_human_stage"])+"</td><td>"+
                     val(",".join(map(str,r["human_stage_changes_at_rounds"])) or "none")+
                     "</td><td>"+val(",".join(map(str,r["private_note_changed_at_rounds"])) or "none")+"</td></tr>")
    parts.append("</tbody></table><p>Original sources untouched. No automated recipient handoff.</p>")
    return html_page("LightUp PRIVATE original HUMAN selection", "".join(parts))


def minimal_html(rows, round_no):
    counts=Counter(r["original_round_human_stage"] for r in rows)
    rows_html="".join("<tr><td>"+html.escape(label)+"</td><td>"+str(counts[label])+
                     "</td></tr>" for label in STAGES)
    return html_page("LightUp anonymous PRIVATE HUMAN selection counts",
        "<p>HUMAN-only operator-selected original proposals, not authorized tasks "
        "or fixes. Source identities, original proposed HUMAN owner label and "
        "all original review SHA are omitted.</p><p>Manually selected HUMAN round "+
        str(round_no)+": "+str(len(rows))+" visible original slots.</p><table><tbody>"+
        rows_html+"</tbody></table>")


def run(args):
    paths=[args.history,args.selection_csv,args.private_parent]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: distinct absolute original PRIVATE custody paths required")
    if type(args.owner) is not str or not args.owner or args.owner != args.owner.strip():
        reject("PRIVATE HOLD: exact original proposed HUMAN owner required")
    safe_human(args.owner,80)
    private_parent(args.private_parent)
    history_raw, history_doc, slots=source_history(args.history)
    if (history_doc["owner_scoped_private_export"] and
        history_doc["selected_original_proposed_human_owner_label"] != args.owner):
        reject("PRIVATE HOLD: cannot widen original HUMAN history owner")
    csv_raw=read_owner_file(args.selection_csv,MAX_MANIFEST)
    chosen, round_no = selected_csv(
        csv_raw, slots, args.owner,
        len(history_doc["original_human_discussion_rounds"]),digest(history_raw))
    if (source_history(args.history)[0]!=history_raw or
        read_owner_file(args.selection_csv,MAX_MANIFEST)!=csv_raw):
        reject("PRIVATE HOLD: original HUMAN source drift before export")
    doc={
        "schema":SCHEMA,"authority":FLAGS,"historical_only":True,
        "sources_reopened":False,"recipient_authenticated":False,
        "consent_assumed":False,"actions_dispatched":False,
        "appointments_booked":False,"verified_remediation":False,
        "original_history_sha256":digest(history_raw),
        "original_human_browser_selection_csv_sha256":digest(csv_raw),
        "selected_original_proposed_human_owner_label":args.owner,
        "selected_original_human_round":round_no,
        "selected_original_human_rows_only":chosen,
    }
    files={
        "OPEN-PRIVATE.html":minimal_html(chosen,round_no),
        "PRIVATE-HUMAN-history-selection.html":private_html(args.owner,chosen,round_no),
        "PRIVATE-HUMAN-history-selection.json":canonical(doc),
        "PRIVATE-HUMAN-original-selection.csv":csv_raw,
    }
    if any(len(v if isinstance(v,bytes) else v.encode("utf-8"))>MAX_MANIFEST
           for v in files.values()):
        reject("PRIVATE HOLD: original HUMAN selection output too large")
    folder=new_private(args.private_parent)
    try:
        for name,data in files.items():write_private(folder,name,data)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: original HUMAN historical selection recorded; no action or authority")
    print(str(Path(folder)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p=argparse.ArgumentParser(
        description="Import exact original source-bound HUMAN timeline owner selection to PRIVATE HOLD")
    p.add_argument("--history",required=True,help="Native original PRIVATE-HUMAN-inbox-history.json")
    p.add_argument("--selection-csv",required=True,help="Browser local PRIVATE HUMAN owner CSV")
    p.add_argument("--owner",required=True,help="EXACT original proposed HUMAN owner label")
    p.add_argument("--private-parent",required=True,help="Existing 0700 PRIVATE operator parent")
    a=p.parse_args()
    try:return run(a)
    except (Hold,OSError,UnicodeError,ValueError,TypeError,csv.Error):
        print("PRIVATE HOLD: owner-scoped original HUMAN selection rejected",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
