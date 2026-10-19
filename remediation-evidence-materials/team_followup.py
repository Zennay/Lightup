#!/usr/bin/env python3
"""Stage multi-recipient conflicting evidence replies as ORIGINAL HUMAN draft requests.

All original source, tenant, attachment and reply admission comes from team.py,
which reuses the original LightUp DomainStore + encrypted PRIVATE workspace.
A conflict is a QUESTION for an owner, never resolved security truth or Apply.
"""
from __future__ import annotations

import argparse
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
import sys
from uuid import uuid4

import team
import transfer

SCOPE_NOTE=("Human-only source-bound material reply disagreement or unresolved "
            "follow-up; NOT verified vulnerability, remediation, retest or consent. ")


def proposals(packet: dict, rows: list[dict]) -> tuple[list[dict],dict]:
    old=packet.get("human_requests",[])
    if type(old) is not list:
        raise ValueError("Original HUMAN Request Desk records are unavailable.")
    open_finding_ids={r["finding_id"] for r in old
                      if r["human_stage"]!="closed_human"}
    grouped=defaultdict(list)
    for row in rows:
        grouped[row["finding_id"]].append(row)
    reviewed=len(grouped)
    created=[]
    already_open=0
    held=0
    needs_review=0
    when=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00","Z")
    for finding_id, group in sorted(grouped.items()):
        statuses={r["human_stage"] for r in group}
        disagreement=len(statuses)>1
        explicit=any(r["human_stage"]=="needs_human_followup" for r in group)
        if not disagreement and not explicit:
            continue
        needs_review+=1
        if finding_id in open_finding_ids:
            already_open+=1
            continue
        category=("CONFLICT: multiple independent HUMAN receipt statuses differ. "
                  if disagreement else
                  "FOLLOW-UP: recipient explicitly requested HUMAN clarification. ")
        # Preserve all HUMAN status opinions, not just a majority or chosen one.
        # Include per-packet notes only if the full original native HUMAN limit fits:
        # otherwise HOLD the entire new workspace rather than silently dropping.
        parts=[]
        for r in sorted(group,key=lambda v:(v["packet"],v["sha256"])):
            excerpt=r["human_note"].strip()
            line=f'Packet {r["packet"]} = {r["human_stage"]}'
            if excerpt:
                line+="; HUMAN note: "+excerpt
            parts.append(line)
        instructions=SCOPE_NOTE+category+" ".join(parts)
        if len(instructions)>1400:
            held+=1
            continue
        candidate={
            "request_id":uuid4().hex,
            "finding_id":finding_id,
            "request_kind":"followup_question",
            "assignee":"",
            "due_date":"",
            "instructions":instructions,
            "linked_sha256":"", # multiple independent local references; no arbitrary favored hash
            "human_stage":"draft",
            "human_response":"",
            "created_utc":when,
            "updated_utc":when,
        }
        created.append(candidate)
    if held:
        raise ValueError("One or more private HUMAN conflicts exceed original native note limit; no partial request set.")
    if len(old)+len(created)>transfer.native.MAX_REQUESTS:
        raise ValueError("Original HUMAN Request Desk capacity exceeded; no partial selection.")
    counts={
        "source_findings_referenced":reviewed,
        "human_disagreements_or_explicit_followups":needs_review,
        "already_open_original_requests_retained":already_open,
        "new_original_human_draft_questions":len(created),
    }
    return created,counts


def operate(args, vault) -> None:
    meta,original_packet,original_findings,rows=team.collect(args,vault)
    candidates,summary=proposals(original_packet,rows)
    print("PRIVATE HUMAN team → original native Request Desk proposals")
    for key,value in summary.items():
        print(key.replace("_"," ")+":",value)
    print("Source-reported severity and retest labels are unverified. No native Apply.")
    if args.action=="preview":
        print("PREVIEW ONLY: nothing exported, merged or applied.")
        return
    if not candidates:
        raise ValueError("No unclaimed original HUMAN follow-up is pending.")
    choice=input('Type "STAGE TEAM FOLLOWUP" to create NEW encrypted native HUMAN workroom: ')
    if choice!="STAGE TEAM FOLLOWUP":
        raise ValueError("Explicit HUMAN draft intent not acknowledged.")
    source=transfer.human._unb64(meta["original_csv_base64"],
                                  transfer.ORIGINAL.MAX_CSV_BYTES)
    native=dict(original_packet)
    native["schema_version"]=2
    native["human_requests"]=[*original_packet.get("human_requests",[]),*candidates]
    source_ids=transfer._current_rows(source)
    transfer.native._records(native,source_ids)
    new_human=transfer.canonical(native)
    packed=transfer.human._make_workspace(source,new_human,
                native["client_reference"],native["engagement_reference"])
    new_password=vault._password("NEW PRIVATE multi-HUMAN follow-up workroom passphrase: ",fresh=True)
    encrypted=vault._seal(vault._inner(packed,"application/json"),new_password)
    output=args.output.expanduser().absolute()
    reserved={args.human.expanduser().absolute(),
              *(x.expanduser().absolute() for x in args.transfer),
              *(x.expanduser().absolute() for x in args.reply)}
    if output.suffix.lower()!=".ltv" or output in reserved:
        raise ValueError("New distinct private encrypted native HUMAN .ltv required.")
    vault._exclusive_output(output,encrypted)
    print("Created NEW 0600 encrypted original-compatible HUMAN workspace.")
    print("Original Casework, Evidence Review, attachments and previous HUMAN requests preserved.")
    print("New requests are DRAFTS requiring original independent source-bound Preview and manual Apply.")
    print("No recipient identity proof, security finding, fix, scan, retest, grant or client consent.")


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="action",required=True)
    for action in ("preview","stage"):
        p=sub.add_parser(action)
        for name in ("db","email","client-id","engagement-id"):
            p.add_argument("--"+name,required=True)
        p.add_argument("--human",type=Path,required=True)
        p.add_argument("--transfer",type=Path,action="append",required=True)
        p.add_argument("--reply",type=Path,action="append",required=True)
        if action=="stage":
            p.add_argument("--output",type=Path,required=True)
        p.add_argument("--ack-private-team-followup",action="store_true")
    args=parser.parse_args(argv)
    try:
        if not args.ack_private_team_followup or not sys.stdin.isatty():
            raise ValueError("Separate HUMAN team-followup acknowledgement and private terminal required.")
        operate(args,transfer.ORIGINAL._vault())
        return 0
    except Exception:
        print("HUMAN HOLD: no changes to original HUMAN records. Check all original-current "
              "source-bound private replies and native request capacity.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
