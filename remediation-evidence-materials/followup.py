#!/usr/bin/env python3
"""Create NEW encrypted original HUMAN workroom with staged recipient follow-up.

No automatic native Apply, live target, scanner, remediation action, retest,
consent, grant or security claim. The original owner vault is unchanged.
"""
from __future__ import annotations

import argparse
import base64
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys
import uuid

import reply
import transfer

MAX_REQUESTS = transfer.native.MAX_REQUESTS
INTRO = ("Recipient requested HUMAN follow-up for locally received, unverified "
         "evidence material. Original source and material require independent review.")
EMPTY_NOTE = ("Recipient requested an original HUMAN follow-up; no additional "
              "private explanation was supplied.")

def _native_candidates(packet: dict, rows: list[dict]) -> tuple[list[dict], int, int]:
    if packet["schema_version"] not in (1, 2):
        raise ValueError("Original HUMAN packet version is unsupported.")
    existing = packet.get("human_requests", [])
    if type(existing) is not list:
        raise ValueError("Original private HUMAN requests must be an array.")
    open_findings = {row["finding_id"] for row in existing
                     if row["human_stage"] != "closed_human"}
    pending = defaultdict(list)
    for row in rows:
        if row["human_stage"] == "needs_human_followup":
            pending[row["finding_id"]].append(row)
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")
    proposals = []
    blocked = 0
    for fid, followups in pending.items():
        if fid in open_findings:
            blocked += 1
            continue
        # Source-reported finding identity only; note is a private HUMAN proposal.
        notes = [row["human_note"] for row in followups if row["human_note"]]
        guidance = INTRO + " " + (" HUMAN notes: " + "; ".join(notes) if notes
                                     else EMPTY_NOTE)
        # Conservative admission: do NOT silently truncate private human notes.
        if len(guidance) > 1400:
            raise ValueError("Original HUMAN request prose exceeds native bounded limit.")
        proposal = {
            "request_id": uuid.uuid4().hex,
            "finding_id": fid,
            "request_kind": "followup_question",
            "assignee": "",
            "due_date": "",
            "instructions": guidance,
            "linked_sha256": followups[0]["sha256"],
            "human_stage": "draft",
            "human_response": "",
            "created_utc": now,
            "updated_utc": now,
        }
        proposals.append(proposal)
    if len(existing) + len(proposals) > MAX_REQUESTS:
        raise ValueError("Original HUMAN Request Desk limit exceeded: no partial carry.")
    return proposals, blocked, len(pending)


def _context(args, vault):
    metadata, packet, indexed, original_key = reply._source(args, vault)
    material_raw, files, material_key = reply._transfer(args, vault, metadata, packet)
    receipt_raw, receipt_key = reply._decrypt(
        args.reply, "Existing PRIVATE HUMAN reply passphrase: ", vault)
    rows = reply._reply_packet(receipt_raw, material_raw, files, metadata, packet)
    return metadata, packet, files, rows, (original_key, transfer.digest(material_key),
                                         transfer.digest(receipt_key))


def _carry(args, vault) -> None:
    metadata, packet, files, rows, old_keys = _context(args, vault)
    candidates, blocked, eligible = _native_candidates(packet, rows)
    print("PRIVATE recipient-to-original-HUMAN-Request-Desk bridge")
    print("Source-bound received material references:", len(files))
    print("Distinct findings requesting HUMAN follow-up:", eligible)
    print("Already-open original HUMAN request findings held unchanged:", blocked)
    print("New original HUMAN draft follow-up requests:", len(candidates))
    print("No changes to pre-existing original notes, evidence or request records.")
    if args.action == "preview":
        print("Preview only. No new PRIVATE file, original application update or Apply.")
        return
    if not candidates:
        raise ValueError("No independent new request is available for safe staging.")
    expected = input('Type "STAGE HUMAN DRAFT" to make a NEW encrypted staging vault: ')
    if expected != "STAGE HUMAN DRAFT":
        raise ValueError("Human did not explicitly acknowledge private draft staging.")
    original_csv = transfer.human._unb64(
        metadata["original_csv_base64"], transfer.ORIGINAL.MAX_CSV_BYTES)
    result = dict(packet)
    result["schema_version"] = 2
    result["human_requests"] = [*packet.get("human_requests", []), *candidates]
    ids = transfer._current_rows(original_csv)
    transfer.native._records(result, ids)
    human_json = transfer.canonical(result)
    composed = transfer.human._make_workspace(
        original_csv, human_json, packet["client_reference"], packet["engagement_reference"])
    secret = vault._password("New PRIVATE HUMAN follow-up staging passphrase: ", fresh=True)
    if transfer.digest(secret) in old_keys:
        raise ValueError("Original and return passphrases cannot be reused for new staging.")
    encrypted = vault._seal(vault._inner(composed,"application/json"),secret)
    destination = args.output.expanduser().absolute()
    if destination.suffix.lower() != ".ltv" or destination in {
        args.human.expanduser().absolute(),
        args.reply.expanduser().absolute(),
        args.transfer.expanduser().absolute()
    }:
        raise ValueError("New distinct PRIVATE .ltv staging destination required.")
    vault._exclusive_output(destination, encrypted)
    print("Created NEW original-compatible encrypted PRIVATE HUMAN workroom.")
    print("Additional HUMAN follow-up drafts:", len(candidates))
    print("Use the unchanged original Ledger's separate source-bound import PREVIEW and HUMAN Apply.")
    print("No finding, fix, consent, security clearance or active retest was verified.")


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="action",required=True)
    for mode in ("preview","carry"):
        p=sub.add_parser(mode)
        for name in ("db","email","client-id","engagement-id"):
            p.add_argument("--"+name,required=True)
        p.add_argument("--human",type=Path,required=True,
                       help="Original current-source encrypted HUMAN workspace .ltv")
        p.add_argument("--transfer",type=Path,required=True,
                       help="Exact original encrypted PRIVATE material transfer .ltv")
        p.add_argument("--reply",type=Path,required=True,
                       help="Encrypted original-source-bound recipient HUMAN reply .ltv")
        if mode=="carry":
            p.add_argument("--output",type=Path,required=True,
                           help="NEW original-compatible HUMAN .ltv with only staged follow-up drafts")
        p.add_argument("--ack-private-followup",action="store_true")
    opts=parser.parse_args(argv)
    try:
        if not opts.ack_private_followup or not sys.stdin.isatty():
            raise ValueError("Interactive HUMAN acknowledgement required.")
        _carry(opts, transfer.ORIGINAL._vault())
        return 0
    except Exception:
        print("HUMAN HOLD: no original HUMAN requests silently created, applied or released. "
              "Check current original source, encrypted reply, and existing HUMAN request owners.",
              file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
