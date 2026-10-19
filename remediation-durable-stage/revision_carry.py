#!/usr/bin/env python3
"""Human-only carry-forward of staged ORIGINAL request closure across source revisions.

Requires CURRENT original account/client/engagement and full real material
admission by journal.py before invocation. Independently decrypts historical
original-native staged workroom, then matches exact current HUMAN-closed IDs.
No assumption of signed Apply, source provenance, authorization or execution.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import os
import stat

import engagement_index as history
import request_handoff as bridge

original = bridge.original


def _ref(row: dict) -> str:
    return hashlib.sha256(original.canonical({
        "finding_id": row["finding_id"], "linked_sha256": row["linked_sha256"],
        "request_id": row["request_id"],
    })).hexdigest()


def _old_native_drafts(path: Path, record: dict, args, vault, private_file) -> set[str]:
    bridge.source._hold_if_not_private_directory(path.parent)
    private_file(path)
    encrypted = vault._private_input(path, vault.MAX_VAULT)
    if hashlib.sha256(encrypted).hexdigest() != record["sha256"]:
        raise ValueError("Historical original HUMAN encrypted draft bytes changed.")
    secret = vault._password("Historical ORIGINAL native HUMAN draft password: ", fresh=False)
    payload, mime, _ = vault._open(encrypted, secret)
    if mime != "application/json":
        raise ValueError("Historical native HUMAN encrypted MIME invalid.")
    envelope, csv_raw, human_raw = original.human._admit_workspace(payload)
    if (envelope["client_reference"] != args.client_id or
            envelope["engagement_reference"] != args.engagement_id):
        raise ValueError("Historical native source is not this client/engagement.")
    digest, count = original.human._native_digest(csv_raw)
    prior = original.human._packet(
        human_raw, source_digest=digest, count=count,
        client=args.client_id, engagement=args.engagement_id)
    original.native._records(prior, original._current_rows(csv_raw))
    expected = set(record["requests"])
    if not expected or len(expected) != len(record["requests"]):
        raise ValueError("Ambiguous historical staged request identity.")
    seen = set()
    for row in prior["human_requests"]:
        identity = _ref(row)
        if identity not in expected:
            continue
        if (identity in seen or row["request_kind"] != "followup_question"
                or row["human_stage"] != "draft" or row["assignee"]
                or row["due_date"] or row["human_response"]
                or not row["instructions"].startswith(bridge.INTRO)):
            raise ValueError("Historical native HUMAN stage identity changed.")
        seen.add(identity)
    if seen != expected:
        raise ValueError("Historical staged original-native HUMAN request(s) missing.")
    return expected


def carry(args, folder, vault, current_packet, current_key,
          read_journal, write_journal, private_file, utc) -> None:
    indexed = history._load(folder, current_packet, vault, private_file)
    available = []
    for key in indexed["sources"]:
        if key == current_key:
            continue
        source_path = folder / (key + ".json")
        if not source_path.exists() or source_path.is_symlink():
            raise ValueError("Registered historical HUMAN journal is missing.")
        old = read_journal(folder, key, vault)
        if old["cycles"] and old["cycles"][-1]["state"] in ("pending", "staged"):
            available.append((key, old))
    if not available:
        raise ValueError("No earlier registered HUMAN source handoff awaiting closeout.")
    print("Historical original HUMAN source handoffs awaiting human review:")
    for ordinal, (_, old) in enumerate(available, 1):
        item = old["cycles"][-1]
        print(ordinal, "·", item["state"], "· original native request count:",
              len(item["requests"]))
    choice = input("Choose one earlier source ordinal for HUMAN closure (empty HOLD): ").strip()
    if not choice.isascii() or not choice.isdecimal() or not 1 <= int(choice) <= len(available):
        raise ValueError("Choose exactly one earlier HUMAN source.")
    key, old = available[int(choice)-1]
    entry = old["cycles"][-1]
    if entry["state"] != "staged" or not entry["sha256"]:
        raise ValueError("Earlier pending native draft needs original recovery first.")
    historical = _old_native_drafts(
        Path(entry["output"]), entry, args, vault, private_file)
    now = current_packet["human_requests"]
    closed = {_ref(row) for row in now if row["human_stage"] == "closed_human"}
    if not historical.issubset(closed):
        raise ValueError("Current ORIGINAL HUMAN workroom does not report all old requests closed.")
    print("Current original HUMAN workroom reports", len(historical),
          "matching historical native request(s) as closed_human.")
    print("This does not prove native Apply, original-client consent, "
          "retention-law determination, evidence provenance or execution.")
    confirm = input('Type "CARRY HUMAN CLOSED LABELS ONLY" to archive this local source handoff: ')
    if confirm != "CARRY HUMAN CLOSED LABELS ONLY":
        raise ValueError("Separate original HUMAN continuity acknowledgment required.")
    # Only a local HUMAN journal state transition; no ORIGINAL source mutation.
    entry["state"] = "reviewed"
    entry["updated"] = utc()
    write_journal(folder, key, old)
    print("Earlier source's PRIVATE local HUMAN journal marked reviewed.")
    print("Original actual source/material must still be independently authorized; "
          "no native Apply, grant, scan, delete or retest occurred.")
