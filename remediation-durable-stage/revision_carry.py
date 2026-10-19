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
    interrupted = (record["state"] == "pending" and record["sha256"] == "")
    if not interrupted and hashlib.sha256(encrypted).hexdigest() != record["sha256"]:
        raise ValueError("Historical original HUMAN encrypted draft bytes changed.")
    if not interrupted and record["state"] != "staged":
        raise ValueError("Historical HUMAN draft is not a staged original record.")
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
          read_journal, write_journal, private_file, utc,
          re_admit_original) -> None:
    indexed = history._load(folder, current_packet, vault, private_file)
    available = []
    for original_ordinal, key in enumerate(indexed["sources"], 1):
        if key == current_key:
            continue
        source_path = folder / (key + ".json")
        if not source_path.exists() or source_path.is_symlink():
            raise ValueError("Registered historical HUMAN journal is missing.")
        old = read_journal(folder, key, vault)
        if old["cycles"] and old["cycles"][-1]["state"] in ("pending", "staged"):
            available.append((original_ordinal, key, old))
    if not available:
        raise ValueError("No earlier registered HUMAN source handoff awaiting closeout.")
    print("Historical original HUMAN source handoffs awaiting human review:")
    for ordinal, (_, _, old) in enumerate(available, 1):
        item = old["cycles"][-1]
        print(ordinal, "·", item["state"], "· original native request count:",
              len(item["requests"]))
    selected_source = getattr(args, "source_ordinal", None)
    if selected_source is not None:
        matches = [(key, old) for source_ordinal, key, old in available
                   if source_ordinal == selected_source]
        if len(matches) != 1:
            raise ValueError("Selected originally indexed source is not awaiting HUMAN review.")
        if input('Type "SELECT REGISTERED HUMAN SOURCE" to inspect that source: ') != (
                "SELECT REGISTERED HUMAN SOURCE"):
            raise ValueError("Explicit source selection confirmation required.")
        key, old = matches[0]
    else:
        choice = input("Choose one earlier source ordinal for HUMAN closure (empty HOLD): ").strip()
        if not choice.isascii() or not choice.isdecimal() or not 1 <= int(choice) <= len(available):
            raise ValueError("Choose exactly one earlier HUMAN source.")
        _, key, old = available[int(choice)-1]
    if (getattr(args, "expected_cycle", None) is not None
            and len(old["cycles"]) != args.expected_cycle):
        raise ValueError("Registered historical HUMAN cycle changed after operator choice.")
    entry = old["cycles"][-1]
    destination = Path(entry["output"])
    bridge.source._hold_if_not_private_directory(destination.parent)
    if entry["state"] == "pending" and not destination.exists() and not destination.is_symlink():
        if entry["sha256"]:
            raise ValueError("Unpublished pending historical HUMAN SHA is not empty.")
        current_ids = {_ref(row) for row in current_packet.get("human_requests", [])}
        if any(ref in current_ids for ref in entry["requests"]):
            raise ValueError(
                "CURRENT original HUMAN workroom contains an older pending request;"
                " missing local file is not proof it was never sent.")
        print("Historical pending original-native draft absent at recorded private output path.")
        if input('Type "CONFIRM HISTORICAL NO DRAFT PUBLISHED" after HUMAN review: ') != (
                "CONFIRM HISTORICAL NO DRAFT PUBLISHED"):
            raise ValueError("Missing ORIGINAL source requires separate HUMAN attention.")
        re_admit_original()
        entry["state"] = "aborted_unpublished"
        entry["updated"] = utc()
        write_journal(folder, key, old)
        print("Only older LOCAL pending record marked aborted_unpublished.")
        return
    if entry["state"] == "pending" and entry["sha256"]:
        raise ValueError("Ambiguous interrupted historical encrypted HUMAN draft.")
    if entry["state"] not in ("pending", "staged"):
        raise ValueError("Earlier source has no eligible native HUMAN draft.")
    historical = _old_native_drafts(destination, entry, args, vault, private_file)
    now = current_packet.get("human_requests", [])
    if type(now) is not list:
        raise ValueError("Current original HUMAN request list is malformed.")
    closed = {_ref(row) for row in now
              if row["human_stage"] == "closed_human"
              and row["request_kind"] == "followup_question"}
    if not historical.issubset(closed):
        raise ValueError("Current ORIGINAL HUMAN workroom does not report all old requests closed.")
    print("Current original HUMAN workroom reports", len(historical),
          "matching historical native request(s) as closed_human.")
    print("This does not prove native Apply, original-client consent, "
          "retention-law determination, evidence provenance or execution.")
    confirm = input('Type "CARRY HUMAN CLOSED LABELS ONLY" to archive this local source handoff: ')
    if confirm != "CARRY HUMAN CLOSED LABELS ONLY":
        raise ValueError("Separate original HUMAN continuity acknowledgment required.")
    # Every HUMAN confirmation expires until the exact CURRENT ORIGINAL
    # account, workroom, retention plan and all local evidence are re-admitted.
    re_admit_original()
    # Only a local HUMAN journal state transition; no ORIGINAL source mutation.
    if entry["state"] == "pending":
        # For a previously interrupted publication, original-native
        # encrypted identity admission + current reported HUMAN closure
        # precede recording the previously missing local SHA.
        entry["sha256"] = hashlib.sha256(
            vault._private_input(destination, vault.MAX_VAULT)).hexdigest()
    entry["state"] = "reviewed"
    entry["updated"] = utc()
    write_journal(folder, key, old)
    print("Earlier source's PRIVATE local HUMAN journal marked reviewed.")
    print("Original actual source/material must still be independently authorized; "
          "no native Apply, grant, scan, delete or retest occurred.")


def adopt_legacy(args, folder, vault, current_packet,
                 read_journal, write_journal, private_file,
                 re_admit_original) -> None:
    """Explicitly enroll one older nonindexed staged source under this engagement."""
    import re
    index = history._load(folder, current_packet, vault, private_file)
    if len(index["sources"]) >= history.MAX_REVISIONS:
        raise ValueError("Original engagement source index full.")
    available = []
    # Names are opaque original source keys. No customer data printed.
    for name in sorted(folder.iterdir(), key=lambda p: p.name):
        if (re.fullmatch(r"[0-9a-f]{64}\.json", name.name)
                and name.stem not in index["sources"]):
            private_file(name)
            old = read_journal(folder, name.stem, vault)
            if old["cycles"]:
                latest = old["cycles"][-1]
                can_adopt = (latest["state"] == "staged" and latest["sha256"]) or (
                    latest["state"] == "pending" and not latest["sha256"]
                    and Path(latest["output"]).is_file())
                if can_adopt:
                    available.append((name.stem, old))
    if not available:
        raise ValueError("No eligible legacy original-native staged HUMAN journal.")
    print("Previously unindexed PRIVATE historical source entries:")
    for ordinal, (_, old) in enumerate(available, 1):
        print(ordinal, "· encrypted native drafts:",
              len(old["cycles"][-1]["requests"]))
    raw = input("Choose one historical HUMAN journal ordinal to enroll: ").strip()
    if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= len(available):
        raise ValueError("Choose one exact historical HUMAN journal.")
    key, old = available[int(raw) - 1]
    entry = old["cycles"][-1]
    # Cryptographically decrypt original-native private historical workroom
    # and independently validate its original exact client/engagement binding.
    accepted = _old_native_drafts(Path(entry["output"]), entry, args, vault, private_file)
    if len(accepted) != len(entry["requests"]):
        raise ValueError("Legacy original-human draft identity count changed.")
    if input('Type "ENROLL OLD HUMAN SOURCE ONLY" after private review: ') != (
            "ENROLL OLD HUMAN SOURCE ONLY"):
        raise ValueError("No explicit legacy HUMAN registration acknowledgment.")
    re_admit_original()
    index["sources"].append(key)
    write_journal(folder, history._name(current_packet), index)
    print("Historical owner-private original-native source journal enrolled.")
    print("It remains HUMAN-only. Existing pending/staged HOLD is preserved.")
