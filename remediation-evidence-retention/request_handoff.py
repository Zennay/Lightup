#!/usr/bin/env python3
"""Bridge due PRIVATE HUMAN evidence-retention reviews to original Request Desk.

Only prepares new ORIGINAL-compatible encrypted HUMAN draft questions from a
strict current original authenticated source + verified local evidence bytes.
No file deletion, legal-hold release, original Apply, retest, scope grant,
client consent, scanner activity or verified security outcome.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
import sys
import uuid

import retention as source

original = source.transfer
MAX_GUIDANCE = 1400
INTRO = (
    "PRIVATE HUMAN EVIDENCE RETENTION REVIEW DUE. Confirm the currently "
    "applicable separately approved retention policy, obligations and next "
    "human review date for this indexed, unverified local evidence material. "
    "Do NOT delete, release a legal hold, retest or publish anything based "
    "on this request. It is a coordination question only."
)


def _eligible(packet: dict, items: list[dict]) -> tuple[list[dict], int, int]:
    """Do not collide with existing active original requests or infer consent."""
    existing = packet.get("human_requests", [])
    if type(existing) is not list:
        raise ValueError("Canonical original HUMAN requests required.")
    open_finding = {row["finding_id"] for row in existing
                    if row["human_stage"] != "closed_human"}
    candidates = defaultdict(list)
    today = date.today().isoformat()
    for item in items:
        if item["review_on"] <= today:
            candidates[item["finding_id"]].append(item)
    kept = []
    blocked = 0
    for finding_id in sorted(candidates, key=lambda name: name.encode("utf-8")):
        if finding_id in open_finding:
            blocked += 1
            continue
        due_items = candidates[finding_id]
        kept.append({
            "finding_id": finding_id,
            "count": len(due_items),
            "oldest_review_day": min(row["review_on"] for row in due_items),
            "linked_sha256": due_items[0]["sha256"],
            "legal_hold_human_count": sum(row["decision"] == "legal_hold" for row in due_items),
        })
    if len(existing) + len(kept) > original.native.MAX_REQUESTS:
        raise ValueError("Original Request Desk cap reached; no partial drafts.")
    return kept, blocked, len(candidates)


def _build(packet: dict, selected: list[dict]) -> list[dict]:
    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")
    requests = []
    for row in selected:
        prose = (INTRO + " HUMAN review-due indexed material count: "
                 + str(row["count"]) + ". Earliest HUMAN review date: "
                 + row["oldest_review_day"]
                 + ". Human-marked legal hold entries: "
                 + str(row["legal_hold_human_count"])
                 + ". Independently verify actual legal authority; this "
                   "request is NOT a disposal or preservation order.")
        if len(prose) > MAX_GUIDANCE:
            raise ValueError("Complete original HUMAN request text is too large.")
        requests.append({
            "request_id": uuid.uuid4().hex,
            "finding_id": row["finding_id"],
            "request_kind": "followup_question",
            "assignee": "",
            "due_date": "",
            "instructions": prose,
            "linked_sha256": row["linked_sha256"],
            "human_stage": "draft",
            "human_response": "",
            "created_utc": timestamp,
            "updated_utc": timestamp,
        })
    return requests


def _load(args, vault):
    envelope, packet, indexed, source_key_hash = original.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    # Does not use self-authored untrusted CSV export: re-open actual material
    # and native encrypted plan, strictly against the CURRENT original source.
    items, plan_key_hash = source._load_current_plan(args, vault, packet, indexed)
    return envelope, packet, indexed, items, source_key_hash, plan_key_hash


def _choose(candidates: list[dict]) -> list[dict]:
    print("Current original-source-bound HUMAN findings due for local review:")
    for ordinal, rec in enumerate(candidates, 1):
        # Never print a private original finding identifier or attachment SHA
        # in a terminal summary. Ordinal choice maps in memory only.
        print(ordinal, "· actual indexed files:", rec["count"],
              "· earliest HUMAN review:", rec["oldest_review_day"],
              "· HUMAN legal-hold caution:", rec["legal_hold_human_count"])
    raw = input("Select 1–N distinct finding ordinals (comma separated; empty HOLD): ").strip()
    parts = [p.strip() for p in raw.split(",")]
    if not raw or len(parts) > len(candidates) or any(
        not p.isascii() or not p.isdecimal() for p in parts
    ):
        raise ValueError("Explicit original HUMANS selection required.")
    picks = [int(p) for p in parts]
    if len(set(picks)) != len(picks) or any(p < 1 or p > len(candidates) for p in picks):
        raise ValueError("Repeated or unknown private finding ordinal.")
    return [candidates[p - 1] for p in picks]


def operate(args, vault) -> int:
    envelope, packet, indexed, items, original_hash, plan_hash = _load(args, vault)
    candidates, blocked, all_due = _eligible(packet, items)
    print("PRIVATE HUMAN retention → original HUMAN Request Desk (NO APPLY)")
    print("Due finding groups:", all_due, "· already-open original HUMAN requests:", blocked)
    print("New original HUMAN follow-up candidates:", len(candidates))
    if args.action == "preview":
        print("No original draft, encrypted file, grant, deletion or retest written.")
        return 0
    if not candidates:
        raise ValueError("No fresh original HUMAN finding review request to stage.")
    chosen = _choose(candidates)
    if input('Type "STAGE RETENTION QUESTIONS" to create a NEW PRIVATE encrypted draft: ') != (
        "STAGE RETENTION QUESTIONS"
    ):
        raise ValueError("No explicit human staging acknowledgement.")
    drafts = _build(packet, chosen)
    updated = dict(packet)
    updated["schema_version"] = 2
    updated["human_requests"] = [*packet.get("human_requests", []), *drafts]
    original_csv = original.human._unb64(
        envelope["original_csv_base64"], original.ORIGINAL.MAX_CSV_BYTES)
    ids = original._current_rows(original_csv)
    original.native._records(updated, ids)
    workroom = original.human._make_workspace(
        original_csv, original.canonical(updated),
        packet["client_reference"], packet["engagement_reference"])
    new_key = vault._password("NEW private HUMAN retention draft passphrase: ", fresh=True)
    if original.digest(new_key) in (original_hash, plan_hash):
        raise ValueError("New PRIVATE draft passphrase may not reuse either original password.")
    destination = args.output.expanduser().absolute()
    if destination.suffix.lower() != ".ltv" or destination in {
        args.human.expanduser().absolute(), args.plan.expanduser().absolute()
    }:
        raise ValueError("Distinct NEW encrypted 0600 .ltv destination required.")
    vault._exclusive_output(
        destination, vault._seal(vault._inner(workroom, "application/json"), new_key))
    print("Created NEW encrypted owner-only 0600 ORIGINAL-compatible HUMAN workroom.")
    print("New HUMAN follow-up draft questions:", len(drafts))
    print("Original files, evidence hashes, Casework, review notes and historical"
          " HUMAN requests remain unchanged.")
    print("Original app still requires separate source-bound Preview + manual HUMAN Apply.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("preview", "stage"):
        p = subs.add_parser(action)
        for key in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + key, required=True)
        p.add_argument("--human", type=Path, required=True,
                       help="Current original encrypted HUMAN Evidence Ledger .ltv")
        p.add_argument("--directory", type=Path, required=True,
                       help="Existing owner-private actual evidence material folder")
        p.add_argument("--plan", type=Path, required=True,
                       help="Original-source-bound encrypted HUMAN retention review .ltv")
        if action == "stage":
            p.add_argument("--output", type=Path, required=True,
                           help="Distinct NEW encrypted original-native HUMAN workroom .ltv")
        p.add_argument("--ack-private-review", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_review or not sys.stdin.isatty():
            raise ValueError("Private HUMAN approval and interactive terminal required.")
        return operate(args, original.ORIGINAL._vault())
    except Exception:
        print("HUMAN HOLD: Current original authenticated source, encrypted retention,"
              " actual private material, native request admission or human approval"
              " refused. No complete HUMAN request draft published.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
