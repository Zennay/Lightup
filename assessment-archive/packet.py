#!/usr/bin/env python3
"""Private or aggregate-only self-contained assessment archive coordination packet."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from io import BytesIO
import json
import sys
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from archive import (FLAGS, Hold, MAX_MANIFEST, _manifest, aggregate,
                     decode_json, encode, html_doc, publish, read_regular)
from followup import load_choices, html_board, SUMMARY_SCHEMA


def _entry(zf, name, content):
    """Deterministic member names, timestamps and private Unix permissions."""
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100600 << 16
    zf.writestr(info, content)


def package(args):
    # One bounded physical manifest snapshot for all entries and optional stages.
    source = read_regular(args.manifest, MAX_MANIFEST)
    original = _manifest(decode_json(source))
    fingerprint = sha256(source).hexdigest()
    public = bool(args.aggregate_only)
    with_studio = bool(getattr(args, "include_studio", False))
    if public and with_studio:
        raise Hold("private interactive studio cannot enter aggregate-only packet")
    previous_name = getattr(args, "previous", None)
    if previous_name and (public or not with_studio):
        raise Hold("historical private manifest requires private studio")
    previous = (_manifest(decode_json(read_regular(previous_name, MAX_MANIFEST)))
                if previous_name else None)
    historical_hold = previous is not None and previous["status"] == "HOLD"
    inventory = aggregate(original) if public else original
    human = None
    stages = None
    agenda_date = getattr(args, "agenda_date", None)
    if agenda_date is not None and args.choices is None:
        raise Hold("human agenda requires original source-bound choices")
    if args.choices is not None:
        stages = load_choices(args.choices, original, fingerprint)
        counts = Counter(item["stage"] for item in stages)
        human = {
            "schema": SUMMARY_SCHEMA, "claimed_status": original["status"],
            "source_count": len(stages), "stage_counts": dict(sorted(counts.items())),
            **{flag: False for flag in FLAGS},
        }
        if not public:
            human["items"] = [
                {"slot": item["slot"], "stage": item["stage"],
                 "next_role": item["next_role"], "review_date": item["review_date"]}
                for item in stages
            ]
    receipt = {
        "schema": "lightup.assessment_archive_coordination_packet.v1",
        "packet_mode": "AGGREGATE_ONLY" if public else "OWNER_PRIVATE",
        "source_count": original["source_count"], "claimed_status": original["status"],
        "has_human_followup": stages is not None,
        "has_human_agenda": agenda_date is not None,
        "has_local_archive_history": previous is not None,
        "original_data_included": False,
        "is_authentication": False,
        **{key: False for key in FLAGS},
    }
    if not public:
        # Private hash only: does not authenticate producer or source truth.
        receipt["local_manifest_sha256"] = fingerprint
    memory = BytesIO()
    with ZipFile(memory, mode="w") as zf:
        member_receipts = []
        def put(name, payload):
            _entry(zf, name, payload)
            member_receipts.append({
                "name": name, "size_bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
            })
        put("README.txt", (
            "LIGHTUP OFFLINE ASSESSMENT COORDINATION · PLAN/LAB ONLY · DRAFT/HOLD\n"
            "This ZIP contains a local metadata inventory and optional human planning.\n"
            "Original target sources, findings, lab evidence, credentials and approvals are NOT included.\n"
            "No SHA hash, claimed status or human stage is authority, verification, consent, GO, risk clearance or remediation proof.\n"
            "Do not deploy, grant, scan, target or execute anything based on this packet.\n"
            "Existing source-owner, privacy/security, CI and authenticated human gates remain mandatory.\n"
        ).encode("utf-8"))
        put("receipt.json", encode(receipt))
        put("archive-index.json", encode(inventory))
        put("archive-dashboard.html", html_doc(inventory, public))
        from portal import render as render_portal
        put("index.html", render_portal(
            is_private=not public, with_followup=stages is not None,
            with_studio=with_studio, with_agenda=agenda_date is not None,
            hold=original["status"] == "HOLD" or historical_hold))
        if with_studio:
            from archive_studio import render_bytes
            put("archive-studio.html", render_bytes(source, original, previous))
        if agenda_date is not None:
            from agenda import render_bytes as render_agenda
            put("human-agenda.html",
                   render_agenda(original, stages, agenda_date, public, "html"))
        if stages is not None:
            put("human-worklist.json", encode(human))
            put("human-worklist.html", html_board(original, stages, public))
        _entry(zf, "packet-integrity.json", encode({
            "schema": "lightup.assessment_archive_packet_integrity.v1",
            "packet_mode": "AGGREGATE_ONLY" if public else "OWNER_PRIVATE",
            "members": member_receipts,
            "member_count": len(member_receipts),
            "authenticated": False,
            **{key: False for key in FLAGS},
        }))
    payload = memory.getvalue()
    if len(payload) > 2 * 1024 * 1024:
        raise Hold("coordination packet exceeds limit")
    publish(args.output, payload)
    print("OFFLINE_COORDINATION_PACKET_CREATED — NO ORIGINAL LAB DATA OR AUTHORITY")
    return 3 if original["status"] == "HOLD" or historical_hold else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private lab archive coordination without original source or authorization.")
    parser.add_argument("--manifest", required=True, help="Previously captured original private archive manifest")
    parser.add_argument("--choices", help="Optional original manifest-bound human follow-up form")
    parser.add_argument("--agenda-date", help="Explicit YYYY-MM-DD human agenda reference; requires --choices")
    parser.add_argument("--previous", help="Owner-private previous archive; requires --include-studio, not aggregate-only")
    parser.add_argument("--output", required=True, help="Exact new private ZIP path; no overwrite")
    parser.add_argument("--aggregate-only", action="store_true", help="Remove all original source byte hashes and human slot, role/date assignments")
    parser.add_argument("--include-studio", action="store_true", help="Owner-private interactive review page; incompatible with --aggregate-only")
    args = parser.parse_args(argv)
    try:
        return package(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, OverflowError,
            RecursionError, KeyError, MemoryError):
        print("ASSESSMENT_COORDINATION_HOLD — invalid, inaccessible or unbound private source", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
