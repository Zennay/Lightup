#!/usr/bin/env python3
"""PRIVATE local HUMAN question history, checkpoint comparison and reversible restore.

Source-byte bound only; never authorizes a scan, native Apply, grant, or verified fix.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import getpass
import html
import json
from pathlib import Path
import sys

from review import FLAGS, Hold, pairs, private_publish, private_read, reject_constant, require
from triage import (STAGES, admit_session, canonical, durable_replace, fresh_original_bytes,
                    make_session, now_utc, selected_sources, sha, single_host_lock)

KIND = "lightup.private_human_evidence_checkpoint"
ENVELOPE = frozenset(("kind", "schema_version", "disposition", "source_packet_sha256",
    "previous_packet_sha256", "proposal_sha256", "session_sha256", "saved_utc",
    "private_session_base64", "warning", *FLAGS))
WARNING = ("Offline local HUMAN checkpoint only. No authenticated chronology, native "
           "LightUp Apply, consent, scan, grant, retest, validated evidence or repair.")


def envelope(expected: dict, session_bytes: bytes) -> dict:
    admit_session(session_bytes, expected)
    return {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_NOTES_BACKUP_NO_AUTHORITY",
        "source_packet_sha256": expected["source_packet_sha256"],
        "previous_packet_sha256": expected["previous_packet_sha256"],
        "proposal_sha256": expected["proposal_sha256"],
        "session_sha256": sha(session_bytes),
        "saved_utc": now_utc(),
        "private_session_base64": base64.b64encode(session_bytes).decode("ascii"),
        **{name: False for name in FLAGS},
        "warning": WARNING,
    }


def open_checkpoint(data: bytes, expected: dict) -> tuple[dict, bytes]:
    require(len(data) <= 2 * 1024 * 1024, "PRIVATE checkpoint exceeds 2 MiB")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Hold("Invalid PRIVATE checkpoint JSON") from exc
    require(type(value) is dict and set(value) == ENVELOPE,
            "Unknown PRIVATE checkpoint schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and
            value["kind"] == KIND and
            value["disposition"] == "PRIVATE_HUMAN_NOTES_BACKUP_NO_AUTHORITY" and
            value["warning"] == WARNING,
            "Wrong HUMAN checkpoint disposition")
    require(all(value[name] is False for name in FLAGS),
            "PRIVATE checkpoint claims unauthorized authority")
    for key in ("source_packet_sha256", "previous_packet_sha256", "proposal_sha256"):
        require(type(value[key]) is type(expected[key]) and value[key] == expected[key],
                "Checkpoint belongs to a different original source or HUMAN question set")
    require(type(value["session_sha256"]) is str and
            len(value["session_sha256"]) == 64 and
            type(value["private_session_base64"]) is str and
            len(value["private_session_base64"]) <= 1500000,
            "Invalid PRIVATE backup binary identity")
    stamp = value.get("saved_utc")
    require(type(stamp) is str and stamp.endswith("Z") and len(stamp) <= 40,
            "Invalid claimed local checkpoint creation time")
    try:
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        stored = base64.b64decode(value["private_session_base64"], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Hold("Invalid local timestamp or private session encoding") from exc
    require(sha(stored) == value["session_sha256"],
            "Checkpoint saved private session bytes do not match declared digest")
    saved = admit_session(stored, expected)
    return saved, stored


def changes(live: dict, archived: dict) -> tuple[dict, list[dict]]:
    altered = []
    transitions = Counter()
    for old, new in zip(archived["records"], live["records"]):
        stage_changed = old["stage"] != new["stage"]
        note_changed = old["human_note"] != new["human_note"]
        if stage_changed or note_changed:
            altered.append({
                "ordinal": new["ordinal"],
                "finding_id": new["finding_id"],
                "local_sha256": new["local_sha256"],
                "checkpoint_human_stage": old["stage"],
                "current_human_stage": new["stage"],
                "private_note_changed": note_changed,
            })
            transitions[old["stage"] + " to " + new["stage"]] += 1
    summary = {
        "kind": "lightup.anonymous_private_human_checkpoint_review",
        "schema_version": 1,
        "disposition": "HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        "local_original_questions": len(live["records"]),
        "changed_human_question_records": len(altered),
        "changed_private_note_records": sum(1 for r in altered if r["private_note_changed"]),
        "local_stage_transitions": dict(sorted(transitions.items())),
        "current_stage_counts": dict(Counter(x["stage"] for x in live["records"])),
        "checkpoint_stage_counts": dict(Counter(x["stage"] for x in archived["records"])),
        "warning": "Local data-only difference; neither snapshot is authenticated reviewer proof or verified remediation.",
    }
    return summary, altered


def report(live: dict, summary: dict, altered: list[dict]) -> bytes:
    e = lambda x: html.escape(str(x), quote=True)
    rows = "".join("<tr><td>" + str(r["ordinal"]) +
        "</td><td><code>" + e(r["finding_id"]) + "</code></td><td><code>" +
        e(r["local_sha256"]) + "</code></td><td>" +
        e(r["checkpoint_human_stage"]) + "</td><td>" +
        e(r["current_human_stage"]) + "</td><td>" +
        ("yes" if r["private_note_changed"] else "no") + "</td></tr>"
        for r in altered)
    markup = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
        "form-action 'none'; base-uri 'none'\"><title>PRIVATE HUMAN review recovery</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:auto;padding:1.3rem;"
        "background:#f7f8fa;color:#1c283a}table{width:100%;border-collapse:collapse;"
        "background:white}th,td{padding:.6rem;border:1px solid #ddd;text-align:left}"
        "code{overflow-wrap:anywhere}aside{padding:1rem;background:#fff4d8;"
        "border-left:4px solid #a60}</style><main><h1>PRIVATE HUMAN checkpoint comparison</h1>"
        "<aside>HUMAN ONLY / DRAFT HOLD. This local checkpoint is unsigned and "
        "provides no independent evidence, source authenticity, reviewer identity, "
        "legal custody, grant, client consent, verified repair or authorized retest. "
        "Never publish this PRIVATE report to public issues.</aside>"
        "<p>Self-declared client " + e(live["client_reference"]) + " / engagement " +
        e(live["engagement_reference"]) + "</p><p>Source claim SHA: <code>" +
        e(live["source_sha256"]) + "</code></p><p>Changed HUMAN actions: " +
        str(summary["changed_human_question_records"]) + " of " +
        str(summary["local_original_questions"]) + " · note changes: " +
        str(summary["changed_private_note_records"]) + "</p>"
        "<table><thead><tr><th>#</th><th>Finding</th><th>Local SHA</th>"
        "<th>Checkpoint stage</th><th>Current stage</th><th>Note different?</th>"
        "</tr></thead><tbody>" + rows + "</tbody></table>"
        "<p>Restoring affects local HUMAN notes only and cannot change the original "
        "source, evidence files, status of any security vulnerability or native workroom.</p>"
        "</main></html>\n"
    )
    return markup.encode("utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE local HUMAN checkpoint/history and safe restore")
    p.add_argument("action", choices=("capture", "inspect", "report", "restore"))
    p.add_argument("--current", type=Path, required=True, help="Original exact PRIVATE source JSON")
    p.add_argument("--previous", type=Path, help="Exact original prior PRIVATE source if used")
    p.add_argument("--session", type=Path, required=True, help="Existing 0600 HUMAN triage state")
    p.add_argument("--checkpoint", type=Path, required=True,
                   help="Capture: unused destination. Others: owner-private original checkpoint.")
    p.add_argument("--output", type=Path, help="New private HTML report for report")
    p.add_argument("--backup-to", type=Path,
                   help="Restore: unused PRIVATE backup for current session before changing it")
    args = p.parse_args()
    try:
        require((args.action == "report") == (args.output is not None) and
                (args.action == "restore") == (args.backup_to is not None),
                "Report requires --output; restore requires new --backup-to")
        inputs = (args.current, args.previous, args.session, args.checkpoint)
        require(args.action != "capture" or args.checkpoint not in inputs[:-1],
                "Cannot checkpoint over source or live HUMAN session")
        for path in (args.output, args.backup_to):
            if path is not None:
                require(path not in inputs and path != args.output if path == args.backup_to
                        else path not in inputs,
                        "Output/backup must be a distinct new PRIVATE path")
        current, previous, current_bytes, previous_bytes = selected_sources(
            args.current, args.previous)
        expected = make_session(current, previous, current_bytes, previous_bytes)
        with single_host_lock(args.session):
            live_bytes = private_read(args.session)
            live = admit_session(live_bytes, expected)
            if args.action == "capture":
                fresh_original_bytes(args, current_bytes, previous_bytes)
                require(private_read(args.session) == live_bytes, "HUMAN state changed while archiving")
                private_publish(args.checkpoint, canonical(envelope(expected, live_bytes)))
                print("Created new owner-private, exact-source HUMAN history checkpoint; original intact.")
                return 2
            archive_bytes = private_read(args.checkpoint)
            saved, saved_bytes = open_checkpoint(archive_bytes, expected)
            summary, delta = changes(live, saved)
            if args.action == "inspect":
                print(json.dumps(summary, indent=2, sort_keys=True))
                return 2
            if args.action == "report":
                payload = report(live, summary, delta)
                fresh_original_bytes(args, current_bytes, previous_bytes)
                require(private_read(args.session) == live_bytes and
                        private_read(args.checkpoint) == archive_bytes,
                        "PRIVATE review source/session/checkpoint changed during report preparation")
                private_publish(args.output, payload)
                print("New scriptless PRIVATE HUMAN checkpoint HTML published; no changes applied.")
                return 2
            require(live_bytes != saved_bytes, "Checkpoint already matches current HUMAN inbox")
            require(sys.stdin.isatty() and sys.stderr.isatty(),
                    "Actual local HUMAN restore requires a private interactive terminal")
            print(json.dumps(summary, indent=2, sort_keys=True))
            confirmation = getpass.getpass(
                "Type RESTORE PRIVATE HUMAN NOTES ONLY to recover local previous statuses: ")
            require(confirmation == "RESTORE PRIVATE HUMAN NOTES ONLY",
                    "Explicit HUMAN-only recovery acknowledgement required")
            fresh_original_bytes(args, current_bytes, previous_bytes)
            require(private_read(args.session) == live_bytes and
                    private_read(args.checkpoint) == archive_bytes,
                    "PRIVATE HUMAN state or checkpoint changed while confirming recovery")
            # Always preserve the just-replaced state as a different immutable PRIVATE checkpoint.
            private_publish(args.backup_to, canonical(envelope(expected, live_bytes)))
            durable_replace(args.session, saved_bytes)
            print("Restored only local HUMAN notes/status from PRIVATE checkpoint. Current state saved separately.")
            return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
