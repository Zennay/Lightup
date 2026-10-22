#!/usr/bin/env python3
"""Durable, source-byte-bound, PRIVATE HUMAN-only artifact relationship triage.

Runs offline and never invokes LightUp grant, scan, Apply or network subsystems.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from review import (FLAGS, Hold, analyze, exact_human_note, exact_string, pairs, parse_packet_data,
                    private_publish, private_read, proposed_actions, reject_constant,
                    require)

KIND = "lightup.private_evidence_reuse_human_triage"
SCHEMA = 1
STAGES = ("open", "in_human_review", "needs_source_owner", "answered_human")
REASONS = frozenset(("VERIFY_INTENTIONAL_CROSS_FINDING_REUSE",
                     "RECONCILE_HUMAN_STAGE_DIFFERENCE",
                     "RECHECK_LOCAL_BYTES_WITH_ORIGINAL_LEDGER",
                     "REVIEW_NEW_LOCAL_LINK",
                     "PREVIOUS_LOCAL_LINK_ABSENT_NOT_PROVEN_FIXED",
                     "REVIEW_CHANGED_LOCAL_HUMAN_METADATA"))
HEADER = {"kind", "schema_version", "disposition", "source_packet_sha256",
          "previous_packet_sha256", "proposal_sha256", "source_sha256",
          "client_reference", "engagement_reference", "records", "warning", *FLAGS}
ITEM = {"ordinal", "finding_id", "local_sha256", "reasons", "stage", "human_note", "updated_utc"}


def canonical(data: object) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def selected_sources(current_path: Path, previous_path: Path | None) -> tuple[dict, dict | None, bytes, bytes | None]:
    current_bytes = private_read(current_path)
    previous_bytes = private_read(previous_path) if previous_path else None
    current = parse_packet_data(current_bytes)
    previous = parse_packet_data(previous_bytes) if previous_bytes is not None else None
    # The same already-read bytes form both the record and its own binding.
    return current, previous, current_bytes, previous_bytes


def proposed(current: dict, previous: dict | None) -> dict:
    return proposed_actions(current, analyze(current, previous))


def fresh_original_bytes(args: argparse.Namespace, current_bytes: bytes,
                         previous_bytes: bytes | None) -> None:
    """Refuse source edits even if they occurred while an operator was typing."""
    require(sha(private_read(args.current)) == sha(current_bytes),
            "Original PRIVATE source bytes changed during HUMAN operation")
    if args.previous is not None:
        require(previous_bytes is not None and
                sha(private_read(args.previous)) == sha(previous_bytes),
                "Earlier PRIVATE source bytes changed during HUMAN operation")


def make_session(current: dict, previous: dict | None, cbytes: bytes,
                 pbytes: bytes | None) -> dict:
    packet = proposed(current, previous)
    records = []
    for index, item in enumerate(packet["actions"], 1):
        records.append({"ordinal": index, "finding_id": item["finding_id"],
                        "local_sha256": item["local_sha256"],
                        "reasons": item["proposed_human_questions"],
                        "stage": "open", "human_note": "", "updated_utc": None})
    return {
        "kind": KIND, "schema_version": SCHEMA,
        "disposition": "UNVERIFIED_HUMAN_FOLLOWUP_ONLY",
        "source_packet_sha256": sha(cbytes),
        "previous_packet_sha256": sha(pbytes) if pbytes is not None else None,
        "proposal_sha256": sha(canonical(packet)),
        "source_sha256": current["source_sha256"],
        "client_reference": current["client_reference"],
        "engagement_reference": current["engagement_reference"],
        **{k: False for k in FLAGS},
        "records": records,
        "warning": "PRIVATE source-byte-bound HUMAN notes only. No original native Apply, evidence authenticity, grant, consent, signed identity, fix, or verified retest.",
    }


def admit_session(raw: bytes, expected: dict) -> dict:
    require(len(raw) <= 1024 * 1024, "PRIVATE session too large")
    try:
        session = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                             parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Hold("Malformed PRIVATE HUMAN review session") from exc
    require(type(session) is dict and set(session) == HEADER,
            "Unknown PRIVATE HUMAN review session fields")
    for k in (HEADER - {"records", "warning"}):
        require(session.get(k) == expected[k] and
                (k not in FLAGS or session[k] is False) and
                (k != "schema_version" or type(session[k]) is int),
                "PRIVATE HUMAN session no longer matches exact original source/proposal")
    require(type(session["warning"]) is str and
            session["warning"] == expected["warning"],
            "PRIVATE HUMAN session warning mismatch")
    items = session["records"]
    candidates = expected["records"]
    require(type(items) is list and len(items) == len(candidates),
            "PRIVATE HUMAN review actions incomplete or re-ordered")
    for index, row in enumerate(items):
        origin = candidates[index]
        require(type(row) is dict and set(row) == ITEM,
                "Unknown PRIVATE HUMAN record fields")
        for k in ("ordinal", "finding_id", "local_sha256", "reasons"):
            require(type(row[k]) is type(origin[k]) and row[k] == origin[k],
                    "Action is not bound to exact source/proposed question")
        require(type(row["ordinal"]) is int and row["ordinal"] == index + 1,
                "Noncanonical action ordinal")
        require(type(row["reasons"]) is list and
                all(type(x) is str and x in REASONS for x in row["reasons"]),
                "Unknown HUMAN question identity")
        require(type(row["stage"]) is str and row["stage"] in STAGES,
                "Invalid HUMAN-only stage")
        exact_human_note(row["human_note"], 1200, "PRIVATE HUMAN note")
        stamp = row["updated_utc"]
        require(stamp is None or (type(stamp) is str and len(stamp) <= 40 and
                stamp.endswith("Z")), "Invalid local HUMAN update timestamp")
        if stamp is not None:
            try:
                datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise Hold("Invalid HUMAN timestamp") from exc
    return session


def private_parent(path: Path) -> Path:
    require(path.is_absolute(), "Use absolute PRIVATE destination paths")
    parent = path.parent.resolve(strict=True)
    require(path.parent == parent and not path.is_symlink(),
            "PRIVATE destination must not use symlinked ancestors")
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            info.st_mode & 0o077 == 0,
            "PRIVATE session parent must be actual owner-only 0700 directory")
    return parent


@contextmanager
def single_host_lock(path: Path):
    private_parent(path)
    lockname = path.with_name(path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lockname, flags, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "HUMAN session lock must be one owner-private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def durable_replace(path: Path, payload: bytes) -> None:
    parent = private_parent(path)
    # Called only while holding the corresponding private single-host lock.
    require(path.exists() and path.is_file() and not path.is_symlink(),
            "Existing private HUMAN session missing or changed")
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_nlink == 1 and
            info.st_mode & 0o077 == 0, "Untrusted session output metadata")
    temp = parent / (".review-pending-" + secrets.token_hex(12))
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as dest:
            dest.write(payload)
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(temp, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp.unlink(missing_ok=True)


def anonymous(session: dict) -> dict:
    counts = Counter(row["stage"] for row in session["records"])
    return {
        "kind": "lightup.anonymous_private_human_evidence_triage_progress",
        "schema_version": 1,
        "disposition": "HUMAN_ONLY_NO_AUTHORITY",
        "local_proposed_actions": len(session["records"]),
        "stage_counts": {key: counts.get(key, 0) for key in STAGES},
        "requires_human_attention": sum(counts.get(k, 0) for k in STAGES[:-1]),
        "notice": "Self-declared local HUMAN review only; NOT verified remediation or permission.",
    }


def private_report(session: dict) -> bytes:
    e = lambda x: html.escape(str(x), quote=True)
    rows = []
    for row in session["records"]:
        why = ", ".join(row["reasons"])
        note = row["human_note"] or "(no note)"
        rows.append("<tr><td>" + str(row["ordinal"]) + "</td><td><code>" +
                    e(row["finding_id"]) + "</code></td><td><code>" +
                    e(row["local_sha256"]) + "</code></td><td>" + e(why) +
                    "</td><td>" + e(row["stage"]) + "</td><td>" + e(note) +
                    "</td></tr>")
    stats = anonymous(session)
    display_counts = " · ".join(k.replace("_", " ") + ": " + str(v)
                                for k, v in stats["stage_counts"].items())
    doc = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
           "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
           "style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'\">"
           "<meta name='viewport' content='width=device-width, initial-scale=1'>"
           "<title>LightUp PRIVATE HUMAN local evidence review</title>"
           "<style>body{font:16px system-ui;max-width:1200px;padding:1rem;margin:auto;"
           "background:#f5f6f8;color:#202738}table{width:100%;border-collapse:collapse;"
           "background:#fff}td,th{padding:.65rem;text-align:left;border:1px solid #ddd;"
           "overflow-wrap:anywhere}aside{background:#fff6e5;padding:1rem;border-left:4px solid #a70}"
           "code{overflow-wrap:anywhere}h1{font-size:1.8rem}</style><main>"
           "<h1>Local evidence relationship HUMAN inbox</h1><aside>"
           "<strong>DRAFT/HOLD · HUMAN ONLY.</strong> Private labels and file fingerprints are "
           "unverified source claims. Human stages/notes do not establish source authenticity, "
           "finding truth, independent reviewer identity, completed repair, client/operator "
           "consent, legal hold, native Apply, execution permission or signed release.</aside>"
           "<p>Self-declared client: " + e(session["client_reference"]) +
           " · engagement: " + e(session["engagement_reference"]) + "</p>"
           "<p>Original source claim SHA-256: <code>" + e(session["source_sha256"]) + "</code></p>"
           "<p>" + e(display_counts) + "</p><table><thead><tr><th>#</th>"
           "<th>Original finding</th><th>Local evidence fingerprint</th><th>Proposed HUMAN question</th>"
           "<th>HUMAN stage</th><th>PRIVATE note</th></tr></thead><tbody>" +
           "".join(rows) + "</tbody></table><p>No scan, grant, retest or automated action occurs."
           " Refresh with the original private source files and CLI, not browser storage.</p>"
           "</main></html>\n")
    return doc.encode("utf-8")


def run(args: argparse.Namespace) -> int:
    current, previous, cbytes, pbytes = selected_sources(args.current, args.previous)
    expected = make_session(current, previous, cbytes, pbytes)
    with single_host_lock(args.session):
        if args.action == "start":
            fresh_original_bytes(args, cbytes, pbytes)
            private_publish(args.session, canonical(expected))
            print("Created new source-byte-bound PRIVATE HUMAN session. Proposed actions: " +
                  str(len(expected["records"])) + ".")
            return 2
        session_bytes = private_read(args.session)
        session = admit_session(session_bytes, expected)
        if args.action == "status":
            print(json.dumps(anonymous(session), indent=2, sort_keys=True))
        elif args.action == "list":
            for row in session["records"]:
                print(str(row["ordinal"]) + " " + row["stage"] + " " +
                      row["finding_id"] + " " + row["local_sha256"] + " " +
                      ",".join(row["reasons"]))
            print("PRIVATE IDs shown locally; no authority claimed.")
        elif args.action == "mark":
            require(type(args.ordinal) is int and 1 <= args.ordinal <= len(session["records"]),
                    "Select an existing action ordinal from PRIVATE list")
            item = session["records"][args.ordinal - 1]
            if args.note_prompt:
                require(sys.stdin.isatty() and sys.stderr.isatty(),
                        "PRIVATE note prompts require an interactive terminal to prevent echo/log exposure")
                note = getpass.getpass("PRIVATE HUMAN note (never used as source evidence): ")
                exact_human_note(note, 1200, "PRIVATE HUMAN note")
                item["human_note"] = note
            if args.clear_note:
                item["human_note"] = ""
            item["stage"] = args.stage
            item["updated_utc"] = now_utc()
            fresh_original_bytes(args, cbytes, pbytes)
            require(private_read(args.session) == session_bytes,
                    "PRIVATE HUMAN session changed after read; reload to avoid lost edits")
            if args.backup_to is not None:
                from history import envelope
                private_publish(args.backup_to, canonical(envelope(expected, session_bytes)))
            durable_replace(args.session, canonical(session))
            print("PRIVATE HUMAN action " + str(args.ordinal) + " updated locally. No native Apply.")
        else:
            if args.action == "html":
                contents = private_report(session)
            elif args.action == "counts":
                contents = canonical(anonymous(session))
            else:
                contents = canonical(session)
            require(args.output is not None and args.output != args.session and
                    args.output != args.current and args.output != args.previous,
                    "Export must have a new separate PRIVATE output destination")
            fresh_original_bytes(args, cbytes, pbytes)
            require(private_read(args.session) == session_bytes,
                    "PRIVATE HUMAN session changed after read; reload before export")
            private_publish(args.output, contents)
            print("PRIVATE HUMAN-only " + args.action + " published; original unchanged.")
    return 2


def main() -> int:
    p = argparse.ArgumentParser(description="Offline persistent PRIVATE HUMAN-only evidence follow-up inbox")
    p.add_argument("action", choices=("start", "status", "list", "mark", "html", "counts", "handoff"))
    p.add_argument("--current", type=Path, required=True, help="Original PRIVATE JSON (0600)")
    p.add_argument("--previous", type=Path, help="Optional earlier same-source PRIVATE JSON (0600)")
    p.add_argument("--session", type=Path, required=True, help="PRIVATE local state JSON (0600)")
    p.add_argument("--output", type=Path, help="New PRIVATE report output (not for status/list/mark)")
    p.add_argument("--backup-to", type=Path,
                   help="Optional exclusive 0600 previous HUMAN checkpoint before mark")
    p.add_argument("--ordinal", type=int, help="1-based item index for mark")
    p.add_argument("--stage", choices=STAGES, help="New HUMAN-only stage for mark")
    notes = p.add_mutually_exclusive_group()
    notes.add_argument("--note-prompt", action="store_true", help="Secure prompt, not shell history")
    notes.add_argument("--clear-note", action="store_true")
    args = p.parse_args()
    try:
        require((args.action in ("html", "counts", "handoff")) == (args.output is not None),
                "--output only with html/counts/handoff")
        require((args.action == "mark") == (args.ordinal is not None and args.stage is not None),
                "mark requires --ordinal and --stage")
        require(args.action == "mark" or (not args.note_prompt and not args.clear_note),
                "PRIVATE note options only apply to mark")
        require(args.action == "mark" or args.backup_to is None,
                "Only mark accepts an optional PRIVATE HUMAN checkpoint")
        if args.backup_to is not None:
            require(args.backup_to not in
                    (args.current, args.previous, args.session, args.output),
                    "New PRIVATE checkpoint must not replace a source, session or export")
        return run(args)
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
