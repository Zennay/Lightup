#!/usr/bin/env python3
"""Owner-private, self-reported HUMAN lab route receive/reopen/history.

Never opens assessment sources or assigns any execution, scope or consent authority.
This consumer deliberately only admits the 20 fixed, source-free browser markers.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from operator_navigation import ACTIONS, LAB_STAGES

SCHEMA = "lightup.private.human-lab-route.self-report.v1"
RECEIPT = "lightup.private.human-lab-route.receipt.v1"
HISTORY = "lightup.private.human-lab-route.history.v1"
STATES = frozenset(("NOT_REVIEWED", "IN_PROGRESS", "NEEDS_INPUT", "DISCUSSED"))
ORDER = tuple(range(52, 72))
FALSE_AUTH = {
    "scan_authorized": False,
    "grant_authorized": False,
    "consent_verified": False,
    "human_go": False,
}
ORIGINAL = "PRIVATE-ORIGINAL-SELF-REPORT.json"
REPORT = "PRIVATE-ROUTE.json"
CSV = "PRIVATE-ROUTE.csv"
HTML = "OPEN-PRIVATE.html"
RECEIPT_FILE = "PRIVATE-RECEIPT.json"
MAX_INPUT = 24576
SOURCE_CHECKOUT = Path(__file__).resolve().parent.parent

class Hold(Exception):
    """Reject entire owner-private operation; never issue a partial receipt."""


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("HOLD: duplicate JSON property")
        result[key] = value
    return result


def _parse(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              Hold("HOLD: invalid JSON numeric value")))
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise Hold("HOLD: JSON is not canonical readable data") from None


def _private_dir(path: Path) -> Path:
    if not path.is_absolute():
        raise Hold("HOLD: choose an absolute owner-private directory")
    try:
        # Never admit through an ancestor symlink, or store private material
        # inside the checked-out source tree where it might be committed.
        resolved = path.resolve(strict=True)
        if (resolved != path or resolved == SOURCE_CHECKOUT
                or SOURCE_CHECKOUT in resolved.parents):
            raise Hold("HOLD: owner-private room cannot be in checkout or via link")
        meta = path.lstat()
    except OSError:
        raise Hold("HOLD: owner-private directory is absent") from None
    if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
        raise Hold("HOLD: no symbolic links or special directories")
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o077:
        raise Hold("HOLD: directory must be owned by you and mode 0700")
    return path


def _read(path: Path, limit: int) -> bytes:
    if path.name in ("", ".", "..") or not path.is_absolute():
        raise Hold("HOLD: absolute owner-private input file required")
    _private_dir(path.parent)
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o077
                or not 0 < before.st_size <= limit):
            raise Hold("HOLD: private input must be 0600, ordinary and bounded")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                    before.st_dev, before.st_ino, before.st_size):
                raise Hold("HOLD: private input changed during admission")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read(limit + 1)
            if len(data) != before.st_size:
                raise Hold("HOLD: private input changed or exceeded its ceiling")
            return data
        finally:
            os.close(fd)
    except Hold:
        raise
    except OSError:
        raise Hold("HOLD: private input cannot be read") from None


def _exact(value: object, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def _admit(raw: bytes) -> tuple[str, ...]:
    if not 0 < len(raw) <= MAX_INPUT:
        raise Hold("HOLD: self-report bytes exceed 24 KiB")
    report = _parse(raw)
    if not _exact(report, {
            "schema", "mode", "authority", "verified_original_source",
            "source_files_included", "private_notes_included", "steps"}):
        raise Hold("HOLD: unknown/missing self-report fields")
    if (report["schema"] != SCHEMA or report["mode"] != "REVIEW_ONLY"
            or report["verified_original_source"] is not False
            or report["source_files_included"] is not False
            or report["private_notes_included"] is not False
            or not _exact(report["authority"], set(FALSE_AUTH))
            or any(report["authority"][key] is not False for key in FALSE_AUTH)):
        raise Hold("HOLD: self-report attempted an authority or source claim")
    items = report["steps"]
    if type(items) is not list or len(items) != len(ORDER):
        raise Hold("HOLD: every original LAB option must occur once")
    result = []
    for expected, row in zip(ORDER, items):
        if (not _exact(row, {"action", "self_reported_state"})
                or type(row["action"]) is not int or row["action"] != expected
                or type(row["self_reported_state"]) is not str
                or row["self_reported_state"] not in STATES):
            raise Hold("HOLD: altered, missing or reordered HUMAN review marker")
        result.append(row["self_reported_state"])
    return tuple(result)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def _canonical(states: tuple[str, ...]) -> bytes:
    return _json({"schema": SCHEMA, "mode": "REVIEW_ONLY",
                  "authority": dict(FALSE_AUTH),
                  "verified_original_source": False,
                  "source_files_included": False,
                  "private_notes_included": False,
                  "steps": [{"action": option, "self_reported_state": state}
                            for option, state in zip(ORDER, states)]})


def _csv(rows: list[list[object]]) -> bytes:
    file = io.StringIO(newline="")
    writer = csv.writer(file, lineterminator="\r\n")
    writer.writerows(rows)
    return file.getvalue().encode("utf-8")


def _page(states: tuple[str, ...]) -> bytes:
    sections = []
    for title, _, options, _ in LAB_STAGES:
        lines = "".join(
            "<tr><th scope='row'>" + html.escape(option) + "</th><td>" +
            html.escape(ACTIONS[option]) + "</td><td>" +
            html.escape(states[int(option) - 52]) + "</td></tr>"
            for option in options)
        sections.append("<section><h2>" + html.escape(title) +
                        "</h2><table><thead><tr><th>Action</th><th>Original HUMAN task</th>" +
                        "<th>Self-report only</th></tr></thead><tbody>" + lines +
                        "</tbody></table></section>")
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';script-src 'none';connect-src 'none';base-uri 'none';form-action 'none'">
<title>LightUp PRIVATE HUMAN LAB receipt</title>
<style>:root{color-scheme:dark;background:#101e30;color:#edf7ff;font:16px/1.5 system-ui}
body{max-width:1040px;margin:auto;padding:24px}header,section,footer{padding:22px;margin:15px 0;border-radius:15px;border:1px solid #55738a;background:#203347}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #5b7184}
strong{color:#ffdb9e}</style></head><body><header>
<strong>PRIVATE · REVIEW_ONLY · HUMAN self-report · DRAFT/HOLD</strong>
<h1>Offline human lab discussion receipt</h1>
<p>Only the 20 fixed browser status markers have been received. This is
NOT original source admission, execution proof, vulnerability verification,
client/operator authentication, actual consent, approval, or a release.</p></header>""" +
            "".join(sections) +
            """<footer><strong>All real authority flags remain false.</strong>
<p>Original owner review, privacy/security/browser signoff, permanent
CI, independent current authenticated consent and revocation at use,
and explicit HUMAN GO remain mandatory. No targets, network,
scanner, grants, dispatch or production deployment are performed.
“Discussed” does not mean a security problem was fixed.</p>
</footer></body></html>""").encode("utf-8")


def _build_files(raw: bytes, states: tuple[str, ...]) -> dict[str, bytes]:
    csv_rows = [["action", "self_reported_state", "authority"]] + [
        [option, state, "REVIEW_ONLY"] for option, state in zip(ORDER, states)]
    return {
        ORIGINAL: raw, REPORT: _canonical(states), CSV: _csv(csv_rows),
        HTML: _page(states),
    }


def _receipt(raw: bytes, generated: dict[str, bytes]) -> bytes:
    return _json({
        "schema": RECEIPT, "mode": "REVIEW_ONLY",
        "self_report_source_sha256_unsigned": _digest(raw),
        "self_report_source_bytes": len(raw),
        "verified_original_source": False, "consent_verified": False,
        "source_authenticated": False, "finding_verified": False,
        "scan_authorized": False, "release_allowed": False,
        "human_go": False,
        "files": {name: {"bytes": len(data), "sha256_unsigned": _digest(data)}
                  for name, data in sorted(generated.items())},
    })


def _write_room(parent: str, folder: str, files: dict[str, bytes]) -> Path:
    base = _private_dir(Path(parent))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", folder):
        raise Hold("HOLD: choose a new simple folder name (max 64 characters)")
    target = base / folder
    try:
        target.mkdir(mode=0o700)
    except OSError:
        raise Hold("HOLD: output room exists or is unavailable") from None
    complete = False
    try:
        for name, contents in files.items():
            if "/" in name or name in (".", ".."):
                raise Hold("HOLD: invalid output file name")
            fd = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
        complete = True
        return target
    finally:
        if not complete:
            shutil.rmtree(target)


def receive(source: str, parent: str, folder: str) -> Path:
    raw = _read(Path(source), MAX_INPUT)
    states = _admit(raw)
    generated = _build_files(raw, states)
    return _write_room(parent, folder, {
        **generated, RECEIPT_FILE: _receipt(raw, generated),
    })


def reopen(room: str) -> tuple[str, ...]:
    source = _private_dir(Path(room))
    raw = _read(source / ORIGINAL, MAX_INPUT)
    states = _admit(raw)
    expected = _build_files(raw, states)
    expected[RECEIPT_FILE] = _receipt(raw, expected)
    for name, data in expected.items():
        if _read(source / name, 262144) != data:
            raise Hold("HOLD: original HUMAN receipt or output bytes changed")
    if set(os.listdir(source)) != set(expected):
        raise Hold("HOLD: unexpected original HUMAN room entries")
    return states


def _history_files(rooms: list[str]) -> dict[str, bytes]:
    if not 2 <= len(rooms) <= 8 or len({Path(room).resolve() for room in rooms}) != len(rooms):
        raise Hold("HOLD: choose two to eight distinct original saved HUMAN rooms")
    states = [reopen(room) for room in rooms]
    changed = []
    for round_no in range(2, len(states) + 1):
        old, current = states[round_no - 2:round_no]
        for action, before, after in zip(ORDER, old, current):
            if before != after:
                changed.append({
                    "declared_round": round_no, "action": action,
                    "before": before, "after": after,
                })
    counts = [
        {"declared_round": no, **{key: state.count(key) for key in sorted(STATES)}}
        for no, state in enumerate(states, 1)
    ]
    # Human coordination view: repeated self-report flags are not proof of elapsed
    # time, execution status, an actual assignment, or a validated issue.
    attention = []
    for index, action in enumerate(ORDER):
        latest = states[-1][index]
        if latest == "DISCUSSED":
            continue
        unchanged_rounds = 0
        for previous in reversed(states):
            if previous[index] != latest:
                break
            unchanged_rounds += 1
        attention.append({
            "action": action, "caption": ACTIONS[str(action)],
            "latest_self_reported_state": latest,
            "consecutive_operator_ordered_rounds": unchanged_rounds,
        })
    phase_summary = []
    for title, _, options, _ in LAB_STAGES:
        values = [states[-1][int(option) - ORDER[0]] for option in options]
        phase_summary.append({
            "stage": title,
            "discussed_only": values.count("DISCUSSED"),
            "needs_original_input": values.count("NEEDS_INPUT"),
            "in_discussion": values.count("IN_PROGRESS"),
            "not_reviewed": values.count("NOT_REVIEWED"),
        })
    attention_html = "".join(
        "<tr><td>" + str(row["action"]) + "</td><td>" +
        html.escape(row["caption"]) + "</td><td>" +
        html.escape(row["latest_self_reported_state"]) + "</td><td>" +
        str(row["consecutive_operator_ordered_rounds"]) + "</td></tr>"
        for row in attention)
    stage_html = "".join(
        "<tr><th scope='row'>" + html.escape(row["stage"]) + "</th><td>" +
        str(row["needs_original_input"]) + "</td><td>" +
        str(row["in_discussion"]) + "</td><td>" +
        str(row["not_reviewed"]) + "</td><td>" +
        str(row["discussed_only"]) + "</td></tr>"
        for row in phase_summary)
    body = "".join(
        "<tr><td>" + str(row["declared_round"]) + "</td><td>" +
        str(row["action"]) + "</td><td>" + html.escape(row["before"]) +
        "</td><td>" + html.escape(row["after"]) + "</td></tr>"
        for row in changed)
    markup = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';script-src 'none'">
<title>PRIVATE HUMAN Lab discussion change history</title>
<style>:root{color-scheme:dark;background:#112339;color:#eff7ff;font:16px/1.55 system-ui}
body{max-width:1000px;margin:auto;padding:26px}table{width:100%}
td,th{text-align:left;padding:10px;border-bottom:1px solid #6a8195}</style>
<h1>PRIVATE HUMAN Lab status changes</h1><p>REVIEW_ONLY / DRAFT/HOLD.
Order of manually supplied rounds is NOT proven chronology. Each room was
re-admitted against its self-reported browser source bytes only.
Changed discussion markers are NOT verified fixes or security outcomes.</p>
<table><thead><tr><th>Human-supplied round</th><th>Action</th>
<th>Previous marker</th><th>New marker</th></tr></thead><tbody>""" +
              (body or "<tr><td colspan='4'>No self-reported marker changes. Nothing verified.</td></tr>") +
              """</tbody></table>
<h2>Latest HUMAN discussion attention, never verified completion</h2>
<p>Counts describe the last OPERATOR-ORDERED local self-report only.
An unchanged flag across multiple supplied rounds is NOT proven aging,
a missed deadline or authenticated work ownership.</p>
<table><thead><tr><th>Action</th><th>Human task</th>
<th>Declared status</th><th>Consecutive supplied rounds</th>
</tr></thead><tbody>""" +
              (attention_html or "<tr><td colspan='4'>Nothing awaiting discussion in these self-reports. No authorization implied.</td></tr>") +
              """</tbody></table>
<h2>Latest discussion stage overview</h2>
<table><thead><tr><th>Stage</th><th>Needs input</th>
<th>Discussing</th><th>Not reviewed</th><th>Discussed only</th>
</tr></thead><tbody>""" + stage_html +
              """</tbody></table>
<p>No scan, grant, consent, release, actor verification,
original assessment source reading, external transfer, or HUMAN GO.</p>""").encode("utf-8")
    summary = _json({"schema": HISTORY, "mode": "REVIEW_ONLY",
                     "authority": dict(FALSE_AUTH),
                     "rounds_are_authenticated": False,
                     "rounds_are_proven_chronological": False,
                     "discussion_change_is_verified_fix": False,
                     "counts": counts, "changed": changed,
                     "attention": attention, "latest_stage_summary": phase_summary})
    table = _csv([["declared_round", "action", "before", "after"]] + [
        [r["declared_round"], r["action"], r["before"], r["after"]]
        for r in changed])
    return {
        "OPEN-PRIVATE.html": markup,
        "PRIVATE-HUMAN-HISTORY.json": summary,
        "PRIVATE-HUMAN-HISTORY.csv": table,
        "PRIVATE-HUMAN-ATTENTION.csv": _csv(
            [["action", "human_task", "latest_self_reported_state",
              "consecutive_operator_ordered_rounds"]] + [
                [row["action"], row["caption"], row["latest_self_reported_state"],
                 row["consecutive_operator_ordered_rounds"]] for row in attention]),
    }


HISTORY_RECEIPT = "PRIVATE-HUMAN-HISTORY-RECEIPT.json"


def _complete_history_files(rooms: list[str]) -> dict[str, bytes]:
    """Re-admit each original room before constructing deterministic outputs."""
    files = _history_files(rooms)
    receipts = [_read(Path(room) / RECEIPT_FILE, 262144) for room in rooms]
    files[HISTORY_RECEIPT] = _json({
        "schema": "lightup.private.human-lab-route.history.receipt.v1",
        "mode": "REVIEW_ONLY", "authority": dict(FALSE_AUTH),
        "original_round_receipts_sha256_unsigned": [_digest(r) for r in receipts],
        "rounds_proven_chronological": False,
        "original_client_source_authenticated": False,
        "finding_verified": False, "consent_verified": False,
        "release_allowed": False,
        "files": {name: {"bytes": len(data), "sha256_unsigned": _digest(data)}
                  for name, data in sorted(files.items())},
    })
    return files


def history(rooms: list[str], parent: str, folder: str) -> Path:
    base = _private_dir(Path(parent))
    # A history output must never modify any original admitted receipt room:
    # even an innocuous new nested directory would change the original inventory.
    for room in rooms:
        origin = _private_dir(Path(room))
        if base == origin or origin in base.parents:
            raise Hold("HOLD: new history must be OUTSIDE original HUMAN rooms")
    files = _complete_history_files(rooms)
    return _write_room(parent, folder, files)


def reopen_history(rooms: list[str], saved_history: str) -> None:
    old = _private_dir(Path(saved_history))
    originals = [_private_dir(Path(room)) for room in rooms]
    if any(old == origin or old in origin.parents for origin in originals):
        raise Hold("HOLD: history cannot replace or contain original receipts")
    expected = _complete_history_files(rooms)
    for name, data in expected.items():
        if _read(old / name, 262144) != data:
            raise Hold("HOLD: saved HUMAN history changed from original review rooms")
    if set(os.listdir(old)) != set(expected):
        raise Hold("HOLD: unexpected saved HUMAN history entries")


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE HUMAN-only Lab route, no live authority")
    commands = parser.add_subparsers(dest="cmd", required=True)
    a = commands.add_parser("receive", help="Receive and seal one owner-private browser self-report")
    a.add_argument("--self-report", required=True)
    a.add_argument("--private-parent", required=True)
    a.add_argument("--folder", required=True)
    b = commands.add_parser("reopen", help="Reopen original exact-byte HUMAN self-report room")
    b.add_argument("--room", required=True)
    c = commands.add_parser("history", help="Compare 2-8 original self-report rooms, manually ordered")
    c.add_argument("--rooms", nargs="+", required=True)
    c.add_argument("--private-parent", required=True)
    c.add_argument("--folder", required=True)
    d = commands.add_parser("reopen-history",
                            help="Re-admit original self-report rooms and exact saved history bytes")
    d.add_argument("--rooms", nargs="+", required=True)
    d.add_argument("--history-room", required=True)
    args = parser.parse_args()
    try:
        if args.cmd == "receive":
            target = receive(args.self_report, args.private_parent, args.folder)
            print("PRIVATE REVIEW_ONLY: original self-report accepted, NOT authenticated.")
            print("OPEN LOCALLY: " + str(target / HTML))
        elif args.cmd == "reopen":
            s = reopen(args.room)
            print("PRIVATE REVIEW_ONLY: original browser and output bytes unchanged.")
            print("Self-reported discussion markers: " + str(s.count("DISCUSSED")))
        elif args.cmd == "history":
            target = history(args.rooms, args.private_parent, args.folder)
            print("PRIVATE REVIEW_ONLY: HUMAN self-report history created, no source proof.")
            print("OPEN LOCALLY: " + str(target / HTML))
        else:
            reopen_history(args.rooms, args.history_room)
            print("PRIVATE REVIEW_ONLY: original source-free HUMAN history bytes unchanged.")
            print("No actor identity, chronology, real source, consent or fix authenticated.")
        return 2
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: private HUMAN route operation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
