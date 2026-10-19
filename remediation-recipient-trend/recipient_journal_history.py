#!/usr/bin/env python3
"""Native PRIVATE HUMAN reason decision history, for the SAME exact source receipt.

Only local human stage/route/note-changed bool differences; no original case IDs,
note contents, evidence bytes, grant or customer identity in output.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import os
from pathlib import Path
import stat
import sys

import recipient_journal as journal
import recipient_journal_receive as receiver

review = journal.review
workspace = journal.workspace
verify = journal.verify
board = journal.board
triage = journal.triage
read_cockpit = journal.recipient_studio.trend.read_cockpit

KIND = "lightup.private_recipient_human_reason_local_changes"
WARNING = (
    "PRIVATE unsigned HUMAN follow-up difference only. Two local journals must "
    "share exactly one originally self-declared source-free report fingerprint. "
    "Operator-selected before/after order is NOT authenticated time. Changes in "
    "HUMAN stage, route or notes never prove a fix, new issue, consent or retest."
)
OUTPUTS = frozenset(("index.html", "private-changes.csv", "summary.json",
                     "anonymous-counts.json", "manifest.json"))
REPORT_KEYS = frozenset(("kind", "schema_version", "disposition", "warning",
                         "reason_groups", "changed_stage", "changed_route",
                         "changed_note", "rows", *review.FLAGS))
ROW_KEYS = frozenset(("reason", "before_stage", "after_stage",
                      "before_route", "after_route", "note_changed"))
MANIFEST_KEYS = frozenset(("kind", "schema_version", "disposition",
                           "warning", "files", *review.FLAGS))


def make_report(before: dict, after: dict) -> dict:
    review.require(before["source_sha256"] == after["source_sha256"] and
                   len(before["entries"]) == len(after["entries"]) and
                   all(a["reason"] == b["reason"] and a["count"] == b["count"] and
                       a["delta"] == b["delta"]
                       for a, b in zip(before["entries"], after["entries"])),
                   "Original source/count/delta membership changed: not one HUMAN workflow")
    rows = [{
        "reason": a["reason"],
        "before_stage": a["stage"], "after_stage": b["stage"],
        "before_route": a["route"], "after_route": b["route"],
        "note_changed": a["note"] != b["note"],
    } for a, b in zip(before["entries"], after["entries"])]
    return {
        "kind": KIND, "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "reason_groups": len(rows),
        "changed_stage": sum(r["before_stage"] != r["after_stage"] for r in rows),
        "changed_route": sum(r["before_route"] != r["after_route"] for r in rows),
        "changed_note": sum(r["note_changed"] for r in rows),
        "rows": rows,
    }


def admit_report(data: object) -> dict:
    review.require(type(data) is dict and set(data) == REPORT_KEYS and
                   data.get("kind") == KIND and
                   type(data.get("schema_version")) is int and
                   data["schema_version"] == 1 and
                   data.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   data.get("warning") == WARNING and
                   all(data.get(flag) is False for flag in review.FLAGS),
                   "Unknown recipient HUMAN comparison authority/schema")
    rows = data.get("rows")
    expected = sorted(triage.REASONS)
    review.require(type(rows) is list and len(rows) == len(expected) and
                   type(data.get("reason_groups")) is int and
                   data["reason_groups"] == len(rows),
                   "Incomplete or ambiguous original HUMAN reason group comparison")
    stage_changes = route_changes = note_changes = 0
    for reason, row in zip(expected, rows):
        review.require(type(row) is dict and set(row) == ROW_KEYS and
                       type(row.get("reason")) is str and row["reason"] == reason and
                       type(row.get("before_stage")) is str and
                       row["before_stage"] in journal.STAGES and
                       type(row.get("after_stage")) is str and
                       row["after_stage"] in journal.STAGES and
                       type(row.get("before_route")) is str and
                       row["before_route"] in journal.ROUTES and
                       type(row.get("after_route")) is str and
                       row["after_route"] in journal.ROUTES and
                       type(row.get("note_changed")) is bool,
                       "Noncanonical native HUMAN local before/after")
        stage_changes += row["before_stage"] != row["after_stage"]
        route_changes += row["before_route"] != row["after_route"]
        note_changes += row["note_changed"]
    review.require(all(type(data[key]) is int for key in
                       ("changed_stage", "changed_route", "changed_note")) and
                   data["changed_stage"] == stage_changes and
                   data["changed_route"] == route_changes and
                   data["changed_note"] == note_changes,
                   "Private HUMAN update totals disagree with original rows")
    return data


def anonymous(data: dict) -> dict:
    return {
        "kind": KIND + ".anonymous",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "reason_groups_not_original_cases": data["reason_groups"],
        "human_stage_groups_changed": data["changed_stage"],
        "human_route_groups_changed": data["changed_route"],
        "private_note_groups_changed_without_text": data["changed_note"],
    }


def render(data: dict) -> bytes:
    markup = []
    for row in data["rows"]:
        changed = (row["before_stage"] != row["after_stage"] or
                   row["before_route"] != row["after_route"] or
                   row["note_changed"])
        if not changed:
            continue
        markup.append(
            "<tr><th scope='row'>" + html.escape(row["reason"]) + "</th>"
            "<td>" + html.escape(row["before_stage"]) + " → " +
            html.escape(row["after_stage"]) + "</td>"
            "<td>" + html.escape(row["before_route"]) + " → " +
            html.escape(row["after_route"]) + "</td>"
            "<td>" + ("yes" if row["note_changed"] else "no") + "</td></tr>")
    if not markup:
        markup.append("<tr><td colspan='4'>No local HUMAN changes recorded. "
                      "This is not a security verdict.</td></tr>")
    body = ("<section><h2>Same claimed source-free recipient snapshot</h2>"
            "<p>Comparison requires equal exact original local source-fingerprint "
            "AND equal unchanged HUMAN reason identity, counts and arithmetic. "
            "Operator-chosen before/after is not authenticated chronology.</p>"
            "<p><strong>" + str(data["changed_stage"]) + "</strong> HUMAN stages, "
            "<strong>" + str(data["changed_route"]) + "</strong> proposed routes, "
            "<strong>" + str(data["changed_note"]) + "</strong> PRIVATE notes changed "
            "(no note contents copied).</p>"
            "<table><thead><tr><th>Human reason</th><th>Stage before → after</th>"
            "<th>Route before → after</th><th>Note changed</th></tr></thead>"
            "<tbody>" + "".join(markup) + "</tbody></table></section>")
    return board.shell(body, "LightUp PRIVATE HUMAN Follow-up Changes")


def csv_view(data: dict) -> bytes:
    out = io.StringIO(newline="")
    csv_writer = csv.writer(out, lineterminator="\n")
    csv_writer.writerow(("reason", "before_stage", "after_stage",
                         "before_route", "after_route", "note_changed"))
    for row in data["rows"]:
        csv_writer.writerow((row["reason"], row["before_stage"], row["after_stage"],
                             row["before_route"], row["after_route"],
                             "yes" if row["note_changed"] else "no"))
    return out.getvalue().encode("utf-8")


def artifacts(data: dict) -> dict[str, bytes]:
    return {"index.html": render(data),
            "summary.json": workspace.pretty(data),
            "anonymous-counts.json": workspace.pretty(anonymous(data)),
            "private-changes.csv": csv_view(data)}


def original_record(path: Path) -> tuple[dict, bytes]:
    receiver.inspect(path)
    raw = review.private_read(path / "journal.json")
    data = receiver.original_local_journal(verify.json_obj(raw))
    review.require(raw == workspace.pretty(data),
                   "Original private HUMAN follow-up JSON must be canonical")
    return data, raw


def publish(before_dir: Path, after_dir: Path, output: Path) -> dict:
    review.require(before_dir != after_dir and output.is_absolute() and
                   all(output != path and path not in output.parents and
                       output not in path.parents and output.parent != path
                       for path in (before_dir, after_dir)),
                   "Human change report cannot alter original private source")
    triage.private_parent(output)
    before, before_raw = original_record(before_dir)
    after, after_raw = original_record(after_dir)
    review.require(before_raw != after_raw,
                   "Identical HUMAN journals are not a new local change")
    data = admit_report(make_report(before, after))
    files = artifacts(data)
    manifest = {
        "kind": KIND + ".local_receipt",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "files": {name: {"bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()}
                  for name, raw in sorted(files.items())},
    }
    for path, original in ((before_dir, before_raw), (after_dir, after_raw)):
        _, now = original_record(path)
        review.require(now == original, "PRIVATE HUMAN journal changed during review")
    workspace.publish_bundle(output, files, workspace.pretty(manifest))
    return {"human_reason_groups": data["reason_groups"],
            "local_changed_stage": data["changed_stage"],
            "local_changed_route": data["changed_route"],
            "private_note_changes": data["changed_note"]}


def inspect(folder: Path) -> dict:
    review.require(folder.is_absolute() and not folder.is_symlink() and
                   folder.parent == folder.parent.resolve(strict=True),
                   "PRIVATE HUMAN change receipt must use a literal owner directory")
    mode = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0 and
                   {p.name for p in folder.iterdir()} == OUTPUTS,
                   "HUMAN change receipt is shared, incomplete or oversized")
    mraw = review.private_read(folder / "manifest.json")
    m = verify.json_obj(mraw)
    review.require(type(m) is dict and set(m) == MANIFEST_KEYS and
                   m.get("kind") == KIND + ".local_receipt" and
                   type(m.get("schema_version")) is int and m["schema_version"] == 1 and
                   m.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   m.get("warning") == WARNING and
                   all(m.get(flag) is False for flag in review.FLAGS) and
                   type(m.get("files")) is dict and
                   set(m["files"]) == OUTPUTS - {"manifest.json"} and
                   mraw == workspace.pretty(m),
                   "Noncanonical original HUMAN change manifest")
    contents = {}
    for name in sorted(OUTPUTS - {"manifest.json"}):
        info = m["files"][name]
        review.require(type(info) is dict and set(info) == {"bytes", "sha256"} and
                       type(info.get("sha256")) is str and
                       review.HEX.fullmatch(info["sha256"]) is not None,
                       "Invalid human change report file SHA")
        size = read_cockpit.nonnegative(info.get("bytes"),
                                       "PRIVATE local change", verify.MAX_BYTES)
        contents[name] = review.private_read(folder / name)
        review.require(len(contents[name]) == size and
                       hashlib.sha256(contents[name]).hexdigest() == info["sha256"],
                       "Local HUMAN change output altered")
    data = admit_report(verify.json_obj(contents["summary.json"]))
    review.require(contents == artifacts(data),
                   "HUMAN change summary, HTML or CSV not native byte-identical")
    review.require(review.private_read(folder / "manifest.json") == mraw,
                   "Local HUMAN change receipt changed during reopen")
    for name, previous in contents.items():
        review.require(review.private_read(folder / name) == previous,
                       "Private HUMAN change file replaced during reopen")
    return {"reason_groups": len(data["rows"]),
            "changed_stage": data["changed_stage"],
            "changed_route": data["changed_route"],
            "changed_notes": data["changed_note"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "PRIVATE local original-source-bound HUMAN follow-up differences, "
        "no evidence, note text, native Apply, fix or consent"))
    mode = parser.add_subparsers(dest="action", required=True)
    p = mode.add_parser("create", help="Create new PRIVATE HUMAN decision differences")
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p = mode.add_parser("reopen", help="Inspect native local HUMAN difference receipt")
    p.add_argument("--folder", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = (publish(args.before, args.after, args.output_dir)
                if args.action == "create" else inspect(args.folder))
        print("REVIEW_ONLY: private local HUMAN reason changes available; " +
              str(data.get("changed_stage", data.get("local_changed_stage", 0))) +
              " stage changes. Not authenticated chronology/verified remediation.")
        return 2
    except (review.Hold, OSError, UnicodeError, ValueError):
        print("HOLD: original PRIVATE HUMAN source or change receipt invalid.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
