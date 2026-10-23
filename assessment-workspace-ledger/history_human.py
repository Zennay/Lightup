#!/usr/bin/env python3
"""Original-ledger-chain-bound HUMAN decision packet for offline historical kit drift.

Explicit input only. No scan, original-kit read, source authentication or grants.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from history import load_history, summarize
from ledger import (
    FLAGS, Hold, STAGES, canonical, digest, html_page, new_private,
    read_owner_file, reject, safe_human, write_private,
)

MAX_PLAN = 192 * 1024
HEADERS = (
    "transition", "from_ledger_sha256", "to_ledger_sha256", "kit_ordinal",
    "to_kit_digest", "label_changed", "added", "removed", "changed",
    "unchanged", "human_stage", "human_owner", "human_question",
)


def expected_rows(sources, transitions):
    rows = []
    for step in transitions:
        kit_source = sources[step["transition"]]["doc"]["kits"]
        for item, kit in zip(step["kits"], kit_source):
            if item["ordinal"] != kit["ordinal"]:
                reject("PRIVATE HOLD: mismatch in original kit ordinal")
            rows.append({
                "transition": str(step["transition"]),
                "from_ledger_sha256": step["from_sha256"],
                "to_ledger_sha256": step["to_sha256"],
                "kit_ordinal": str(item["ordinal"]),
                "to_kit_digest": kit["digest"],
                "label_changed": str(int(item["label_changed"])),
                "added": str(item["added_file_count"]),
                "removed": str(item["removed_file_count"]),
                "changed": str(item["changed_file_count"]),
                "unchanged": str(item["unchanged_file_count"]),
                "human_stage": "needs_review",
                "human_owner": "",
                "human_question": "",
            })
    return rows


def encode_csv(rows):
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=HEADERS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


def read_browser_csv(path):
    """Read explicitly selected browser Downloads without following symlinks.

    Original possibly public-readable Downloads are NOT changed; privacy cannot
    be retroactively restored. This is a bounded normal file read only.
    """
    p = Path(path)
    if not p.is_absolute() or not re.fullmatch(
        r"HUMAN-history-review(?: ?\([1-9][0-9]{0,3}\))?\.csv", p.name
    ):
        reject("PRIVATE HOLD: choose absolute original HUMAN-history-review.csv download")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_PLAN):
            reject("PRIVATE HOLD: browser plan must be current-user regular single-link bounded file")
        chunks, amount = [], 0
        while True:
            piece = os.read(fd, 32768)
            if not piece:
                break
            amount += len(piece)
            if amount > MAX_PLAN:
                reject("PRIVATE HOLD: browser CSV exceeds explicit byte limit")
            chunks.append(piece)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns, after.st_ctime_ns) or amount != before.st_size):
            reject("PRIVATE HOLD: browser CSV changed during chosen read")
        return b"".join(chunks), bool(before.st_mode & 0o077)
    finally:
        os.close(fd)


def parse_plan(data, expected):
    if not data or len(data) > MAX_PLAN:
        reject("PRIVATE HOLD: empty or oversized HUMAN historical plan")
    try:
        decoded = data.decode("utf-8", errors="strict")
        if "\x00" in decoded or "\r" in decoded:
            reject("PRIVATE HOLD: historical CSV invalid newline/control")
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != HEADERS:
            reject("PRIVATE HOLD: wrong historical HUMAN CSV columns")
        actual = list(reader)
    except (UnicodeError, csv.Error, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: invalid historical HUMAN CSV") from exc
    if len(actual) != len(expected):
        reject("PRIVATE HOLD: expected one original source-bound HUMAN row per kit/transition")
    rows = []
    original_keys = HEADERS[:10]
    for row, reference in zip(actual, expected):
        if None in row or set(row) != set(HEADERS) or any(row[key] != reference[key] for key in original_keys):
            reject("PRIVATE HOLD: HUMAN row/source binding or source-count mismatch")
        if row["human_stage"] not in STAGES:
            reject("PRIVATE HOLD: unknown HUMAN status")
        owner = safe_human(row["human_owner"], 80)
        question = safe_human(row["human_question"], 500)
        if any("\n" in x or "\t" in x for x in (owner, question)):
            reject("PRIVATE HOLD: multiline HUMAN details refused")
        rows.append({
            "transition": int(reference["transition"]),
            "kit_ordinal": int(reference["kit_ordinal"]),
            "from_ledger_sha256": reference["from_ledger_sha256"],
            "to_ledger_sha256": reference["to_ledger_sha256"],
            "to_kit_digest": reference["to_kit_digest"],
            "label_changed": bool(int(reference["label_changed"])),
            "change_counts": {
                key: int(reference[key]) for key in ("added", "removed", "changed", "unchanged")
            },
            "stage": row["human_stage"],
            "owner": owner,
            "question": question,
        })
    return rows


def private_report(rows, sources, plan_sha):
    body = [
        "<p>All entries are UNSIGNED, PRIVATE HUMAN proposals linked to exact "
        "historical ORIGINAL ledger bytes, not authenticated customers, a "
        "real client/operator grant, a remediation finding or a live scan. "
        "Original source kit bytes were NOT reopened by this historical review. "
        "This packet is ALWAYS HOLD.</p>",
        "<p>Human CSV SHA-256: <code>" + plan_sha + "</code> (unsigned)</p>",
        "<table><thead><tr><th>Step</th><th>Kit</th><th>Human label</th>"
        "<th>Byte changes (added / removed / changed)</th><th>Stage</th>"
        "<th>HUMAN owner</th><th>HUMAN question</th></tr></thead><tbody>"
    ]
    for row in rows:
        label = sources[row["transition"]]["doc"]["kits"][row["kit_ordinal"] - 1]["label"]
        counts = row["change_counts"]
        body.append(
            "<tr><td>" + str(row["transition"]) + "</td><td>" +
            str(row["kit_ordinal"]) + "</td><td>" + html.escape(label) +
            (" (HUMAN RELABEL)" if row["label_changed"] else "") +
            "</td><td>" + " / ".join(str(counts[k]) for k in ("added", "removed", "changed")) +
            "</td><td>" + html.escape(row["stage"]) +
            "</td><td>" + html.escape(row["owner"]) +
            "</td><td>" + html.escape(row["question"]) + "</td></tr>"
        )
    body.append(
        "</tbody></table><p>PRIVATE local historical HUMAN record only. "
        "Reopen current original source separately before any fresh decision. "
        "Missing file is NOT verified remediation; human stage is NEVER permission.</p>"
    )
    return html_page("LightUp PRIVATE HUMAN historical review packet", "".join(body))


def finalize(args):
    sources = load_history(args.ledger)
    transitions, _, _ = summarize(sources)
    expected = expected_rows(sources, transitions)
    if bool(args.plan) == bool(args.browser_csv):
        reject("PRIVATE HOLD: choose exactly one PRIVATE plan or explicit browser download")
    if args.plan:
        payload = read_owner_file(args.plan, MAX_PLAN)
        exposed = False
    else:
        payload, exposed = read_browser_csv(args.browser_csv)
    rows = parse_plan(payload, expected)
    private_parent = os.path.normpath(args.private_parent)
    if not os.path.isabs(private_parent) or args.private_parent != private_parent:
        reject("PRIVATE HOLD: canonical absolute private output required")
    for kit in sources[0]["doc"]["kits"]:
        if os.path.commonpath((kit["path"], private_parent)) == kit["path"]:
            reject("PRIVATE HOLD: cannot write human history inside an original kit")
    # Reopen the exact archived original LEDGER bytes before publishing, but
    # never pretend this reopens the original customer source kit contents.
    recent = load_history(args.ledger)
    if [x["sha256"] for x in recent] != [x["sha256"] for x in sources]:
        reject("PRIVATE HOLD: original ledger bytes changed during HUMAN review")
    report = {
        "schema": "lightup.private.workspace-ledger-history-human.v1",
        "authority": FLAGS,
        "sources_reopened": False,
        "historical_only": True,
        "human_review_is_not_authorization": True,
        "original_ledger_sha256": [x["sha256"] for x in sources],
        "human_plan_sha256": digest(payload),
        "rows": rows,
    }
    output = new_private(private_parent)
    try:
        write_private(output, "PRIVATE-HUMAN-history.json", canonical(report))
        write_private(output, "PRIVATE-HUMAN-history.html", private_report(rows, sources, digest(payload)))
        write_private(output, "HUMAN-history-review.csv", payload)
        write_private(output, "OPEN-PRIVATE.html", html_page(
            "LightUp PRIVATE historical HUMAN custody",
            "<p>HUMAN proposals linked to each EXACT archived ledger transition. "
            "Original source kits NOT reopened; no permission, verified fix, "
            "consent or external release.</p><p><a href='PRIVATE-HUMAN-history.html'>"
            "Open source-minimal HUMAN decisions locally</a>.</p>" +
            ("<p>Selected browser Downloads may have been public-readable; this private "
             "copy cannot reverse ANY prior disclosure. Original download NOT changed.</p>"
             if args.browser_csv and exposed else
             "<p>Original input has not been modified or removed.</p>")
        ))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: stored HUMAN historical proposals, never authorization or verified remediation")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(description="Native exact original ledger chain-bound HUMAN-only historical review")
    p.add_argument("--ledger", action="append", required=True, help="Original 0600 ledger.json in exact chained order (2-12)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--plan", help="Existing owner-private 0600 HUMAN-history-review.csv")
    g.add_argument("--browser-csv", help="Explicit original browser-download HUMAN-history-review.csv")
    p.add_argument("--private-parent", required=True, help="Existing 0700 output parent outside the source checkout")
    a = p.parse_args()
    try:
        return finalize(a)
    except (Hold, OSError, ValueError, UnicodeError, TypeError, csv.Error):
        print("PRIVATE HOLD: historic HUMAN source-bound finalization refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
