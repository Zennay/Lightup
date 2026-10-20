#!/usr/bin/env python3
"""Explicit offline browser CSV ingress into a PRIVATE HUMAN assessment workspace.

A typical browser downloads HUMAN-review.csv as a user-owned 0644 file.
Rather than chmod/mutate a possibly exposed original, this foreground tool
reads exactly a user-chosen bounded regular file without following symlinks,
rechecks the original kit inventory, checks every original HUMAN row, and
creates a new owner-private 0700/0600 copy. It never grants authority.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
from pathlib import Path
import shutil
import stat
import sys

import ledger

MAX_BROWSER_CSV = ledger.MAX_CSV


def read_explicit_browser_csv(path):
    p = Path(path)
    if not p.is_absolute() or not re.fullmatch(r"HUMAN-review(?: ?\([1-9][0-9]{0,3}\))?\.csv", p.name):
        ledger.reject("PRIVATE HOLD: choose exact absolute HUMAN-review.csv path")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        original = os.fstat(fd)
        if (not stat.S_ISREG(original.st_mode) or original.st_uid != os.geteuid()
                or original.st_nlink != 1 or original.st_size <= 0
                or original.st_size > MAX_BROWSER_CSV):
            ledger.reject("PRIVATE HOLD: chosen browser CSV must be owner-owned regular and bounded")
        parts = []
        amount = 0
        while True:
            part = os.read(fd, 32768)
            if not part:
                break
            amount += len(part)
            if amount > MAX_BROWSER_CSV:
                ledger.reject("PRIVATE HOLD: browser CSV exceeds byte limit")
            parts.append(part)
        now = os.fstat(fd)
        if (original.st_dev, original.st_ino, original.st_mtime_ns, original.st_ctime_ns,
            original.st_size) != (now.st_dev, now.st_ino, now.st_mtime_ns, now.st_ctime_ns,
                                now.st_size) or amount != original.st_size:
            ledger.reject("PRIVATE HOLD: browser CSV changed during explicit source intake")
        return b"".join(parts), bool(original.st_mode & 0o077)
    finally:
        os.close(fd)


def admit_rows(payload, document, exact_ledger_sha256):
    try:
        text = payload.decode("utf-8", errors="strict")
        if "\x00" in text or "\r" in text:
            ledger.reject("PRIVATE HOLD: control bytes in source CSV")
        data = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, ValueError, csv.Error) as exc:
        raise ledger.Hold("PRIVATE HOLD: malformed HUMAN CSV") from exc
    if len(data) != len(document["kits"]) + 1 or not data or tuple(data[0]) != ledger.CSV_HEADERS:
        ledger.reject("PRIVATE HOLD: HUMAN CSV columns or count")
    for row, kit in zip(data[1:], document["kits"]):
        if (len(row) != 6 or row[0] != str(kit["ordinal"]) or
                row[1] != exact_ledger_sha256 or row[2] != kit["digest"]):
            ledger.reject("PRIVATE HOLD: HUMAN CSV does not match original exact kit")
        if row[3] not in ledger.STAGES:
            ledger.reject("PRIVATE HOLD: HUMAN stage outside original source-bound schema")
        ledger.safe_human(row[4], 80)
        ledger.safe_human(row[5], 500)
        if "\n" in row[4] or "\n" in row[5]:
            ledger.reject("PRIVATE HOLD: multiline HUMAN value")
    return len(data) - 1


def import_browser(args):
    if args.csv == args.ledger:
        ledger.reject("PRIVATE HOLD: original ledger and chosen HUMAN source must differ")
    original = ledger.read_owner_file(args.ledger, ledger.MAX_MANIFEST)
    document = ledger.manifest_from_source(original)
    # ORIGINAL source kit files must still be present with unchanged byte identity.
    ledger.verify_snapshot(document)
    payload, was_exposed = read_explicit_browser_csv(args.csv)
    count = admit_rows(payload, document, ledger.digest(original))
    if not count:
        ledger.reject("PRIVATE HOLD: no human rows")
    path = ledger.new_private(args.private_parent)
    try:
        ledger.write_private(path, "HUMAN-review.csv", payload)
        ledger.write_private(path, "OPEN-PRIVATE.html", ledger.html_page(
            "LightUp PRIVATE browser download custody",
            "<p>Original HUMAN source CSV was selected deliberately and copied to a separate "
            "owner-private location. The original browser file was NOT modified, chmodded, "
            "published, uploaded, deleted or renamed. Its original filesystem access flags "
            "may still expose it to other local users, which this import CANNOT reverse.</p>"
            "<p>All EXACT FULL-ledger SHA and kit-bound HUMAN rows plus current kit bytes matched "
            "the original ledger at intake. This is an unsigned local consistency check, "
            "NOT identity, client consent, review or clearance. "
            "The staged HUMAN-review.csv can now be passed to native ledger.py finalize "
            "with the same original ledger path; that command checks current source bytes again.</p>"
            "<p>Count of PRIVATE HUMAN proposals: " + str(count) + ". Source browser file "
            "was " + ("group/other-readable: review its original location." if was_exposed
                       else "already owner-private.") + "</p>"
        ))
    except BaseException:
        shutil.rmtree(path)
        raise
    print("PRIVATE REVIEW_ONLY: browser CSV admitted to separate 0700/0600 local custody")
    print("Original download unchanged; previous public read exposure cannot be undone.")
    print(str(Path(path) / "OPEN-PRIVATE.html"))
    print("Private CSV: " + str(Path(path) / "HUMAN-review.csv"))
    if args.finalize:
        # Delegates unchanged exact-original reinspection and HUMAN packet validation.
        return ledger.finalize(argparse.Namespace(
            ledger=args.ledger, plan=str(Path(path) / "HUMAN-review.csv"),
            private_parent=args.private_parent
        ))
    return 2


def main():
    p = argparse.ArgumentParser(
        description="Explicitly admit browser HUMAN CSV and optionally native-finalize privately"
    )
    p.add_argument("--ledger", required=True, help="Original owner-private ledger.json")
    p.add_argument("--csv", required=True, help="Explicit browser-downloaded HUMAN-review.csv path")
    p.add_argument("--private-parent", required=True, help="Existing 0700 private parent outside repo")
    p.add_argument("--finalize", action="store_true",
                   help="Immediately call unchanged native source-revalidating HUMAN finalizer")
    args = p.parse_args()
    try:
        return import_browser(args)
    except (ledger.Hold, OSError, UnicodeError, ValueError, csv.Error):
        print("PRIVATE HOLD: source-bound browser CSV admission refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
