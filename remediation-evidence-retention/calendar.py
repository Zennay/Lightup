#!/usr/bin/env python3
"""PRIVATE anonymous iCalendar reminders from current original HUMAN retention.

Creates a new owner-private 0600 local .ics only after current original LightUp
account/tenant/engagement read, native encrypted HUMAN source admission, actual
original 0600 evidence bytes and encrypted retention plan checks. No calendar
network connection, account sync, targets, scan, release or legal decision.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys

import retention as native

original = native.transfer
MAX_DATES = 120
MAX_ICS = 60 * 1024
HEADER = "LightUp HUMAN evidence review"
DESCRIPTION = (
    "PRIVATE human review reminder, not a legally approved retention policy, "
    "authority to delete, legal-hold release, evidence provenance, verified "
    "remediation, consent, grant or security retest."
)


def _date_counts(items: list[dict]) -> list[tuple[str, int]]:
    if type(items) is not list or not 1 <= len(items) <= native.transfer.MAX_FILES:
        raise ValueError("Expected existing full bounded original PRIVATE material review.")
    dates = Counter()
    for row in items:
        # Admission into native._admit_plan already happened, nevertheless
        # fail closed on unfamiliar shapes before emitting any calendar bytes.
        if type(row) is not dict or type(row.get("review_on")) is not str:
            raise ValueError("Noncanonical HUMAN review date.")
        day = date.fromisoformat(row["review_on"])
        if day.isoformat() != row["review_on"]:
            raise ValueError("Invalid canonical HUMAN review date.")
        dates[day.isoformat()] += 1
    if not dates or len(dates) > MAX_DATES:
        raise ValueError("Bounded original private HUMAN review calendar required.")
    return sorted(dates.items())


def _fold(text: str) -> str:
    """RFC5545 75-octet folding; input is deliberately ASCII only."""
    if not text.isascii() or "\r" in text or "\n" in text:
        raise ValueError("Expected safe ASCII-only calendar property.")
    chunks = []
    while len(text) > 73:
        chunks.append(text[:73])
        text = " " + text[73:]
    chunks.append(text)
    return "\r\n".join(chunks)


def _calendar(rows: list[tuple[str, int]], source_hash: str) -> bytes:
    if (type(source_hash) is not str or len(source_hash) != 64
            or any(c not in "0123456789abcdef" for c in source_hash)):
        raise ValueError("Original current source digest is noncanonical.")
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0",
        "PRODID:-//LightUp//PRIVATE HUMAN Retention Reminder//EN",
        "CALSCALE:GREGORIAN", "X-WR-CALNAME:LightUp PRIVATE HUMAN reviews",
    ]
    for yyyy_mm_dd, count in rows:
        day = date.fromisoformat(yyyy_mm_dd)
        uid = hashlib.sha256(
            (source_hash + ":" + yyyy_mm_dd + ":HUMAN_REVIEW_ONLY").encode("ascii")
        ).hexdigest()[:40] + "@lightup.invalid"
        lines.extend([
            "BEGIN:VEVENT",
            "UID:" + uid,
            "DTSTAMP:" + now,
            "DTSTART;VALUE=DATE:" + day.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:" + (day + timedelta(days=1)).strftime("%Y%m%d"),
            "SUMMARY:" + HEADER,
            "DESCRIPTION:" + str(count) + " PRIVATE local evidence material review(s). "
            + DESCRIPTION,
            "STATUS:TENTATIVE",
            "TRANSP:TRANSPARENT",
            "END:VEVENT",
        ])
    lines.append("END:VCALENDAR")
    rendered = ("\r\n".join(_fold(line) for line in lines) + "\r\n").encode("ascii")
    if len(rendered) > MAX_ICS:
        raise ValueError("PRIVATE original source-bound calendar output oversized.")
    return rendered


def current_calendar(args, vault) -> tuple[bytes, int, int]:
    _, packet, indexed = original.current_human(args, vault)
    items, _ = native._load_current_plan(args, vault, packet, indexed)
    rows = _date_counts(items)
    return _calendar(rows, packet["source_sha256"]), len(rows), len(items)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("db", "email", "client-id", "engagement-id"):
        p.add_argument("--" + key, required=True)
    for key in ("human", "directory", "plan", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--ack-private-material", action="store_true")
    args = p.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Interactive PRIVATE HUMAN acknowledgement required.")
        output = args.output.expanduser().absolute()
        if (output.suffix.lower() != ".ics" or output in
                {args.plan.expanduser().absolute(), args.human.expanduser().absolute()}):
            raise ValueError("NEW distinct PRIVATE .ics output required.")
        vault = original.ORIGINAL._vault()
        rendered, days, count = current_calendar(args, vault)
        vault._exclusive_output(output, rendered)
        print("Created NEW original-source- and actual-private-bytes-bound "
              "anonymous HUMAN calendar, 0600.")
        print("Human review days:", days, "· original PRIVATE files:", count)
        print("No identifiers, paths, finding IDs, hashes, filenames, passwords "
              "or freeform notes in calendar.")
        print("No external calendar connected, actual deletion, release or grant.")
        return 0
    except Exception:
        print("HUMAN HOLD: Current original authorized source, complete actual "
              "private bytes, original encrypted review or PRIVATE output refused. "
              "No completed calendar published.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
