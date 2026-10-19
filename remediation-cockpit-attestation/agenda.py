#!/usr/bin/env python3
"""Privacy-minimal offline iCalendar agenda from encrypted local HUMAN slot plans.

Calendar contains dates and aggregate workload counts only; no identifiers,
aliases, source fingerprint digests, note text, client names or evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys

import attest
import coordination
import inbox
import transport

review = attest.review
native = attest.read_cockpit
DOMAIN = b"LightUp PRIVATE HUMAN local calendar UID v1\x00"
WARNING = ("LOCAL HUMAN review calendar only; tentative reminders do not "
           "authenticate consent, ownership, actual remediation or retest.")


def require(value: bool) -> None:
    attest.require(value)


def escaped(text: str) -> str:
    return text.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def folded(line: str) -> str:
    # RFC 5545 line folding at 75 octets, preserve complete UTF-8 codepoints.
    result = []
    part = ""
    size = 0
    for letter in line:
        width = len(letter.encode("utf-8"))
        if size + width > 75:
            result.append(part)
            part = " "
            size = 1
        part += letter
        size += width
    result.append(part)
    return "\r\n".join(result)


def agenda(plan: dict) -> dict:
    counts = Counter(row["due_date"] for row in plan["slots"]
                     if row["due_date"] is not None and row["stage"] != "locally_answered")
    return {
        "kind": "lightup.anonymous_private_human_review_agenda",
        "schema_version": 1,
        "disposition": "TENTATIVE_LOCAL_HUMAN_DATE_COUNTS_ONLY",
        "undated_local_human_slots": sum(
            row["due_date"] is None and row["stage"] != "locally_answered"
            for row in plan["slots"]),
        "due_dates": [{"date": label, "human_review_slots_not_unique_cases": counts[label]}
                      for label in sorted(counts)],
        "warning": WARNING,
        **{flag: False for flag in review.FLAGS},
    }


def render_ical(summary: dict, root_secret: bytes) -> bytes:
    require(type(root_secret) is bytes and len(root_secret) == 32)
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//LightUp//PRIVATE HUMAN review agenda//EN",
        "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
        "X-WR-CALNAME:LightUp PRIVATE HUMAN review (unverified)",
    ]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for item in summary["due_dates"]:
        day = date.fromisoformat(item["date"])
        uid = hmac.new(root_secret, DOMAIN + day.isoformat().encode("ascii"),
                       hashlib.sha256).hexdigest()[:32] + "@lightup-local-human"
        lines += [
            "BEGIN:VEVENT",
            "UID:" + uid,
            "DTSTAMP:" + stamp,
            "DTSTART;VALUE=DATE:" + day.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:" + (day + timedelta(days=1)).strftime("%Y%m%d"),
            "SUMMARY:" + escaped("LightUp private HUMAN review (" +
                                 str(item["human_review_slots_not_unique_cases"]) +
                                 " slot(s), not verified fixes)"),
            "DESCRIPTION:" + escaped(WARNING),
            "STATUS:TENTATIVE", "TRANSP:TRANSPARENT", "CLASS:PRIVATE", "END:VEVENT"
        ]
    lines.append("END:VCALENDAR")
    return ("\r\n".join(folded(line) for line in lines) + "\r\n").encode("utf-8")


def emit(folder: Path, secret_file: Path, plan_file: Path, output: Path,
         output_format: str) -> dict:
    original, inbox_sha = coordination.admitted_inbox(folder, secret_file)
    document, encrypted = coordination.decrypt(plan_file, secret_file, original, inbox_sha)
    summary = agenda(document)
    require(output.is_absolute() and output != plan_file and output != secret_file and
            output != folder and folder not in output.parents and
            not output.exists() and not output.is_symlink())
    if output_format == "ics":
        output_bytes = render_ical(summary, attest.key_bytes(secret_file))
    elif output_format == "json":
        output_bytes = native.workspace.pretty(summary)
    else:
        raise ValueError("Unsupported HUMAN agenda format")
    # Mutations to the original inbox/plan between receipt and export HOLD.
    require(inbox.inspect(folder, secret_file) == original and
            coordination.manifest_sha(folder) == inbox_sha and
            attest.private_file(plan_file, coordination.MAX_FILE) == encrypted)
    attest.exclusive_private_write(output, output_bytes)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Publish PRIVATE 0600 all-day TENTATIVE HUMAN review calendar or "
        "anonymous counts from locally encrypted and source-bound inbox plan"))
    parser.add_argument("--inbox", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--format", choices=("ics", "json"), default="ics")
    args = parser.parse_args()
    try:
        summary = emit(args.inbox, args.key_file, args.plan, args.output, args.format)
        print(f"PRIVATE anonymous HUMAN {args.format} published to new 0600 file.")
        print(str(len(summary["due_dates"])) + " local review date(s), " +
              str(summary["undated_local_human_slots"]) +
              " pending local slots without due dates.")
        print("No calendar sync, identifiable source evidence, authorization or verified fix.")
        return 2
    except (OSError, ValueError, OverflowError, TypeError, KeyError,
            UnicodeError, RecursionError, transport.InvalidTag,
            transport.binascii.Error, review.Hold):
        print("HOLD: PRIVATE HUMAN agenda could not be admitted; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
