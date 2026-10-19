"""Standalone privacy-minimal offline ICS for original-source HUMAN follow-up.

Dates are unverified HUMAN *proposals*, not confirmed remediation windows or
technical deadlines. The default calendar has no client, finding, owner, asset,
remediation or evidence information. No external calendar API or sync.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
import secrets
import sys

from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_history import _read_history

LIMIT = 512 * 1024
DESCRIPTION = (
    "PRIVATE HUMAN coordination only. Dates are self-declared proposals, not "
    "active assessment permission, verified fixes, retests or approved change windows. "
    "Recipient and calendar privacy must be independently reviewed."
)
KIND = "lightup.private_human_followup_calendar"


def _escape_ical(value: str) -> str:
    if type(value) is not str:
        raise ValueError("noncanonical HUMAN calendar presentation")
    if any(ord(c) < 32 and c not in "\r\n\t" for c in value):
        raise ValueError("unsafe HUMAN calendar control")
    return value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace(
        "\r\n", "\n"
    ).replace("\r", "\n").replace("\n", "\\n")


def _fold(name: str, value: str) -> str:
    """Fold RFC 5545 content at UTF-8 boundaries, max 75 octets per line."""
    if not name or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;=-" for c in name):
        raise ValueError("invalid static calendar property name")
    input_line = name + ":" + value
    lines = []
    segment = ""
    segment_bytes = 0
    for char in input_line:
        width = len(char.encode("utf-8", "strict"))
        if segment_bytes + width > 75:
            lines.append(segment)
            segment, segment_bytes = " ", 1
        segment += char
        segment_bytes += width
    if segment:
        lines.append(segment)
    return "\r\n".join(lines) + "\r\n"


def _event(uid: str, day: date, title: str, description: str) -> str:
    if len(uid) > 180 or not uid:
        raise ValueError("bad local event identity")
    if day >= date(9999, 12, 31):
        raise ValueError("proposed HUMAN date cannot be the terminal calendar day")
    next_day = day + timedelta(days=1)
    properties = (
        ("BEGIN", "VEVENT"),
        ("UID", uid),
        ("DTSTAMP", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")),
        ("DTSTART;VALUE=DATE", day.strftime("%Y%m%d")),
        ("DTEND;VALUE=DATE", next_day.strftime("%Y%m%d")),
        ("SUMMARY", _escape_ical(title)),
        ("DESCRIPTION", _escape_ical(description)),
        ("STATUS", "TENTATIVE"),
        ("TRANSP", "TRANSPARENT"),
        ("X-LIGHTUP-HUMAN-PLAN-ONLY", "TRUE"),
        ("END", "VEVENT"),
    )
    return "".join(_fold(name, value) for name, value in properties)


def _calendar(rows: list[dict], current: dict, detailed: bool) -> tuple[bytes, int, int]:
    due_items = []
    for row in rows:
        item = current[row["finding_id"]]
        due = item["due_date"]
        if not due:
            continue
        day = date.fromisoformat(due)
        due_items.append((day, row, item))
    result = "".join((
        _fold("BEGIN", "VCALENDAR"),
        _fold("VERSION", "2.0"),
        _fold("CALSCALE", "GREGORIAN"),
        _fold("METHOD", "PUBLISH"),
        _fold("PRODID", "-//LightUp//PRIVATE HUMAN Proposed Followups//EN"),
        _fold("X-WR-CALNAME", _escape_ical(
            "LightUp PRIVATE HUMAN proposed follow-ups · NOT security deadlines"
        )),
    ))
    event_count = 0
    if detailed:
        for day, row, item in sorted(due_items, key=lambda x: (
            x[0], x[1]["finding_id"]
        )):
            # Distinct new local opaque UID for each manually exported package.
            # Reimporting calendars may duplicate events; original sources are
            # never named in UID/PRODID/URLs.
            uid = secrets.token_hex(16) + "@lightup-private-human.invalid"
            title = "PRIVATE proposed HUMAN follow-up · " + row["title"]
            description = (
                DESCRIPTION + "\nOriginal finding ID: " + row["finding_id"] +
                "\nSource-reported severity: " + row["severity"] +
                "\nHUMAN stage: " + item["stage"] +
                "\nSelf-declared owner alias: " + item["owner_alias"] +
                "\nNo raw evidence, target, remedy, or HUMAN note content is exported."
            )
            result += _event(uid, day, title, description)
            event_count += 1
    else:
        groups: dict[date, int] = defaultdict(int)
        for day, _row, _item in due_items:
            groups[day] += 1
        for day, count in sorted(groups.items()):
            uid = secrets.token_hex(16) + "@lightup-private-human.invalid"
            title = "PRIVATE proposed HUMAN follow-ups · " + str(count) + " items"
            result += _event(
                uid, day, title,
                DESCRIPTION + "\nOnly total proposed human follow-up count is included. "
                "No original finding, title, owner alias, client, source SHA or notes."
            )
            event_count += 1
    result += _fold("END", "VCALENDAR")
    payload = result.encode("utf-8", "strict")
    if len(payload) > LIMIT:
        raise ValueError("HUMAN calendar exceeds bounded 512 KiB limit")
    return payload, event_count, len(due_items)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline PRIVATE HUMAN proposed follow-up calendar; NEVER an approved remediation window"
    )
    parser.add_argument("source", help="original encrypted source .lue")
    parser.add_argument("plan", help="latest exact-source encrypted HUMAN .lun")
    parser.add_argument("--output", required=True, help="new privately stored unencrypted .ics")
    parser.add_argument("--include-private-events", action="store_true",
                        help="one event per original finding with ID, title and owner alias")
    parser.add_argument("--ack-private-records", action="store_true")
    parser.add_argument("--ack-unencrypted-calendar", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_unencrypted_calendar:
            raise ValueError("explicit unencrypted calendar privacy consent required")
        if args.include_private_events and not args.ack_private_records:
            raise ValueError("original ID/owner details need separate private acknowledgment")
        destination = _output_path(args.output, ".ics")
        _manifest, rows, versions = _read_history(args.source, [args.plan])
        content, events, entries = _calendar(
            rows, versions[0], args.include_private_events
        )
        _atomic_private_publish(destination, content)
        print("Created OFFLINE UNENCRYPTED PRIVATE HUMAN proposed follow-up calendar.")
        print("Calendar entries:", events, "· source records with proposed dates:", entries)
        print("No client ID, real owner identity, permission, confirmed fix or retest verified.")
        print("Calendar import is manual; repeated imports may create duplicates.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN calendar HOLD: source, due-date, recipient privacy or output invalid.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
