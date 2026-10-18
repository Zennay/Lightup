"""Offline human review calendar for an original, privately exported LightUp Casebook.

Retrospective, unsigned evidence only. Does not import a scanner, domain writer,
authorization gate, task dispatcher or network client.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import uuid

SCHEMA = "lightup.scope_window_review.v1"
SOURCE_SCHEMA = "lightup.auth_casebook.v1"
AUTHORITY_FLAGS = (
    "source_authenticated", "client_consent_verified", "operator_consent_verified",
    "authorization_granted", "execution_allowed", "release_approved",
)
MAX_SOURCE = 512 * 1024
MAX_RECORDS = 200
WINDOW_STATES = {
    "EXPIRED_RECORDED_WINDOW", "FUTURE_RECORDED_WINDOW",
    "HOLD_INVALID_RECORDED_WINDOW", "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY",
}


class ReviewHold(ValueError):
    pass


def no_duplicate_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ReviewHold("duplicate JSON key")
        output[key] = value
    return output


def reject_constant(_):
    raise ReviewHold("non-finite source value")


def source_file(path: Path) -> dict:
    # Open once with O_NOFOLLOW; reject FIFOs, links, devices and oversized input.
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_SOURCE:
            raise ReviewHold("source is not a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_SOURCE + 1)
        if len(raw) > MAX_SOURCE:
            raise ReviewHold("source exceeds 512 KiB")
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                         parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewHold("malformed original Casebook JSON") from exc
    if type(doc) is not dict or doc.get("schema") != SOURCE_SCHEMA:
        raise ReviewHold("not an original Casebook v1 export")
    if doc.get("status") != "REVIEW_ONLY" or doc.get("source") != "original_persisted_domain_unverified":
        raise ReviewHold("unknown original Casebook provenance")
    if any(doc.get(key) is not False for key in AUTHORITY_FLAGS):
        raise ReviewHold("Casebook asserts or omits non-authority flags")
    return doc


def identity(value: object) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 180
            or value.strip() != value
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise ReviewHold("invalid source record identifier")
    return value


def when(value: object) -> datetime:
    if type(value) is not str or len(value) > 80:
        raise ReviewHold("noncanonical source timestamp")
    try:
        date = datetime.fromisoformat(value)
        if date.tzinfo is None or date.utcoffset() is None:
            raise ValueError("naive timestamp")
        return date.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ReviewHold("invalid original timestamp") from exc


def derive(casebook: dict, *, now: datetime, lead_days: int,
           future_days: int) -> dict:
    identity(casebook.get("client_id"))
    as_of = when(casebook.get("as_of"))
    if as_of > now + timedelta(minutes=5):
        raise ReviewHold("source claims a future observation time")
    grants = casebook.get("grants")
    engagements = casebook.get("engagements")
    counts = casebook.get("declared_counts")
    if (type(grants) is not list or type(engagements) is not list
            or type(counts) is not dict or len(grants) > MAX_RECORDS
            or len(engagements) > MAX_RECORDS
            or type(counts.get("grants")) is not int
            or counts["grants"] != len(grants)
            or type(counts.get("engagements")) is not int
            or counts["engagements"] != len(engagements)):
        raise ReviewHold("original collection/count mismatch")
    owned = set()
    for record in engagements:
        if type(record) is not dict:
            raise ReviewHold("invalid original engagement")
        item = identity(record.get("engagement_id"))
        if item in owned:
            raise ReviewHold("duplicate original engagement")
        owned.add(item)
    seen = set()
    events = []
    summary = Counter()
    stale = now - as_of > timedelta(hours=24)
    for row in grants:
        if type(row) is not dict:
            raise ReviewHold("invalid grant record")
        grant_id = identity(row.get("grant_id"))
        if grant_id in seen:
            raise ReviewHold("duplicate grant identity")
        seen.add(grant_id)
        eid = row.get("engagement_id")
        # A detached original grant is a HOLD and cannot be put on a normal calendar.
        detached = eid is None
        if not detached and identity(eid) not in owned:
            raise ReviewHold("cross-source engagement mismatch")
        observation = row.get("validity_observation")
        link = row.get("request_link_observation")
        if observation not in WINDOW_STATES or type(link) is not str or len(link) > 90:
            raise ReviewHold("unrecognized original observation")
        if not (link.startswith("HOLD_") or link == "REQUEST_SCOPE_COMPATIBLE_UNVERIFIED"):
            raise ReviewHold("unknown original grant link status")
        start = end = None
        invalid = observation == "HOLD_INVALID_RECORDED_WINDOW"
        try:
            start = when(row.get("valid_from"))
            end = when(row.get("valid_until"))
            if start >= end:
                raise ReviewHold("reversed source window")
        except ReviewHold:
            invalid = True
        if not invalid:
            expected = ("EXPIRED_RECORDED_WINDOW" if as_of > end else
                        "FUTURE_RECORDED_WINDOW" if as_of < start else
                        "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY")
            if observation != expected:
                raise ReviewHold("original recorded window contradicts timestamp")
        elif observation != "HOLD_INVALID_RECORDED_WINDOW":
            raise ReviewHold("invalid source window lacks HOLD")
        # The window classification is about a *historic* source record, not consent.
        hold = bool(detached or invalid or link.startswith("HOLD_") or stale
                    or (end is not None and now > end))
        phase = ("INVALID_WINDOW" if invalid else
                 "RECORDED_WINDOW_PASSED" if now > end else
                 "RECORDED_START_UPCOMING" if now < start else
                 "RECORDED_END_UPCOMING")
        if invalid or detached:
            planned = now.date() + timedelta(days=1)
        else:
            boundary = start if phase == "RECORDED_START_UPCOMING" else end
            planned = (boundary - timedelta(days=lead_days)).date()
            if planned <= now.date():
                planned = now.date() + timedelta(days=1)
        delay = (planned - now.date()).days
        # Include immediate human HOLD/expired follow-up, and near-term upcoming windows.
        if delay <= future_days or hold or phase == "RECORDED_WINDOW_PASSED":
            events.append({
                "grant_id": grant_id,
                "engagement_id": eid,
                "review_date_utc": planned.isoformat(),
                "original_valid_from": row.get("valid_from"),
                "original_valid_until": row.get("valid_until"),
                "original_recorded_observation": observation,
                "original_link_observation": link,
                "phase": phase,
                "human_priority": "HOLD" if hold else "REVIEW_ONLY",
                "next_action": ("VERIFY_SOURCE_WITH_AUTHENTICATED_OPERATOR" if hold
                                else "RECHECK_ACTUAL_CONSENT_AND_LIVE_REVOCATION"),
            })
            summary["HOLD" if hold else "REVIEW_ONLY"] += 1
    events.sort(key=lambda x: (x["review_date_utc"], x["human_priority"] != "HOLD",
                               x["engagement_id"] or "", x["grant_id"]))
    return {
        "schema": SCHEMA, "status": "HOLD" if stale or summary["HOLD"] else "REVIEW_ONLY",
        "source": "unsigned_original_casebook_retrospective",
        "as_of": as_of.isoformat(), "prepared_at": now.isoformat(),
        "stale_source_over_24h": stale,
        "limits": {"lead_days": lead_days, "future_days": future_days},
        "client_id": casebook["client_id"], "items": events,
        "declared_counts": {"items": len(events),
                            "hold": summary["HOLD"],
                            "review_only": summary["REVIEW_ONLY"]},
        **dict.fromkeys(AUTHORITY_FLAGS, False),
    }


def ics(agenda: dict) -> bytes:
    # The calendar never embeds original identities, assets, risk, evidence or URLs.
    now = when(agenda["prepared_at"]).strftime("%Y%m%dT%H%M%SZ")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//LightUp//Human Review Calendar//EN",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
             "X-WR-CALNAME:LightUp human reviews - NOT AUTHORIZATION"]
    # One generic group per human review day and priority: no private source
    # identities and no duplicated same-day calendar appointments.
    groups = sorted({(item["review_date_utc"], item["human_priority"])
                     for item in agenda["items"]})
    for review_day, priority in groups:
        day = review_day.replace("-", "")
        start = f"{day}T090000Z"
        end = f"{day}T091500Z"
        lines.extend([
            "BEGIN:VEVENT", f"UID:{uuid.uuid4()}@lightup-review.invalid",
            f"DTSTAMP:{now}", f"DTSTART:{start}", f"DTEND:{end}",
            "SUMMARY:LightUp human follow-up (NOT AUTHORIZATION)",
            "DESCRIPTION:Unsigned retrospective " + priority +
            " human review. Recheck original authenticated source and independently"
            " verify current consent and at-use revocation.",
            "TRANSP:TRANSPARENT", "STATUS:TENTATIVE", "END:VEVENT",
        ])
    lines.append("END:VCALENDAR")
    # No source text is used in ICS, so no untrusted ICS property injection.
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def ensure_private_destination(path: Path) -> None:
    parent = path.parent
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or parent.is_symlink()
            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ReviewHold("output folder must be owned by actor and mode 0700")
    if path.exists() or path.is_symlink():
        raise ReviewHold("output exists; refusing overwrite")


def private_publish(path: Path, payload: bytes) -> None:
    ensure_private_destination(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lightup-window-pending-")
    linked = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, path, follow_symlinks=False)
        linked = True
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    if not linked:
        raise ReviewHold("private exclusive output failed")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--casebook", required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--agenda-json", type=Path, help="private IDs included; owner-only directory")
    group.add_argument("--calendar", type=Path, help="identity-free generic calendar events")
    group.add_argument("--board", type=Path, help="private self-contained interactive offline HTML")
    parser.add_argument("--lead-days", type=int, default=7)
    parser.add_argument("--future-days", type=int, default=45)
    args = parser.parse_args(argv)
    try:
        if not 0 <= args.lead_days <= 30 or not 1 <= args.future_days <= 366:
            raise ReviewHold("invalid planning horizon")
        out = args.agenda_json or args.calendar or args.board
        ensure_private_destination(out)
        source = source_file(args.casebook)
        agenda = derive(source, now=datetime.now(timezone.utc), lead_days=args.lead_days,
                        future_days=args.future_days)
        if args.agenda_json:
            payload = (json.dumps(agenda, ensure_ascii=True, indent=2,
                                  allow_nan=False) + "\n").encode("utf-8")
        elif args.board:
            from board_html import render
            payload = render(agenda)
        else:
            payload = ics(agenda)
        private_publish(out, payload)
        counts = agenda["declared_counts"]
        print(f"{agenda['status']}: {counts['items']} planned human review entries; "
              f"{counts['hold']} HOLD; no authorization/consent/execution.")
        return 3 if agenda["status"] == "HOLD" else 2
    except (ReviewHold, OSError, ValueError) as exc:
        print(f"HOLD: no authority or execution; {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
