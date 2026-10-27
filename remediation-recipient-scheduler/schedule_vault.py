#!/usr/bin/env python3
"""Native offline reopening of browser-encrypted PRIVATE HUMAN schedule receipts.

Exact original source-free Cockpit admission is mandatory. No browser, network,
model, scan, grant, actual consent, verified finding or remediation.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
from datetime import date, timedelta, datetime, timezone
import getpass
import hashlib
import html
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import unicodedata

import schedule
import single_review
sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import encrypted_cockpit as crypto
import install
import workflow

KIND = "lightup.source_free_human_schedule_encrypted.v1"
AAD = b"LIGHTUP_PRIVATE_SOURCE_FREE_HUMAN_SCHEDULE_V1"
MAX_ENVELOPE = 4194304
MAX_PLAIN = 4194304
MAX_TASKS = schedule.MAX_TASKS
WARNING = schedule.WARNING
ENVELOPE_FIELDS = frozenset((
    "kind", "disposition", "authority_granted", "consent_verified",
    "remediation_verified", "kdf", "iterations", "algorithm",
    "salt_b64", "nonce_b64", "ciphertext_b64", "warning"
))
PLAN_FIELDS = frozenset((
    "kind", "version", "disposition", "authority_granted", "consent_verified",
    "remediation_verified", "warning", "sources", "tasks"
))
TASK_FIELDS = frozenset((
    "packet", "slot", "reason", "count", "stage", "human_note",
    "owner", "due", "next_action"
))
STYLES = """
body{font:15px/1.55 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:1rem;color:#22354b}
h1{font-size:1.8rem}h2{font-size:1.15rem}aside{padding:1rem;border:2px solid #ae7b35;background:#fff7e6}
article{padding:1rem;border:1px solid #bdccd7;border-radius:8px;margin:1rem 0;break-inside:avoid}
dt{font-weight:bold}dd{margin:0 0 .7rem;white-space:pre-wrap}
small{color:#48617b}@media print{body{margin:0}article{page-break-inside:avoid}}
"""

def require(condition: bool, reason: str) -> None:
    single_review.review.require(condition, reason)

def strict_json(raw: bytes, maximum: int) -> dict:
    require(type(raw) is bytes and 1 <= len(raw) <= maximum,
            "Encrypted schedule exceeds private bounded input size")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=install.pairs,
                            parse_constant=lambda v: (_ for _ in ()).throw(
                                ValueError("Nonfinite JSON field")))
        # JS JSON.stringify-generated source uses exactly this compact UTF-8
        # object order. Prevent duplicate members and altered serialization.
        normalized = json.dumps(parsed, ensure_ascii=False,
                                separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise single_review.review.Hold("Malformed or duplicate-key PRIVATE HUMAN schedule") from exc
    require(type(parsed) is dict and normalized == raw,
            "Noncanonical PRIVATE HUMAN schedule payload")
    return parsed

def decode64(value: object, size_low: int, size_high: int) -> bytes:
    require(type(value) is str and len(value) <= MAX_ENVELOPE,
            "Invalid encrypted HUMAN base64 field")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise single_review.review.Hold("Invalid encrypted HUMAN encoding") from exc
    require(size_low <= len(decoded) <= size_high and
            base64.b64encode(decoded).decode("ascii") == value,
            "Noncanonical encrypted HUMAN binary encoding")
    return decoded

def private_vault(path: Path) -> bytes:
    require(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
            and not path.is_symlink(), "PRIVATE HUMAN encrypted receipt needs absolute path")
    install.owner_dir(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_mode & 0o077 == 0
            and 100 <= before.st_size <= MAX_ENVELOPE,
            "PRIVATE HUMAN receipt requires owner-only 0600 regular one-link file")
    data = crypto.private_envelope(path)
    require(len(data) == before.st_size, "PRIVATE encrypted schedule changed before read")
    return data

def open_vault(path: Path) -> dict:
    encrypted = private_vault(path)
    packet = strict_json(encrypted, MAX_ENVELOPE)
    require(frozenset(packet) == ENVELOPE_FIELDS and
            packet["kind"] == KIND and
            packet["disposition"] == "PRIVATE_HUMAN_ONLY_NO_AUTHORITY" and
            packet["authority_granted"] is False and
            packet["consent_verified"] is False and
            packet["remediation_verified"] is False and
            packet["kdf"] == "PBKDF2-HMAC-SHA256" and
            type(packet["iterations"]) is int and packet["iterations"] == 600000 and
            packet["algorithm"] == "AES-256-GCM" and packet["warning"] == WARNING,
            "Unknown HUMAN schedule format, parameters or elevated authority")
    salt = decode64(packet["salt_b64"], 16, 16)
    nonce = decode64(packet["nonce_b64"], 12, 12)
    ciphertext = decode64(packet["ciphertext_b64"], 17, MAX_PLAIN + 16)
    require(sys.stdin.isatty(), "Password entry requires PRIVATE interactive terminal")
    password = getpass.getpass("Previously saved HUMAN planning file passphrase: ")
    require(type(password) is str and 12 <= len(password) <= 256,
            "Invalid HUMAN password length")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    try:
        opened = AESGCM(crypto.aead_key(password, salt)).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise single_review.review.Hold(
            "Incorrect private HUMAN password or modified encrypted receipt") from exc
    require(private_vault(path) == encrypted,
            "Encrypted PRIVATE HUMAN plan changed during native opening")
    return strict_json(opened, MAX_PLAIN)

def local_text(text: object, max_chars: int, max_bytes: int,
               multiline: bool = False) -> bool:
    return (type(text) is str and len(text) <= max_chars and
            len(text.encode("utf-8")) <= max_bytes and
            all((ch == "\n" and multiline) or
                unicodedata.category(ch)[0] != "C" for ch in text))

def admit(plan: dict, cockpits: list[str]) -> list[dict]:
    originals, tasks = schedule.source_records(cockpits, [])
    require(frozenset(plan) == PLAN_FIELDS and
            plan["kind"] == schedule.KIND and
            type(plan["version"]) is int and plan["version"] == 1 and
            plan["disposition"] == "PRIVATE_HUMAN_ONLY_NO_AUTHORITY" and
            plan["authority_granted"] is False and
            plan["consent_verified"] is False and
            plan["remediation_verified"] is False and
            plan["warning"] == WARNING, "Original source-free HUMAN planning authority mismatch")
    sources = plan["sources"]
    require(type(sources) is list and len(sources) == len(originals),
            "Original source-free Cockpit inventory differs")
    for a,b in zip(sources, originals):
        require(type(a) is dict and
                frozenset(a) == {"packet","source_sha256","reason_groups"} and
                type(a.get("packet")) is int and a["packet"] == b["packet"] and
                type(a.get("source_sha256")) is str and
                a["source_sha256"] == b["source_sha256"] and
                type(a.get("reason_groups")) is int and
                a["reason_groups"] == b["reason_groups"],
                "Source-free original packet/order/hashes changed")
    selected = plan["tasks"]
    require(type(selected) is list and len(selected) == len(tasks) and
            len(selected) <= MAX_TASKS, "Incomplete original HUMAN group membership")
    result = []
    for previous, canonical in zip(selected,tasks):
        require(type(previous) is dict and frozenset(previous) == TASK_FIELDS and
                type(previous.get("packet")) is int and
                previous["packet"] == canonical["packet"] and
                type(previous.get("slot")) is int and
                previous["slot"] == canonical["slot"] and
                type(previous.get("reason")) is str and
                previous["reason"] == canonical["reason"] and
                type(previous.get("count")) is int and
                previous["count"] == canonical["count"] and
                type(previous.get("stage")) is str and
                previous["stage"] in single_review.STAGES and
                local_text(previous.get("human_note"),240,960,True) and
                local_text(previous.get("owner"),64,256) and
                local_text(previous.get("next_action"),240,960,True) and
                (previous.get("due") == "" or
                 (type(previous.get("due")) is str and
                  len(previous["due"]) == 10 and
                  date.fromisoformat(previous["due"]).isoformat() == previous["due"])),
                "Unsafe HUMAN plan fields or original source-free reason identity")
        result.append(previous)
    return result

def private_report(tasks: list[dict], include_notes: bool) -> bytes:
    def quote(value: object) -> str:
        return html.escape(str(value), quote=True)
    output = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; script-src \'none\'; style-src \'sha256-' +
        base64.b64encode(hashlib.sha256(STYLES.encode("utf-8")).digest()).decode("ascii") + '\'">',
        '<title>PRIVATE HUMAN schedule</title><style>', STYLES,
        '</style></head><body><h1>PRIVATE HUMAN source-free planning brief</h1>',
        '<aside>', quote(WARNING),
        '<p>All owner, stage and due labels remain HUMAN-only and unverified. '
        'Missing records never mean that an issue was fixed. '
        'Do not share without real independent consent and disclosure permission.</p></aside>'
    ]
    for i, task in enumerate(sorted(tasks,key=lambda t:(
            t["due"] or "9999-12-31",t["owner"],t["packet"],t["slot"])),1):
        output.extend([
            '<article><h2>HUMAN task ',str(i),'</h2><dl>',
            '<dt>Anonymous source-free packet selection</dt><dd>',
            str(task["packet"]),'</dd>',
            '<dt>Original source-free HUMAN reason group</dt><dd>',
            quote(task["reason"]),'</dd>',
            '<dt>HUMAN state</dt><dd>',quote(task["stage"]),'</dd>',
            '<dt>Self-declared owner</dt><dd>',quote(task["owner"] or "Unassigned"),'</dd>',
            '<dt>Tentative due</dt><dd>',quote(task["due"] or "Not scheduled"),'</dd>',
            '<dt>Next HUMAN action</dt><dd>',
            quote(task["next_action"] or "Unspecified"),'</dd>'
        ])
        if include_notes:
            output.extend(['<dt>Additional PRIVATE HUMAN note</dt><dd>',
                           quote(task["human_note"] or "Not recorded"),'</dd>'])
        output.extend(['</dl><small>Original source-free counts are not individual verified findings. '
                       'No network or authorized remediation.</small></article>'])
    output.append('</body></html>')
    result = "".join(output).encode("utf-8")
    require(len(result) <= MAX_PLAIN, "Private HUMAN report too large")
    return result

def calendar(tasks: list[dict]) -> bytes:
    def clock(s: date) -> str:
        return s.strftime("%Y%m%d")
    lines=["BEGIN:VCALENDAR","VERSION:2.0","CALSCALE:GREGORIAN",
           "PRODID:-//LightUp//PRIVATE HUMAN offline scheduling//EN"]
    timestamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for task in tasks:
        if not task["due"]: continue
        start=date.fromisoformat(task["due"])
        lines.extend(["BEGIN:VEVENT", "UID:"+secrets.token_hex(16)+"@lightup-private.invalid",
                      "DTSTAMP:"+timestamp, "DTSTART;VALUE=DATE:"+clock(start),
                      "DTEND;VALUE=DATE:"+clock(start+timedelta(days=1)),
                      "CLASS:PRIVATE", "TRANSP:TRANSPARENT",
                      "SUMMARY:PRIVATE HUMAN follow-up (not verified)",
                      "DESCRIPTION:Tentative HUMAN-only date. Not grant or verified remediation.",
                      "END:VEVENT"])
    lines.append("END:VCALENDAR")
    return ("\r\n".join(lines)+"\r\n").encode("utf-8")

def select_human_work(rows: list[dict], *, owner: str | None,
                      unassigned: bool, pending: bool, overdue: bool,
                      due_next_days: int | None, stage: str | None) -> list[dict]:
    """Create one HUMAN recipient agenda; never reinterpret source-free records."""
    require(not (owner is not None and unassigned)
            and not (overdue and due_next_days is not None),
            "Conflicting private HUMAN assignment/date filters")
    require(owner is None or (local_text(owner, 64, 256) and owner.strip()),
            "Owner filter must be one bounded literal HUMAN self-declared owner")
    require(due_next_days is None or
            (type(due_next_days) is int and 0 <= due_next_days <= 90),
            "HUMAN upcoming window must be 0–90 days")
    require(stage is None or stage in single_review.STAGES,
            "Unknown HUMAN-only stage")
    today = date.today()
    last_day = today + timedelta(days=due_next_days or 0)
    selected = []
    for row in rows:
        if owner is not None and row["owner"] != owner: continue
        if unassigned and row["owner"].strip(): continue
        if pending and row["stage"] == "answered_human_only": continue
        if stage is not None and row["stage"] != stage: continue
        if overdue and not (row["due"] and date.fromisoformat(row["due"]) < today
                            and row["stage"] != "answered_human_only"): continue
        if due_next_days is not None and not (
                row["due"] and today <= date.fromisoformat(row["due"]) <= last_day
                and row["stage"] != "answered_human_only"): continue
        selected.append(row)
    require(selected, "No exact HUMAN planning items match the private work-queue filters")
    return selected


def publish(vault: Path, cockpits: list[str], destination: Path,
            include_notes: bool, include_calendar: bool, *,
            owner: str | None, unassigned: bool, pending: bool,
            overdue: bool, due_next_days: int | None, stage: str | None) -> None:
    schedule.private_parent(destination.parent)
    require(destination.is_absolute() and destination.parent == destination.parent.resolve(strict=True)
            and not destination.exists() and not destination.is_symlink() and
            vault not in destination.parents and vault != destination and
            all(Path(p).is_absolute() and
                Path(p) != destination and destination not in Path(p).parents
                and Path(p) not in destination.parents
                for p in cockpits),
            "New owner-only output must not overlap source or encrypted input")
    plan = open_vault(vault)
    admitted = admit(plan, cockpits)
    rows = select_human_work(admitted, owner=owner, unassigned=unassigned,
                             pending=pending, overdue=overdue,
                             due_next_days=due_next_days, stage=stage)
    require(not include_calendar or any(t["due"] for t in rows),
            "No scheduled HUMAN follow-up in selected private calendar queue")
    temp = destination.parent / (".lightup-human-plan-open-" + secrets.token_hex(12))
    os.mkdir(temp, 0o700)
    try:
        schedule.private_write(temp, "private-human-agenda.html",
                               private_report(rows,include_notes))
        data = {"kind":"lightup.source_free_human_schedule_native_counts",
                "version":1, "disposition":"REVIEW_ONLY",
                "authority_granted":False,"consent_verified":False,
                "remediation_verified":False,
                "human_reason_groups":len(rows),
                "human_overdue":sum(bool(t["due"] and t["due"] < date.today().isoformat()
                                        and t["stage"]!="answered_human_only") for t in rows),
                "human_unscheduled":sum(not t["due"] for t in rows),
                "human_unassigned":sum(not t["owner"].strip() for t in rows),
                "warning":WARNING}
        schedule.private_write(temp,"anonymous-counts.json",schedule.canonical(data))
        if include_calendar:
            schedule.private_write(temp,"tentative-human-calendar.ics",calendar(rows))
        require(not destination.exists(), "Private destination appeared before publish")
        workflow.workspace.exclusive_dir_publish(temp,destination)
    finally:
        if temp.exists(): shutil.rmtree(temp)
    print("REVIEW_ONLY: independently source-bound HUMAN planning brief:",destination)
    print("Original source-free groups:",len(rows))
    print("Unkeyed source hashes and encrypted notes are not consent, authority or verified fixes.")

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault",required=True,type=Path,help="PRIVATE browser-generated encrypted .lurp")
    parser.add_argument("--cockpit",required=True,action="append",
                        help="Original PRIVATE source-free Cockpit directory; 1-12x, same exact order")
    parser.add_argument("--output-dir",type=Path,required=True,
                        help="Fresh absolute 0700 output below existing private parent")
    parser.add_argument("--include-notes",action="store_true",
                        help="Include sensitive HUMAN notes in private scriptless HTML output")
    parser.add_argument("--calendar",action="store_true",
                        help="Add anonymous self-declared all-day reminders; never sends them")
    parser.add_argument("--owner", type=str,
                        help="Exact local HUMAN owner label to produce one private work queue")
    parser.add_argument("--unassigned", action="store_true",
                        help="Include only ownerless HUMAN follow-ups")
    parser.add_argument("--pending", action="store_true",
                        help="Exclude self-reported answered HUMAN tasks")
    parser.add_argument("--overdue", action="store_true",
                        help="Only locally overdue, still-pending HUMAN tasks")
    parser.add_argument("--due-next-days", type=int,
                        help="Only still-pending HUMAN tasks due within 0–90 days")
    parser.add_argument("--stage", type=str,
                        help="Exact local HUMAN stage (not a verified remediation status)")
    a=parser.parse_args()
    try:
        publish(a.vault,a.cockpit,a.output_dir,a.include_notes,a.calendar,
                owner=a.owner, unassigned=a.unassigned, pending=a.pending,
                overdue=a.overdue, due_next_days=a.due_next_days, stage=a.stage)
        return 2
    except (single_review.review.Hold,install.Hold,UnicodeError,ValueError,
            OSError,KeyError,TypeError,OverflowError,ImportError,RuntimeError,
            EOFError) as exc:
        print("HOLD: PRIVATE source-bound HUMAN schedule reopening refused: "+str(exc),
              file=sys.stderr)
        return 3
if __name__=="__main__":
    raise SystemExit(main())
