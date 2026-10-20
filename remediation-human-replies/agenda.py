#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN due-date agenda, optional local .ics export.

Uses ONLY originally selected HUMAN dates from native source-redacted .luhq,
paired with an independently admitted password-encrypted HUMAN reply .luhr.
No date inference, calendar API, reminders, automatic messages, verification,
grant, consent, source reconstruction or live target action.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import html
from pathlib import Path
import secrets
import sys

import reply

KIND = "lightup.private_selected_human_due_date_agenda.v1"
WARNING = (
    "PRIVATE HUMAN-only DRAFT/HOLD scheduling. Dates are self-declared from the "
    "original selected source-redacted handoff, not guaranteed obligations, "
    "verified findings, client consent, authenticated sender, permission, "
    "fix/retest, release, grant or HUMAN GO. No calendar API/network."
)
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;background:#edf2f7;color:#20364c;margin:0}
main{max-width:1080px;margin:1.5rem auto;padding:1rem}
aside,section,article{border:1px solid #c3d0e1;padding:1rem 1.2rem;border-radius:9px;background:white;margin:1rem 0}
aside{border-left:6px solid #aa7730}article{break-inside:avoid}
dt{font-weight:600}dd{margin:0 0 .8rem;white-space:pre-wrap;overflow-wrap:anywhere}
h1{font-size:1.8rem}small{color:#52657a}@media print{body{background:white}}
"""

def require(ok: bool, why: str) -> None:
    reply.require(ok, why)

def esc(x: object) -> str:
    return html.escape(str(x), quote=True)

def agenda_items(original: dict, returned: list[dict]) -> tuple[list[dict], list[dict]]:
    require(type(returned) is list and len(returned) == len(original["items"]),
            "Incomplete originally selected HUMAN agenda membership")
    dated = []
    unscheduled = []
    for ordinal, (source, human) in enumerate(zip(original["items"], returned), 1):
        # The unchanged original native handoff admission already validates
        # ISO dates and selected original source-free HUMAN text.
        declared = source["due"]
        if declared:
            require(type(declared) is str and len(declared) == 10
                    and date.fromisoformat(declared).isoformat() == declared,
                    "Source-declared original HUMAN due date changed")
        row = {
            "ordinal": ordinal,
            "original_human_reason": source["reason"],
            "original_human_due_date": declared or None,
            "original_human_requested_action": source["next_action"],
            "current_human_self_declared_stage": human["status"],
            "human_self_declared_question": human["question"],
            "human_self_declared_answer": human["answer"],
            "verified_remediation": False,
        }
        (dated if declared else unscheduled).append(row)
    dated.sort(key=lambda x: (x["original_human_due_date"], x["ordinal"]))
    unscheduled.sort(key=lambda x: x["ordinal"])
    return dated, unscheduled

def document(dated: list[dict], missing: list[dict]) -> bytes:
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ',
        'script-src \'none\'; style-src ', reply.hash_csp(STYLE.encode()),
        '; connect-src \'none\'; form-action \'none\'; img-src \'none\'; ',
        'object-src \'none\'; base-uri \'none\'">',
        '<title>LightUp PRIVATE source-redacted HUMAN due agenda</title>',
        '<style>', STYLE, '</style></head><body><main>',
        '<h1>PRIVATE source-redacted HUMAN follow-up calendar</h1>',
        '<aside><strong>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN ONLY</strong>',
        '<p>', esc(WARNING), '</p>',
        '<p>Only original human-supplied calendar dates are used. ',
        'A due date or answered HUMAN status never establishes a verified ',
        'technical fix or authorization. This is local offline reading only.</p></aside>',
        '<section><h2>HUMAN schedule overview</h2><p>',
        str(len(dated)), ' originally dated HUMAN selected groups · ',
        str(len(missing)), ' originally undated HUMAN selected groups.',
        '</p><p>Calendar import is optional and PRIVATE. It only includes the ',
        'dated, still-open self-declared HUMAN groups; no appointments are ',
        'sent or synchronized by this tool.</p></section>'
    ]
    for heading, records in [
        ("Originally dated HUMAN follow-ups", dated),
        ("Unscheduled HUMAN follow-ups (no invented date)", missing),
    ]:
        parts.extend(['<section><h2>', esc(heading), '</h2>'])
        if not records:
            parts.append('<p>None in this original selection.</p>')
        for task in records:
            parts.extend([
                '<article><h3>Original selected HUMAN group ',
                str(task["ordinal"]), '</h3><dl>',
                '<dt>Original selected due date</dt><dd>',
                esc(task["original_human_due_date"] or "Not provided"),
                '</dd><dt>Source-redacted HUMAN reason</dt><dd>',
                esc(task["original_human_reason"]),
                '</dd><dt>Original human-requested action</dt><dd>',
                esc(task["original_human_requested_action"] or "Not recorded"),
                '</dd><dt>Self-declared HUMAN stage</dt><dd>',
                esc(task["current_human_self_declared_stage"]),
                '</dd><dt>Human question</dt><dd>',
                esc(task["human_self_declared_question"] or "None"),
                '</dd><dt>Human answer (NOT fix evidence)</dt><dd>',
                esc(task["human_self_declared_answer"] or "None"),
                '</dd></dl><small>No authenticated client/case identity, ',
                'independent HUMAN GO, technical severity, approval, ',
                'verification or automatic closure.</small></article>'
            ])
        parts.append('</section>')
    parts.append('</main></body></html>')
    page = "".join(parts).encode("utf-8")
    require(len(page) <= 2_000_000, "Source-bound HUMAN agenda HTML too large")
    return page

def fold(line: str) -> bytes:
    """Fold one RFC 5545 content line to 75 UTF-8 OCTETS without splits."""
    result = []
    current = b""
    for ch in line:
        unit = ch.encode("utf-8")
        if len(current) + len(unit) > 75:
            result.append(current)
            current = b" " + unit
        else:
            current += unit
    result.append(current)
    return b"\r\n".join(result) + b"\r\n"

def calendar(dated: list[dict]) -> tuple[bytes, int]:
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//LightUp//PRIVATE HUMAN ONLY//EN",
        "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
        "X-WR-CALNAME:LightUp PRIVATE HUMAN follow-up (DRAFT HOLD)",
    ]
    generated = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exported = 0
    for row in dated:
        if row["current_human_self_declared_stage"] in ("answered_human_only", "declined_human"):
            # Human answered/declined != fixed, but do not autonomously
            # schedule outreach for these HUMAN-only stages.
            continue
        day = date.fromisoformat(row["original_human_due_date"])
        end = day + timedelta(days=1)
        exported += 1
        lines.extend([
            "BEGIN:VEVENT",
            "UID:" + secrets.token_hex(18) + "@lightup-human-only.invalid",
            "DTSTAMP:" + generated,
            "DTSTART;VALUE=DATE:" + day.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:" + end.strftime("%Y%m%d"),
            "CLASS:PRIVATE",
            "TRANSP:TRANSPARENT",
            "STATUS:TENTATIVE",
            "SUMMARY:PRIVATE HUMAN follow-up " + str(row["ordinal"]) + " - DRAFT HOLD",
            "DESCRIPTION:Original source-redacted HUMAN request only. No "
            "verified finding, authorized scan, fix, consent or approval.",
            "END:VEVENT",
        ])
    lines.append("END:VCALENDAR")
    content = b"".join(fold(line) for line in lines)
    require(len(content) <= 250000 and exported <= reply.original.MAX_ITEMS,
            "Generated HUMAN-only calendar outside bounded limits")
    return content, exported

def publish(original_file: Path, reply_file: Path, output: Path) -> None:
    require(original_file.is_absolute() and reply_file.is_absolute()
            and original_file != reply_file and output.is_absolute()
            and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Select separate original encrypted HUMAN inputs and NEW PRIVATE output")
    for item in (original_file, reply_file):
        require(item != output and item.parent != output
                and output not in item.parents and item not in output.parents,
                "PRIVATE HUMAN calendar input and output paths cannot overlap")
    original, key, exact_source = reply.source(original_file)
    returned, exact_reply = reply.admitted_reply(reply_file, original, key)
    dated, missing = agenda_items(original, returned)
    page = document(dated, missing)
    ics, exported = calendar(dated)
    private = reply.schedule.canonical({
        "kind": KIND, "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "warning": WARNING,
        "original_selected_source_redacted_digest": key,
        "original_selected_human_groups": len(dated) + len(missing),
        "original_declared_date_groups": len(dated),
        "original_undated_groups": len(missing),
        "calendar_tentative_private_events": exported,
        "tasks_with_declared_date": dated,
        "tasks_missing_declared_date": missing,
    })
    require(len(private) <= 2_000_000, "PRIVATE dated HUMAN record too large")
    require(reply.encrypted_cockpit.private_envelope(original_file) == exact_source
            and reply.schedule_vault.private_vault(reply_file) == exact_reply,
            "Original encrypted HUMAN due source or answer changed during export")
    reply.exclusive_output(output, [original_file, reply_file], {
        "index.html": page,
        "private-human-agenda.json": private,
        "private-human-calendar.ics": ics,
        "README.txt": (
            WARNING + "\nHTML and private-human-agenda.json contain PRIVATE "
            "HUMAN text, answers, optional original labels and requests, "
            "so treat as confidential plaintext. The .ics intentionally "
            "omits original reason, owner, question and response text, "
            "uses only originally declared dates, and does not auto-import, "
            "email, notify or contact anyone; even event timing may be "
            "PRIVATE. Manual calendar import can copy event data into "
            "an independently managed calendar service: real separate "
            "disclosure permission is mandatory. Answered/declined HUMAN "
            "groups are excluded from .ics ONLY, NOT classified as resolved.\n"
        ).encode("utf-8"),
    })
    print("REVIEW_ONLY: source-bound private HUMAN calendar:", output / "index.html")
    print("Tentative local .ics events:", exported, "; originally undated groups:", len(missing))
    print("Nothing was sent, imported, approved, scanned, granted or verified.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", required=True, type=Path,
                        help="Exact original encrypted selected HUMAN .luhq")
    parser.add_argument("--reply", required=True, type=Path,
                        help="Existing separately encrypted selected HUMAN .luhr")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="NEW separate absolute owner-private offline HUMAN calendar")
    args = parser.parse_args()
    try:
        publish(args.handoff, args.reply, args.output_dir)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            KeyError, TypeError, OverflowError, RuntimeError,
            UnicodeError, ImportError) as exc:
        print("HOLD: PRIVATE selected HUMAN calendar:", str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
