#!/usr/bin/env python3
"""LightUp private offline human agenda from original source-bound choices.

No assessment, vulnerability scoring, grants, due-date enforcement or target work.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
from hashlib import sha256
from base64 import b64encode
from html import escape
import sys

from archive import (FLAGS, Hold, MAX_MANIFEST, _manifest, read_regular,
                     decode_json, encode, publish, STYLE)
from followup import GUIDANCE, STAGES, ROLES, load_choices


AGENDA_SCHEMA = "lightup.archive_human_agenda.v1"
PRIORITY = {
    "NEEDS_PRIVACY_REVIEW": 0, "NEEDS_ORIGINAL_EVIDENCE": 1,
    "NEEDS_SOURCE_OWNER": 2, "AWAITING_INPUT": 3,
    "PENDING_ORIGINAL": 4, "HUMAN_DISCUSSION": 5,
}
DATE_BUCKETS = ("PAST_PLANNED_DATE", "PLANNED_FOR_REFERENCE_DAY", "FUTURE_PLANNED_DATE", "UNSCHEDULED")


def selected_day(text):
    if type(text) is not str or len(text) != 10:
        raise Hold("invalid agenda reference date")
    try:
        day = date.fromisoformat(text)
    except ValueError as e:
        raise Hold("invalid agenda reference date") from e
    if day.isoformat() != text or not 2020 <= day.year <= 2100:
        raise Hold("invalid agenda reference date")
    return day


def date_bucket(text, as_of):
    if text is None:
        return "UNSCHEDULED"
    candidate = selected_day(text)
    if candidate < as_of:
        return "PAST_PLANNED_DATE"
    if candidate == as_of:
        return "PLANNED_FOR_REFERENCE_DAY"
    return "FUTURE_PLANNED_DATE"


def build_agenda(original, choices, as_of, private):
    rows = []
    for source, followup in zip(original["entries"], choices):
        row = {
            "slot": source["slot"], "source_kind": source["kind"],
            "stage": followup["stage"], "next_role": followup["next_role"],
            "review_date": followup["review_date"],
            "date_bucket": date_bucket(followup["review_date"], as_of),
            "suggested_human_question": GUIDANCE[source["kind"]],
        }
        rows.append(row)
    rows.sort(key=lambda r: (
        0 if r["date_bucket"] == "PAST_PLANNED_DATE" else
        1 if r["date_bucket"] == "PLANNED_FOR_REFERENCE_DAY" else
        2 if r["date_bucket"] == "UNSCHEDULED" else 3,
        PRIORITY[r["stage"]],
        r["review_date"] or "",
        r["slot"],
    ))
    buckets = Counter(row["date_bucket"] for row in rows)
    stages = Counter(row["stage"] for row in rows)
    roles = Counter(row["next_role"] for row in rows)
    doc = {
        "schema": AGENDA_SCHEMA,
        "claimed_status": original["status"],
        "reference_date": as_of.isoformat(),
        "source_count": original["source_count"],
        "human_stage_counts": {s: stages[s] for s in STAGES},
        "neutral_role_counts": {r: roles[r] for r in ROLES},
        "date_bucket_counts": {b: buckets[b] for b in DATE_BUCKETS},
        "planning_not_permission": True,
        **{key: False for key in FLAGS},
    }
    if private:
        doc["items"] = rows
    return doc


def render_html(doc):
    private = "items" in doc
    style_hash = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    flag = doc["claimed_status"]
    if private:
        rows = "".join(
            "<tr><th scope='row'>#" + str(item["slot"]) + "</th><td>" +
            escape(item["stage"]) + "</td><td>" +
            escape(item["next_role"]) + "</td><td>" +
            escape(item["review_date"] or "Not specified") + "</td><td>" +
            escape(item["date_bucket"]) + "</td><td>" +
            escape(item["suggested_human_question"]) + "</td></tr>"
            for item in doc["items"]
        )
        headers = "<th>Source slot</th><th>Human stage</th><th>Neutral role</th><th>Proposed date</th><th>Date status</th><th>Suggested source question</th>"
        privacy = "Private ordinal source planning, not a verified case decision or identity."
    else:
        rows = "".join(
            f"<tr><th scope='row'>{escape(k)}</th><td>{v}</td></tr>"
            for k, v in doc["human_stage_counts"].items() if v
        )
        headers = "<th>Human stage</th><th>Anonymous count</th>"
        privacy = "Anonymous human stage counts only; no source identifiers, individual dates, owners or source fingerprints."
    past = doc["date_bucket_counts"]["PAST_PLANNED_DATE"]
    no_date = doc["date_bucket_counts"]["UNSCHEDULED"]
    today = doc["date_bucket_counts"]["PLANNED_FOR_REFERENCE_DAY"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{style_hash}'; img-src 'none'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp — Private Human Review Agenda</title><style>{STYLE}</style></head>
<body><header class="hero"><div class="kicker">LIGHTUP / HUMAN REVIEW AGENDA / OFFLINE</div>
<h1>Follow-up priorities</h1><p>Snapshot compared with human-selected planning reference {doc['reference_date']}.
Past proposed dates are discussion prompts only; nothing can be automatically authorized, scheduled or executed.</p>
<div class="state">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · {escape(flag)} · NOT AUTHORIZED</div></header>
<main><div class="card"><div class="kicker">Past planned dates</div><div class="big">{past}</div></div>
<div class="card"><div class="kicker">Reference-day plans</div><div class="big">{today}</div></div>
<div class="card"><div class="kicker">No planned date</div><div class="big">{no_date}</div></div></main>
<section><h2>Source-neutral human coordination</h2><p>{escape(privacy)}</p>
<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table></section>
<section><aside><h2>Not a security verdict</h2><p>A previous planned date is not a missed legal deadline,
verified finding, security severity or authorization expiry. Human work is not customer permission.
Source-owner review, original CI, privacy/security and independent authenticated customer/operator
approval remain required before any actual assessment/release.</p></aside></section>
<footer><p>Standalone, read-only local HTML. No client IDs, target endpoints, credentials, execution or network.</p></footer>
</body></html>""".encode("utf-8")


def render_markdown(doc):
    lines = [
        "# LightUp · Offline human review agenda",
        "",
        f"Planning reference: {doc['reference_date']} · status: {doc['claimed_status']}.",
        "**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**",
        "",
        "Nothing in this agenda authenticates a customer, approves a scope, verifies a fix or authorizes execution.",
        "",
        "## Human attention",
    ]
    for key in DATE_BUCKETS:
        lines.append(f"- {key}: {doc['date_bucket_counts'][key]}")
    lines.extend(["", "## Human planning stages"])
    for key in STAGES:
        lines.append(f"- {key}: {doc['human_stage_counts'][key]}")
    if "items" in doc:
        lines.extend(["", "## Private original source slots"])
        for item in doc["items"]:
            lines.append(f"- Slot {item['slot']}: {item['stage']} | {item['next_role']} | "
                         f"{item['review_date'] or 'undated'} | {item['date_bucket']}")
            lines.append(f"  - Human question: {item['suggested_human_question']}")
    lines.extend(["", "Unsigned human coordination only. Original release and consent gates unchanged.", ""])
    return "\n".join(lines).encode("utf-8")


def render_bytes(original, choices, reference, aggregate_only=False, format="html"):
    agenda = build_agenda(original, choices, selected_day(reference), not aggregate_only)
    if format == "html":
        return render_html(agenda)
    if format == "md":
        return render_markdown(agenda)
    if format == "json":
        return encode(agenda)
    raise Hold("unsupported output format")


def action(args):
    raw = read_regular(args.manifest, MAX_MANIFEST)
    original = _manifest(decode_json(raw))
    choices = load_choices(args.choices, original, sha256(raw).hexdigest())
    result = render_bytes(original, choices, args.as_of, args.aggregate_only, args.format)
    publish(args.output, result)
    print("HUMAN_REVIEW_AGENDA_CREATED — PLANNING ONLY; NOT AUTHORIZED")
    return 3 if original["status"] == "HOLD" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline human follow-up agenda; no authorization or target contact.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--choices", required=True)
    parser.add_argument("--as-of", required=True, help="Explicit human planning reference YYYY-MM-DD")
    parser.add_argument("--format", choices=("html", "md", "json"), default="html")
    parser.add_argument("--aggregate-only", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        return action(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError):
        print("HUMAN_AGENDA_HOLD — invalid or unbound private source", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
