#!/usr/bin/env python3
"""Local source-bound human follow-up on previously captured lab archive manifests."""
from __future__ import annotations

import argparse
from base64 import b64encode
from collections import Counter
from datetime import date
from hashlib import sha256
from html import escape
import json
import sys

from archive import (FLAGS, Hold, STYLE, MAX_MANIFEST, _manifest, decode_json,
                     encode, publish, read_regular)

CHOICES_SCHEMA = "lightup.archive_human_followup.v1"
SUMMARY_SCHEMA = "lightup.archive_human_followup_aggregate.v1"
STAGES = (
    "PENDING_ORIGINAL", "NEEDS_ORIGINAL_EVIDENCE", "NEEDS_SOURCE_OWNER",
    "NEEDS_PRIVACY_REVIEW", "AWAITING_INPUT", "HUMAN_DISCUSSION"
)
ROLES = ("unassigned", "source_owner", "reviewer", "privacy", "operator")

GUIDANCE = {
    "completed_lab_case_claim": "Compare source-run facts with the original isolated lab scenario and provenance.",
    "completed_lab_cohort_claim": "Check original cohort membership and source-bound baseline/candidate choices.",
    "offline_comparison_claim": "Discuss flagged source metrics using the canonical original comparator.",
    "studio_catalog_draft": "Review scenario authorship, declared ground truth and separate numeric lab bindings.",
    "other_lightup_draft": "Confirm original producer/schema and assess privacy before sharing details.",
    "private_review_zip_claim": "Inspect with the original review-pack tool and verify the responsible source owner."
}


def manifest_identity(path):
    raw = read_regular(path, MAX_MANIFEST)
    original = _manifest(decode_json(raw))
    return original, sha256(raw).hexdigest()


def draft(args):
    original, fingerprint = manifest_identity(args.manifest)
    entries = [
        {"slot": row["slot"], "source_sha256": row["sha256"],
         "stage": "PENDING_ORIGINAL", "next_role": "unassigned", "review_date": None}
        for row in original["entries"]
    ]
    document = {"schema": CHOICES_SCHEMA, "manifest_sha256": fingerprint,
                "items": entries, **{flag: False for flag in FLAGS}}
    publish(args.output, encode(document))
    print(f"PRIVATE_FOLLOWUP_DRAFT_CREATED slots={len(entries)} — NO APPROVAL")
    return 2


def _validate_date(value):
    if value is None:
        return
    if type(value) is not str or len(value) != 10:
        raise Hold("invalid date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise Hold("invalid date") from error
    if parsed.isoformat() != value or not 2020 <= parsed.year <= 2100:
        raise Hold("invalid date")


def load_choices(path, original, fingerprint):
    doc = decode_json(read_regular(path, MAX_MANIFEST))
    required = {"schema", "manifest_sha256", "items", *FLAGS}
    if (type(doc) is not dict or set(doc) != required or
            doc["schema"] != CHOICES_SCHEMA or
            doc["manifest_sha256"] != fingerprint or
            any(doc[flag] is not False for flag in FLAGS)):
        raise Hold("unbound or malformed follow-up source")
    entries = doc["items"]
    if type(entries) is not list or len(entries) != original["source_count"]:
        raise Hold("wrong follow-up count")
    for before, item in zip(original["entries"], entries):
        if type(item) is not dict or set(item) != {
            "slot", "source_sha256", "stage", "next_role", "review_date"
        }:
            raise Hold("wrong follow-up shape")
        if (type(item["slot"]) is not int or item["slot"] != before["slot"] or
                type(item["source_sha256"]) is not str or
                item["source_sha256"] != before["sha256"] or
                item["stage"] not in STAGES or item["next_role"] not in ROLES):
            raise Hold("source mismatch or invalid stage")
        _validate_date(item["review_date"])
    return entries


def html_board(original, entries, public):
    state = original["status"]
    stamp = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    stage_counts = Counter(item["stage"] for item in entries)
    if public:
        lines = "".join(f"<tr><th scope='row'>{escape(stage)}</th><td>{stage_counts[stage]}</td></tr>"
                        for stage in STAGES if stage_counts[stage])
        columns = "<th>Human follow-up stage</th><th>Count</th>"
        desc = "Counts only: no source bytes, fingerprints, role assignments, dates or original target information."
    else:
        lines = "".join(
            f"<tr><th scope='row'>#{item['slot']}</th>"
            f"<td>{escape(row['kind'])}</td>"
            f"<td>{escape(item['stage'])}</td><td>{escape(item['next_role'])}</td>"
            f"<td>{escape(item['review_date'] or 'Not selected')}</td>"
            f"<td>{escape(GUIDANCE[row['kind']])}</td></tr>"
            for row, item in zip(original["entries"], entries)
        )
        columns = "<th>Slot</th><th>Source kind</th><th>Human stage</th><th>Next role</th><th>Review date</th><th>Suggested source question</th>"
        desc = "Owner-private source-neutral human worklist. Human stage assignments are planning notes, not approval."
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'; style-src 'sha256-{stamp}'">
<title>LightUp — Lab Follow-up</title><style>{STYLE}</style></head><body>
<header class="hero"><div class="kicker">LIGHTUP / HUMAN LAB REVIEW / OFFLINE</div>
<h1>Assessment follow-up worklist</h1>
<p>Explicitly human-selected next actions for already-recorded source claims; never a permission or a clearance.</p>
<div class="state">INCUBATE M3/M7 · PLAN/LAB ONLY · {escape(state)} · NO GO</div></header>
<main><div class="card"><div class="kicker">Source slots</div><div class="big">{len(entries)}</div></div>
<div class="card"><div class="kicker">Pending original</div><div class="big">{stage_counts['PENDING_ORIGINAL']}</div></div>
<div class="card"><div class="kicker">Awaiting input</div><div class="big">{stage_counts['AWAITING_INPUT']}</div></div></main>
<section><h2>Next human conversation</h2><p>{escape(desc)}</p>
<table><thead><tr>{columns}</tr></thead><tbody>{lines}</tbody></table></section>
<section><aside><h2>No implicit completion</h2><p>None of the planning stages mean verification, approved assessment, ownership, remediation success, validated client scope, release or GO. Original evidence, independent human decisions and all authorization/CI/security gates remain outside this tool.</p></aside></section>
<footer><p>Fully local static handoff · no network, browser persistence, forms or JavaScript.</p></footer></body></html>""".encode("utf-8")


def render(args):
    original, fingerprint = manifest_identity(args.manifest)
    entries = load_choices(args.choices, original, fingerprint)
    if args.format == "html":
        result = html_board(original, entries, args.aggregate_only)
    else:
        counts = Counter(item["stage"] for item in entries)
        summary = {"schema": SUMMARY_SCHEMA, "source_count": len(entries),
                   "claimed_status": original["status"],
                   "stage_counts": dict(sorted(counts.items())),
                   **{flag: False for flag in FLAGS}}
        if not args.aggregate_only:
            summary["items"] = [
                {"slot": item["slot"], "stage": item["stage"],
                 "next_role": item["next_role"], "review_date": item["review_date"]}
                for item in entries
            ]
            # Original source SHA-256 remains in the validated input, not the portable output.
        result = encode(summary)
    publish(args.output, result)
    print("SOURCE_BOUND_HUMAN_WORKLIST_CREATED — NO APPROVAL")
    return 3 if original["status"] == "HOLD" else 2


def main(argv=None):
    p = argparse.ArgumentParser(description="Offline owner-private human follow-up; never source authorization.")
    subs = p.add_subparsers(dest="action", required=True)
    draft_p = subs.add_parser("draft", help="Create an editable private, source-bound JSON planning form")
    draft_p.add_argument("--manifest", required=True)
    draft_p.add_argument("--output", required=True)
    render_p = subs.add_parser("render", help="Review edited source-bound form and publish local human worklist")
    render_p.add_argument("--manifest", required=True)
    render_p.add_argument("--choices", required=True)
    render_p.add_argument("--output", required=True)
    render_p.add_argument("--format", choices=("html", "json"), default="html")
    render_p.add_argument("--aggregate-only", action="store_true")
    args = p.parse_args(argv)
    try:
        return draft(args) if args.action == "draft" else render(args)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError):
        print("HUMAN_FOLLOWUP_HOLD — invalid, inaccessible or unbound local source", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
