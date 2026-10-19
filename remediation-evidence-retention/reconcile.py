#!/usr/bin/env python3
"""PRIVATE HUMAN retention Request Desk reconciliation from original workrooms.

Compares our previously source-bound staged draft requests to another separately
decrypted ORIGINAL-native HUMAN workroom after fresh original authentication.
Never asserts that native Apply happened, that identity was signed, or that a
remediation, retest, actual evidence disposal or legal-hold release occurred.
"""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
from pathlib import Path
import sys

import retention as retention
import request_handoff as handoff

original = retention.transfer
MAX_HTML = 256 * 1024


def _private_workroom(path: Path, args, vault, original_envelope: dict,
                      original_packet: dict, original_csv: bytes):
    if path.suffix.lower() != ".ltv":
        raise ValueError("Original-compatible encrypted HUMAN .ltv required.")
    raw = vault._private_input(path.expanduser().absolute(), vault.MAX_VAULT)
    password = vault._password("Existing PRIVATE HUMAN workroom passphrase: ", fresh=False)
    payload, mime, _ = vault._open(raw, password)
    if mime != "application/json":
        raise ValueError("Invalid source-native encrypted HUMAN MIME.")
    meta, csv_raw, human = original.human._admit_workspace(payload)
    if csv_raw != original_csv or any(
        meta[field] != original_envelope[field] for field in (
            "original_csv_sha256", "original_finding_count",
            "client_reference", "engagement_reference",
            "original_source_digest")
    ):
        raise ValueError("Encrypted HUMAN workroom is not bound to CURRENT original source.")
    packet = original.human._packet(
        human, source_digest=original_packet["source_sha256"],
        count=original_packet["source_count"], client=args.client_id,
        engagement=args.engagement_id)
    original.native._records(packet, original._current_rows(original_csv))
    if packet["attachments"] != original_packet["attachments"]:
        raise ValueError("Original indexed private attachment inventory changed.")
    return packet


def _admit_staged(baseline: dict, staging: dict, items: list[dict]) -> list[dict]:
    for key in ("casework", "evidence_review", "attachments", "warning",
                "source_sha256", "source_count", "client_reference",
                "engagement_reference"):
        if baseline.get(key) != staging.get(key):
            raise ValueError("Staged original human workroom source or earlier data changed.")
    earlier = baseline.get("human_requests", [])
    staged = staging.get("human_requests", [])
    if type(earlier) is not list or type(staged) is not list or (
        staged[:len(earlier)] != earlier):
        raise ValueError("Staging changed original previously existing HUMAN requests.")
    fresh = staged[len(earlier):]
    if not fresh or len(fresh) > len(items):
        raise ValueError("No bounded new original HUMAN retention questions.")
    eligible = {}
    for item in items:
        if item["review_on"] <= __import__("datetime").date.today().isoformat():
            eligible.setdefault(item["finding_id"], set()).add(item["sha256"])
    existing_open = {row["finding_id"] for row in earlier
                     if row["human_stage"] != "closed_human"}
    known = set()
    for row in fresh:
        if (row["request_id"] in known or
                row["finding_id"] in existing_open or
                row["finding_id"] not in eligible or
                row["linked_sha256"] not in eligible[row["finding_id"]] or
                row["request_kind"] != "followup_question" or
                row["human_stage"] != "draft" or
                row["human_response"] or row["assignee"] or row["due_date"] or
                not row["instructions"].startswith(handoff.INTRO)):
            raise ValueError("Staged draft identity not linked to due current original retention.")
        known.add(row["request_id"])
    if len({row["finding_id"] for row in fresh}) != len(fresh):
        raise ValueError("Multiple new staged requests for one finding.")
    return fresh


def _reconcile(staged: list[dict], later: dict) -> tuple[list[dict], dict]:
    available = {record["request_id"]: record
                 for record in later.get("human_requests", [])}
    summary = Counter()
    rows = []
    for original_request in staged:
        later_request = available.get(original_request["request_id"])
        if later_request is None:
            status = "not_observed_in_supplied_later_human_workroom"
            changed = False
            modified = False
        else:
            if any(later_request[key] != original_request[key] for key in (
                    "request_id", "finding_id", "request_kind", "linked_sha256")):
                raise ValueError("Original staged request identity rebinding attempted.")
            status = later_request["human_stage"]
            changed = status != "draft"
            modified = any(later_request[k] != original_request[k] for k in
                           ("instructions", "assignee", "due_date", "human_response"))
        summary[status] += 1
        if modified:
            summary["human_content_edited"] += 1
        if changed:
            summary["reported_human_stage_changed"] += 1
        rows.append({
            "finding": original_request["finding_id"],
            "fingerprint": original_request["linked_sha256"],
            "request": original_request["request_id"],
            "status": status,
            "modified": modified,
        })
    summary["staged"] = len(staged)
    return rows, dict(summary)


def _html(rows: list[dict], stats: dict, digest: str) -> bytes:
    e = lambda val: escape(str(val), quote=True)
    html_rows = []
    for row in rows:
        html_rows.append("<tr><td><bdi>" + e(row["finding"]) +
                         "</bdi></td><td>" + e(row["request"][:12]) +
                         "…</td><td>" + e(row["fingerprint"][:12]) +
                         "…</td><td>" + e(row["status"]) +
                         "</td><td>" + ("HUMAN text changed — review manually"
                                       if row["modified"] else "No textual change observed") +
                         "</td></tr>")
    rendered = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; script-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN request handoff reconciliation</title>
<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:1rem;background:#f7f7f7;color:#222;line-height:1.5}article{background:white;padding:1rem;border-left:5px solid #444}table{width:100%;background:white;border-collapse:collapse;margin-top:1rem}th,td{padding:.7rem;border:1px solid #aaa;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eee}bdi{unicode-bidi:isolate}</style>
</head><body><h1>PRIVATE HUMAN retention Request Desk continuity</h1>
<article><strong>Human workroom comparison only.</strong>
Matching encrypted files and original source do NOT prove original native Apply,
signed reviewer identity, actual request execution, retention-law compliance,
client authorization, legal hold release, data deletion, remediation or retest.
A missing request may simply mean the supplied later HUMAN workroom did not
receive the staged draft.</article><p>Staged human questions: """ + str(stats.get("staged", 0)) + """
 · HUMAN stage differences: """ + str(stats.get("reported_human_stage_changed", 0)) + """
 · Changed private request text: """ + str(stats.get("human_content_edited", 0)) + """
 · Not observed: """ + str(stats.get("not_observed_in_supplied_later_human_workroom",0)) + """</p>
<small>Current ORIGINAL authorized source fingerprint: """ + e(digest) + """</small>
<table><caption>Original source-bound HUMAN request IDs and local stage observations</caption>
<thead><tr><th>Finding (unverified)</th><th>Request ID prefix</th><th>Material SHA prefix</th><th>Later HUMAN status</th><th>Follow-up</th></tr></thead>
<tbody>""" + "".join(html_rows) + """</tbody></table><p>""" + e(retention.WARNING) + """</p></body></html>"""
    return rendered.encode("utf-8", "strict")


def operate(args, vault) -> int:
    original_envelope, baseline, indexed, _ = original.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    items, _ = retention._load_current_plan(args, vault, baseline, indexed)
    current_csv = original.human._unb64(
        original_envelope["original_csv_base64"], original.ORIGINAL.MAX_CSV_BYTES)
    staged = _private_workroom(args.drafts, args, vault, original_envelope,
                               baseline, current_csv)
    fresh = _admit_staged(baseline, staged, items)
    later = _private_workroom(args.later, args, vault, original_envelope,
                              baseline, current_csv)
    rows, stats = _reconcile(fresh, later)
    print("Current original-account/source and local PRIVATE material match.")
    print("Staged HUMAN drafts:", stats.get("staged",0),
          "· reported HUMAN stage changes:", stats.get("reported_human_stage_changed",0))
    print("No original native Apply, actual client authorization, remediation or deletion inferred.")
    if args.action == "inspect":
        return 0
    target = args.output.expanduser().absolute()
    if target.suffix.lower() != ".html" or target in {
        args.human.expanduser().absolute(), args.plan.expanduser().absolute(),
        args.drafts.expanduser().absolute(), args.later.expanduser().absolute()
    }:
        raise ValueError("Distinct NEW owner-private HTML output required.")
    body = _html(rows, stats, baseline["source_sha256"])
    if len(body) > MAX_HTML:
        raise ValueError("PRIVATE original HUMAN continuity output too large.")
    vault._exclusive_output(target, body)
    print("NEW 0600 private offline scriptless HUMAN continuity HTML published.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for operation in ("inspect", "publish"):
        p = subs.add_parser(operation)
        for field in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + field, required=True)
        for field in ("human", "directory", "plan", "drafts", "later"):
            p.add_argument("--" + field, type=Path, required=True)
        if operation == "publish":
            p.add_argument("--output", type=Path, required=True)
        p.add_argument("--ack-private-review", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_review or not sys.stdin.isatty():
            raise ValueError("Interactive HUMAN review terminal required.")
        if args.drafts.expanduser().absolute() == args.later.expanduser().absolute():
            raise ValueError("Two distinct native original-human workrooms required.")
        return operate(args, original.ORIGINAL._vault())
    except Exception:
        print("HUMAN HOLD: No original source-current PRIVATE request continuity report "
              "published. Later HUMAN workroom status is not proof of Apply or authority.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
