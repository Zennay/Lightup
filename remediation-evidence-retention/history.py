#!/usr/bin/env python3
"""PRIVATE original-source-bound HUMAN retention-plan revision history.

Human-provided file order is NOT an authenticated chronology. Every native
plan is decrypted only after an original current-account/source read and full
private actual-material fingerprint admission. No targets, deletion, grants,
remediation, releases or test activity.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
from html import escape
from pathlib import Path
import sys

import retention as native

MAX_PLANS = 12
MAX_OUTPUT = 512 * 1024
KIND = "PRIVATE_UNVERIFIED_HUMAN_REVIEW_HISTORY"


def _open_plans(args, vault, packet, indexed):
    files, receipt_digest = native._read_material(
        args.directory, packet, indexed, vault)
    if not 2 <= len(args.plan) <= MAX_PLANS:
        raise ValueError("Exactly 2–12 original native encrypted review plans required.")
    snapshots = []
    seen_cipher = set()
    for ordinal, path in enumerate(args.plan, 1):
        if path.suffix.lower() != ".ltv":
            raise ValueError("Only original private encrypted retention .ltv accepted.")
        encrypted = vault._private_input(path.expanduser().absolute(), vault.MAX_VAULT)
        digest = native.transfer.digest(encrypted)
        if digest in seen_cipher:
            raise ValueError("Duplicate encrypted HUMAN plan in claimed sequence.")
        seen_cipher.add(digest)
        password = vault._password(
            f"Existing PRIVATE retention-plan #{ordinal} passphrase: ", fresh=False)
        plain, mime, _ = vault._open(encrypted, password)
        if mime != "application/json":
            raise ValueError("Noncanonical private review content type.")
        items = native._admit_plan(plain, files, receipt_digest, packet)
        snapshots.append({"digest": digest, "items": items})
    return files, snapshots


def _row_deltas(files: list[dict], snapshots: list[dict]) -> tuple[list[dict], dict]:
    today = date.today().isoformat()
    rows = []
    aggregate = Counter()
    for pos, file in enumerate(files):
        states = [snapshot["items"][pos] for snapshot in snapshots]
        changes = []
        for n in range(1, len(states)):
            former = states[n - 1]
            later = states[n]
            changed = [field for field in ("decision", "review_on", "note")
                       if former[field] != later[field]]
            if not changed:
                continue
            legal_release = (former["decision"] == "legal_hold"
                             and later["decision"] != "legal_hold")
            changes.append({"from": n, "to": n + 1, "fields": changed,
                            "legal_caution": legal_release})
            aggregate["changed_steps"] += 1
            if legal_release:
                aggregate["legal_review_required"] += 1
        current = states[-1]
        if current["review_on"] <= today:
            aggregate["human_reviews_due"] += 1
        aggregate["file_count"] += 1
        if changes:
            aggregate["files_changed"] += 1
        rows.append({"file": file, "initial": states[0], "current": current,
                     "changes": changes})
    return rows, dict(aggregate)


def _render(rows: list[dict], snapshots: list[dict], aggregate: dict,
            current_source: str) -> bytes:
    fmt = lambda value: escape(str(value), quote=True)
    def display(value):
        return "<bdi>" + fmt(value) + "</bdi>"
    table = []
    for r in rows:
        changes = ", ".join(
            f'{event["from"]}→{event["to"]}: {"/".join(event["fields"])}'
            + (" · LEGAL HOLD RELEASE REVIEW REQUIRED" if event["legal_caution"] else "")
            for event in r["changes"]
        ) or "No user-selected revision difference"
        current = r["current"]
        cell = ("HUMAN REVIEW DUE"
                if current["review_on"] <= date.today().isoformat()
                else "Scheduled")
        table.append("<tr><td>" + display(r["file"]["stored_as"]) +
                     "</td><td>" + display(r["file"]["finding_id"]) +
                     "</td><td>" + display(r["initial"]["decision"]) +
                     "</td><td>" + display(current["decision"]) +
                     "</td><td>" + display(current["review_on"]) +
                     "</td><td>" + fmt(cell) +
                     "</td><td>" + fmt(changes) + "</td></tr>")
    stages = "".join("<li>Operator-selected slot " + str(i + 1)
                     + " · encrypted private plan SHA-256: "
                     + fmt(snap["digest"]) + "</li>"
                     for i, snap in enumerate(snapshots))
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'; script-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>PRIVATE HUMAN retention revision desk</title>
<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:1rem;line-height:1.5;background:#f7f7f7;color:#222}table{width:100%;border-collapse:collapse;background:white}td,th{border:1px solid #aaa;padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eee}.notice{border-left:5px solid #333;padding:1rem;background:white}bdi{unicode-bidi:isolate}</style>
</head><body><h1>PRIVATE HUMAN retention review revisions</h1>
<div class="notice">HUMAN REVIEW ONLY. Selected plan order is user supplied, NOT a verified chronology or signed reviewer sequence.
No automatic deletion, legal-hold release, client approval, consent, grant, evidence provenance, fix or retest.
Changing a HUMAN legal_hold status NEVER authorizes actual deletion.</div>
<p>Private files: """ + str(aggregate.get("file_count",0)) + """
 · Changed rows: """ + str(aggregate.get("files_changed",0)) + """
 · Transition events: """ + str(aggregate.get("changed_steps",0)) + """
 · Human reviews due: """ + str(aggregate.get("human_reviews_due",0)) + """
 · Legal-review cautions: """ + str(aggregate.get("legal_review_required",0)) + """</p>
<p>Current original authenticated source fingerprint: """ + fmt(current_source) + """</p>
<details><summary>Encrypted input identity (local and sensitive)</summary><ol>""" + stages + """</ol></details>
<table><caption>Human revisions — original evidence bytes and receipt fully rechecked</caption>
<thead><tr><th>Neutral file</th><th>Original finding (unverified)</th><th>First human status</th><th>Current human status</th><th>Next review</th><th>Attention</th><th>Operator-selected differences</th></tr></thead><tbody>""" + "".join(table) + """</tbody></table>
<p>""" + fmt(native.WARNING) + """</p></body></html>"""
    return html.encode("utf-8", "strict")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--human", type=Path, required=True,
                   help="Existing ORIGINAL source-current encrypted HUMAN evidence workroom")
    p.add_argument("--directory", type=Path, required=True,
                   help="Actual existing 0700 recipient PRIVATE evidence folder")
    p.add_argument("--plan", type=Path, action="append", required=True,
                   help="2–12 DISTINCT existing encrypted PRIVATE retention .ltv in HUMAN selected order")
    p.add_argument("--output", type=Path, required=True,
                   help="NEW 0600 HTML; private, scriptless and offline")
    p.add_argument("--ack-private-material", action="store_true")
    args = p.parse_args(argv)
    try:
        if (not args.ack_private_material or not sys.stdin.isatty()
                or not 2 <= len(args.plan) <= MAX_PLANS):
            raise ValueError("Interactive HUMAN private-source acknowledgement and 2–12 plans required.")
        output = args.output.expanduser().absolute()
        if (output.suffix.lower() != ".html"
                or output == args.human.expanduser().absolute()
                or output in {p.expanduser().absolute() for p in args.plan}):
            raise ValueError("Separate new private HTML path required.")
        vault = native.transfer.ORIGINAL._vault()
        packet, indexed, _ = native._current(args, vault)
        files, snapshots = _open_plans(args, vault, packet, indexed)
        rows, aggregate = _row_deltas(files, snapshots)
        result = _render(rows, snapshots, aggregate, packet["source_sha256"])
        if len(result) > MAX_OUTPUT:
            raise ValueError("PRIVATE HTML revision report exceeds bounded size.")
        vault._exclusive_output(output, result)
        print("New private 0600 scriptless HUMAN revision history created.")
        print("Plan slots:", len(snapshots), "· files:", len(files))
        print("Changed files:", aggregate.get("files_changed",0),
              "· human review due:", aggregate.get("human_reviews_due",0))
        print("No active authorization, remediation, release or evidence deletion.")
        return 0
    except Exception:
        print("HUMAN HOLD: Original current login/source, native receipt, actual file bytes,"
              " encrypted review admission, bounds or private output unavailable. "
              "No complete HTML published.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
