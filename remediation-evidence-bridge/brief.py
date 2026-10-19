#!/usr/bin/env python3
"""LightUp offline encrypted source-severity briefing (counts-only, HUMAN planning).

Reads the source-bound encrypted Evidence Ledger; never opens HTML, targets or
the scanner. Optionally re-authenticates the exact existing client/engagement.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
from getpass import GetPassWarning

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_original_authenticated_evidence_bridge", Path(__file__).with_name("bridge.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Original Evidence Ledger bridge unavailable.")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

COLUMNS = ("source_severity_claim", "source_retest_claim", "finding_count")
SEVERITIES = ("critical", "high", "medium", "low", "info")
RETEST = ("not_tested", "fix_pending", "fixed", "regression")


def _source_summary(data: dict) -> dict[tuple[str, str], int]:
    """The ORIGINAL five-column source is validated in bridge._read_envelope."""
    raw = base64.b64decode(data["source_csv_base64"], validate=True)
    text = raw.decode("utf-8", "strict")
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    if tuple(reader.fieldnames or ()) != bridge.original.COLUMNS:
        raise ValueError("Original protected CSV columns changed.")
    counts = {(severity, status): 0 for severity in SEVERITIES for status in RETEST}
    observed = 0
    for row in reader:
        if None in row or row.get(None) is not None:
            raise ValueError("Original protected CSV row changed.")
        severity = row["severity"]
        status = row["retest_status"]
        if (severity, status) not in counts:
            raise ValueError("Invalid original source severity/retest status.")
        counts[(severity, status)] += 1
        observed += 1
    if observed != data["original_finding_count"]:
        raise ValueError("Original source finding count drift.")
    return counts


def _render(counts: dict[tuple[str, str], int], *, fmt: str) -> bytes:
    summary = [
        "LightUp / anonymous original-source claim counts / HUMAN review only",
        "These are originally reported severity and retest LABELS, NOT independent findings,",
        "confirmed remediations, authorization, consent, verified retests or release.",
        "Status: INCUBATE M3/M7 PLAN/LAB ONLY / DRAFT HOLD."
    ]
    if fmt == "markdown":
        rows = ["# Original-source HUMAN evidence triage · ANONYMOUS",
                "", *summary, "",
                "| Source severity label | Source retest label | Finding count |",
                "|---|---|---:|"]
        for severity in SEVERITIES:
            for status in RETEST:
                count = counts[(severity, status)]
                if count:
                    rows.append(f"| {severity} | {status} | {count} |")
        rows += ["", "Zero is no local source count; source-reported fixed is NOT a verified fix.",
                 "No original ID, title, remediation, source hash, account, client or engagement disclosed."]
        return ("\n".join(rows) + "\n").encode("utf-8")
    target = io.StringIO(newline="")
    writer = csv.writer(target, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    writer.writerow(COLUMNS)
    for severity in SEVERITIES:
        for status in RETEST:
            count = counts[(severity, status)]
            if count:
                writer.writerow((severity, status, count))
    # CSV is a counts-only data format. Do not attach client/source identity in the output.
    return ("\ufeff" + target.getvalue()).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True, help="Existing owner-private original Evidence Ledger .ltv")
    p.add_argument("--format", choices=("markdown", "csv"), default="markdown")
    p.add_argument("--output", type=Path, help="NEW private .md/.csv in an owner-only directory; otherwise anonymous terminal counts")
    p.add_argument("--current", action="store_true", help="Re-authenticate genuine original client/engagement read and exact source")
    for name in ("db", "email", "client-id", "engagement-id"):
        p.add_argument("--" + name, help="Required only with --current")
    args = p.parse_args(argv)
    try:
        if args.input.suffix.lower() != ".ltv":
            raise ValueError("Original encrypted Evidence Ledger .ltv required.")
        if args.output and args.output.suffix.lower() != (".md" if args.format == "markdown" else ".csv"):
            raise ValueError("Output format does not match selected filename.")
        current = None
        if args.current:
            if any(not value for value in (args.db, args.email, args.client_id, args.engagement_id)):
                raise ValueError("All original authentication fields required for --current.")
            original_csv = bridge.original._authorized_summary(db=args.db, email=args.email,
                client_id=args.client_id, engagement_id=args.engagement_id)
            current = bridge.original._strict_summary(original_csv)
        elif any(value is not None for value in (args.db, args.email, args.client_id, args.engagement_id)):
            raise ValueError("Original account selectors require --current.")
        vault = bridge.original._vault()
        encrypted = vault._private_input(args.input.expanduser().absolute(), vault.MAX_VAULT)
        password = vault._password("PRIVATE Evidence Ledger passphrase (anonymous brief): ", fresh=False)
        payload, mime, _ = vault._open(encrypted, password)
        if mime != "application/json":
            raise ValueError("Unexpected encrypted source content.")
        data, _ = bridge._read_envelope(payload)
        if args.current and (
            data["client_reference"] != args.client_id or
            data["engagement_reference"] != args.engagement_id or
            (data["original_csv_sha256"], data["original_finding_count"]) != current
        ):
            raise ValueError("Original source changed or account cannot access: HUMAN HOLD.")
        counts = _source_summary(data)
        result = _render(counts, fmt=args.format)
        if args.output:
            vault._exclusive_output(args.output.expanduser().absolute(), result)
            print("One NEW 0600 original-source counts-only HUMAN brief created.")
            print("No source ID, finding details, real-world target or proof of remediation published.")
        else:
            sys.stdout.buffer.write(result)
        return 0
    except Exception:
        print("HOLD: Source-bound anonymous brief unavailable; review encrypted source and original account permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
