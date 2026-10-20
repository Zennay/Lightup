"""ID-free, offline HUMAN owner reply portfolio pulse.

Decrypts original source, workplan and every one-owner encrypted reply. Checks
their exact binding and produces only unverified source-claimed aggregate counts.
A checksum is NOT an authenticated owner identity, consent, fix or retest.
"""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import sys

from .private_export_encrypted import _passphrase
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_owner_exchange import (
    REPLY_MAGIC, REPLY_LIMIT, REPLY_STATES,
    _decode, _get_owner_packet, _owner_packet, _read_original, _validate_reply,
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _html(owner_count: int, record_count: int, severity: Counter, progress: Counter,
          source_total: int, assigned_count: int) -> bytes:
    def table(heading: str, labels: tuple[str, ...], counts: Counter) -> str:
        rows = "".join(
            "<tr><th>" + escape(label.replace("_", " ")) + "</th><td>" +
            str(counts.get(label, 0)) + "</td></tr>"
            for label in labels
        )
        return "<h2>" + escape(heading) + "</h2><table><thead><tr><th>Self-declared source label</th><th>Count</th></tr></thead><tbody>" + rows + "</tbody></table>"
    html = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<title>LightUp · PRIVATE HUMAN owner reply pulse</title>'
        '<style>body{font:16px system-ui;line-height:1.55;color:#172238;background:#f6f8fc;'
        'max-width:860px;margin:30px auto;padding:20px}'
        'h1{font-size:clamp(22px,4vw,34px)}h2{font-size:21px;margin-top:30px}'
        '.warning{background:#fff3d8;border-left:5px solid #b46800;padding:20px}'
        '.metrics{display:flex;flex-wrap:wrap;gap:15px;margin:25px 0}'
        '.metrics div{min-width:145px;flex:1;background:white;border:1px solid #d1dce9;'
        'border-radius:10px;padding:14px}.metrics strong{display:block;font-size:26px}'
        'table{width:100%;border-collapse:collapse;background:white}'
        'th,td{border:1px solid #d3dfea;text-align:left;padding:12px}'
        '@media print{body{background:white;margin:0;padding:0}}</style></head><body>'
        '<h1>LightUp · PRIVATE HUMAN follow-up pulse</h1>'
        '<p class="warning"><strong>HUMAN HOLD · SOURCE CLAIMS ONLY.</strong> '
        'An exact decrypted encrypted-brief checksum confirms only local data '
        'consistency. It does NOT authenticate the actual client, owner, responder, '
        'authorization, consent, finding truth, implemented remediation or retest. '
        'No original state or finding is updated. '
        'This file is UNENCRYPTED private local HTML. Small cohorts can still '
        'be identifying; verify every recipient and approved transport.</p>'
        '<div class="metrics">'
        '<div>Original source finding count<strong>' + str(source_total) + '</strong></div>'
        '<div>Original assigned finding count<strong>' + str(assigned_count) + '</strong></div>'
        '<div>Distinct returned human aliases<strong>' + str(owner_count) + '</strong></div>'
        '<div>Original findings included in replies<strong>' + str(record_count) +
        '</strong></div></div>'
        + table("Source severity for returned records (unverified)", SEVERITY_ORDER, severity)
        + table("Self-declared HUMAN progress", REPLY_STATES, progress)
        + '<p>Report excludes the original source digest, client/engagement declarations, '
        'all owner aliases, original finding IDs, titles, asset references, '
        'raw evidence and all private notes/replies. Aggregate values are '
        'not signed, authenticated or proven progress. No owner response '
        'is interpreted as a repaired finding.</p></body></html>'
    )
    return html.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE ID-free human progress pulse from exact original encrypted source"
    )
    parser.add_argument("original_source", help="original encrypted source .lue")
    parser.add_argument("original_plan", help="exact source-bound original HUMAN .lun")
    parser.add_argument("--pair", nargs=2, action="append",
                        metavar=("BRIEF_LUO", "REPLY_LUR"), required=True)
    parser.add_argument("--output", required=True, help="NEW ID-free private local .html")
    parser.add_argument("--ack-human-recipient-verification", action="store_true")
    parser.add_argument("--ack-unencrypted-private-summary", action="store_true")
    args = parser.parse_args(argv)
    try:
        if (not args.ack_human_recipient_verification or
                not args.ack_unencrypted_private_summary or
                len(args.pair) > 32):
            raise ValueError("private human review/batch limit acknowledgment missing")
        output = _output_path(args.output, ".html")
        manifest, rows, notes = _read_original(args.original_source, args.original_plan)
        owners: set[str] = set()
        identifiers: set[str] = set()
        severity, progress = Counter(), Counter()
        for brief_path, response_path in args.pair:
            phrase = _passphrase("Encrypted one-owner brief passphrase")
            brief, original_cipher = _get_owner_packet(brief_path, phrase)
            del phrase
            if brief != _owner_packet(manifest, rows, notes, brief["owner_alias"]):
                raise ValueError("brief does not match exact original source or HUMAN plan")
            alias = brief["owner_alias"]
            if alias in owners:
                raise ValueError("repeated owner alias is not a distinct response")
            owners.add(alias)
            response_phrase = _passphrase("Encrypted HUMAN owner reply passphrase")
            response, _ = _decode(response_path, response_phrase, REPLY_MAGIC, REPLY_LIMIT)
            del response_phrase
            valid = _validate_reply(response, brief, original_cipher)
            original = {item["source"]["finding_id"]: item["source"] for item in brief["records"]}
            for item in valid:
                identity = item["finding_id"]
                if identity in identifiers:
                    raise ValueError("overlapping original finding in owner portfolio")
                identifiers.add(identity)
                severity[original[identity]["severity"]] += 1
                progress[item["reported_human_state"]] += 1
        assigned_count = sum(bool(notes[row["finding_id"]]["owner_alias"]) for row in rows)
        content = _html(len(owners), len(identifiers), severity, progress,
                        len(rows), assigned_count)
        _atomic_private_publish(output, content)
        print("Created PRIVATE ID-free source-bound HUMAN response pulse.")
        print("No actual owner identity, client consent, completed fix or retest verified.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("HUMAN PULSE HOLD: source, owner/reply binding, privacy or output invalid.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
