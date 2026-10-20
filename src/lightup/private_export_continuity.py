"""Offline human-only continuity of two source-bound PRIVATE finding handoffs.

No client authenticated here; archive digest equality is not an authority grant,
and disappearing records are NOT verified fixes. Outputs are private local HTML.
"""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import sys

from .private_export_handoff import (
    _atomic_private_publish,
    _output_path,
    _read_archive,
)

_COLUMNS = ("title", "severity", "retest_status", "remediation")


def _source_comparison(before: list[dict[str, str]], after: list[dict[str, str]]) -> dict:
    old = {record["finding_id"]: record for record in before}
    new = {record["finding_id"]: record for record in after}
    added = set(new) - set(old)
    absent = set(old) - set(new)
    common = set(old) & set(new)
    changed = {identifier for identifier in common
               if any(old[identifier][field] != new[identifier][field] for field in _COLUMNS)}
    fields = Counter(field for identifier in changed for field in _COLUMNS
                     if old[identifier][field] != new[identifier][field])
    severity_moves = Counter(
        (old[identifier]["severity"], new[identifier]["severity"]) for identifier in changed
        if old[identifier]["severity"] != new[identifier]["severity"])
    status_moves = Counter(
        (old[identifier]["retest_status"], new[identifier]["retest_status"])
        for identifier in changed
        if old[identifier]["retest_status"] != new[identifier]["retest_status"])
    details = []
    for identifier in sorted(set(old) | set(new)):
        if identifier in added:
            details.append((identifier, "new original source record", "—", "—"))
        elif identifier in absent:
            details.append((identifier, "absent from newer export; NOT fixed", "—", "—"))
        elif identifier in changed:
            field_names = ", ".join(
                field for field in _COLUMNS
                if old[identifier][field] != new[identifier][field])
            details.append((identifier, "source content changed", field_names,
                            old[identifier]["retest_status"] + " → " + new[identifier]["retest_status"]))
    return {
        "old_count": len(before), "new_count": len(after),
        "added": len(added), "absent": len(absent), "changed": len(changed),
        "unchanged": len(common) - len(changed), "fields": fields,
        "severity_moves": severity_moves, "status_moves": status_moves,
        "details": details,
    }


def _table(items: list[tuple[str, int]]) -> str:
    return (
        '<table><thead><tr><th scope="col">Human follow-up category</th>'
        '<th scope="col">Source count</th></tr></thead><tbody>' +
        "".join('<tr><th scope="row">' + escape(label) + '</th><td>' + str(number) +
                "</td></tr>" for label, number in items) + "</tbody></table>"
    )


def _html(delta: dict, private_ids: bool) -> str:
    overview = [
        ("Earlier original-source records", delta["old_count"]),
        ("Later original-source records", delta["new_count"]),
        ("Newly present IDs — new source claims", delta["added"]),
        ("Absent IDs — NOT resolved", delta["absent"]),
        ("Changed original source records", delta["changed"]),
        ("Unchanged compared source records", delta["unchanged"]),
    ]
    changed_fields = [(name, delta["fields"][name]) for name in _COLUMNS]
    severity = [
        (old + " → " + new, number) for (old, new), number
        in sorted(delta["severity_moves"].items())
    ]
    retest = [
        (old + " → " + new, number) for (old, new), number
        in sorted(delta["status_moves"].items())
    ]
    detail = ""
    if private_ids:
        detail = (
            "<h2>PRIVATE original IDs requiring human source review</h2>"
            "<p>These self-described IDs must not be redistributed as an anonymous report. "
            "Any changed source record requires independent human re-binding before interpreting "
            "existing owner notes, evidence or remediation.</p>"
            '<table><thead><tr><th>Original ID</th><th>Source change</th>'
            '<th>Changed source fields</th><th>Source retest labels</th></tr></thead><tbody>' +
            "".join(
                "<tr><td>" + escape(identifier) + "</td><td>" + escape(state) +
                "</td><td>" + escape(fields) + "</td><td>" + escape(status) + "</td></tr>"
                for identifier, state, fields, status in delta["details"]
            ) + "</tbody></table>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<title>LightUp — PRIVATE source continuity</title>'
        '<style>body{font:16px system-ui;line-height:1.5;max-width:920px;margin:4vh auto;padding:24px;color:#16202e}'
        'h1{font-size:2rem}table{border-collapse:collapse;width:100%;margin:15px 0 30px}'
        'th,td{padding:10px;border:1px solid #cbd5e1;text-align:left;vertical-align:top;overflow-wrap:anywhere}'
        '.warning{padding:15px;border-left:4px solid #92400e;background:#fffbeb}'
        '@media print{body{margin:0;padding:0}}</style><body>'
        '<h1>LightUp · original source continuity</h1>'
        '<p>PRIVATE, offline, non-authorizing comparison of two explicit export snapshots.</p>'
        '<div class="warning"><strong>HUMAN HOLD.</strong> Matching declared client and engagement '
        'labels and matching source checksums do not authenticate identity, permission, evidence or '
        'remediation. <strong>Absent ≠ fixed</strong>, changed status ≠ verified retest, and even a '
        'stable source ID is not proof of real-world identity. Independent human owner review '
        'is required. No active tests, scans or grants were created.</div>'
        "<h2>Original source membership</h2>" + _table(overview) +
        "<h2>Changed original source field counts</h2>" + _table(changed_fields) +
        "<h2>Source severity transitions (not verified)</h2>" + _table(severity) +
        "<h2>Source retest-label transitions (not verified)</h2>" + _table(retest) + detail +
        "<p>Report deliberately excludes original client/engagement labels, assets, titles, "
        "remediation, source digests and evidence. Optional detailed mode contains original IDs; "
        "all reports require private recipient/privacy review.</p></body></html>"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PRIVATE offline evidence source continuity; never authorize or infer fixes")
    parser.add_argument("earlier", help="original earlier PRIVATE ZIP")
    parser.add_argument("later", help="original later PRIVATE ZIP")
    parser.add_argument("--output", required=True, help="new .html output file, never overwritten")
    parser.add_argument("--acknowledge-same-client", action="store_true",
                        help="human independently confirms the real client and engagement, not only labels")
    parser.add_argument("--ack-private-plaintext", action="store_true")
    parser.add_argument("--include-original-ids", action="store_true",
                        help="include original IDs for PRIVATE human investigation (never anonymous)")
    args = parser.parse_args(argv)
    try:
        if not args.acknowledge_same_client or not args.ack_private_plaintext:
            raise ValueError("explicit human context and plaintext acknowledgments are required")
        target = _output_path(args.output, ".html")
        old_manifest, before = _read_archive(args.earlier)
        new_manifest, after = _read_archive(args.later)
        if (old_manifest["declared_client_id"] != new_manifest["declared_client_id"] or
                old_manifest["declared_engagement_id"] != new_manifest["declared_engagement_id"]):
            raise ValueError("claimed client or engagement mismatch")
        # This is deliberately a declaration consistency check, NOT authentication.
        delta = _source_comparison(before, after)
        _atomic_private_publish(target, _html(delta, args.include_original_ids).encode("utf-8"))
        print("Created PRIVATE human source-continuity brief; no fixes, identity or permissions verified.")
        return 0
    except (OSError, ValueError, PermissionError):
        print("PRIVATE source continuity HOLD: mismatched, invalid or inaccessible source/output.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
