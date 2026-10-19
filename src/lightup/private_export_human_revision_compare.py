"""Source-ciphertext-exact offline HUMAN decision revision comparison.

Compares two independently decrypted v2 .lud decisions against the SAME
three original encrypted .lue/.lun/.lue files. Report is a private scriptless
0600 HTML, ID-free by default; original IDs/titles require explicit opt-in.
No finding, original evidence, grant, decision ciphertext or plan is mutated.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from html import escape
import sys

from .private_export_encrypted import _passphrase
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_human_revision_vault import (
    _current_source, _read_decisions, _reconcile, _source_binding,
)

_SEVERITY = ("critical", "high", "medium", "low", "info")
_STATE = {
    (False, False): "not selected",
    (True, False): "HUMAN owner and note",
    (True, True): "HUMAN owner, note, proposed stage and date",
}


def _delta(before: dict, after: dict, canonical: dict) -> tuple[dict, list[dict[str, str]]]:
    old = before["decisions"]
    new = after["decisions"]
    expected = canonical["decisions"]
    if len(old) != len(new) or len(new) != len(expected):
        raise ValueError("original source decision membership mismatch")
    movements = Counter()
    severity_changes = Counter()
    changed = []
    for first, second, source in zip(old, new, expected):
        if first["finding_id"] != source["finding_id"] or second["finding_id"] != source["finding_id"]:
            raise ValueError("unexpected original finding identity drift")
        original = (first["copy_owner_and_note"], first["copy_stage_and_due"])
        updated = (second["copy_owner_and_note"], second["copy_stage_and_due"])
        if original == updated:
            continue
        # Both decision files were already admitted through original parser;
        # use only their bounded boolean states, never original fix contents.
        if original not in _STATE or updated not in _STATE:
            raise ValueError("invalid source-bound HUMAN decision state")
        direction = _STATE[original] + " → " + _STATE[updated]
        movements[direction] += 1
        severity_changes[source["severity"]] += 1
        changed.append({
            "id": source["finding_id"],
            "title": source["title"],
            "severity": source["severity"],
            "from": _STATE[original],
            "to": _STATE[updated],
        })
    changed.sort(key=lambda row: (
        _SEVERITY.index(row["severity"]) if row["severity"] in _SEVERITY else 9,
        row["id"],
    ))
    return {
        "source_findings": len(expected),
        "changed_human_decisions": len(changed),
        "unchanged_human_decisions": len(expected) - len(changed),
        "old_selected": sum(row["copy_owner_and_note"] for row in old),
        "new_selected": sum(row["copy_owner_and_note"] for row in new),
        "old_stage_dates": sum(row["copy_stage_and_due"] for row in old),
        "new_stage_dates": sum(row["copy_stage_and_due"] for row in new),
        "transition_counts": dict(sorted(movements.items())),
        "severity_counts": {
            level: severity_changes[level] for level in _SEVERITY
            if severity_changes[level]
        },
    }, changed


def _render(summary: dict, changes: list[dict[str, str]], private_ids: bool) -> bytes:
    def data_table(records: list[tuple[str, str]]) -> str:
        return (
            "<table><tbody>" + "".join(
                "<tr><th scope='row'>" + escape(label) + "</th><td>" +
                escape(value) + "</td></tr>" for label, value in records
            ) + "</tbody></table>"
        )
    overview = data_table([
        ("Original later-source findings", str(summary["source_findings"])),
        ("Changed HUMAN-only decisions", str(summary["changed_human_decisions"])),
        ("Unchanged HUMAN decisions", str(summary["unchanged_human_decisions"])),
        ("Earlier HUMAN owner/note selections", str(summary["old_selected"])),
        ("Later HUMAN owner/note selections", str(summary["new_selected"])),
        ("Earlier HUMAN proposed stage/date selections", str(summary["old_stage_dates"])),
        ("Later HUMAN proposed stage/date selections", str(summary["new_stage_dates"])),
    ])
    transitions = data_table([
        (label, str(n)) for label, n in summary["transition_counts"].items()
    ] or [("No HUMAN decision changes", "0")])
    severity = data_table([
        (level, str(n)) for level, n in summary["severity_counts"].items()
    ] or [("No original severity groups changed", "0")])
    details = ""
    if private_ids:
        cards = "".join(
            "<article><h3>" + escape(item["title"]) + "</h3><p>Original finding ID: <code>" +
            escape(item["id"]) + "</code> · Source-declared severity: " +
            escape(item["severity"]) + "</p><p>Human-only selection: " +
            escape(item["from"]) + " → " + escape(item["to"]) +
            "</p></article>" for item in changes
        )
        details = (
            "<h2>PRIVATE original ID / title changes</h2>" + (
                cards if cards else "<p>No original human selection changed.</p>"
            )
        )
    notice = (
        "PRIVATE UNENCRYPTED original-identifier review." if private_ids else
        "ID-free PRIVATE HUMAN-only summary."
    )
    notice += (
        " INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD. These are changes to locally"
        " selected HUMAN notes, ownership and proposed coordination dates,"
        " NEVER actual remediation results, verified fixes, retests, source"
        " authenticity, client identity, scope authorization or consent."
        " The five exported source columns omit underlying evidence."
        " Even ID-free small counts may identify a client. Validate the"
        " real recipient and protect this private HTML manually."
    )
    html = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;; style-src &#39;unsafe-inline&#39;">'
        "<title>LightUp PRIVATE HUMAN decision revision comparison</title>"
        "<style>body{font:16px/1.55 system-ui,sans-serif;color:#14263c;background:#f1f5fa;"
        "margin:0}header{background:#143353;color:#fff;padding:26px 4vw}"
        "main{max-width:1000px;margin:auto;padding:22px}table{border-collapse:collapse;"
        "width:100%;background:white;margin:15px 0 22px}td,th{border-bottom:1px solid #d0dbe7;"
        "padding:11px;text-align:left}td{text-align:right;overflow-wrap:anywhere}"
        "aside{background:#fff1d9;border-left:5px solid #a96d17;padding:19px;margin:14px 0 24px}"
        "article{padding:14px;border:1px solid #d0dbe7;border-radius:10px;"
        "background:white;margin:10px 0;break-inside:avoid}article h3{margin:0}"
        "code{overflow-wrap:anywhere}</style>"
        "<header><h1>HUMAN decision revision comparison</h1>"
        "<p>Strictly matching original encrypted source custody · local only</p>"
        "</header><main><aside>" + escape(notice) + "</aside>"
        "<h2>Human decision overview</h2>" + overview +
        "<h2>Types of HUMAN changes</h2>" + transitions +
        "<h2>Source-reported severity of affected original records</h2>" +
        severity + details + "</main></html>"
    )
    return html.encode("utf-8", "strict")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two encrypted original-source HUMAN decisions; no security verdict"
    )
    parser.add_argument("earlier_source")
    parser.add_argument("earlier_plan")
    parser.add_argument("later_source")
    parser.add_argument("--earlier-choices", required=True)
    parser.add_argument("--later-choices", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--include-private-ids", action="store_true")
    parser.add_argument("--ack-private-handling", action="store_true")
    parser.add_argument("--ack-same-real-client", action="store_true")
    parser.add_argument("--ack-plaintext-original-ids", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_handling or not args.ack_same_real_client:
            raise ValueError("private recipient and independent real-client confirmation required")
        if args.include_private_ids and not args.ack_plaintext_original_ids:
            raise ValueError("private original-ID HTML needs separate human recipient consent")
        output = _output_path(args.output, ".html")
        expected, template, rows, new_meta, binding = _current_source(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        before_secret = _passphrase("Earlier encrypted HUMAN choice passphrase")
        previous, _ = _read_decisions(args.earlier_choices, before_secret, binding)
        del before_secret
        later_secret = _passphrase("Later encrypted HUMAN choice passphrase")
        current, _ = _read_decisions(args.later_choices, later_secret, binding)
        del later_secret
        _reconcile(previous, expected, deepcopy(template), new_meta, rows)
        _reconcile(current, expected, deepcopy(template), new_meta, rows)
        overview, details = _delta(previous, current, expected)
        if binding != _source_binding(
            args.earlier_source, args.earlier_plan, args.later_source
        ):
            raise ValueError("original encrypted source changed during decision comparison")
        _atomic_private_publish(output, _render(overview, details, args.include_private_ids))
        print("Created NEW UNENCRYPTED 0600 PRIVATE HUMAN decision comparison.")
        for field in (
            "source_findings", "changed_human_decisions",
            "unchanged_human_decisions", "old_selected", "new_selected"
        ):
            print(field + ":", overview[field])
        print("Only local HUMAN coordination changed; source findings and plans untouched.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN decision comparison HOLD: original source or encrypted choices denied.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
