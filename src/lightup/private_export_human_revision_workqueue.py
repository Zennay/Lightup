"""Scriptless original-ID PRIVATE HUMAN revision reconciliation queue.

Uses only source and HUMAN inputs already strictly admitted by the separate
private_export_human_revision bridge. Does not infer security fixes or consent.
"""
from __future__ import annotations

import argparse
from html import escape
import sys

from .private_export_human_revision import _read_inputs, _review_revision, _COLUMNS
from .private_export_handoff import _atomic_private_publish, _output_path

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_ACTION_ORDER = {"changed": 0, "new": 1, "absent": 2, "carry_candidate": 3}


def _queue(old_rows: list[dict[str, str]], new_rows: list[dict[str, str]],
           earlier_annotations: dict) -> list[dict[str, str]]:
    old = {item["finding_id"]: item for item in old_rows}
    later = {item["finding_id"]: item for item in new_rows}
    items: list[dict[str, str]] = []
    for fid in old.keys() | later.keys():
        earlier = old.get(fid)
        current = later.get(fid)
        if earlier is None:
            kind, reason = "new", "New original source row; fresh HUMAN review required"
        elif current is None:
            kind, reason = "absent", "Absent from new export; NOT fixed or resolved"
        elif any(earlier[field] != current[field] for field in _COLUMNS):
            kind = "changed"
            reason = "Original columns changed: " + ", ".join(
                field for field in _COLUMNS if earlier[field] != current[field]
            ) + ". Previously entered HUMAN plan NOT carried."
        else:
            kind = "carry_candidate"
            reason = "Five-column identical; alias/note eligible. Underlying evidence UNKNOWN."
        original = earlier_annotations.get(fid)
        # Do not include actual original private notes, aliases, proposed dates,
        # customer labels, raw remediation instructions or raw evidence.
        items.append({
            "id": fid,
            "title": (current or earlier)["title"],
            "severity": (current or earlier)["severity"],
            "kind": kind,
            "reason": reason,
            "earlier_human_stage": original["stage"] if original else "not present",
            "earlier_human_note": "present" if original and original["human_note"] else "none",
        })
    items.sort(key=lambda item: (
        _ACTION_ORDER[item["kind"]],
        _SEVERITY_ORDER.get(item["severity"], 9),
        item["id"],
    ))
    return items


def _html(items: list[dict[str, str]], summary: dict) -> bytes:
    sections = {
        "changed": "Changed source records — all HUMAN fields reset",
        "new": "New original records — fresh HUMAN review",
        "absent": "Absent from later export — never assume fixed",
        "carry_candidate": "Exactly matching five exported columns — human carry candidates",
    }
    result = [
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE source revision human reconciliation</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#f2f6fc;"
        "color:#14263e}main{max-width:1100px;margin:auto;padding:28px}header{background:#15304d;"
        "color:white;padding:30px}h1{margin:0}aside{padding:18px;background:#fff0d7;"
        "border-left:5px solid #ba731c;margin:24px 0}section{margin-top:32px}"
        "article{break-inside:avoid;background:white;border:1px solid #cfdbeb;"
        "border-left:5px solid #3b69a8;border-radius:9px;padding:18px;margin:12px 0}"
        "article.changed{border-left-color:#a12c26}article.absent{border-left-color:#7840a0}"
        "article.new{border-left-color:#d78a12}code{overflow-wrap:anywhere}"
        ".cols{display:flex;gap:18px;flex-wrap:wrap}.cols p{margin:6px 0}"
        "p{overflow-wrap:anywhere}@media print{header{color:#14263e;background:white}"
        "article{break-inside:avoid}}</style>"
        "<header><h1>PRIVATE HUMAN revision reconciliation</h1>"
        "<p>Original source claims · local reviewer work only · DRAFT/HOLD</p></header><main>"
        "<aside><strong>PRIVATE, UNENCRYPTED, ORIGINAL IDS AND TITLES.</strong> "
        "Store and share only after independent real recipient/privacy review. "
        "The original five-column CSV omits evidence, asset and authentic consent. "
        "Matching source records do not prove underlying evidence equality, ownership "
        "or a repaired condition. An absent finding is NEVER a confirmed fix, and "
        "no status here grants testing, retest or remediation authority. "
        "All dates/stages/notes are unverified HUMAN proposals.</aside>"
        "<p>Earlier source count: " + str(summary["old"]) + " · Later source count: " +
        str(summary["new"]) + " · Changed: " + str(summary["modified"]) +
        " · Newly present: " + str(summary["newly_present"]) + " · Absent: " +
        str(summary["absent_not_fixed"]) + " · Five-column unchanged: " +
        str(summary["same_five_columns"]) + ".</p>"
    ]
    for kind, title in sections.items():
        records = [item for item in items if item["kind"] == kind]
        result.append("<section><h2>" + escape(title) + " (" + str(len(records)) + ")</h2>")
        if not records:
            result.append("<p>No rows in this group.</p>")
        for item in records:
            result.append(
                "<article class='" + kind + "'><h3>" + escape(item["title"]) +
                "</h3><div class='cols'><p>Original finding ID: <code>" +
                escape(item["id"]) + "</code></p><p>Source-claimed severity: " +
                escape(item["severity"]) + "</p></div><p>" +
                escape(item["reason"]) + "</p><div class='cols'>"
                "<p>Prior unverified HUMAN stage: " + escape(item["earlier_human_stage"]) +
                "</p><p>Prior private HUMAN note: " + escape(item["earlier_human_note"]) +
                "</p></div></article>"
            )
        result.append("</section>")
    result.append("</main></html>")
    return "".join(result).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Original-ID PRIVATE HUMAN source-revision reconciliation (DRAFT/HOLD)"
    )
    parser.add_argument("earlier_source")
    parser.add_argument("earlier_plan")
    parser.add_argument("later_source")
    parser.add_argument("--output", required=True, help="NEW 0600 PRIVATE unencrypted .html")
    parser.add_argument("--ack-private-handling", action="store_true")
    parser.add_argument("--ack-same-real-client", action="store_true")
    parser.add_argument("--ack-original-ids-plaintext", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not (args.ack_private_handling and args.ack_same_real_client
                and args.ack_original_ids_plaintext):
            raise ValueError("real-client and unencrypted original identifier acknowledgment required")
        output = _output_path(args.output, ".html")
        before, old_rows, old_notes, later, new_rows = _read_inputs(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        _, summary = _review_revision(
            before, old_rows, old_notes, later, new_rows, carry_stage=False
        )
        items = _queue(old_rows, new_rows, old_notes)
        _atomic_private_publish(output, _html(items, summary))
        print("Created PRIVATE unencrypted HUMAN reconciliation workqueue.",
              "Original findings:", len(items), ". No fix or consent established.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN revision workqueue HOLD: input or output admission failed.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
