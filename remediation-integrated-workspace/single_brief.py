#!/usr/bin/env python3
"""Source-free, scriptless HUMAN follow-up brief from ONE original Cockpit.

Consumes an original natively admitted anonymous Cockpit plus a separately
saved exact-source-bound HUMAN journal. Does not authenticate sender, consent,
evidence, security fixes, client scope, retest, grants or release authority.
"""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import sys

import single_review as single

review = single.review
workspace = single.workspace
WARNING = ("PRIVATE local HUMAN-only review notes. No authenticated original "
           "source/client/consent; no security finding, grant, verified repair, "
           "retest or authority. One source-free packet is NOT a timeline.")

def esc(x: object) -> str:
    return html.escape(str(x), quote=True)

def generate(doc: dict) -> bytes:
    rows = []
    for row in doc["items"]:
        style = "OPEN HUMAN DISCUSSION" if row["stage"] != "answered_human_only" else "HUMAN ANSWERED (NOT FIXED)"
        rows.append(
            "<tr><td>" + esc(row["slot"]) + "</td><td>" +
            esc(row["reason"].replace("_", " ")) + "</td><td>" +
            esc(row["count"]) + "</td><td>" + esc(style) +
            "<br><small>" + esc(row["stage"]) + "</small></td><td>" +
            esc(row["note"]) + "</td></tr>"
        )
    if not rows:
        rows = ["<tr><td colspan='5'>No currently declared original source-free HUMAN reason occurrences. This does not prove security clearance.</td></tr>"]
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; connect-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; object-src 'none'; base-uri 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HUMAN-only single Cockpit follow-up</title>
<style>body{font:16px/1.5 system-ui;background:#f6f8fb;color:#15263e;margin:2rem auto;max-width:1040px;padding:1rem}
aside,section{background:white;padding:1.3rem;margin:1rem 0;border-radius:10px}
aside{border-left:6px solid #ac7a18}table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid #d4dee7;text-align:left;padding:.65rem;vertical-align:top}
td:last-child{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#495f75}</style>
<main><h1>PRIVATE one-Cockpit HUMAN follow-up brief</h1>
<aside><strong>DRAFT/HOLD · REVIEW ONLY</strong><p>""" + esc(WARNING) +
            """</p><p>Human answers are NOT verified remediation or retests.
Notes can contain personal/confidential details and must never be published
or forwarded without separate genuine disclosure permission.</p></aside>
<section><p><strong>Original anonymous source slots:</strong> """ +
            esc(doc["original_slots"]) +
            """ · <strong>HUMAN reason groups:</strong> """ +
            esc(doc["human_reason_groups"]) +
            """ · <strong>Locally open HUMAN reason groups:</strong> """ +
            esc(doc["open_human_groups"]) +
            """ · <strong>Locally answered HUMAN reason groups, NOT fixes:</strong> """ +
            esc(doc["answered_human_groups"]) +
            """</p><p>Reason counts are occurrences, not unique cases. Slot ordinals
and local acknowledgements do not identify a real owner or establish chronology.</p>
<table><thead><tr><th>Source-free slot</th><th>HUMAN reason</th><th>Occurrences</th>
<th>Human state</th><th>Private local note</th></tr></thead><tbody>""" +
            "".join(rows) +
            """</tbody></table></section>
<p>Scriptless offline report. No source writeback, network, scanning or native Apply.</p>
</main></html>\n""").encode("utf-8")

def publish(cockpit: Path, journal: Path | bytes, output: Path) -> None:
    single.require(output.is_absolute()
                   and output.parent == output.parent.resolve(strict=True)
                   and not output.exists() and not output.is_symlink()
                   and cockpit not in output.parents
                   and output not in cockpit.parents
                   and output.parent != cockpit
                   and (type(journal) is bytes or
                        (journal.parent != output and journal != output)),
                   "Follow-up brief cannot modify original PRIVATE inputs")
    single.install.owner_dir(output.parent)
    baseline, source_key, manifest, portfolio = single.original(cockpit)
    raw = journal if type(journal) is bytes else review.private_read(journal)
    single.require(type(raw) is bytes and len(raw) <= 262144,
                   "Private HUMAN journal source exceeds native bound")
    saved = single.admit_journal(raw, baseline, source_key)
    rows = [{k: item[k] for k in ("slot", "reason", "count", "stage", "note")}
            for item in saved]
    open_rows = sum(row["stage"] != "answered_human_only" for row in rows)
    stats = {
        "kind": "lightup.source_free_single_cockpit_human_followup_brief",
        "schema_version": 1, "disposition": "PRIVATE_HUMAN_ONLY_NO_AUTHORITY",
        "authority_granted": False, "consent_verified": False,
        "remediation_verified": False, "warning": WARNING,
        "original_slots": len(single.verify.json_obj(portfolio)["source_slots"]),
        "source_free_packet_sha256": source_key,
        "human_reason_groups": len(rows),
        "open_human_groups": open_rows,
        "answered_human_groups": len(rows) - open_rows,
        "items": rows,
    }
    json_bytes = workspace.pretty(stats)
    page_bytes = generate(stats)
    payloads = {"index.html": page_bytes, "brief.json": json_bytes}
    receipt = {
        "kind": stats["kind"] + ".receipt", "schema_version": 1,
        "disposition": stats["disposition"], "authority_granted": False,
        "consent_verified": False, "remediation_verified": False,
        "warning": WARNING, "files": {
            name: {"sha256": single.sha(data), "bytes": len(data)}
            for name, data in sorted(payloads.items())
        },
    }
    single.read_cockpit.inspect(cockpit)
    single.require(review.private_read(cockpit / "manifest.json") == manifest
                   and review.private_read(cockpit / "portfolio.json") == portfolio,
                   "Original source-free packet changed during local HUMAN review")
    workspace.publish_bundle(output, payloads, workspace.pretty(receipt))
    print("REVIEW_ONLY: PRIVATE scriptless single-Cockpit HUMAN brief:", output)
    print("HUMAN reason groups locally open:", open_rows)
    print("No original authenticated identity, consent, verified fix or authority.")

def main() -> int:
    p = argparse.ArgumentParser(description="Publish one source-free PRIVATE HUMAN-only scriptless follow-up brief")
    p.add_argument("--cockpit", type=Path, required=True)
    p.add_argument("--journal", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    try:
        publish(args.cockpit, args.journal, args.output_dir)
        return 2
    except (review.Hold, UnicodeError, ValueError, TypeError, KeyError, OSError) as exc:
        print("HOLD: PRIVATE original HUMAN source/journal refused: " + str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
