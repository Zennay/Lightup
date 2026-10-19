#!/usr/bin/env python3
"""Complete PRIVATE offline original Evidence + HUMAN Casework retention desk.

ONE original CURRENT authenticated LightUp account/client/engagement source read,
one encrypted original HUMAN workroom and one encrypted retention plan, plus the
actual original local evidence bytes. Exports ONE NEW scriptless 0600 HTML desk.
Original records, permissions, files and targets are never changed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import date, timedelta
from html import escape
from pathlib import Path
import sys

import retention as native
import request_handoff as followup

original = native.transfer
MAX_HTML = 384 * 1024


def _items(packet: dict, reviewed: list[dict]):
    cases = packet.get("casework")
    evidence = packet.get("evidence_review")
    human_requests = packet.get("human_requests", [])
    if cases is not None and type(cases) is not list:
        raise ValueError("Canonical original Casework must be a list or absent.")
    if evidence is not None and type(evidence) is not list:
        raise ValueError("Canonical original Evidence Review must be a list or absent.")
    if type(human_requests) is not list:
        raise ValueError("Canonical original HUMAN requests required.")
    case_by_id = {x["finding_id"]: x for x in cases or []}
    evidence_by_id = {x["finding_id"]: x for x in evidence or []}
    request_by_id = defaultdict(list)
    for request in human_requests:
        request_by_id[request["finding_id"]].append(request)
    grouped = defaultdict(list)
    for row in reviewed:
        grouped[row["finding_id"]].append(row)
    now = date.today()
    soon = now + timedelta(days=14)
    rows = []
    stats = {"findings": len(grouped), "files": len(reviewed), "due": 0,
             "soon": 0, "later": 0, "human_legal_hold": 0,
             "open_native_requests": 0, "new_request_candidates": 0}
    for finding_id, items in grouped.items():
        for row in items:
            day = date.fromisoformat(row["review_on"])
            if day <= now:
                stats["due"] += 1
            elif day <= soon:
                stats["soon"] += 1
            else:
                stats["later"] += 1
            stats["human_legal_hold"] += int(row["decision"] == "legal_hold")
        live = [x for x in request_by_id[finding_id]
                if x["human_stage"] != "closed_human"]
        stats["open_native_requests"] += len(live)
        if not live and any(x["review_on"] <= now.isoformat() for x in items):
            stats["new_request_candidates"] += 1
        rows.append({
            "finding_id": finding_id,
            "items": sorted(items, key=lambda x: (x["review_on"], x["stored_as"])),
            "case": case_by_id.get(finding_id),
            "evidence": evidence_by_id.get(finding_id),
            "open_requests": live,
            "total_request_count": len(request_by_id[finding_id]),
        })
    rows.sort(key=lambda x: (
        min(row["review_on"] for row in x["items"]),
        -int(any(row["decision"] == "legal_hold" for row in x["items"])),
        x["finding_id"].encode("utf-8"),
    ))
    return rows, stats


def _html(rows, stats, source_digest: str, *, private_casework: bool) -> bytes:
    h = lambda x: escape(str(x), quote=True)
    today = date.today().isoformat()
    due_anchor = ""
    overview = []
    cards = []
    for ordinal, group in enumerate(rows, 1):
        anchor = "record-" + str(ordinal)
        due = sum(item["review_on"] <= today for item in group["items"])
        flags = sum(item["decision"] == "legal_hold" for item in group["items"])
        status = "HUMAN REVIEW DUE" if due else "Review scheduled"
        if due and not due_anchor:
            due_anchor = anchor
        overview.append("<tr><td><a href='#" + anchor + "'>#" + str(ordinal)
                        + "</a></td><td><bdi>" + h(group["finding_id"])
                        + "</bdi></td><td>" + h(status)
                        + "</td><td>" + str(len(group["items"]))
                        + "</td><td>" + str(flags)
                        + "</td><td>" + str(len(group["open_requests"]))
                        + "</td></tr>")
        file_html = []
        for item in group["items"]:
            when = ("Review due" if item["review_on"] <= today else "Scheduled")
            file_html.append("<tr><td>" + h(item["stored_as"]) + "</td><td>"
                             + h(item["sha256"][:14]) + "…</td><td>"
                             + h(item["decision"].replace("_", " ")) + "</td><td>"
                             + h(item["review_on"]) + "</td><td>" + h(when)
                             + "</td>" + (
                                "<td>" + h(item["note"]) + "</td>"
                                if private_casework else ""
                             ) + "</tr>")
        case = group["case"]
        evidence = group["evidence"]
        original_state = (
            "<p><strong>Original source Casework:</strong> "
            + (h(case["status"]) if case is not None else "Not present")
            + " · <strong>Evidence Review:</strong> "
            + (h(evidence["stage"]) if evidence is not None else "Not present")
            + " · <strong>Current HUMAN requests:</strong> "
            + str(len(group["open_requests"])) + " open of "
            + str(group["total_request_count"]) + " historical.</p>")
        details = ""
        if private_casework:
            details = ("<details><summary>PRIVATE original HUMAN Casework details"
                       " (unverified)</summary><dl>"
                       "<dt>Human owner</dt><dd>" + h(case["owner"] if case else "") +
                       "</dd><dt>Human next action</dt><dd>" +
                       h(case["next_action"] if case else "") +
                       "</dd><dt>Human blocker</dt><dd>" +
                       h(case["blocker"] if case else "") +
                       "</dd><dt>Human note</dt><dd>" + h(case["note"] if case else "") +
                       "</dd><dt>Evidence next step</dt><dd>" +
                       h(evidence["next_step"] if evidence else "") +
                       "</dd></dl></details>")
        cards.append(
            "<section id='" + anchor + "'><h2>#" + str(ordinal)
            + " · <bdi>" + h(group["finding_id"]) + "</bdi></h2>"
            + "<p><strong>" + h(status) + "</strong> · Evidence material: "
            + str(len(group["items"])) + " · HUMAN legal-hold markings: "
            + str(flags) + "</p>" + original_state
            + "<table><caption>Actual local source-fingerprint-checked PRIVATE files</caption>"
            + "<thead><tr><th>Neutral file</th><th>SHA prefix</th><th>HUMAN status</th>"
            + "<th>Next review</th><th>Attention</th>"
            + ("<th>PRIVATE note</th>" if private_casework else "")
            + "</tr></thead><tbody>" + "".join(file_html) + "</tbody></table>"
            + details + "</section>")
    nav = ("<a href='#" + due_anchor + "'>Jump to earliest review</a>"
           if due_anchor else "No due reviews in current HUMAN plan.")
    body = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; script-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE Evidence Retention Operations</title>
<style>
:root{font-family:system-ui,sans-serif;color:#202329;background:#f6f6f6}
body{max-width:1200px;margin:0 auto;padding:2rem 1rem;line-height:1.5}
header,section{background:white;padding:1.4rem;margin-bottom:1.4rem;border:1px solid #dadada;border-radius:8px}
h1{margin:0 0 .4rem} h2{margin:0 0 .3rem;font-size:1.3rem}
.notice{border-left:6px solid #373737;padding:1rem;background:#f5f5f5}
.stats{display:flex;flex-wrap:wrap;gap:.8rem}.metric{background:#f5f5f5;padding:.65rem 1rem;border-radius:5px;min-width:110px}
.metric strong{display:block;font-size:1.5rem}table{border-collapse:collapse;width:100%;margin:.8rem 0}
th,td{border:1px solid #aaa;padding:.55rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#eee}a{color:#17417b} bdi{unicode-bidi:isolate}details{margin-top:1rem}dd{margin-left:0;overflow-wrap:anywhere}dt{font-weight:600;margin-top:.65rem}
@media print{body{padding:0;background:white}header,section{break-inside:avoid}}
</style></head><body><header><h1>PRIVATE Evidence Retention Operations</h1>
<p>Current source-authenticated read, original HUMAN Casework and actual locally verified PRIVATE evidence fingerprints.
Dates and HUMAN statuses are unverified coordination only.</p>
<div class="notice"><strong>Never a scan, grant, deletion instruction or valid policy approval.</strong>
No automatic clearing of legal holds, no verified security findings/fixes/retests, no native Request Desk Apply, no proof of original client consent or actual evidence custody.
The source can change; recreate this view after a fresh authenticated read.</div>
<h2>PRIVATE HUMAN review attention</h2><div class="stats">""" + "".join(
        "<div class='metric'><strong>" + str(stats[key]) + "</strong>"
        + h(label) + "</div>" for key,label in (
            ("findings", "Original findings"),("files", "Evidence files"),
            ("due", "Due"),("soon", "Next 14 days"),
            ("human_legal_hold", "HUMAN legal holds"),
            ("open_native_requests", "Open original HUMAN requests"),
            ("new_request_candidates", "Potential HUMAN follow-ups")
        )
    ) + """</div><p>""" + nav + """</p><small>Source fingerprint: """ + h(source_digest) + """</small>
</header><section><h2>Original source-bound review index</h2>
<table><caption>Human reported retention state, not a legal retention schedule</caption>
<thead><tr><th>Entry</th><th>Original finding</th><th>Review attention</th>
<th>Files</th><th>HUMAN holds</th><th>Open native requests</th></tr></thead>
<tbody>""" + "".join(overview) + """</tbody></table></section>""" + "".join(cards)
    body += "<footer><p>" + h(native.WARNING) + "</p></footer></body></html>"
    return body.encode("utf-8", "strict")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    for field in ("db", "email", "client-id", "engagement-id"):
        ap.add_argument("--" + field, required=True)
    for field in ("human", "directory", "plan", "output"):
        ap.add_argument("--" + field, type=Path, required=True)
    ap.add_argument("--include-private-casework", action="store_true",
                    help="Deliberately include original HUMAN notes only in private 0600 HTML")
    ap.add_argument("--ack-private-material", action="store_true")
    args = ap.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Private actual-evidence HUMAN terminal acknowledgment required.")
        vault = original.ORIGINAL._vault()
        _, packet, indexed, _ = original.current_human(
            args, vault, keep_passphrase_fingerprint=True)
        reviewed, _ = native._load_current_plan(args, vault, packet, indexed)
        rows, totals = _items(packet, reviewed)
        rendered = _html(rows, totals, packet["source_sha256"],
                         private_casework=args.include_private_casework)
        if len(rendered) > MAX_HTML:
            raise ValueError("PRIVATE desk exceeds bounded output size.")
        target = args.output.expanduser().absolute()
        if target.suffix.lower() != ".html" or target in {
            args.human.expanduser().absolute(), args.plan.expanduser().absolute()
        }:
            raise ValueError("New independent PRIVATE 0600 .html output required.")
        vault._exclusive_output(target, rendered)
        print("Complete NEW private static 0600 Evidence/Casework retention desk created.")
        print("Source-bound files:",totals["files"],
              "· HUMAN review due:",totals["due"],
              "· eligible original HUMAN follow-up groups:",totals["new_request_candidates"])
        print("No permission, legal rule, original Apply, target contact or data deletion.")
        return 0
    except Exception:
        print("HUMAN HOLD: current original authenticated source, exact private evidence bytes,"
              " encrypted review or private output could not be admitted. No complete desk published.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
