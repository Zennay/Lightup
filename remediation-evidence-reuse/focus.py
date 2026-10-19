#!/usr/bin/env python3
"""PRIVATE, scriptless original-source HUMAN evidence follow-up attention board."""
from __future__ import annotations

import argparse
from collections import Counter
import html
import json
from pathlib import Path
import sys

from review import Hold, private_publish, private_read, require
from triage import (STAGES, admit_session, fresh_original_bytes, make_session,
                    selected_sources, single_host_lock)

ORDER = ("needs_source_owner", "source_local_data_conflict",
         "stage_conflict", "new_or_lost_local_reference",
         "open_human_questions", "under_human_review",
         "answered_human_local_only")
TITLE = {
    "needs_source_owner": "Awaiting original HUMAN source owner",
    "source_local_data_conflict": "Contradictory local evidence file sizes",
    "stage_conflict": "Conflicting human review stages",
    "new_or_lost_local_reference": "New or absent local evidence association",
    "open_human_questions": "Unassigned/open HUMAN follow-up",
    "under_human_review": "Currently in HUMAN review",
    "answered_human_local_only": "Answered by HUMAN locally — NOT a verified fix",
}
QUESTION = {
    "VERIFY_INTENTIONAL_CROSS_FINDING_REUSE":
        "Ask original reviewer whether reusing one local file fingerprint across findings is intentional.",
    "RECONCILE_HUMAN_STAGE_DIFFERENCE":
        "Ask the original HUMAN owner to reconcile conflicting local review stages.",
    "RECHECK_LOCAL_BYTES_WITH_ORIGINAL_LEDGER":
        "Reselect actual bytes inside the original Ledger; a same SHA with unlike sizes is inconsistent metadata.",
    "REVIEW_NEW_LOCAL_LINK":
        "Confirm that a new local link belongs to the same original finding and source.",
    "PREVIOUS_LOCAL_LINK_ABSENT_NOT_PROVEN_FIXED":
        "Seek original HUMAN explanation for missing local association; absence is NOT repair.",
    "REVIEW_CHANGED_LOCAL_HUMAN_METADATA":
        "Confirm why local HUMAN reviewer/stage/note metadata changed.",
}


def classify(row: dict) -> str:
    if row["stage"] == "needs_source_owner":
        return "needs_source_owner"
    reasons = set(row["reasons"])
    if "RECHECK_LOCAL_BYTES_WITH_ORIGINAL_LEDGER" in reasons:
        return "source_local_data_conflict"
    if "RECONCILE_HUMAN_STAGE_DIFFERENCE" in reasons:
        return "stage_conflict"
    if reasons & {"PREVIOUS_LOCAL_LINK_ABSENT_NOT_PROVEN_FIXED", "REVIEW_NEW_LOCAL_LINK"}:
        return "new_or_lost_local_reference"
    if row["stage"] == "answered_human":
        return "answered_human_local_only"
    if row["stage"] == "in_human_review":
        return "under_human_review"
    return "open_human_questions"


def summarize(session: dict) -> dict:
    grouped = {kind: [] for kind in ORDER}
    for row in session["records"]:
        grouped[classify(row)].append(row)
    counts = Counter(row["stage"] for row in session["records"])
    return {
        "kind": "lightup.anonymous_human_fingerprint_attention_desk",
        "schema_version": 1,
        "disposition": "HUMAN_ONLY_NO_AUTHORITY",
        "local_human_questions": len(session["records"]),
        "groups": {kind: len(grouped[kind]) for kind in ORDER},
        "human_stages": {kind: counts.get(kind, 0) for kind in STAGES},
        "needs_human_attention": sum(len(grouped[key]) for key in ORDER
                                      if key != "answered_human_local_only"),
        "notice": "Only local source-bound HUMAN question grouping; not verified exposure, compliance, remediation, identity, consent or permission.",
    }


def render(session: dict) -> bytes:
    h = lambda v: html.escape(str(v), quote=True)
    grouped = {kind: [] for kind in ORDER}
    for row in session["records"]:
        grouped[classify(row)].append(row)
    total = summarize(session)
    parts = []
    for key in ORDER:
        rows = grouped[key]
        if not rows:
            continue
        cards = []
        for row in rows:
            guidance = "".join("<li>" + h(QUESTION[code]) + "</li>" for code in row["reasons"])
            cards.append(
                "<article><h3>HUMAN action #" + str(row["ordinal"]) +
                " · " + h(row["stage"].replace("_", " ")) + "</h3>"
                "<p>Original finding <code>" + h(row["finding_id"]) + "</code></p>"
                "<p>Local evidence SHA-256 <code>" + h(row["local_sha256"]) + "</code></p>"
                "<p>Local note present: <strong>" +
                ("yes" if row["human_note"] else "no") + "</strong></p>"
                "<ul>" + guidance + "</ul>"
                "<p>Review in original local inbox: select ordinal " +
                str(row["ordinal"]) + " with a HUMAN-only status update. "
                "Do not infer a native authorization, retest or repair.</p></article>")
        parts.append(
            "<section><details " + ("open" if key in ORDER[:3] else "") +
            "><summary>" + h(TITLE[key]) + " <small>(" + str(len(rows)) +
            " local HUMAN questions)</small></summary><div class='cards'>" +
            "".join(cards) + "</div></details></section>")
    if not parts:
        parts.append("<p>No local proposed HUMAN questions in the admitted original packet. "
                     "This is not evidence of no vulnerabilities or no existing global evidence.</p>")
    badges = " · ".join(h(TITLE[k]) + ": " + str(total["groups"][k]) for k in ORDER)
    doc = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
        "form-action 'none'; base-uri 'none'\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>PRIVATE LightUp local HUMAN attention inbox</title>"
        "<style>body{font:16px system-ui;max-width:1200px;margin:1.5rem auto;"
        "padding:0 1rem;color:#1e293b;background:#f4f6fa}"
        "h1{font-size:1.85rem}aside{padding:1rem;background:#fff2da;"
        "border-left:4px solid #a87608}"
        "section{margin:1rem 0;background:#fff;border:1px solid #ddd;border-radius:.6rem;"
        "overflow:hidden}summary{padding:1rem;cursor:pointer;font-weight:700;"
        "background:#eef1f6}summary small{font-weight:400}"
        ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem;"
        "padding:1rem}article{padding:1rem;border:1px solid #dee2e7;border-radius:.6rem;"
        "background:#fbfcff}article h3{font-size:1rem;margin:0 0 .5rem}"
        "code{overflow-wrap:anywhere}ul{padding-left:1.3rem}li{margin:.3rem 0}"
        "@media print{body{background:white}section{break-inside:avoid}details{display:block}"
        "details:not([open]) .cards{display:block}article{break-inside:avoid}}</style>"
        "<main><h1>PRIVATE HUMAN source-evidence attention desk</h1>"
        "<aside><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY.</strong> Local metadata "
        "and SHA fingerprints are not independently authenticated and do not establish "
        "the real source, evidence authenticity, resolution, reviewer identity, consent, "
        "legal custody, scan authority, native Apply or verified retest. "
        "Nothing on this page can execute an action or send data.</aside>"
        "<p>Self-declared client: " + h(session["client_reference"]) + " · engagement: " +
        h(session["engagement_reference"]) + "</p>"
        "<p>Original source claim SHA: <code>" + h(session["source_sha256"]) + "</code></p>"
        "<p>" + badges + "</p>" + "".join(parts) +
        "<p>Use the original source owner and separately authenticated LightUp workflow "
        "for actual decisions. This HTML is PRIVATE; it includes original finding IDs "
        "and local evidence fingerprints. Private human note text is not embedded.</p>"
        "</main></html>\n"
    )
    return doc.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Private scriptless stage/reason grouped HUMAN review board")
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--format", choices=("inspect", "html", "counts"), default="inspect")
    parser.add_argument("--output", type=Path, help="New PRIVATE 0600 HTML/counts in true owner-only directory")
    args = parser.parse_args()
    try:
        require((args.format == "inspect") == (args.output is None),
                "Output file required only for html/counts")
        if args.output is not None:
            require(args.output not in (args.current, args.previous, args.session),
                    "Never overwrite original PRIVATE source/session")
        current, previous, current_bytes, previous_bytes = selected_sources(args.current, args.previous)
        expected = make_session(current, previous, current_bytes, previous_bytes)
        with single_host_lock(args.session):
            loaded = private_read(args.session)
            session = admit_session(loaded, expected)
            if args.format == "inspect":
                print(json.dumps(summarize(session), indent=2, sort_keys=True))
                return 2
            output = (render(session) if args.format == "html"
                      else (json.dumps(summarize(session), indent=2, sort_keys=True) + "\n").encode("utf-8"))
            fresh_original_bytes(args, current_bytes, previous_bytes)
            require(private_read(args.session) == loaded, "HUMAN inbox changed before focus report publication")
            private_publish(args.output, output)
            print("Published PRIVATE HUMAN attention board, original unchanged.")
        return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
