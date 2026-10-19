#!/usr/bin/env python3
"""Publish a complete private offline evidence workload cockpit from 2–12 original desks.

Read-only human coordination. Never grants consent, issues requests, scans, executes
tasks or authenticates the original producer. No network, subprocess or browser JS.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
from pathlib import Path
import sys

import portfolio
import progression
import verify

review = verify.review
workspace = verify.workspace
triage = verify.triage
WARNING = "This is an unsigned PRIVATE owner-only HTML and JSON snapshot with NO original source identities, grants, client consent, or security/retest/remediation authority."

KIND = "lightup.private_human_evidence_operating_cockpit"
ADVICE = {
    "VERIFY_INTENTIONAL_CROSS_FINDING_REUSE":
        "Ask the original source owner if reuse of local evidence was intentional.",
    "RECONCILE_HUMAN_STAGE_DIFFERENCE":
        "Ask original HUMAN reviewers to reconcile their different local stage labels.",
    "RECHECK_LOCAL_BYTES_WITH_ORIGINAL_LEDGER":
        "Use the original PRIVATE Ledger to reselect and recheck locally referenced file bytes.",
    "REVIEW_NEW_LOCAL_LINK":
        "Ask a source owner to assess a newly associated local evidence fingerprint.",
    "PREVIOUS_LOCAL_LINK_ABSENT_NOT_PROVEN_FIXED":
        "Ask the source owner about a disappeared local link. Never infer a fix.",
    "REVIEW_CHANGED_LOCAL_HUMAN_METADATA":
        "Ask a HUMAN reviewer about local stage/reviewer/note metadata changes.",
}

def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe(value: object) -> str:
    return html.escape(str(value), quote=True)

def shell(body: str, title: str) -> bytes:
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; "
            "connect-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>" + safe(title) + "</title>"
            "<style>body{font:16px system-ui;line-height:1.5;color:#233349;"
            "background:#f4f6fa;margin:0}main{max-width:1020px;margin:auto;padding:2rem 1rem}"
            "header{background:#16304f;color:white;padding:1.5rem 0}header h1{margin:0}"
            "section,aside{background:white;border-radius:12px;padding:1.25rem;"
            "margin:1.25rem 0}aside{border-left:5px solid #a56d00}"
            "a{color:#115496}li{margin:.7rem 0}"
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;"
            "padding:.65rem;border-bottom:1px solid #dfe4ee}"
            "th{font-weight:650}small{color:#52616d}</style>"
            "<header><main><h1>" + safe(title) + "</h1></main></header>"
            "<main><aside><strong>HUMAN-ONLY · INCUBATE M3/M7 · DRAFT/HOLD.</strong> "
            "These are unverified self-declared source snapshots and local HUMAN "
            "acknowledgements. No source authentication, security verdict, "
            "vulnerability reproduction, evidence-byte verification, remediation, "
            "legal custody, grant, consent or verified retest. No authorized "
            "scan, workflow execution, live target or original native Apply.</aside>"
            + body +
            "<section><p><small>Generated fully offline. Source slots are not "
            "proven unique clients or chronological assessments. Output is "
            "owner-private; do not publish or place on shared cloud storage. "
            "Original inputs remain where the operator kept them.</small></p></section>"
            "</main></html>\n").encode("utf-8")

def overview(summary: dict, has_history: bool) -> bytes:
    slots = len(summary["source_slots"])
    pending = sum(row["locally_pending"] for row in summary["source_slots"])
    overlaps = len(summary["possible_repeated_original_source_slot_groups"])
    links = [
        ("portfolio.html", "Workload by original-private source slot",
         "Human stage, question workload and possible original-source overlap."),
        ("actions.html", "Actionable HUMAN follow-up brief",
         "Human-only follow-up questions grouped by original reason across slots."),
        ("portfolio.json", "PRIVATE anonymous aggregate JSON",
         "Structured source-free slot workload for local operator reference."),
    ]
    if has_history:
        links.extend([
            ("history.html", "Same-source HUMAN local progression",
             "Changes between user-ordered snapshots; not authenticated chronology."),
            ("history.json", "Same-source HUMAN progression counts",
             "Anonymous stage, reopened and note-change totals by selected slot."),
        ])
    items = "".join("<li><a href='" + safe(name) + "'><strong>" +
                    safe(title) + "</strong></a><br><small>" + safe(detail) +
                    "</small></li>" for name, title, detail in links)
    text = ("<section><h2>One offline workspace, separated original sources</h2>"
            "<p><strong>" + str(slots) + "</strong> original private source slots · "
            "<strong>" + str(pending) + "</strong> locally pending HUMAN questions "
            "(not unique cases) · <strong>" + str(overlaps) +
            "</strong> potential repeated original source groups.</p>"
            "<p>Every source folder was independently admitted against original "
            "native manifest, original source-bound HUMAN journal and regenerated "
            "original browser pages before this private summary was created.</p>"
            "<ul>" + items + "</ul></section>"
            "<section><h2>Safe operator handoff</h2><ol>"
            "<li>Start with the follow-up brief. Discuss which HUMAN source owner "
            "can re-examine private evidence references on the original private machine.</li>"
            "<li>Use the portfolio for approximate slot workload, never to count unique "
            "clients or claim that an issue is fixed.</li>"
            "<li>Return to each original PRIVATE Evidence Relationship Desk for HUMAN "
            "note/stage updates. This summary is read-only and never writes those records.</li>"
            "<li>Publish a completely NEW workspace directory after any original "
            "HUMAN session change; this folder represents one local snapshot.</li>"
            "</ol></section>")
    return shell(text, "LightUp PRIVATE HUMAN Evidence Cockpit")

def reviewed_reasons() -> tuple[str, ...]:
    return tuple(sorted(triage.REASONS))

def action_brief(summary: dict) -> bytes:
    slot_cards = []
    portfolio_reasons = Counter()
    for row in summary["source_slots"]:
        pending = row["locally_pending"]
        pieces = []
        for key in sorted(reviewed_reasons()):
            total = row["pending_human_reasons"].get(key, 0)
            if total <= 0:
                continue
            review.require(key in ADVICE, "Unknown original HUMAN question reason")
            portfolio_reasons[key] += total
            pieces.append("<li><strong>" + str(total) + " local question(s)</strong>: " +
                          safe(ADVICE[key]) + "</li>")
        if not pieces:
            pieces.append("<li>No proposed HUMAN follow-up questions remain locally "
                          "pending. This never implies successful security remediation.</li>")
        slot_cards.append("<section><h2>Source slot " + str(row["slot"]) +
                          " · " + str(pending) + " pending local HUMAN question(s)</h2>"
                          "<ul>" + "".join(pieces) + "</ul><p><small>Slot label is "
                          "not a client ID. Ask the operator maintaining this "
                          "private original source which specific records these "
                          "counts refer to.</small></p></section>")
    heading = ("<section><h2>HUMAN-only attention summary</h2><p>Source slot totals "
               "may overlap, and one local HUMAN question may have multiple reason "
               "codes. The original finding, source or filename is never "
               "included here. This is an advisory agenda, not an "
               "authorized task dispatch.</p>"
               "<p>Pending proposed reason occurrences across source slots: " +
               str(sum(portfolio_reasons.values())) + ".</p></section>")
    return shell(heading + "".join(slot_cards),
                 "LightUp PRIVATE HUMAN Follow-up Brief")

def publish(folders: list[Path], destination: Path) -> dict:
    review.require(2 <= len(folders) <= 12, "Expected 2 to 12 original sources")
    review.require(destination not in folders and all(destination.parent != p for p in folders),
                   "Cannot publish within an original private source directory")
    # The original source files were admitted completely by every existing
    # native verifier. Never create/fabricate a new client identity.
    summary = portfolio.plan(folders)
    identities = []
    source_snapshots = []
    for folder in folders:
        _, current_snapshot = verify.inspect(folder)
        identities.append((current_snapshot["current.json"],
                           current_snapshot.get("previous.json")))
        source_snapshots.append(current_snapshot)
    one_source = all(pair == identities[0] for pair in identities[1:])
    history = progression.assemble(folders) if one_source else None

    artifacts = {
        "portfolio.html": portfolio.render(summary),
        "portfolio.json": workspace.pretty(summary),
        "actions.html": action_brief(summary),
        "index.html": overview(summary, history is not None),
    }
    if history is not None:
        artifacts["history.html"] = progression.render(history)
        artifacts["history.json"] = workspace.pretty(history)

    manifest = {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        **{flag: False for flag in review.FLAGS},
        "slot_count": len(folders),
        "original_packet_context_repeated": one_source,
        "files": {k: {"bytes": len(v), "sha256": hash_bytes(v)}
                  for k, v in sorted(artifacts.items())},
        "warning": WARNING,
    }

    # Fresh complete source admission directly before final atomic bundle publication.
    for folder, admitted in zip(folders, source_snapshots):
        _, latest = verify.inspect(folder)
        review.require(latest == admitted,
                       "Original PRIVATE snapshot changed during cockpit construction")
    workspace.publish_bundle(destination, artifacts, workspace.pretty(manifest))
    return {"source_slots": len(folders), "locally_pending": sum(
        row["locally_pending"] for row in summary["source_slots"]),
        "history_included": history is not None,
        "private_files": len(artifacts) + 1}

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Make one complete, browser-ready PRIVATE offline HUMAN evidence coordination portal"))
    parser.add_argument("--bundle", type=Path, action="append", required=True,
                        help="Existing original Evidence Relationship Desk directory; 2–12")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW unused PRIVATE directory under an existing owner-only 0700 parent")
    args = parser.parse_args()
    try:
        review.require(args.output_dir.is_absolute() and args.output_dir not in args.bundle,
                       "Output must be a fresh absolute directory, not a source")
        result = publish(args.bundle, args.output_dir)
        print("PRIVATE HUMAN offline cockpit published as a new complete directory.")
        print("Slots " + str(result["source_slots"]) + "; locally pending " +
              str(result["locally_pending"]) + "; history: " +
              ("included" if result["history_included"] else "not applicable") +
              ". Open index.html on a trusted PRIVATE local machine.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE original sources or new offline cockpit cannot be admitted. "
              "No successful summary or authority issued.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
