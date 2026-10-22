#!/usr/bin/env python3
"""Compare two complete original PRIVATE HUMAN workrooms offline, source slot by slot.

Self-declared current/previous original source bytes MUST be identical. This
is user-ordered LOCAL HUMAN review change, never authenticated chronology or fix.
"""
from __future__ import annotations

import argparse
from collections import Counter
import html
from pathlib import Path
import sys

import board
import revise

review = revise.review
triage = revise.triage
workspace = revise.workspace
verify = revise.verify
read_cockpit = revise.read_cockpit

KIND = "lightup.private_human_workroom_revision_comparison"
WARNING = ("Operator-selected BEFORE/AFTER is not authenticated chronology. "
           "Local HUMAN status and notes do not prove reviewer identity, consent, "
           "authentic evidence, repair, retest, security approval or release.")
MAX_BYTES = 4 * 1024 * 1024

def esc(value: object) -> str:
    return html.escape(str(value), quote=True)

def admit_pair(old_root: Path, new_root: Path) -> tuple[dict, list[dict]]:
    review.require(old_root != new_root and
                   old_root not in new_root.parents and new_root not in old_root.parents,
                   "Revision comparison requires two different complete PRIVATE workrooms")
    previous, old_source = revise.private_workroom(old_root)
    updated, new_source = revise.private_workroom(new_root)
    review.require(len(previous) == len(updated),
                   "Complete HUMAN workroom source slots changed")
    detail = []
    totals = Counter()
    stage_totals_before = Counter()
    stage_totals_after = Counter()
    by_slot = []
    for pos, (old, new) in enumerate(zip(old_source, new_source), 1):
        review.require(old["current.json"] == new["current.json"] and
                       old.get("previous.json") == new.get("previous.json"),
                       "Original source packet changed; not the same HUMAN-only revision")
        current = review.parse_packet_data(old["current.json"])
        older = old.get("previous.json")
        prior = review.parse_packet_data(older) if older is not None else None
        expected = triage.make_session(current, prior, old["current.json"], older)
        before = triage.admit_session(old["session.json"], expected)
        after = triage.admit_session(new["session.json"], expected)
        review.require(len(before["records"]) == len(after["records"]),
                       "Original HUMAN proposal/question membership changed")
        slot_stats = Counter()
        for a, b in zip(before["records"], after["records"]):
            review.require(a["ordinal"] == b["ordinal"] and
                           a["finding_id"] == b["finding_id"] and
                           a["local_sha256"] == b["local_sha256"] and
                           a["reasons"] == b["reasons"],
                           "Original source-bound HUMAN question identity changed")
            stage_totals_before[a["stage"]] += 1
            stage_totals_after[b["stage"]] += 1
            stage_changed = a["stage"] != b["stage"]
            note_changed = a["human_note"] != b["human_note"]
            if not stage_changed and not note_changed:
                continue
            slot_stats["changed_human_rows"] += 1
            if stage_changed:
                slot_stats["changed_human_stage"] += 1
            if note_changed:
                slot_stats["changed_private_note"] += 1
            if a["stage"] != "answered_human" and b["stage"] == "answered_human":
                slot_stats["locally_answered_not_fixed"] += 1
            if a["stage"] == "answered_human" and b["stage"] != "answered_human":
                slot_stats["reopened_human_question"] += 1
            detail.append({
                "slot": pos, "ordinal": a["ordinal"],
                "finding_id": a["finding_id"],
                "local_sha256": a["local_sha256"],
                "before": a["stage"], "after": b["stage"],
                "note_changed": note_changed,
                "reason_codes": a["reasons"],
            })
        totals.update(slot_stats)
        by_slot.append({"slot": pos, "changed_human_rows": slot_stats["changed_human_rows"],
                        "locally_answered_not_fixed": slot_stats["locally_answered_not_fixed"],
                        "reopened_human_question": slot_stats["reopened_human_question"]})
    review.require(detail, "No meaningful original HUMAN stage or note differences")
    summary = {
        "kind": KIND, "schema_version": 1,
        "disposition": "UNVERIFIED_ORIGINAL_HUMAN_REVIEW_ONLY",
        **{f: False for f in review.FLAGS},
        "original_source_slots_not_unique_clients": len(previous),
        "changed_original_human_rows": totals["changed_human_rows"],
        "changed_original_human_stages": totals["changed_human_stage"],
        "changed_private_notes_without_contents": totals["changed_private_note"],
        "locally_answered_not_fixed": totals["locally_answered_not_fixed"],
        "reopened_human_question": totals["reopened_human_question"],
        "original_stage_counts_before_not_verdict": {
            k: stage_totals_before.get(k, 0) for k in triage.STAGES},
        "original_stage_counts_after_not_verdict": {
            k: stage_totals_after.get(k, 0) for k in triage.STAGES},
        "source_slots": by_slot,
        "warning": WARNING,
    }
    review.require(len(workspace.pretty(summary)) <= MAX_BYTES,
                   "PRIVATE HUMAN revision counts too large")
    return summary, detail

def private_details(summary: dict, rows: list[dict]) -> bytes:
    table = []
    for row in rows:
        notes = "changed (contents hidden)" if row["note_changed"] else "unchanged"
        reasons = ", ".join(row["reason_codes"])
        table.append(
            "<tr><th scope='row'>" + str(row["slot"]) + "/" +
            str(row["ordinal"]) + "</th><td><code>" +
            esc(row["finding_id"]) + "</code></td><td><code>" +
            esc(row["local_sha256"]) + "</code></td><td>" +
            esc(row["before"]) + " &rarr; " + esc(row["after"]) +
            "</td><td>" + esc(notes) + "</td><td>" +
            esc(reasons) + "</td></tr>")
    content = (
        "<section><h2>Actual local HUMAN differences, by source slot</h2><p>"
        "Only modified original HUMAN stage/note records appear. All finding "
        "IDs and digest labels are self-declared original-private references, "
        "never proof of actual file bytes. PRIVATE note text is never displayed.</p>"
        "<div style='overflow:auto'><table><thead><tr><th>Slot / question</th>"
        "<th>Original claimed finding</th><th>Local SHA label</th>"
        "<th>Local HUMAN stage</th><th>Note</th><th>Original HUMAN question</th>"
        "</tr></thead><tbody>" + "".join(table) +
        "</tbody></table></div></section>"
        "<section><h2>PRIVATE source-owner follow-up</h2>"
        "<p>Use the original PRIVATE tasks.html and inbox in the selected new "
        "workroom to inspect full local context. Local answered is NOT fixed "
        "or approved. The BEFORE/AFTER selection is human supplied and NOT "
        "verified order or provenance.</p></section>")
    payload = board.shell(content, "LightUp PRIVATE Source HUMAN Revision Differences")
    review.require(len(payload) <= MAX_BYTES, "Detailed PRIVATE HUMAN change view too large")
    return payload

def summary_home(summary: dict) -> bytes:
    text = ("<section><h2>Local HUMAN workroom comparison</h2><p><strong>" +
            str(summary["original_source_slots_not_unique_clients"]) +
            "</strong> original source slots; <strong>" +
            str(summary["changed_original_human_rows"]) +
            "</strong> changed local HUMAN question(s); <strong>" +
            str(summary["changed_original_human_stages"]) +
            "</strong> changed local stage(s); <strong>" +
            str(summary["changed_private_notes_without_contents"]) +
            "</strong> changed PRIVATE notes (contents hidden).</p><p><strong>" +
            str(summary["locally_answered_not_fixed"]) +
            "</strong> newly locally answered, NOT proven fixed; <strong>" +
            str(summary["reopened_human_question"]) +
            "</strong> locally reopened.</p>"
            "<ul><li><a href='details.html'>PRIVATE source-bound changed question desk</a> "
            "(original labels; source-owner PRIVATE only)</li>"
            "<li><a href='counts.json'>Anonymous local HUMAN change counts JSON</a> "
            "(not authenticated chronology)</li></ul></section>"
            "<section><h2>Meaning and limits</h2><p>Only HUMAN status and "
            "private note text changed. Original packet bytes must match on "
            "both workrooms, but that alone does not prove identity, consent, "
            "independent fixes, vulnerability truth or retest.</p></section>")
    return board.shell(text, "LightUp PRIVATE HUMAN Workroom Comparison")

def publish(before: Path, after: Path, output: Path) -> dict:
    review.require(output.is_absolute() and
                   output not in (before, after) and
                   before not in output.parents and after not in output.parents and
                   output not in before.parents and output not in after.parents,
                   "Cannot publish inside either original PRIVATE workroom")
    triage.private_parent(output)
    summary, details = admit_pair(before, after)
    documents = {
        "index.html": summary_home(summary),
        "details.html": private_details(summary, details),
        "counts.json": workspace.pretty(summary),
    }
    manifest = {
        "kind": "lightup.private_source_human_revision_report_bundle",
        "schema_version": 1, "disposition": "HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        **{f: False for f in review.FLAGS},
        "files": {k: {"bytes": len(v), "sha256": revise.digest(v)}
                  for k, v in sorted(documents.items())},
        "warning": WARNING,
    }
    # Report reflects only a stable pair of admitted original sources.
    latest, latest_detail = admit_pair(before, after)
    review.require(latest == summary and latest_detail == details,
                   "PRIVATE workroom HUMAN inputs changed before report publication")
    workspace.publish_bundle(output, documents, workspace.pretty(manifest))
    return summary

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Compare two complete ORIGINAL private HUMAN workrooms offline, "
        "publish a new private human-diff desk without notes"))
    parser.add_argument("--before", type=Path, required=True,
                        help="First complete original PRIVATE source-owner workroom")
    parser.add_argument("--after", type=Path, required=True,
                        help="Second complete PRIVATE HUMAN workroom, same original source bytes")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW owner-only private comparison directory, never a source folder")
    args = parser.parse_args()
    try:
        summary = publish(args.before, args.after, args.output_dir)
        print("PRIVATE original HUMAN workroom comparison published offline.")
        print(str(summary["changed_original_human_rows"]) +
              " locally changed questions; " +
              str(summary["locally_answered_not_fixed"]) +
              " locally answered, never verified fixed.")
        print("REVIEW_ONLY: no authenticated history, source, consent, scan or remediation.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: complete PRIVATE HUMAN workroom comparison cannot be admitted.",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
