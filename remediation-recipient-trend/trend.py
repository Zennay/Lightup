#!/usr/bin/env python3
"""PRIVATE offline recipient comparison of two fully admitted source-free cockpits.

Aggregates are human work counts, NOT matched cases, chronological observations,
verified evidence, evidence remediation, grant, consent or source authentication.
No network, subprocess, target, scanner or persistent storage outside output.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
from pathlib import Path
import sys

# Reuse the *original* accepted source-free cockpit admission, not a new
# approximation of the original verifier. No source-owner file is edited.
sys.path.append(str(Path(__file__).resolve().parent.parent /
                       "remediation-evidence-bundle-integrity"))
import board
import read_cockpit
import verify

review = verify.review
workspace = verify.workspace
triage = verify.triage

KIND = "lightup.private_human_recipient_aggregate_trend"
WARNING = (
    "UNVERIFIED PRIVATE HUMAN-only aggregate comparison. Input packets may "
    "represent different source cohorts, different slot order or duplicate "
    "underlying cases. Left/right ordering is operator-selected, not "
    "authenticated chronology. A lower pending count never proves a fix, "
    "retest, risk reduction, consent, source identity or authorization."
)
FIELDS = ("slots", "questions", "pending", "local_attachment_links",
          "shared_sha_groups", "human_attention_groups")
MAX_INPUTS = 2


def admit_received(folder: Path) -> tuple[dict, bytes, bytes]:
    """Require the unchanged original exact inventory + HTML re-renderer."""
    read_cockpit.inspect(folder)
    manifest = review.private_read(folder / "manifest.json")
    raw = review.private_read(folder / "portfolio.json")
    data = verify.json_obj(raw)
    # read_cockpit inspected complete file bytes, and this direct re-read
    # additionally pins the consumed JSON/manifest for final re-admission.
    original_manifest = verify.json_obj(manifest)
    review.require(raw == workspace.pretty(data) and
                   manifest == workspace.pretty(original_manifest),
                   "Noncanonical original source-free cockpit")
    return data, manifest, raw


def aggregate(data: dict) -> dict:
    slots = data["source_slots"]
    summary = {
        "slots": len(slots),
        "questions": sum(row["human_questions"] for row in slots),
        "pending": sum(row["locally_pending"] for row in slots),
        "local_attachment_links": sum(row["local_attachment_links"] for row in slots),
        "shared_sha_groups": sum(row["cross_finding_shared_sha_groups"] for row in slots),
        "human_attention_groups": sum(row["human_attention_groups"] for row in slots),
        "stages": {k: data["slot_human_stage_totals_not_unique_cases"][k]
                   for k in sorted(triage.STAGES)},
        "reasons": {k: data["slot_pending_human_reason_totals_not_unique_cases"][k]
                    for k in sorted(triage.REASONS)},
    }
    review.require(summary["questions"] == sum(summary["stages"].values()) and
                   summary["pending"] == summary["questions"] -
                   summary["stages"]["answered_human"],
                   "Original HUMAN aggregate mismatch")
    return summary


def difference(left: dict, right: dict) -> dict:
    return {
        **{key: right[key] - left[key] for key in FIELDS},
        "stages": {k: right["stages"][k] - left["stages"][k]
                   for k in sorted(triage.STAGES)},
        "reasons": {k: right["reasons"][k] - left["reasons"][k]
                    for k in sorted(triage.REASONS)},
    }


def assemble(left: dict, right: dict) -> dict:
    a, b = aggregate(left), aggregate(right)
    return {
        "kind": KIND,
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "comparison": "operator_selected_left_to_right_not_proven_time",
        "cohort_match": "UNKNOWN_NOT_SOURCE_AUTHENTICATED",
        "left": a,
        "right": b,
        "delta_right_minus_left": difference(a, b),
    }


def html_view(result: dict) -> bytes:
    left, right, delta = (result["left"], result["right"],
                          result["delta_right_minus_left"])
    rows = []
    def add(label: str, a: int, b: int, d: int) -> None:
        rows.append("<tr><th scope='row'>" + board.safe(label) + "</th><td>" +
                    str(a) + "</td><td>" + str(b) + "</td><td>" +
                    ("+" if d > 0 else "") + str(d) + "</td></tr>")
    for key in FIELDS:
        add(key.replace("_", " ").title(), left[key], right[key], delta[key])
    for key in sorted(triage.STAGES):
        add("HUMAN stage: " + key, left["stages"][key],
            right["stages"][key], delta["stages"][key])
    for key in sorted(triage.REASONS):
        add("Pending HUMAN reason: " + key, left["reasons"][key],
            right["reasons"][key], delta["reasons"][key])
    body = ("<section><h2>Two independently received HUMAN-only workspaces</h2>"
            "<p>Left and right are explicitly selected local snapshots. "
            "Totals are source-slot workloads, not matched original findings "
            "or clients. A positive or negative delta is only arithmetic, "
            "not a verified change to underlying security.</p>"
            "<table><thead><tr><th>Aggregate</th><th>Left</th><th>Right</th>"
            "<th>Right − left</th></tr></thead><tbody>" +
            "".join(rows) + "</tbody></table></section>"
            "<section><h2>Questions for the original source owners</h2>"
            "<ol><li>Did the same private source slots and HUMAN case membership "
            "appear in both handoffs? This source-free product cannot know.</li>"
            "<li>Were HUMAN stage changes recorded in the original private "
            "workroom, with approval from the appropriate owner?</li>"
            "<li>Can a separately authorized person assess the underlying "
            "evidence and retest state? Counts alone cannot establish a fix.</li>"
            "</ol><p>The original human-only snapshots remain unchanged. "
            "No recipient action is pushed to a source system.</p></section>")
    return board.shell(body, "LightUp PRIVATE HUMAN Recipient Comparison")


def csv_view(result: dict) -> bytes:
    left, right, delta = (result["left"], result["right"],
                          result["delta_right_minus_left"])
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("category", "label", "left", "right", "delta_right_minus_left"))
    for category, keys in (("aggregate", FIELDS),
                           ("stage", tuple(sorted(triage.STAGES))),
                           ("reason", tuple(sorted(triage.REASONS)))):
        for name in keys:
            if category == "aggregate":
                writer.writerow((category, name, left[name], right[name], delta[name]))
            else:
                sub = "stages" if category == "stage" else "reasons"
                writer.writerow((category, name, left[sub][name],
                                 right[sub][name], delta[sub][name]))
    return buf.getvalue().encode("utf-8")


def followup_view(result: dict) -> bytes:
    """Recipient-only count-based HUMAN questions, never original-source tasks."""
    left, right, delta = (result["left"], result["right"],
                          result["delta_right_minus_left"])
    lines = [
        "# PRIVATE HUMAN recipient follow-up (not a source task order)",
        "",
        WARNING,
        "",
        "## Count-based discussion prompts",
        "",
        "This recipient handoff contains no original client, finding, owner or",
        "evidence identity. Do not action a remediation or infer any fix.",
        "Ask the trusted original private source owner to reconcile original",
        "cohort membership and HUMAN stages before interpreting changes.",
        "",
        "Left: " + str(left["slots"]) + " local slots / " +
        str(left["pending"]) + " locally pending HUMAN questions.",
        "Right: " + str(right["slots"]) + " local slots / " +
        str(right["pending"]) + " locally pending HUMAN questions.",
        "",
        "### Follow-up reasons with local pending occurrences",
        "",
    ]
    active = [key for key in triage.REASONS if right["reasons"][key] > 0]
    active.sort(key=lambda key: (-max(delta["reasons"][key], 0),
                                 -right["reasons"][key], key))
    if not active:
        lines.append("- None locally reported in this right-hand snapshot; "
                     "this does NOT mean security issues are fixed.")
    for key in active:
        review.require(key in board.ADVICE,
                       "Unknown native original human reason")
        lines.append("- " + key + ": " + str(right["reasons"][key]) +
                     " right-hand local occurrences, delta " +
                     ("%+d" % delta["reasons"][key]) + ". " + board.ADVICE[key])
    lines += [
        "",
        "### Human handoff boundaries",
        "",
        "- Verify whether original source populations/slot orders truly match.",
        "- Ask original owner who should review the evidence PRIVATE-side.",
        "- Keep source-free counters PRIVATE; small groups may reveal workload.",
        "- Original source authorization and independent retest remain separate.",
        "- No authenticated chronology, grant, consent, fix or scan is issued.",
        "",
    ]
    return ("\n".join(lines)).encode("utf-8")


def artifacts(result: dict) -> dict[str, bytes]:
    return {"index.html": html_view(result),
            "counts.json": workspace.pretty(result),
            "counts.csv": csv_view(result),
            "recipient-actions.md": followup_view(result)}


def publish(left_dir: Path, right_dir: Path, output: Path) -> dict:
    review.require(left_dir != right_dir and output.is_absolute() and
                   output not in (left_dir, right_dir) and
                   all(source not in output.parents and
                       output not in source.parents and
                       output.parent != source
                       for source in (left_dir, right_dir)),
                   "Comparison destination cannot be a source path")
    triage.private_parent(output)
    left, left_manifest, left_raw = admit_received(left_dir)
    right, right_manifest, right_raw = admit_received(right_dir)
    # Different packet order or repeated original sources CANNOT be
    # authenticated with anonymous inputs; no per-case joins are attempted.
    result = assemble(left, right)
    files = artifacts(result)
    manifest = {
        "kind": KIND + ".local_receipt",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "files": {name: {"bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(files.items())},
    }
    # Before any artifact becomes visible, re-admit EACH complete unchanged
    # source-free cockpit, including all deterministic HTML and original docs.
    for folder, source_manifest, source_raw in (
        (left_dir, left_manifest, left_raw),
        (right_dir, right_manifest, right_raw),
    ):
        _, latest_manifest, latest_raw = admit_received(folder)
        review.require(latest_manifest == source_manifest and
                       latest_raw == source_raw,
                       "Received PRIVATE snapshot changed during comparison")
    workspace.publish_bundle(output, files, workspace.pretty(manifest))
    return {"left_source_slots": result["left"]["slots"],
            "right_source_slots": result["right"]["slots"],
            "left_pending_human": result["left"]["pending"],
            "right_pending_human": result["right"]["pending"]}


def main() -> int:
    p = argparse.ArgumentParser(description=(
        "PRIVATE offline HUMAN-only aggregate differences between two "
        "fully received native source-free Evidence Cockpits"))
    p.add_argument("--left", type=Path, required=True,
                   help="First complete original source-free 0700 cockpit folder")
    p.add_argument("--right", type=Path, required=True,
                   help="Second complete original source-free 0700 cockpit folder")
    p.add_argument("--output-dir", type=Path, required=True,
                   help="NEW owner-private comparison folder under existing 0700 parent")
    args = p.parse_args()
    try:
        summary = publish(args.left, args.right, args.output_dir)
        print("REVIEW_ONLY: PRIVATE source-free HUMAN comparison created.")
        print("Left/right locally pending: " +
              str(summary["left_pending_human"]) + "/" +
              str(summary["right_pending_human"]) +
              ". Not matched cohorts, authenticated time or verified remediation.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: complete source-free cockpit comparison refused; "
              "no security or consent decision.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
