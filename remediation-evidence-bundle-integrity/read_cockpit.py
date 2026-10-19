#!/usr/bin/env python3
"""Receive and recheck a self-contained PRIVATE HUMAN Evidence Cockpit offline.

An unsigned local manifest is NOT authentic source provenance. Independently
reconstruct browser pages from the accompanying source-free anonymous JSON,
so a changed HTML payload cannot be accepted by checksum replacement alone.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

import board
import portfolio
import progression
import verify

review = verify.review
workspace = verify.workspace
triage = verify.triage

DEFAULT = frozenset(("index.html", "portfolio.html", "portfolio.json", "actions.html"))
HISTORY = frozenset(("history.html", "history.json"))
MANIFEST = frozenset(("kind", "schema_version", "disposition",
                      "slot_count", "original_packet_context_repeated",
                      "files", "warning", *review.FLAGS))
PORTFOLIO = frozenset(("kind", "schema_version", "disposition",
                       "source_slots", "possible_repeated_original_source_slot_groups",
                       "slot_human_stage_totals_not_unique_cases",
                       "slot_pending_human_reason_totals_not_unique_cases",
                       "warning", *review.FLAGS))
SLOT = frozenset(("slot", "human_questions", "locally_pending",
                  "local_human_stages", "pending_human_reasons",
                  "local_attachment_links", "cross_finding_shared_sha_groups",
                  "human_attention_groups"))
HISTORY_FIELDS = frozenset(("kind", "schema_version", "disposition",
                           "snapshots", "adjacent_user_order_transitions",
                           "warning", *review.FLAGS))
HISTORY_SLOT = frozenset(("slot", "question_count", "human_stage_counts",
                          "locally_pending"))
TRANSITION = frozenset(("from_slot", "to_slot", "changed_stage",
                        "reopened_local_human_question",
                        "locally_answered_since_prior_slot", "now_needs_source_owner",
                        "changed_private_note_without_note_contents",
                        "unchanged_local_human_record"))

def nonnegative(value: object, label: str, ceiling: int = 100000) -> int:
    review.require(type(value) is int and 0 <= value <= ceiling,
                   "Invalid bounded anonymous count: " + label)
    return value

def counts(data: object, keys: set | frozenset, name: str) -> dict:
    review.require(type(data) is dict and set(data) == set(keys),
                   "Invalid HUMAN stage/reason shape: " + name)
    for key, value in data.items():
        nonnegative(value, "anonymous stage/reason")
    return data

def admit_portfolio(data: dict, slot_count: int) -> None:
    review.require(set(data) == PORTFOLIO and
                   data.get("kind") == "lightup.anonymous_private_human_evidence_workload_portfolio" and
                   type(data.get("schema_version")) is int and
                   data["schema_version"] == 1 and
                   data.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   all(data.get(f) is False for f in review.FLAGS),
                   "Unknown source-free private workload schema or authority claim")
    review.require(data.get("warning") == portfolio.WARNING,
                   "Source-free portfolio warning changed")
    rows = data.get("source_slots")
    review.require(type(rows) is list and len(rows) == slot_count,
                   "Incomplete source-free original slot list")
    totals = {k: 0 for k in triage.STAGES}
    reasons = {k: 0 for k in triage.REASONS}
    for idx, row in enumerate(rows, 1):
        review.require(type(row) is dict and set(row) == SLOT and
                       type(row.get("slot")) is int and row["slot"] == idx,
                       "Invalid or reordered source slot")
        stages = counts(row["local_human_stages"], triage.STAGES, "stages")
        reason_counts = counts(row["pending_human_reasons"], triage.REASONS, "reasons")
        n = nonnegative(row["human_questions"], "HUMAN questions", 2000)
        review.require(sum(stages.values()) == n and
                       row["locally_pending"] ==
                       sum(stages[k] for k in triage.STAGES if k != "answered_human"),
                       "Human question count inconsistent with stage counts")
        for key in ("local_attachment_links", "cross_finding_shared_sha_groups",
                    "human_attention_groups"):
            nonnegative(row[key], "attachment/reuse/attention", 2000)
        review.require(row["cross_finding_shared_sha_groups"] <= row["local_attachment_links"]
                       and row["human_attention_groups"] <= row["cross_finding_shared_sha_groups"],
                       "Impossible local fingerprint attention count")
        for key in triage.STAGES:
            totals[key] += stages[key]
        for key in triage.REASONS:
            reasons[key] += reason_counts[key]
    counts(data.get("slot_human_stage_totals_not_unique_cases"), triage.STAGES, "totals")
    counts(data.get("slot_pending_human_reason_totals_not_unique_cases"), triage.REASONS, "reason totals")
    review.require(data["slot_human_stage_totals_not_unique_cases"] == totals and
                   data["slot_pending_human_reason_totals_not_unique_cases"] == reasons,
                   "Source-slot aggregate totals inconsistent")
    overlap = data.get("possible_repeated_original_source_slot_groups")
    review.require(type(overlap) is list and len(overlap) <= 6,
                   "Invalid original source overlap grouping")
    seen = set()
    for group in overlap:
        review.require(type(group) is list and 2 <= len(group) <= slot_count and
                       all(type(x) is int and 1 <= x <= slot_count for x in group),
                       "Invalid overlap slot numbers")
        review.require(len(set(group)) == len(group) and
                       not seen.intersection(group) and group == sorted(group),
                       "Overlapping or repeated exact original source slots")
        seen.update(group)

def admit_history(data: dict, portfolio_data: dict) -> None:
    review.require(set(data) == HISTORY_FIELDS and
                   data.get("kind") == "lightup.anonymous_private_human_workspace_progression" and
                   type(data.get("schema_version")) is int and data["schema_version"] == 1 and
                   data.get("disposition") == "UNVERIFIED_HUMAN_REVIEW_ONLY" and
                   all(data.get(f) is False for f in review.FLAGS),
                   "Unsupported original-source HUMAN progression envelope")
    review.require(data.get("warning") == progression.WARNING,
                   "Source-free chronology warning changed")
    slots = data.get("snapshots")
    originals = portfolio_data["source_slots"]
    review.require(type(slots) is list and len(slots) == len(originals),
                   "Original same-source slots are incomplete")
    for idx, row in enumerate(slots, 1):
        main = originals[idx-1]
        review.require(type(row) is dict and set(row) == HISTORY_SLOT and
                       type(row["slot"]) is int and row["slot"] == idx and
                       row["human_stage_counts"] == main["local_human_stages"] and
                       row["question_count"] == main["human_questions"] and
                       row["locally_pending"] == main["locally_pending"],
                       "Original-source progression differs from portfolio HUMAN state")
    transitions = data.get("adjacent_user_order_transitions")
    review.require(type(transitions) is list and len(transitions) == len(slots)-1,
                   "Incomplete original HUMAN adjacent slot changes")
    for idx, row in enumerate(transitions, 1):
        review.require(type(row) is dict and set(row) == TRANSITION and
                       type(row["from_slot"]) is int and row["from_slot"] == idx and
                       type(row["to_slot"]) is int and row["to_slot"] == idx+1,
                       "Misordered HUMAN transitions")
        for key in TRANSITION - {"from_slot", "to_slot"}:
            nonnegative(row[key], "transition count", 2000)
        n = originals[idx]["human_questions"]
        review.require(row["changed_stage"] <= n and
                       row["changed_private_note_without_note_contents"] <= n and
                       row["unchanged_local_human_record"] <= n and
                       row["reopened_local_human_question"] <= row["changed_stage"] and
                       row["locally_answered_since_prior_slot"] <= row["changed_stage"],
                       "Impossible human transition count")

def inspect(path: Path) -> dict:
    review.require(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
                   and not path.is_symlink(), "Original private cockpit path must be literal")
    mode = path.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0, "Private operator cockpit requires 0700")
    mbytes = review.private_read(path / "manifest.json")
    m = verify.json_obj(mbytes)
    review.require(set(m) == MANIFEST and
                   m.get("kind") == board.KIND and
                   type(m.get("schema_version")) is int and m["schema_version"] == 1 and
                   m.get("disposition") == "PRIVATE_HUMAN_REVIEW_ONLY_NO_AUTHORITY" and
                   all(m.get(f) is False for f in review.FLAGS),
                   "Unrecognized original PRIVATE operating cockpit manifest")
    review.require(m.get("warning") == board.WARNING,
                   "Offline cockpit disclaimer changed")
    total = nonnegative(m.get("slot_count"), "PRIVATE slot count", 12)
    review.require(2 <= total <= 12 and type(m.get("original_packet_context_repeated")) is bool,
                   "Invalid original source-slot metadata")
    hist = m["original_packet_context_repeated"]
    filenames = DEFAULT | (HISTORY if hist else frozenset())
    review.require(type(m.get("files")) is dict and set(m["files"]) == filenames and
                   {p.name for p in path.iterdir()} == set(filenames) | {"manifest.json"},
                   "Missing or unlisted standalone PRIVATE cockpit file")
    payloads = {}
    for name in sorted(filenames):
        info = m["files"][name]
        review.require(type(info) is dict and set(info) == {"bytes", "sha256"} and
                       type(info["sha256"]) is str and
                       review.HEX.fullmatch(info["sha256"]) is not None,
                       "Invalid private output file descriptor")
        declared_size = nonnegative(info["bytes"], "private output size", verify.MAX_BYTES)
        raw = review.private_read(path / name)
        review.require(len(raw) == declared_size and board.hash_bytes(raw) == info["sha256"],
                       "Private cockpit output checksum does not match")
        payloads[name] = raw
    review.require(mbytes == workspace.pretty(m),
                   "Noncanonical output manifest was supplied")

    portfolio_doc = verify.json_obj(payloads["portfolio.json"])
    review.require(payloads["portfolio.json"] == workspace.pretty(portfolio_doc),
                   "Source-free original portfolio JSON must be canonical")
    admit_portfolio(portfolio_doc, total)
    review.require(payloads["portfolio.html"] == portfolio.render(portfolio_doc) and
                   payloads["actions.html"] == board.action_brief(portfolio_doc) and
                   payloads["index.html"] == board.overview(portfolio_doc, hist),
                   "Offline HUMAN browser content differs from native deterministic renderer")
    if hist:
        history_doc = verify.json_obj(payloads["history.json"])
        review.require(payloads["history.json"] == workspace.pretty(history_doc),
                       "Source-free original history JSON must be canonical")
        admit_history(history_doc, portfolio_doc)
        review.require(payloads["history.html"] == progression.render(history_doc),
                       "Human history page differs from original source-free renderer")
        review.require(portfolio_doc["possible_repeated_original_source_slot_groups"]
                       == [list(range(1, total + 1))],
                       "Same-source history must account for all original source slots")
    # Re-open every file: reject a moving/replaced cockpit before a HUMAN uses it.
    review.require(review.private_read(path / "manifest.json") == mbytes,
                   "PRIVATE cockpit manifest changed during admission")
    for name, original in payloads.items():
        review.require(review.private_read(path / name) == original,
                       "PRIVATE cockpit changed during admission")
    return {
        "original_source_slots_not_unique_cases": total,
        "local_pending_human_questions_not_fixes": sum(
            row["locally_pending"] for row in portfolio_doc["source_slots"]),
        "same_original_source_claimed": hist,
        "accepted_private_files": len(payloads) + 1,
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Read-only receipt of a PRIVATE offline HUMAN cockpit, with native HTML reconstruction"))
    parser.add_argument("--cockpit", type=Path, required=True,
                        help="Owner-private existing generated operating cockpit directory")
    args = parser.parse_args()
    try:
        status = inspect(args.cockpit)
        print("REVIEW_ONLY: original PRIVATE cockpit local bytes and rendered pages consistent.")
        print("Source slots " + str(status["original_source_slots_not_unique_cases"]) +
              "; pending HUMAN questions " +
              str(status["local_pending_human_questions_not_fixes"]) +
              "; files " + str(status["accepted_private_files"]) +
              ". Original identity, consent and remediation are NOT authenticated.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE HUMAN cockpit admission failed. No original client "
              "approval or security verdict has been issued.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
