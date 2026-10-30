"""Canonical source-free human text exports, shared by producer and recipient.

ZIP hashes are unsigned. Never display attacker-supplied Markdown or CSV
merely because a manifest with recomputed digests matches.
"""
from __future__ import annotations

import csv
import io
from typing import Any

README = (
    "LightUp synthetic fixed-loopback offline review, HUMAN only.\n"
    "Open index.html for global PASS/HOLD, priorities and pair navigation.\n"
    "Scriptless, offline, source-free display; no network/authorization.\n"
    "A PASS means only local consistency, NEVER external authority.\n"
    "HTML may show first-party allowlisted numeric scorer changes.\n"
    "CSV/JSON/Markdown omit raw numeric metric values.\n"
    "Private source archives, saved receipt bindings and source IDs "
    "are NOT included. ZIP hashes prove transport integrity only.\n"
).encode("utf-8")


def csv_bytes(summary: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(("previous_index", "current_index", "status",
                     "independent_evaluations", "score_stable"))
    for pair in summary["pairs"]:
        writer.writerow((
            pair["previous_index"], pair["current_index"],
            "PASS" if pair["passed"] else "HOLD",
            pair["independent_evaluations"], pair["score_stable"],
        ))
    return buffer.getvalue().encode("utf-8")


def markdown_bytes(summary: dict[str, Any]) -> bytes:
    """Canonical human brief from *only* admitted anonymous flags and labels."""
    n = summary["archives_checked"]
    pairs = summary["pairs"]
    holds = [item for item in pairs if not item["passed"]]
    lines = [
        "# LightUp synthetic lab history — " +
        ("PASS" if summary["passed"] else "HOLD"),
        "",
        f"{n} verified local archives; {summary['pairs_checked']} original pairs; {len(holds)} HOLD pairs.",
        "",
        "**LAB ONLY.** Source chronology and identity are not authenticated. No external "
        "targets, scans, grants, consent, dispatch, deployment or release authority.",
        "",
        "## Operator review priorities", "",
    ]
    if summary["archive_review_queue"]:
        lines += ["| Archive | HOLD pairs | Evidence reuse | Score drift |",
                  "| --- | ---: | ---: | ---: |"]
        for item in summary["archive_review_queue"]:
            lines.append(f"| {item['index']} | {item['hold_pairs']} | "
                         f"{item['reused_evidence_pairs']} | {item['score_drift_pairs']} |")
    else:
        lines.append("No archive requires review.")
    lines += ["", "## First-party scorer hotspots", ""]
    if summary["capability_hotspots"]:
        lines += ["| Scorer | Affected pairs | Metrics |",
                  "| --- | ---: | --- |"]
        for item in summary["capability_hotspots"]:
            lines.append(f"| {item['capability']} | {item['affected_pairs']} | "
                         f"{', '.join(item['metrics'])} |")
    else:
        lines.append("No score-drift hotspot.")
    lines += ["", "## Original pairwise verification", "",
              "| Archives | Result | Evidence independent | Score stable |",
              "| --- | --- | --- | --- |"]
    for pair in pairs:
        lines.append(f"| {pair['previous_index']}–{pair['current_index']} | "
                     f"{'PASS' if pair['passed'] else 'HOLD'} | "
                     f"{'yes' if pair['independent_evaluations'] else 'no'} | "
                     f"{'yes' if pair['score_stable'] else 'no'} |")
    return ("\n".join(lines) + "\n").encode("utf-8")


def admit_text_exports(summary: dict[str, Any], files: dict[str, bytes]) -> None:
    """Reject rewritten CSV formulas, Markdown links, and false handling text."""
    expected = {
        "review.csv": csv_bytes(summary),
        "review.md": markdown_bytes(summary),
        "README.txt": README,
    }
    for name, canonical in expected.items():
        if files.get(name) != canonical:
            raise ValueError("non-canonical portable human-readable export")
