#!/usr/bin/env python3
"""Atomic multi-row local HUMAN status returns to original offline Studio v1."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import action_board
import portfolio

import return_to_studio

BATCH_KIND = "lightup.private_local_human_routing_changes"
BATCH_DISPOSITION = "HUMAN_ONLY_UNVERIFIED_LOCAL_ROUTING_PROPOSALS"
BATCH_WARNING = (
    "Self-declared proposed LOCAL HUMAN routing states only. Not an authentic "
    "reviewer reply, source observation, authorization, remediation, retest, "
    "client consent, finding, grant, scan or release."
)
BATCH_FIELDS = {"kind", "schema_version", "disposition", "changes", "warning",
                *portfolio.FLAGS}
CHANGE_FIELDS = {"ordinal", "expect_action", "expect_state", "new_state"}
RETURN_NOTICE = (
    "All HUMAN choices remain self-declared and offline. This PRIVATE local "
    "board is only a proposal for the original Studio's separate source-free "
    "numeric session. No authenticated case state, evidence, reviewer, "
    "retest, fix, client consent or permission is changed."
)


def updates(path: Path) -> list[dict]:
    packet = portfolio.parse(portfolio.read_private(path))
    portfolio.header(packet, BATCH_KIND, BATCH_FIELDS, BATCH_DISPOSITION)
    portfolio.require(packet["warning"] == BATCH_WARNING)
    changes = packet["changes"]
    portfolio.require(type(changes) is list and 1 <= len(changes) <= 12)
    seen = set()
    for c in changes:
        portfolio.require(type(c) is dict and set(c) == CHANGE_FIELDS)
        ordinal = c["ordinal"]
        portfolio.require(type(ordinal) is int and 1 <= ordinal <= 12
                          and ordinal not in seen)
        seen.add(ordinal)
        portfolio.require(type(c["expect_action"]) is str and
                          c["expect_action"] in action_board.ACTION_CODES)
        portfolio.require(type(c["expect_state"]) is str and
                          c["expect_state"] in action_board.STATE_CODES)
        portfolio.require(type(c["new_state"]) is str and
                          c["new_state"] in action_board.STATE_CODES and
                          c["new_state"] != c["expect_state"])
    return changes


def build_changes(session_path: Path, board_path: Path,
                  changes: list[dict]) -> tuple[dict, dict]:
    first = changes[0]
    # Original full-batch privately admitted, exact-current board/session match.
    board, record = return_to_studio.updated_board(
        session_path, board_path, first["ordinal"], first["expect_action"],
        first["new_state"])
    portfolio.require(record["previous_local_state"] == first["expect_state"])
    results = [{
        "local_ordinal_not_original_case": first["ordinal"],
        "action": first["expect_action"],
        "prior_state": first["expect_state"],
        "new_local_state": first["new_state"],
    }]
    # Apply all further disjoint updates to the same validated in-memory board.
    # Never publish or mutate either original input on a partial failure.
    for c in changes[1:]:
        ordinal = c["ordinal"]
        portfolio.require(ordinal <= len(board["assignments"]))
        row = board["assignments"][ordinal - 1]
        portfolio.require(row["ordinal"] == ordinal and
                          row["action"] == c["expect_action"] and
                          row["state"] == c["expect_state"])
        board["assignments"][ordinal - 1] = {
            "ordinal": ordinal, "action": c["expect_action"],
            "state": c["new_state"],
        }
        results.append({
            "local_ordinal_not_original_case": ordinal,
            "action": c["expect_action"],
            "prior_state": c["expect_state"],
            "new_local_state": c["new_state"],
        })
    summary = {
        "kind": "lightup.private_local_human_routing_bulk_return",
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_ROUTING_ONLY_DRAFT_HOLD",
        "number_of_self_declared_changes_not_original_cases": len(results),
        "changes": results,
        "warning": RETURN_NOTICE,
        **{flag: False for flag in portfolio.FLAGS},
    }
    return board, summary


def render(summary: dict) -> bytes:
    rows = []
    for item in summary["changes"]:
        rows.append("<tr><th>%d</th><td>%s</td><td>%s</td><td>%s</td></tr>" %
                    (item["local_ordinal_not_original_case"],
                     html.escape(item["action"]),
                     html.escape(item["prior_state"]),
                     html.escape(item["new_local_state"])))
    result = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN bulk return</title>
<style>:root{color-scheme:dark}body{margin:auto;max-width:1000px;
padding:clamp(18px,4vw,50px);background:#132034;color:#f2f7fe;
font:16px/1.6 system-ui}aside{padding:20px;background:#2d394b;
border-left:5px solid #f6cb86;border-radius:14px}
table{border-collapse:collapse;width:100%%;min-width:580px}th,td{padding:13px;
text-align:left;border-bottom:1px solid #526176}.scroll{overflow:auto}</style>
</head><body><small>LIGHTUP / HUMAN ONLY / INCUBATE / DRAFT HOLD</small>
<h1>Offline HUMAN routing return</h1>
<aside><strong>Not sent. Not authenticated source.</strong><p>%s</p></aside>
<p>%d self-declared LOCAL HUMAN state transitions; all original source data
and original board files are unchanged. No reviewer identity is asserted.</p>
<div class="scroll"><table><thead><tr><th>Local ordinal, NOT case</th>
<th>HUMAN action</th><th>Prior local state</th><th>New local state</th>
</tr></thead><tbody>%s</tbody></table></div>
<p>To continue, load the same source-free numeric session in the unchanged
offline Studio, then manually restore the new owner-private <code>board.json</code>.
The original Studio must admit the entire current packet/ordinal set again.
Changing local statuses never verifies real remediation or grants authority.</p>
</body></html>""" % (
        html.escape(RETURN_NOTICE),
        summary["number_of_self_declared_changes_not_original_cases"],
        "".join(rows))
    return result.encode("utf-8")


def build(session_path: Path, board_path: Path, changes_path: Path,
          destination: Path) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    # Strict entire human-edited update manifest is admitted BEFORE publication.
    changes = updates(changes_path)
    board, summary = build_changes(session_path, board_path, changes)
    stage = Path(tempfile.mkdtemp(dir=destination.parent,
                                  prefix=".lightup-human-bulk-return-"))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "board.json", portfolio.serialize(board))
        # The actual ORIGINAL parser validates the resulting native board against
        # the entire unchanged private numeric session before publishing.
        action_board.board_import(stage / "board.json", session_path)
        portfolio.exclusive_write(stage / "change-summary.json",
                                  portfolio.serialize(summary))
        portfolio.exclusive_write(stage / "index.html", render(summary))
        return_to_studio.sync_dir(stage)
        portfolio.publish(stage, destination)
        return_to_studio.sync_dir(destination.parent)
        return summary
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline all-or-nothing PRIVATE HUMAN routing state update "
                    "batch; returns native Studio board without original authority.")
    parser.add_argument("--session", required=True, type=Path)
    parser.add_argument("--board", required=True, type=Path)
    parser.add_argument("--changes", required=True, type=Path,
                        help="Owner-private 0600 strict local change manifest JSON")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="Fresh owner-only output directory")
    args = parser.parse_args()
    try:
        receipt = build(args.session, args.board, args.changes, args.output_dir)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no partial private HUMAN state update was published.",
              file=sys.stderr)
        return 2
    print("Offline HUMAN state return created: %d local changes; not original "
          "source authority or verified remediation." %
          receipt["number_of_self_declared_changes_not_original_cases"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
