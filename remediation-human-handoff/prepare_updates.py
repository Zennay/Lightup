#!/usr/bin/env python3
"""Prepare fail-safe LOCAL HUMAN return manifest, all proposed changes disabled."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import action_board
import portfolio

import bulk_return
import return_to_studio

INSTRUCTIONS = (
    "LightUp PRIVATE local HUMAN routing edit worksheet (DRAFT/HOLD)\n\n"
    "This template is produced only from the current strictly matched offline "
    "self-declared numeric session and action board. Not original evidence or "
    "authorization. No network, client identifiers, scans or grants.\n\n"
    "1. Keep all files in owner-private 0700 folders and 0600 files.\n"
    "2. Open updates.json with a local private plain-text editor.\n"
    "3. Remove every changes[] row you do NOT intend to change.\n"
    "4. For each remaining row, change ONLY new_state to one of:\n"
    "   not_triaged | needs_human_followup | waiting_original_owner | "
    "locally_discussed.\n"
    "5. Do not modify ordinal, expect_action, expect_state, schema, flags or "
    "warning. Duplicate ordinals, unchanged values, unknown fields, or "
    "unsupported states fail completely.\n"
    "6. The return tool independently re-admits the current entire original "
    "private numeric session and HUMAN board again; a local return is NOT "
    "an authenticated original source reply.\n\n"
    "python3 remediation-human-handoff/bulk_return.py "
    "--session /absolute/0700/session.json --board /absolute/0700/board.json "
    "--changes /absolute/0700/updates.json "
    "--output-dir /absolute/0700/new-return-folder\n"
    "The output must be a FRESH private folder. A human must manually restore "
    "the new board.json in the original offline Studio.\n"
)


def build(session_path: Path, board_path: Path, destination: Path) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    # Original parser owns all input admission, canonical packet matching and
    # literal false-flag contract. The generated default is intentionally a
    # no-op for every row; apply must reject until human explicitly edits it.
    rows = action_board.board_import(board_path, session_path)
    changes = [
        {
            "ordinal": row["packet_ordinal_not_original_case"],
            "expect_action": row["local_followup_action_code"],
            "expect_state": row["local_planning_state_code"],
            "new_state": row["local_planning_state_code"],
        }
        for row in rows
    ]
    template = {
        "kind": bulk_return.BATCH_KIND,
        "schema_version": 1,
        "disposition": bulk_return.BATCH_DISPOSITION,
        "changes": changes,
        "warning": bulk_return.BATCH_WARNING,
        **{flag: False for flag in portfolio.FLAGS},
    }
    stage = Path(tempfile.mkdtemp(dir=destination.parent,
                                  prefix=".lightup-human-worksheet-"))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "updates.json",
                                  portfolio.serialize(template))
        portfolio.exclusive_write(stage / "HOW_TO_EDIT.txt",
                                  INSTRUCTIONS.encode("utf-8"))
        return_to_studio.sync_dir(stage)
        portfolio.publish(stage, destination)
        return_to_studio.sync_dir(destination.parent)
        return template
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate complete PRIVATE source-free HUMAN change worksheet "
                    "whose default no-ops must be explicitly edited before apply.")
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh PRIVATE output directory containing updates.json")
    args = parser.parse_args()
    try:
        result = build(args.session, args.board, args.output_dir)
    except (OSError, ValueError, RecursionError):
        print("HOLD: no private HUMAN edit worksheet published.", file=sys.stderr)
        return 2
    print("PRIVATE HUMAN worksheet: %d disabled-by-default rows. Explicitly "
          "edit/remove rows before local application; no original authority." %
          len(result["changes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
