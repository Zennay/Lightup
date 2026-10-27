#!/usr/bin/env python3
"""Strict local HUMAN routing-state return to existing offline Studio board v1.

Not a client reply, authenticated reviewer, evidence or remediation action.
"""
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
import session

NOTICE = (
    "LOCAL SELF-DECLARED HUMAN ROUTING UPDATE ONLY. This is NOT a reply by an "
    "authenticated person, original evidence review, consent, security finding, "
    "verified remediation, retest, grant, approval or any target action."
)


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def updated_board(session_path: Path, board_path: Path, ordinal: int,
                  expected_action: str, new_state: str) -> tuple[dict, dict]:
    portfolio.require(type(ordinal) is int and 1 <= ordinal <= 12)
    portfolio.require(expected_action in action_board.ACTION_CODES
                      and new_state in action_board.STATE_CODES)
    # First independent validated full-session/source contract.
    original_rows = action_board.board_import(board_path, session_path)
    portfolio.require(ordinal <= len(original_rows))
    original_row = original_rows[ordinal - 1]
    portfolio.require(original_row["local_followup_action_code"] == expected_action)
    # The independently re-read private inputs must still match EXACT numeric
    # shape and action/state sequence; no reliance on unchecked user metadata.
    saved, _ = session.read_session(session_path)
    board = portfolio.parse(portfolio.read_private(board_path))
    portfolio.header(board, action_board.BOARD_KIND, action_board.FIELDS,
                     action_board.BOARD_DISPOSITION)
    portfolio.require(board["warning"] == action_board.BOARD_WARNING)
    portfolio.require(board["numeric_packets"] ==
                      [action_board.native_packet(row) for row in saved])
    portfolio.require(type(board["assignments"]) is list and
                      len(board["assignments"]) == len(original_rows))
    for index, (before, current) in enumerate(zip(original_rows,
                                                   board["assignments"]), 1):
        portfolio.require(type(current) is dict and
                          set(current) == action_board.ASSIGNMENT_FIELDS and
                          type(current["ordinal"]) is int and
                          current["ordinal"] == index and
                          current["action"] == before["local_followup_action_code"] and
                          current["state"] == before["local_planning_state_code"])
    old_state = board["assignments"][ordinal - 1]["state"]
    portfolio.require(old_state != new_state)  # avoid pretending to update a no-op
    board["assignments"][ordinal - 1] = {
        "ordinal": ordinal,
        "action": expected_action,
        "state": new_state,
    }
    change = {
        "kind": "lightup.local_private_human_routing_return",
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_ROUTING_CHANGE_ONLY_NO_AUTHORITY",
        "local_packet_ordinal_not_case": ordinal,
        "human_action": expected_action,
        "previous_local_state": old_state,
        "proposed_new_local_state": new_state,
        "original_source_not_authenticated": True,
        "restoration_requires_same_local_numeric_session": True,
        "warning": NOTICE,
        **{flag: False for flag in portfolio.FLAGS},
    }
    return board, change


def browser_page(change: dict) -> bytes:
    def v(k: str) -> str:
        return html.escape(str(change[k]))
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE local HUMAN return</title><style>
:root{color-scheme:dark}body{font:16px/1.6 system-ui;max-width:850px;margin:auto;
background:#122034;color:#eef9fc;padding:clamp(18px,5vw,50px)}
aside,article{background:#253953;padding:20px;margin:22px 0;border-radius:14px}
aside{border-left:5px solid #f7ce86}p{color:#d3dee6}</style></head><body>
<small>LIGHTUP / PRIVATE HUMAN / INCUBATE / DRAFT HOLD</small>
<h1>Local HUMAN routing return</h1><aside><strong>NOT ORIGINAL EVIDENCE OR AUTHORITY.</strong>
<p>""" + html.escape(NOTICE) + """</p></aside><article>
<p>Local ordinal (not original case): <strong>""" + v("local_packet_ordinal_not_case") +
"""</strong></p><p>HUMAN action: <strong>""" + v("human_action") +
"""</strong></p><p>Previous local state: <strong>""" + v("previous_local_state") +
"""</strong></p><p>New local state: <strong>""" + v("proposed_new_local_state") +
"""</strong></p></article><h2>Manual return to offline Studio</h2>
<p>Open the unchanged original local saved numeric session in the offline HUMAN Studio,
then use its HUMAN action board restore to load the separate private
<code>board.json</code> created alongside this page. The Studio independently
checks the exact numeric packet shape and all ordinals before accepting it.</p>
<p>This never marks a finding, original record, consent, fix or assessment as
verified. A HUMAN must independently inspect the current genuine authenticated
source. The new board is private but not encrypted at rest.</p>
</body></html>""").encode("utf-8")


def build(session_path: Path, board_path: Path, destination: Path, ordinal: int,
          expected_action: str, state: str) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    board, change = updated_board(session_path, board_path, ordinal,
                                  expected_action, state)
    stage = Path(tempfile.mkdtemp(prefix=".lightup-private-routing-return-",
                                  dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "board.json", portfolio.serialize(board))
        # Re-admit final v1 board as original exact session-bound format BEFORE
        # publishing, without any code path to native source/update operations.
        action_board.board_import(stage / "board.json", session_path)
        portfolio.exclusive_write(stage / "change-summary.json",
                                  portfolio.serialize(change))
        portfolio.exclusive_write(stage / "index.html", browser_page(change))
        sync_dir(stage)
        portfolio.publish(stage, destination)
        sync_dir(destination.parent)
        return change
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One explicit PRIVATE local HUMAN status change returned to "
                    "offline Studio v1, not an authentic source or client update.")
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--ordinal", type=int, required=True,
                        help="Local packet number only; never original case ID")
    parser.add_argument("--expect-action", choices=action_board.ACTION_CODES,
                        required=True, help="Explicitly pin prior HUMAN action")
    parser.add_argument("--new-state", choices=action_board.STATE_CODES,
                        required=True, help="A HUMAN-only self-declared local state")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW PRIVATE folder; original board not modified")
    args = parser.parse_args()
    try:
        record = build(args.session, args.board, args.output_dir,
                       args.ordinal, args.expect_action, args.new_state)
    except (ValueError, OSError, RecursionError):
        print("HOLD: original private board unchanged; no complete routing return.",
              file=sys.stderr)
        return 2
    print("PRIVATE local HUMAN board return ready: ordinal %d, state %s. "
          "No authenticated source action." %
          (record["local_packet_ordinal_not_case"],
           record["proposed_new_local_state"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
