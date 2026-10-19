#!/usr/bin/env python3
"""Compose one complete offline PRIVATE HUMAN workroom from a browser board.

Uses the strict ORIGINAL session-and-board parser on both local snapshots.
Neither snapshot can authorize real work or identify a real original case.
"""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import action_board
import portfolio

import handoff
import encrypt_handoff
import compare_returns
import return_to_studio
import workflow


def original_source_free_diff(session_path: Path, old_path: Path,
                              proposed_path: Path) -> tuple[dict, int]:
    earlier = action_board.board_import(old_path, session_path)
    proposed = action_board.board_import(proposed_path, session_path)
    portfolio.require(len(earlier) == len(proposed) and 1 <= len(earlier) <= 12)
    changed = 0
    for ordinal, (a, b) in enumerate(zip(earlier, proposed), 1):
        portfolio.require(
            type(a["packet_ordinal_not_original_case"]) is int and
            a["packet_ordinal_not_original_case"] ==
            b["packet_ordinal_not_original_case"] == ordinal and
            a["source_type"] == b["source_type"] and
            a["anonymous_slot_appearances_not_unique"] ==
            b["anonymous_slot_appearances_not_unique"] and
            a["unverified_pending_human_questions"] ==
            b["unverified_pending_human_questions"]
        )
        if (a["local_followup_action_code"] != b["local_followup_action_code"]
            or a["local_planning_state_code"] != b["local_planning_state_code"]):
            changed += 1
    portfolio.require(changed > 0)
    # The proposed PRIVATE file is already strict, but canonicalize a new
    # private native output without trusting its unvalidated raw text.
    payload = portfolio.parse(portfolio.read_private(proposed_path))
    portfolio.header(payload, action_board.BOARD_KIND, action_board.FIELDS,
                     action_board.BOARD_DISPOSITION)
    portfolio.require(payload["warning"] == action_board.BOARD_WARNING)
    return payload, changed


def return_page(changed: int) -> bytes:
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN return</title><style>
:root{color-scheme:dark}body{margin:auto;max-width:880px;padding:clamp(17px,4vw,44px);
background:#112035;color:#eff8fc;font:16px/1.6 system-ui}
article{background:#20364b;padding:20px;border-radius:14px}
a{color:#abe9d4}</style></head><body>
<small>LIGHTUP / HUMAN ONLY / INCUBATE / DRAFT HOLD</small>
<h1>Local source-free HUMAN Studio return</h1>
<article><p><strong>%d locally changed anonymous packet appearances</strong>
have an exact native Studio-v1 routing-board return.</p>
<p>Download <a href="board.json">PRIVATE native board.json</a> only for
manual restore in the original offline Studio against the same privately
saved numeric session. Do NOT treat this as an authenticated reviewer
response, client finding, consent, scan, grant, fixed vulnerability or
original source edit.</p></article>
<p><a href="../index.html">Back to the private local workroom</a></p>
</body></html>""" % changed).encode("utf-8")


def create(session_path: Path, original_path: Path, proposed_path: Path,
           destination: Path, only: str | None = None, ordinal: int | None = None,
           peer_board: Path | None = None,
           handoff_password: str | None = None) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    portfolio.require(only is None or only in handoff.ACTIONS)
    portfolio.require(handoff_password is None or only in handoff.ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and only in handoff.ACTIONS and
                       1 <= ordinal <= 12))
    proposed, changed = original_source_free_diff(
        session_path, original_path, proposed_path)
    stage = Path(tempfile.mkdtemp(prefix=".lightup-browser-human-workflow-",
                                  dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        proposed_stage = stage / "return"
        proposed_stage.mkdir(mode=0o700)
        portfolio.exclusive_write(proposed_stage / "board.json",
                                  portfolio.serialize(proposed))
        # A genuinely unchanged original strict parser re-reads the new board
        # from this exact staged file before any public publication.
        action_board.board_import(proposed_stage / "board.json", session_path)
        portfolio.exclusive_write(
            proposed_stage / "index.html", return_page(changed))
        return_to_studio.sync_dir(proposed_stage)

        own_board = proposed_stage / "board.json"
        actions = handoff.build(session_path, own_board, stage / "handoff", only, ordinal)
        if handoff_password is not None:
            encrypt_handoff.create(
                session_path, own_board, stage / "handoff-selected.lheh",
                handoff_password, only, ordinal)
        diff = compare_returns.build(session_path, original_path, own_board,
                                     stage / "difference")
        portfolio.require(
            changed == diff["ordinal_appearances_with_local_changes"]
        )
        peer_delta = 0
        if peer_board is not None:
            # Source-free peer candidate is independently admitted using the
            # original strict native parser. It is not an authentic reviewer.
            previous_rows = action_board.board_import(original_path, session_path)
            candidate_rows = action_board.board_import(peer_board, session_path)
            changed_peer = any(
                before["local_followup_action_code"] != candidate["local_followup_action_code"]
                or before["local_planning_state_code"] != candidate["local_planning_state_code"]
                for before, candidate in zip(previous_rows, candidate_rows)
            )
            if changed_peer:
                peer_report = compare_returns.build(
                    session_path, original_path, peer_board, stage / "peer")
                peer_delta = peer_report["ordinal_appearances_with_local_changes"]
        groups = [g["action"] for g in actions["groups"]
                  if g["packet_appearances_not_unique"] > 0]
        result = {
            "kind": "lightup.private_browser_to_native_human_offline_workflow",
            "schema_version": 1,
            "disposition": "LOCAL_HUMAN_PROPOSAL_DRAFT_HOLD_NO_AUTHORITY",
            "changed_anonymous_routing_appearances_not_original_cases": changed,
            "locally_changed_action_appearances": diff["ordinals_with_action_changes"],
            "locally_changed_state_appearances": diff["ordinals_with_state_changes"],
            "selected_human_action_groups": groups,
            "encrypted_selected_human_capsule_private_not_sent":
                handoff_password is not None,
            "peer_local_differences_not_authenticated_reviews": peer_delta,
            "warning": workflow.DISCLAIMER,
            **{flag: False for flag in portfolio.FLAGS},
        }
        portfolio.exclusive_write(stage / "index.html",
                                  workflow.landing(changed, len(groups), peer_delta > 0,
                                                   handoff_password is not None))
        portfolio.exclusive_write(stage / "summary.json",
                                  portfolio.serialize(result))
        return_to_studio.sync_dir(stage)
        portfolio.publish(stage, destination)
        return_to_studio.sync_dir(destination.parent)
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline atomic original numeric Studio pair + edited browser "
                    "native board -> complete private HUMAN handoff, native return, "
                    "and action/state difference workroom. No real source authority.")
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--original-board", type=Path, required=True)
    parser.add_argument("--proposed-board", type=Path, required=True,
                        help="PRIVATE 0600 native Studio-v1 board exported by browser")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New PRIVATE 0700 full workroom, never overwrite")
    parser.add_argument("--only", choices=handoff.ACTIONS,
                        help="Limit HUMAN follow-up handoffs to one action")
    parser.add_argument("--ordinal", type=int,
                        help="With --only, disclose one exact local anonymous ordinal")
    parser.add_argument("--peer-board", type=Path,
                        help="Optional same-session anonymous peer HUMAN board; no identity claim")
    parser.add_argument("--encrypt-selected-handoff", action="store_true",
                        help="Also create password-protected selected .lheh")
    args = parser.parse_args()
    if args.encrypt_selected_handoff and args.only is None:
        parser.error("--encrypt-selected-handoff requires explicit --only ACTION")
    try:
        password = None
        if args.encrypt_selected_handoff:
            password = getpass.getpass("New PRIVATE HUMAN handoff passphrase: ")
            confirm = getpass.getpass("Confirm PRIVATE handoff passphrase: ")
            portfolio.require(password == confirm)
        result = create(args.session, args.original_board,
                        args.proposed_board, args.output_dir, args.only,
                        args.ordinal, args.peer_board, password)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no complete private browser-to-native HUMAN workroom published.",
              file=sys.stderr)
        return 2
    print("PRIVATE browser-to-native HUMAN workroom: %d local changes, %d "
          "action handoff groups. No verified fixes, authorization or original "
          "source edits." %
          (result["changed_anonymous_routing_appearances_not_original_cases"],
           len(result["selected_human_action_groups"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
