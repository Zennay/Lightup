#!/usr/bin/env python3
"""One offline atomic PRIVATE HUMAN edit -> Studio return -> handoff -> local diff.

No original client identities, network, authenticated review, consent, scan,
remediation, permission or real service update.
"""
from __future__ import annotations

import argparse
import getpass
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import portfolio
import action_board

import bulk_return
import encrypt_handoff
import handoff
import compare_returns
import return_to_studio

DISCLAIMER = (
    "DRAFT/HOLD: This is a LOCAL, self-declared anonymous HUMAN routing "
    "proposal, NOT source-authenticated cases, reviewer decisions, evidence, "
    "consent, remediation, verified fixes, scans, grants or release. "
    "An original authorized HUMAN operator must independently check the "
    "current source and permissions before any real work."
)


def landing(changes: int, selected: int, peer_diff: bool = False,
            encrypted: bool = False) -> bytes:
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN local workflow</title>
<style>:root{color-scheme:dark}body{margin:0;background:#101c2e;color:#f0f7fc;
padding:clamp(17px,4vw,50px);font:16px/1.55 system-ui}
main{max-width:960px;margin:auto}article,aside{background:#1e3349;
padding:20px;border-radius:16px;margin:16px 0}
aside{border-left:5px solid #efc37e}a{color:#a3e9d4}
h1{font-size:clamp(2rem,4vw,3rem)}p{color:#d5e0ea}</style>
</head><body><main><small>LIGHTUP / PRIVATE / HUMAN ONLY / INCUBATE / DRAFT HOLD</small>
<h1>Offline HUMAN routing workroom</h1>
<aside><strong>Self-declared local numeric packet proposals only.</strong>
<p>%s</p></aside>
<article><h2>Completed PRIVATE local workflow</h2>
<p>%d HUMAN-only local changes prepared and %d new HUMAN follow-up action
groups included in the packet. Both are anonymous appearances, never
original cases, verified fixes or performed source-owner decisions.</p>
<p><a href="return/index.html">1. See the proposed native Studio-v1 HUMAN board return</a></p>
<p><a href="handoff/index.html">2. Open action-specific offline HUMAN handoffs</a></p>
<p><a href="difference/index.html">3. Review local action/state differences</a></p>
<p><a href="summary.json">4. Inspect source-free non-authorizing workflow counts</a></p>
%s
%s
</article>
<p>The old original board was never overwritten. Manually use
<code>return/board.json</code> with the same source-free numeric session in
the unchanged original offline HUMAN Studio. All files may still be sensitive
small-cell numbers, are PRIVATE and are not encrypted at rest. No file in
this workroom proves client identity, authorization or delivery.</p>
</main></body></html>""" % (html.escape(DISCLAIMER), changes, selected,
        '<p><a href="peer/index.html">5. Compare separate local peer routing proposal</a></p>'
        if peer_diff else "",
        '<p><a href="handoff-selected.lheh">6. Encrypted selected HUMAN capsule (not sent)</a></p>'
        if encrypted else "")
    return page.encode("utf-8")


def create(session_path: Path, original_board: Path, changes_path: Path,
           destination: Path, only: str | None = None, ordinal: int | None = None,
           handoff_password: str | None = None) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    portfolio.require(only is None or only in handoff.ACTIONS)
    portfolio.require(handoff_password is None or only in handoff.ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and only in handoff.ACTIONS and
                       1 <= ordinal <= 12))

    stage = Path(tempfile.mkdtemp(prefix=".lightup-private-human-workflow-",
                                  dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        # Each existing component validates against the same current saved
        # ORIGINAL source-free numeric session. Each subfolder is itself
        # exclusively published inside this still-unpublished private staging
        # folder. Any failure removes the ENTIRE tree before public visibility.
        change = bulk_return.build(session_path, original_board, changes_path,
                                   stage / "return")
        new_board = stage / "return" / "board.json"
        action = handoff.build(session_path, new_board, stage / "handoff", only, ordinal)
        if handoff_password is not None:
            encrypt_handoff.create(
                session_path, new_board, stage / "handoff-selected.lheh",
                handoff_password, only, ordinal)
        difference = compare_returns.build(
            session_path, original_board, new_board, stage / "difference")
        portfolio.require(
            change["number_of_self_declared_changes_not_original_cases"] ==
            difference["ordinal_appearances_with_local_changes"]
        )
        summary = {
            "kind": "lightup.private_human_offline_workflow_handoff",
            "schema_version": 1,
            "disposition": "LOCAL_HUMAN_NUMERIC_DRAFT_HOLD_NO_AUTHORITY",
            "local_human_state_changes_not_original_cases":
                change["number_of_self_declared_changes_not_original_cases"],
            "local_action_differences_not_source_changes":
                difference["ordinals_with_action_changes"],
            "local_state_differences_not_verified_remediation":
                difference["ordinals_with_state_changes"],
            "selected_human_action_groups": [
                group["action"] for group in action["groups"]
                if group["packet_appearances_not_unique"] > 0
            ],
            "encrypted_selected_human_capsule_private_not_sent":
                handoff_password is not None,
            "warning": DISCLAIMER,
            **{flag: False for flag in portfolio.FLAGS},
        }
        portfolio.exclusive_write(stage / "index.html",
                                  landing(summary["local_human_state_changes_not_original_cases"],
                                          len(summary["selected_human_action_groups"]),
                                          encrypted=handoff_password is not None))
        portfolio.exclusive_write(stage / "summary.json",
                                  portfolio.serialize(summary))
        return_to_studio.sync_dir(stage)
        portfolio.publish(stage, destination)
        return_to_studio.sync_dir(destination.parent)
        return summary
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare complete PRIVATE anonymous HUMAN workroom: original "
                    "session+board+strict edits -> native board, handoff, local diff "
                    "in a single atomic offline folder. No target or authority.")
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--changes", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh owner-private directory, never overwrite")
    parser.add_argument("--only", choices=handoff.ACTIONS,
                        help="Limit action handoff to one non-authorizing HUMAN group")
    parser.add_argument("--ordinal", type=int,
                        help="With --only, disclose one exact local anonymous ordinal")
    parser.add_argument("--encrypt-selected-handoff", action="store_true",
                        help="Prompt for a separate handoff secret and emit .lheh")
    args = parser.parse_args()
    if args.encrypt_selected_handoff and args.only is None:
        parser.error("--encrypt-selected-handoff requires explicit --only ACTION")
    try:
        password = None
        if args.encrypt_selected_handoff:
            password = getpass.getpass("New PRIVATE HUMAN handoff passphrase: ")
            confirm = getpass.getpass("Confirm PRIVATE handoff passphrase: ")
            portfolio.require(password == confirm)
        receipt = create(args.session, args.board, args.changes,
                         args.output_dir, args.only, args.ordinal, password)
    except (OSError, ValueError, RecursionError):
        print("HOLD: no complete private HUMAN workflow was published.",
              file=sys.stderr)
        return 2
    print("PRIVATE HUMAN workflow published: %d local proposal differences, "
          "%d follow-up groups. No real remediation or source authorization." %
          (receipt["local_human_state_changes_not_original_cases"],
           len(receipt["selected_human_action_groups"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
