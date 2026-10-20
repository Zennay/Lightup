#!/usr/bin/env python3
"""Offline PRIVATE read-only recipient for a selected encrypted HUMAN .lheh.

No original case identity, reviewer authentication, consent, assessment,
remediation, verified fix, scan authority, grant or released security finding.
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

import encrypted_workflow
import handoff

ENVELOPE_KIND = "lightup.private_human_encrypted_handoff_v1"
ENVELOPE_AAD = b"LIGHTUP_PRIVATE_HUMAN_LOCAL_HANDOFF_AES_GCM_V1"
PAYLOAD_KIND = "lightup.private_human_encrypted_handoff_payload"
PAYLOAD_DISPOSITION = "LOCAL_SELECTED_HUMAN_COUNTS_DRAFT_HOLD"
WARNING = ("Encrypted locally selected HUMAN follow-up counts only. An ordinal is "
           "NOT an authenticated case, recipient, finding, consent, original "
           "evidence, reviewer decision, remediation, scan authority or release.")
FIELDS = {"kind", "schema_version", "disposition", "rows", "warning",
          *portfolio.FLAGS}
ROW_FIELDS = {"ordinal", "type", "slots", "questions", "action", "state"}


def admit(path: Path, passphrase: str) -> list[dict]:
    packet = encrypted_workflow.decrypt_payload(
        path, passphrase, ENVELOPE_KIND, ENVELOPE_AAD)
    portfolio.header(packet, PAYLOAD_KIND, FIELDS, PAYLOAD_DISPOSITION)
    portfolio.require(packet["warning"] == WARNING)
    supplied = packet["rows"]
    portfolio.require(type(supplied) is list and 1 <= len(supplied) <= 12)
    rows = []
    last = 0
    for raw in supplied:
        portfolio.require(type(raw) is dict and set(raw) == ROW_FIELDS)
        ordinal = raw["ordinal"]
        portfolio.require(type(ordinal) is int and last < ordinal <= 12)
        last = ordinal
        portfolio.require(type(raw["type"]) is str and
                          raw["type"] in ("inbox", "workroom"))
        portfolio.nonnegative(raw["slots"], 12)
        portfolio.require(raw["slots"] >= 1)
        portfolio.nonnegative(raw["questions"], 1000000)
        portfolio.require(type(raw["action"]) is str and
                          raw["action"] in handoff.ACTIONS and
                          type(raw["state"]) is str and
                          raw["state"] in action_board.STATE_CODES)
        rows.append({
            "packet_ordinal_not_original_case": ordinal,
            "source_type": raw["type"],
            "anonymous_slot_appearances_not_unique": raw["slots"],
            "unverified_pending_human_questions": raw["questions"],
            "local_followup_action_code": raw["action"],
            "local_planning_state_code": raw["state"],
        })
    return rows


def build(path: Path, destination: Path, passphrase: str) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    rows = admit(path, passphrase)
    kinds = tuple(code for code in handoff.ACTIONS
                  if any(row["local_followup_action_code"] == code for row in rows))
    groups = {kind: handoff.selected(rows, kind) for kind in kinds}
    summary = handoff.summary(groups, rows, None, None)
    stage = Path(tempfile.mkdtemp(
        prefix=".lightup-encrypted-human-recipient-", dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "index.html",
                                  handoff.index_page(groups, summary))
        portfolio.exclusive_write(stage / "summary.json",
                                  portfolio.serialize(summary))
        for kind, group in groups.items():
            portfolio.exclusive_write(stage / ("handoff-" + kind + ".html"),
                                      handoff.group_page(kind, group))
            portfolio.exclusive_write(stage / ("handoff-" + kind + ".csv"),
                                      handoff.action_csv(kind, group))
            portfolio.exclusive_write(stage / ("handoff-" + kind + ".txt"),
                                      handoff.action_brief(kind, group))
        handoff.sync_directory(stage)
        portfolio.publish(stage, destination)
        handoff.sync_directory(destination.parent)
        return summary
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read only a selected encrypted source-free HUMAN handoff "
                    "with an interactive password into a PRIVATE offline "
                    "0600 HTML/CSV/TXT dossier. No original source identity, "
                    "client permission, verified security finding or delivery.")
    parser.add_argument("--encrypted-handoff", type=Path, required=True,
                        help="PRIVATE owner-only 0600 .lheh file in 0700 folder")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh owner-only 0700 recipient dossier; not overwritten")
    args = parser.parse_args()
    try:
        password = getpass.getpass("PRIVATE selected HUMAN handoff passphrase: ")
        result = build(args.encrypted_handoff, args.output_dir, password)
    except (ValueError, OSError, EOFError, KeyboardInterrupt, RecursionError):
        print("HOLD: no complete private HUMAN handoff recipient dossier published.",
              file=sys.stderr)
        return 2
    print("Opened selected source-free PRIVATE HUMAN handoff: %d anonymous "
          "packet appearances, no authenticated sender or verified source." %
          result["selected_packet_appearances_not_unique"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
