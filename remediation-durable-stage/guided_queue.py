#!/usr/bin/env python3
"""PRIVATE engagement HUMAN worklist: inspect, select, and explicitly act.

Only dispatches existing original-authenticated CLI commands, never bypasses
their original source/material checks or independent HUMAN acknowledgments.
"""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import engagement_inbox as inbox
import journal

EXECUTABLE = {"review", "recover", "resolve", "carry-closed", "status"}


def _admitted_list(args, human: Path, plan: Path) -> tuple[list[dict], dict, dict]:
    """Read the genuine ORIGINAL source and PRIVATE local journals under lock."""
    native = Namespace(
        db=args.db, email=args.email,
        client_id=args.client_id, engagement_id=args.engagement_id,
        human=human, plan=plan, directory=args.directory,
        journal_dir=args.journal_dir,
    )
    vault = journal.original.ORIGINAL._vault()
    with journal._locked(args.journal_dir) as folder:
        current = journal._source(native, vault)
        packet, current_key = current[1], current[6]
        rows, totals = inbox.collect(
            folder, packet, vault, journal._owned_regular, journal._read,
            current_key,
        )
        indexed, _ = journal.source_revisions.inspect(
            folder, packet, vault, journal._owned_regular, journal._read)
        lengths = {
            ordinal: len(journal._read(folder, key, vault)["cycles"])
            for ordinal, key in enumerate(indexed["sources"], 1)
        }
    return rows, totals, lengths


def run(args, human: Path, plan: Path, build_common) -> int:
    """Return no decision until a real HUMAN confirms one exact inbox row."""
    try:
        rows, totals, latest_lengths = _admitted_list(args, human, plan)
    except Exception:
        print("HUMAN HOLD: original authenticated engagement queue unavailable.")
        return 2
    if not rows:
        print("No registered local HUMAN handoffs. No action taken.")
        print("Older nonindexed local folders/devices remain outside this inbox.")
        return 0
    print("\nPRIVATE original HUMAN action queue (NO native Apply or consent)")
    print("Registered source versions:", totals["source_revisions"],
          "· local HUMAN cycles:", totals["cycles"])
    for number, row in enumerate(rows, 1):
        level = inbox.PRIORITY_NAME[row["priority"]]
        desc = inbox.LABELS[row["attention"]][0]
        print(f"{number}. {level} · source {row['source_ordinal']}"
              f" / cycle {row['cycle_ordinal']} · {desc}")
        print(f"   Local days: {row['elapsed_days']} · suggested:"
              f" {row['suggested_operator_action']}")
    raw = input("Select one LOCAL HUMAN queue number (Enter cancels): ").strip()
    if not raw:
        return 0
    if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= len(rows):
        print("HUMAN HOLD: no valid exact queue row selected.")
        return 2
    item = rows[int(raw) - 1]
    command = item["suggested_operator_action"]
    if command not in EXECUTABLE:
        print("This registered original HUMAN entry requires independent owner"
              " review; it cannot safely be auto-dispatched.")
        return 2
    if item["cycle_ordinal"] != latest_lengths[item["source_ordinal"]]:
        print("HUMAN HOLD: a historical non-latest local cycle needs independent"
              " source-owner review before changing newer local history.")
        return 2
    if command == "carry-closed" and item["current_revision"]:
        print("HUMAN HOLD: historical carry cannot act on the current source.")
        return 2
    if command in ("review", "recover", "resolve") and not item["current_revision"]:
        print("HUMAN HOLD: this command requires the current source; use"
              " explicit historical review for older native evidence.")
        return 2
    if (item["attention"] in ("reviewed_current_closed", "aborted_unpublished")
            and command == "status"):
        print("Only source-current status is available; no stored HUMAN"
              " request will be changed by status.")
    print("The next command reauthenticates the CURRENT original account, client,"
          " engagement, HUMAN workroom, retention plan and every evidence byte.")
    print("Local HUMAN annotations remain unverified; this never applies original"
          " requests, signs client consent, authorizes scans or changes evidence.")
    if input(f'Type "RUN LOCAL HUMAN {command}" to continue: ') != (
            f"RUN LOCAL HUMAN {command}"):
        print("No HUMAN command selected.")
        return 0
    argv = [command, *build_common(args, human=human, plan=plan)]
    if command in ("review", "recover", "resolve", "carry-closed"):
        argv.extend(("--expected-cycle", str(item["cycle_ordinal"])))
    if command == "carry-closed":
        argv.extend(("--source-ordinal", str(item["source_ordinal"])))
    # IMPORTANT: the initial file lock was released. journal.main obtains a
    # new private lock, reauthenticates, re-reads actual material and
    # re-checks the exact selected source/cycle BEFORE any local mutation.
    return journal.main(argv)
