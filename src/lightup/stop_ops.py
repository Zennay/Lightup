"""Interactive, no-network incident STOP operator workspace.

A real previously authenticated LightUp operator/client can review existing
engagements, record bounded STOPs and coordinate acknowledgments. There is no
scan/start/resume/permit/grant action or synthetic source in this workspace.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import json
import sys

from .revocation_stop import (
    StopLedgerError, authenticate_domain_user, engagement_inbox,
    initialize_authenticated_stop_ledger, status_for_actor,
    _private_receipt,
)
from .stop_batch import record_authenticated_stop_batch
from .stop_acknowledgment import pending_stops, acknowledge_stop
from .stop_exposure import grant_exposure


def _menu() -> None:
    print("\nLightUp emergency STOP · DRAFT/HOLD / deny-only")
    print("  1  View real engagement inbox")
    print("  2  Record emergency STOP for selected engagements")
    print("  3  Inspect an engagement STOP history")
    print("  4  Review operator acknowledgment inbox")
    print("  5  Acknowledge existing STOP (different original operator)")
    print("  6  Initialize empty STOP ledger (real operator only)")
    print("  7  Review stored grant exposure for an engagement")
    print("  q  Close this offline workspace")


def _inbox(db: str, actor: str) -> dict:
    result = engagement_inbox(db, actor_id=actor)
    print("\nCurrent source declarations only; no permission is implied.")
    for index, item in enumerate(result["engagements"], 1):
        print(f"{index:3d}  {item['engagement_id']}  "
              f"[{item['stop_status']}]")
    if result["truncated"]:
        print("HOLD: inbox is truncated; use exact original source IDs.")
    if not result["engagements"]:
        print("No engagements in authenticated inbox.")
    return result


def _choose(db: str, actor: str, email: str, password: str) -> None:
    inbox = _inbox(db, actor)
    entries = inbox["engagements"]
    if inbox["truncated"]:
        print("Refusing batch selection from a truncated inbox.")
        return
    if not entries:
        return
    print("Select 1–32 existing rows as comma-separated numbers; blank cancels.")
    raw = input("STOP rows: ").strip()
    if not raw:
        return
    try:
        fields = raw.split(",")
        if not 1 <= len(fields) <= 32:
            raise ValueError
        if any(not v.isascii() or not v.isdigit() for v in fields):
            raise ValueError
        positions = [int(v) for v in fields]
        if len(set(positions)) != len(positions) or any(
            n < 1 or n > len(entries) for n in positions
        ):
            raise ValueError
    except ValueError:
        print("HOLD: invalid or duplicate row selection; nothing written.")
        return
    selected = tuple(entries[n - 1]["engagement_id"] for n in positions)
    print("\nSelected exact persisted engagement IDs:")
    for entry in selected:
        print("  ", entry)
    print("This will append permanent STOP event(s). It cannot be undone here.")
    confirm = input(f"Type exactly STOP {len(selected)} to commit: ").strip()
    if confirm != f"STOP {len(selected)}":
        print("Cancelled; no STOP recorded.")
        return
    reason = input("Private local incident reason (optional, max 500 chars): ")
    result = record_authenticated_stop_batch(
        db, engagements=selected, email=email, password=password, reason=reason,
    )
    print(f"STOP_RECORDED_BATCH: {result['recorded_count']} engagements.")
    receipt = input("Private receipt NEW filename (blank skips): ").strip()
    if receipt:
        try:
            _private_receipt(receipt, result)
            print("Private 0600 receipt atomically published.")
        except StopLedgerError:
            print("STOP ALREADY RECORDED; private receipt was NOT published.")
    print("Authorizing, dispatching or restarting an assessment: NEVER.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.stop_ops",
        description="Authenticated local STOP incident control room (no network).",
    )
    parser.add_argument("--database", required=True, help="existing private LightUp SQLite")
    parser.add_argument("--email", required=True, help="original registered account")
    args = parser.parse_args(argv)
    try:
        password = getpass("Original LightUp account password: ")
        actor = authenticate_domain_user(args.database, args.email, password)
        print("\nOriginal account authenticated; STOP/hold never authorizes tools.")
        # This interactive process is finite; closing drops all in-memory
        # credentials. Mutations re-authenticate against original persisted
        # credentials and recheck the real role before writing.
        for _ in range(100):
            _menu()
            choice = input("Choice: ").strip().lower()
            if choice == "q":
                return 0
            try:
                if choice == "1":
                    _inbox(args.database, actor)
                elif choice == "2":
                    _choose(args.database, actor, args.email, password)
                elif choice == "3":
                    engagement_id = input("Exact engagement ID: ").strip()
                    result = status_for_actor(
                        args.database, engagement_id=engagement_id,
                        actor_id=actor,
                    )
                    print(json.dumps(result, sort_keys=True, indent=2))
                elif choice == "4":
                    result = pending_stops(
                        args.database, email=args.email, password=password,
                    )
                    print(json.dumps(result, sort_keys=True, indent=2))
                elif choice == "5":
                    stop_id = input("Exact existing STOP event ID: ").strip()
                    if input("Type ACK STOP exactly: ").strip() != "ACK STOP":
                        print("Cancelled; no acknowledgment written.")
                        continue
                    result = acknowledge_stop(
                        args.database, stop_id=stop_id,
                        email=args.email, password=password,
                    )
                    print(result["status"], result["acknowledgment_id"])
                elif choice == "6":
                    if input("Type INIT LEDGER exactly: ").strip() != "INIT LEDGER":
                        print("Cancelled; database unchanged.")
                        continue
                    result = initialize_authenticated_stop_ledger(
                        args.database, email=args.email, password=password,
                    )
                    print(result["status"], "· NO execution permission")
                elif choice == "7":
                    engagement_id = input("Exact persisted engagement ID: ").strip()
                    print(json.dumps(grant_exposure(
                        args.database, engagement_id=engagement_id,
                        email=args.email, password=password,
                    ), sort_keys=True, indent=2))
                else:
                    print("Unknown operation. No changes made.")
            except StopLedgerError:
                print("HOLD: source/account unavailable or action refused.")
        print("Workspace session ended after bounded operator interactions.")
        return 0
    except (StopLedgerError, KeyboardInterrupt, EOFError):
        print("HOLD: original account unavailable or interactive input closed.")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
