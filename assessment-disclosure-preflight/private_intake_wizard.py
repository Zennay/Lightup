"""Interactive offline PRIVATE HUMAN browser intake wizard.

All original authority boundaries are delegated to private_intake.stage()
and the unchanged native reconcile.main(). Prompts collect local paths only.
The wizard makes no network call and never deletes browser downloads.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import sys

import private_intake as inbox


class Cancelled(Exception):
    pass


def choose(prompt: str, options: tuple[str, ...]) -> str:
    """Strict explicit HUMAN choice; no default source or silent promotion."""
    print(prompt)
    for index, label in enumerate(options, 1):
        print(" ", index, "—", label)
    answer = input("Choose number, or Q to cancel: ").strip().upper()
    if answer == "Q":
        raise Cancelled()
    if not answer.isascii() or not answer.isdigit():
        raise Cancelled()
    number = int(answer)
    if not 1 <= number <= len(options):
        raise Cancelled()
    return options[number - 1]


def private_path(label: str) -> str:
    """Do not echo original client-sensitive local download filenames."""
    value = getpass("PRIVATE local path for " + label + " (not echoed; Q cancels): ")
    if not value or value.upper() == "Q" or "\x00" in value:
        raise Cancelled()
    return value


def wizard() -> argparse.Namespace:
    if not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty():
        raise Cancelled()
    print("LightUp PRIVATE HUMAN browser receiving · INCUBATE M3/M7 DRAFT/HOLD")
    print("This never authenticates clients, approves assessments, scans or releases.")
    print("Inputs stay in Downloads after receipt; old copy privacy is still your responsibility.")
    parent = private_path("EXISTING owner-only 0700 inbox parent")
    room = input("NEW private room identifier (letters, digits, - or _, Q cancels): ").strip()
    if room.upper() == "Q" or not inbox.ROOM_PATTERN.fullmatch(room):
        raise Cancelled()

    answer = argparse.Namespace(
        private_parent=parent, room=room, receipt=None,
        a_csv=None, a_vault=None, a_bundle=None,
        b_csv=None, b_vault=None, b_bundle=None,
        decisions=None, result_csv=None, result_bundle=None,
        counts=None, minimum_cohort=5
    )
    answer.receipt = private_path("original PRIVATE unsigned receipt JSON")
    for role in ("a", "b"):
        source_mode = choose(
            "Choose original independently received HUMAN reviewer " + role.upper() + " format:",
            ("csv", "vault", "bundle")
        )
        setattr(answer, role + "_" + source_mode,
                private_path("original HUMAN reviewer " + role.upper() +
                             " " + source_mode + " file"))
    answer.decisions = private_path("original complete seven-column A/B/HOLD decisions CSV")
    result_mode = choose(
        "Choose the original HUMAN final result transport:",
        ("csv", "bundle")
    )
    setattr(answer, "result_" + result_mode,
            private_path("original complete HUMAN final " + result_mode))
    answer.counts = private_path("original independent suppressed-counts CSV")

    floor = input("Original separate suppressed-counts minimum cohort [5-12; default 5, Q cancels]: ").strip()
    if floor.upper() == "Q" or (floor and (not floor.isascii() or not floor.isdigit())):
        raise Cancelled()
    answer.minimum_cohort = int(floor) if floor else 5
    if not 5 <= answer.minimum_cohort <= 12:
        raise Cancelled()

    print("Source inputs: six exact roles specified, original filenames never printed.")
    print("Reconciliation: original full receipt + BOTH reviewer submissions + all")
    print("decisions + full result + counts; decrypt locally only when required.")
    print("Destination: a NEW 0700 room, SIX 0600 source files plus private receipt.")
    print("Any mismatch = HOLD; original Downloads unchanged and not secured.")
    print("Local SHA-256 and REVIEW_ONLY prove no sender, source identity or consent.")
    if input("Type exactly RECEIVE to start original PRIVATE local receipt, or cancel: ").strip() != "RECEIVE":
        raise Cancelled()
    return answer


def main() -> int:
    try:
        args = wizard()
        return inbox.stage(args)
    except (Cancelled, KeyboardInterrupt, EOFError, OSError, ValueError, TypeError, MemoryError):
        print("HOLD: PRIVATE HUMAN wizard cancelled or source refused; no release", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
