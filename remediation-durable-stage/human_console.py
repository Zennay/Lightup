#!/usr/bin/env python3
"""One PRIVATE interactive operator console for durable HUMAN evidence staging.

Keeps all original source authentication, password prompts and actual evidence
admission inside journal.main(), on EVERY separate operator action.
No network execution, authorization, native Apply or legal hold decisions.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import sys

import journal

ACTIONS = {
    "1": ("status", "Inspect original current HUMAN journal"),
    "2": ("stage", "Create NEW source-bound encrypted native HUMAN draft"),
    "3": ("review", "Inspect current original HUMAN delivery"),
    "4": ("review-html", "Publish PRIVATE offline HUMAN delivery desk"),
    "5": ("report", "Publish PRIVATE local staging chronology"),
    "6": ("recover", "Recover interrupted encrypted native HUMAN draft"),
    "7": ("resolve", "Resolve original HUMAN stage with separate acknowledgment"),
    "10": ("carry-closed", "Review closure from an earlier ORIGINAL source revision"),
}
NAMES = {
    "stage": ("native-human-draft-", ".ltv"),
    "review-html": ("human-delivery-", ".html"),
    "report": ("human-stage-history-", ".html"),
}

def _common(args, *, human: Path, plan: Path) -> list[str]:
    """No passwords and no shell; pass direct argv to the real native workflow."""
    return [
        "--db", args.db,
        "--email", args.email,
        "--client-id", args.client_id,
        "--engagement-id", args.engagement_id,
        "--human", str(human),
        "--directory", str(args.directory),
        "--plan", str(plan),
        "--journal-dir", str(args.journal_dir),
        "--ack-private-material",
    ]

def _private_new_output(folder: Path, action: str) -> Path:
    prefix, suffix = NAMES[action]
    # Only a privacy-neutral random path (no source ids, hashes or names).
    return folder / (prefix + secrets.token_hex(16) + suffix)

def _switch(args, human: Path, plan: Path, *, field: str) -> tuple[Path, Path]:
    label = "CURRENT original encrypted HUMAN workroom" if field == "human" else (
        "CURRENT source-bound encrypted retention review plan")
    text = input("Enter absolute existing PRIVATE path to " + label + " (Enter cancels): ").strip()
    if not text:
        print("No source selected; current source unchanged.")
        return human, plan
    requested = Path(text).expanduser()
    candidate = requested.absolute()
    try:
        if not requested.is_absolute() or candidate.suffix.lower() != ".ltv":
            raise ValueError("Exact private .ltv file required.")
        journal.source._hold_if_not_private_directory(candidate.parent)
        journal._owned_regular(candidate)
        next_human = candidate if field == "human" else human
        next_plan = candidate if field == "plan" else plan
        # DO NOT promote a new filename until ORIGINAL source, login, private
        # actual evidence bytes and new encrypted HUMAN/plan are all admitted.
        status = journal.main(["status", *_common(args, human=next_human, plan=next_plan)])
        if status != 0:
            raise ValueError("New original source and actual material not admitted.")
    except (OSError, ValueError):
        print("HUMAN HOLD: Candidate original source or plan refused; old selection kept.")
        return human, plan
    print("Original current authenticated source accepted; selection changed only locally.")
    return next_human, next_plan

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        p.add_argument("--" + name, required=True)
    for name in ("human", "plan", "directory", "journal-dir", "output-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--ack-private-material", action="store_true")
    args = p.parse_args(argv)
    if not args.ack_private_material or not sys.stdin.isatty():
        print("HUMAN HOLD: Real private interactive terminal and original PRIVATE acknowledgment required.",
              file=sys.stderr)
        return 2
    try:
        output = journal.source._hold_if_not_private_directory(args.output_dir)
        if output == args.directory.expanduser().absolute():
            raise ValueError("Never place private reports in original evidence material folder.")
        if output == args.journal_dir.expanduser().absolute():
            raise ValueError("Never place native draft/report outputs in the journal folder.")
        journal.source._hold_if_not_private_directory(args.journal_dir)
        journal.source._hold_if_not_private_directory(args.directory)
    except (OSError, ValueError):
        print("HUMAN HOLD: Separate real owner-private directories are required.", file=sys.stderr)
        return 2
    human = args.human.expanduser().absolute()
    plan = args.plan.expanduser().absolute()
    # Starting under a rejected/stale original source must HOLD, not open a
    # working menu suggesting the human can proceed.
    if journal.main(["status", *_common(args, human=human, plan=plan)]) != 0:
        return 2
    staged_in_session = False
    while True:
        print("\nPRIVATE ORIGINAL HUMAN EVIDENCE · LOCAL durable staging")
        print("NO native Apply, legal release, consent, grants, scans, deletion or retest")
        for key, (_, caption) in ACTIONS.items():
            print(key, "·", caption)
        print("8 · Select a separately supplied CURRENT original HUMAN workroom")
        print("9 · Select a different original source-bound retention plan")
        print("0 · Exit private operator console")
        try:
            choice = input("HUMAN choice: ").strip()
            if choice == "0":
                print("Private operator console closed. No background task.")
                return 0
            if choice in ("8", "9"):
                human, plan = _switch(args, human, plan,
                                      field="human" if choice == "8" else "plan")
                continue
            if choice not in ACTIONS:
                print("Unknown HUMAN command. No state changed.")
                continue
            action = ACTIONS[choice][0]
            if action == "stage" and staged_in_session:
                print("HUMAN HOLD: A new native draft was already staged this operator"
                      " session. Independently review it in the original app first.")
                continue
            cmd = [action, *_common(args, human=human, plan=plan)]
            output_file = None
            if action in NAMES:
                output_file = _private_new_output(output, action)
                cmd += ["--output", str(output_file)]
            code = journal.main(cmd)
            if code == 0:
                if action == "stage":
                    staged_in_session = True
                if output_file is not None:
                    print("New PRIVATE operator artifact:", output_file.name)
            else:
                print("The requested HUMAN action is on HOLD. Other private work remains available.")
        except (KeyboardInterrupt, EOFError):
            print("\nClosed private terminal operation. No background actions.")
            return 130

if __name__ == "__main__":
    raise SystemExit(main())
