#!/usr/bin/env python3
"""Transform encrypted LOCAL HUMAN work-session into a selected encrypted handoff.

No permanent plaintext workspace; uses short-lived owner-only native source
files solely so the unchanged Studio parser can independently admit inputs.
Local counts do not authenticate original security findings, clients or users.
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
import session

import encrypted_workflow
import encrypt_handoff
import handoff


def create(encrypted_source: Path, destination_file: Path,
           unlock_secret: str, recipient_secret: str,
           only: str, ordinal: int | None = None) -> int:
    portfolio.require(destination_file.is_absolute()
                      and destination_file.suffix == ".lheh")
    portfolio.private_dir(destination_file.parent)
    portfolio.require(not destination_file.exists()
                      and not destination_file.is_symlink())
    portfolio.require(type(only) is str and only in handoff.ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and 1 <= ordinal <= 12))
    # The original browser source-free vault schema is independently admitted
    # using the same authenticated encrypted reader as the full CLI workroom.
    payload = encrypted_workflow.unlock(encrypted_source, unlock_secret)
    private = Path(tempfile.mkdtemp(
        prefix=".lightup-private-encrypted-selection-",
        dir=destination_file.parent))
    os.chmod(private, 0o700)
    try:
        # Never write a whole plaintext final workroom. Short-lived 0600 files
        # exist only for native unchanged original parser source admission.
        input_files = {
            "session.json": payload["original_session"],
            "original.json": payload["original_board"],
            "proposed.json": payload["working_board"],
        }
        if payload["peer_board"] is not None:
            input_files["peer.json"] = payload["peer_board"]
        for filename, value in input_files.items():
            portfolio.require(type(value) is dict)
            portfolio.exclusive_write(private / filename,
                                      portfolio.serialize(value))
        source = private / "session.json"
        session.read_session(source)
        for filename in ("original.json", "proposed.json"):
            action_board.board_import(private / filename, source)
        if "peer.json" in input_files:
            action_board.board_import(private / "peer.json", source)
        # Only the strict edited/working local HUMAN routing board enters the
        # recipient capsule. Never include the original, peer or entire session.
        return encrypt_handoff.create(
            source, private / "proposed.json", destination_file,
            recipient_secret, only, ordinal)
    finally:
        if private.exists():
            shutil.rmtree(private)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Extract a selected source-free HUMAN action directly from the local "
        "AES-256-GCM .lhew work-session to a distinct newly encrypted .lheh "
        "recipient capsule, without publishing a plaintext workroom. "
        "No source authentication, grant, consent, verified fix or delivery."
    ))
    parser.add_argument("--encrypted-workspace", type=Path, required=True,
                        help="Existing PRIVATE 0600 .lhew inside private 0700 folder")
    parser.add_argument("--only", choices=handoff.ACTIONS, required=True,
                        help="Required explicit self-declared HUMAN action")
    parser.add_argument("--ordinal", type=int,
                        help="Optionally one exact local ordinal, never a case")
    parser.add_argument("--output-file", type=Path, required=True,
                        help="New 0600 .lheh inside owner-private 0700 folder")
    args = parser.parse_args()
    try:
        unlock = getpass.getpass("Original PRIVATE workspace passphrase: ")
        outgoing = getpass.getpass("NEW separate selected handoff passphrase: ")
        verify = getpass.getpass("Confirm NEW handoff passphrase: ")
        portfolio.require(outgoing == verify)
        count = create(args.encrypted_workspace, args.output_file, unlock,
                       outgoing, args.only, args.ordinal)
    except (OSError, ValueError, RecursionError, EOFError, KeyboardInterrupt):
        print("HOLD: no PRIVATE encrypted selected handoff published.",
              file=sys.stderr)
        return 2
    print("Private selected encrypted HUMAN handoff generated: %d local "
          "anonymous appearances, no full workroom published or sent." % count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
