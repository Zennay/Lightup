#!/usr/bin/env python3
"""Create a PRIVATE password-encrypted .lheh HUMAN capsule from native Studio files.

All original session and board admission is delegated to the unchanged Studio
producer. No original case, security finding, grant, delivery, consent or fix
is established. This does not transmit anything.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import action_board
import portfolio

import encrypted_handoff
import encrypted_workflow
import handoff

ITERATIONS = 600000


def _password_bytes(password: str) -> bytes:
    portfolio.require(type(password) is str
                      and password == unicodedata.normalize("NFC", password)
                      and password.strip() == password
                      and 14 <= len(password) <= 256)
    data = password.encode("utf-8")
    portfolio.require(14 <= len(data) <= 1024)
    return data


def selected_payload(session_path: Path, board_path: Path,
                     only: str, ordinal: int | None) -> dict:
    portfolio.require(type(only) is str and only in handoff.ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and 1 <= ordinal <= 12))
    # The original native parser enforces 0700/0600, no-follow, duplicate-key
    # admission, numeric shape and ordinal equality, and all 12 false flags.
    rows = action_board.board_import(board_path, session_path)
    if ordinal is not None:
        portfolio.require(ordinal <= len(rows) and
                          rows[ordinal - 1]["local_followup_action_code"] == only)
        rows = [rows[ordinal - 1]]
    else:
        rows = [row for row in rows
                if row["local_followup_action_code"] == only]
    # An empty category must NOT produce an apparently completed handoff.
    portfolio.require(1 <= len(rows) <= 12)
    selected = sorted(rows, key=lambda r: r["packet_ordinal_not_original_case"])
    items = []
    for row in selected:
        items.append({
            "ordinal": row["packet_ordinal_not_original_case"],
            "type": row["source_type"],
            "slots": row["anonymous_slot_appearances_not_unique"],
            "questions": row["unverified_pending_human_questions"],
            "action": row["local_followup_action_code"],
            "state": row["local_planning_state_code"],
        })
    packet = {
        "kind": encrypted_handoff.PAYLOAD_KIND,
        "schema_version": 1,
        "disposition": encrypted_handoff.PAYLOAD_DISPOSITION,
        "rows": items,
        "warning": encrypted_handoff.WARNING,
        **{flag: False for flag in portfolio.FLAGS},
    }
    # Validate typed local HUMAN payload before encrypting it.
    portfolio.header(packet, encrypted_handoff.PAYLOAD_KIND,
                     encrypted_handoff.FIELDS,
                     encrypted_handoff.PAYLOAD_DISPOSITION)
    portfolio.require(packet["warning"] == encrypted_handoff.WARNING)
    return packet


def create(session_path: Path, board_path: Path, output_file: Path,
           password: str, only: str, ordinal: int | None = None) -> int:
    portfolio.require(output_file.is_absolute() and output_file.suffix == ".lheh")
    portfolio.private_dir(output_file.parent)
    portfolio.require(not output_file.exists() and not output_file.is_symlink())
    password_bytes = _password_bytes(password)
    packet = selected_payload(session_path, board_path, only, ordinal)
    plaintext = portfolio.serialize(packet)
    portfolio.require(1 <= len(plaintext) <= encrypted_workflow.MAX_PAYLOAD_BYTES)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = hashlib.pbkdf2_hmac(
            "sha256", password_bytes, salt, ITERATIONS, dklen=32)
        encrypted = AESGCM(key).encrypt(
            nonce, plaintext, encrypted_handoff.ENVELOPE_AAD)
    except ImportError as exc:
        raise portfolio.Hold("HOLD: cryptography package unavailable") from exc
    envelope = {
        "kind": encrypted_handoff.ENVELOPE_KIND,
        "schema_version": 1,
        "disposition": encrypted_workflow.DISPOSITION,
        "kdf": "PBKDF2-HMAC-SHA256-AES256GCM",
        "iterations": ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(encrypted).decode("ascii"),
    }
    data = portfolio.serialize(envelope)
    portfolio.require(len(data) <= encrypted_workflow.MAX_FILE_BYTES)
    portfolio.exclusive_write(output_file, data)
    handoff.sync_directory(output_file.parent)
    return len(packet["rows"])


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Create one password-encrypted PRIVATE source-free HUMAN follow-up "
        "capsule (.lheh) from the exact original native numeric Studio pair. "
        "No external recipient, consent, authorization or delivery."
    ))
    parser.add_argument("--session", type=Path, required=True,
                        help="Original saved native numeric session, PRIVATE 0600")
    parser.add_argument("--board", type=Path, required=True,
                        help="Corresponding original/native HUMAN board, PRIVATE 0600")
    parser.add_argument("--only", choices=handoff.ACTIONS, required=True,
                        help="Explicit HUMAN action category to disclose")
    parser.add_argument("--ordinal", type=int,
                        help="Further restrict to one exact local ordinal, not case")
    parser.add_argument("--output-file", type=Path, required=True,
                        help="Fresh .lheh file under existing owner-only 0700 directory")
    args = parser.parse_args()
    try:
        password = getpass.getpass("New PRIVATE selected HUMAN handoff passphrase: ")
        repeat = getpass.getpass("Confirm handoff passphrase: ")
        portfolio.require(password == repeat)
        count = create(args.session, args.board, args.output_file,
                       password, args.only, args.ordinal)
    except (OSError, ValueError, RecursionError, EOFError, KeyboardInterrupt):
        print("HOLD: no complete encrypted HUMAN handoff published.",
              file=sys.stderr)
        return 2
    print("PRIVATE encrypted selected HUMAN handoff: %d anonymous local "
          "appearances. No original source identity or actual delivery." % count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
