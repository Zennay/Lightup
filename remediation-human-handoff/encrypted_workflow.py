#!/usr/bin/env python3
"""Offline encrypted browser .lhew -> original source-free HUMAN workroom.

The passphrase is read through an interactive prompt, not command-line args,
shell history, environment variables, logs or a stored configuration. This is
local self-declared HUMAN routing, NOT authenticated original case evidence.
Requires the optional Python 'cryptography' package.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import action_board
import portfolio
import session

import browser_workflow
import handoff

KIND = "lightup.private_human_encrypted_workspace_v1"
PAYLOAD_KIND = "lightup.private_human_encrypted_workspace_payload"
DISPOSITION = "PASSWORD_ENCRYPTED_LOCAL_FILE_NOT_SOURCE_AUTHORITY"
PAYLOAD_DISPOSITION = "SELF_DECLARED_LOCAL_HUMAN_ONLY_DRAFT_HOLD"
VAULT_WARNING = ("Self-declared encrypted offline HUMAN routing draft. Not original "
                 "authenticated evidence, client identity, consent, remediation, "
                 "grant, verified fix or release.")
AAD = b"LIGHTUP_PRIVATE_HUMAN_LOCAL_WORKSESSION_AES_GCM_V1"
FIELDS = {"kind", "schema_version", "disposition", "kdf", "iterations",
          "salt_b64", "nonce_b64", "ciphertext_b64"}
PAYLOAD_FIELDS = {"kind", "schema_version", "disposition", "original_session",
                  "original_board", "working_board", "peer_board", "warning",
                  *portfolio.FLAGS}
MAX_FILE_BYTES = 131072
MAX_PAYLOAD_BYTES = 65536


def private_ciphertext(path: Path) -> bytes:
    portfolio.require(path.is_absolute() and not path.is_symlink())
    portfolio.private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        portfolio.require(
            stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_mode & 0o077 == 0
            and 1 <= before.st_size <= MAX_FILE_BYTES
        )
        blob = os.read(fd, MAX_FILE_BYTES + 1)
        after = os.fstat(fd)
        portfolio.require(
            len(blob) == before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
        )
        return blob
    finally:
        os.close(fd)


def strict_json(raw: bytes) -> dict:
    portfolio.require(1 <= len(raw) <= MAX_FILE_BYTES)
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=portfolio.pairs,
            parse_constant=lambda _: portfolio.require(False),
            parse_float=lambda _: portfolio.require(False),
        )
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        raise portfolio.Hold("HOLD: invalid PRIVATE encrypted HUMAN JSON") from exc
    portfolio.require(type(data) is dict)
    return data


def canonical_b64(data: object, length: int | tuple[int, int]) -> bytes:
    portfolio.require(type(data) is str and 1 <= len(data) <= 131200)
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise portfolio.Hold("HOLD: noncanonical encrypted PRIVATE binary field") from exc
    limits = (length, length) if type(length) is int else length
    portfolio.require(limits[0] <= len(raw) <= limits[1])
    portfolio.require(base64.b64encode(raw).decode("ascii") == data)
    return raw


def decrypt_payload(path: Path, passphrase: str,
                    expected_kind: str = KIND, aad: bytes = AAD) -> dict:
    # A deliberate interactive passphrase cannot be blank or ambiguous unicode.
    portfolio.require(type(passphrase) is str and
                      passphrase == unicodedata.normalize("NFC", passphrase)
                      and passphrase.strip() == passphrase
                      and 14 <= len(passphrase) <= 256)
    password = passphrase.encode("utf-8")
    portfolio.require(14 <= len(password) <= 1024)
    envelope = strict_json(private_ciphertext(path))
    portfolio.require(set(envelope) == FIELDS and
                      envelope["kind"] == expected_kind and
                      type(envelope["schema_version"]) is int and
                      envelope["schema_version"] == 1 and
                      envelope["disposition"] == DISPOSITION and
                      envelope["kdf"] == "PBKDF2-HMAC-SHA256-AES256GCM" and
                      type(envelope["iterations"]) is int and
                      envelope["iterations"] == 600000)
    salt = canonical_b64(envelope["salt_b64"], 16)
    nonce = canonical_b64(envelope["nonce_b64"], 12)
    ciphertext = canonical_b64(envelope["ciphertext_b64"], (17, 65600))

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = hashlib.pbkdf2_hmac("sha256", password, salt, 600000, dklen=32)
        plain = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except ImportError as exc:
        raise portfolio.Hold("HOLD: cryptography package unavailable") from exc
    except ValueError as exc:
        raise portfolio.Hold("HOLD: invalid encrypted PRIVATE HUMAN payload") from exc
    except Exception as exc:
        # Never reveal whether the file was tampered with or password differs.
        raise portfolio.Hold("HOLD: encrypted PRIVATE HUMAN admission failed") from exc

    portfolio.require(1 <= len(plain) <= MAX_PAYLOAD_BYTES)
    return strict_json(plain)


def unlock(path: Path, passphrase: str) -> dict:
    payload = decrypt_payload(path, passphrase)
    portfolio.header(payload, PAYLOAD_KIND, PAYLOAD_FIELDS,
                     PAYLOAD_DISPOSITION)
    portfolio.require(payload["warning"] == VAULT_WARNING)
    portfolio.require(type(payload["peer_board"]) is dict or
                      payload["peer_board"] is None)
    return payload


def create(cipher_path: Path, destination: Path, passphrase: str,
           only: str | None = None, ordinal: int | None = None,
           handoff_password: str | None = None) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    portfolio.require(only is None or only in handoff.ACTIONS)
    portfolio.require(handoff_password is None or only in handoff.ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and only in handoff.ACTIONS and
                       1 <= ordinal <= 12))

    # Decrypted bytes exist only inside the user-owned temp directory, and
    # are removed on both success and failure. They are never uploaded.
    payload = unlock(cipher_path, passphrase)
    temp = Path(tempfile.mkdtemp(
        prefix=".lightup-unlocked-private-human-", dir=destination.parent))
    os.chmod(temp, 0o700)
    try:
        names = {
            "session.json": payload["original_session"],
            "original.json": payload["original_board"],
            "proposed.json": payload["working_board"],
        }
        if payload["peer_board"] is not None:
            names["peer.json"] = payload["peer_board"]
        for filename, value in names.items():
            portfolio.require(type(value) is dict)
            portfolio.exclusive_write(temp / filename, portfolio.serialize(value))

        session_path = temp / "session.json"
        source, _ = session.read_session(session_path)
        portfolio.require(1 <= len(source) <= portfolio.MAX_FILES)
        for filename in ("original.json", "proposed.json"):
            action_board.board_import(temp / filename, session_path)
        if "peer.json" in names:
            action_board.board_import(temp / "peer.json", session_path)

        # Existing original-source-parsed browser CLI provides atomic,
        # source-free return + HUMAN handoff + local delta workroom.
        return browser_workflow.create(
            session_path, temp / "original.json", temp / "proposed.json",
            destination, only, ordinal,
            temp / "peer.json" if "peer.json" in names else None,
            handoff_password
        )
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Unlock locally encrypted .lhew browser workspace with interactive "
        "password and produce complete PRIVATE original-source-free HUMAN "
        "workroom. No target, grant, authenticated case or real remediation."
    ))
    parser.add_argument("--encrypted-workspace", type=Path, required=True,
                        help="Owner-private 0600 .lhew under existing 0700 folder")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh PRIVATE 0700 operator folder, no overwrite")
    parser.add_argument("--only", choices=handoff.ACTIONS,
                        help="Limit outbound HUMAN handoff to one action group")
    parser.add_argument("--ordinal", type=int,
                        help="With --only, one exact local ordinal, not a case ID")
    parser.add_argument("--encrypt-selected-handoff", action="store_true",
                        help="Also write selected encrypted .lheh in private workroom")
    args = parser.parse_args()
    if args.encrypt_selected_handoff and args.only is None:
        parser.error("--encrypt-selected-handoff requires explicit --only ACTION")
    try:
        password = getpass.getpass("PRIVATE HUMAN workspace passphrase: ")
        outgoing = None
        if args.encrypt_selected_handoff:
            outgoing = getpass.getpass("New selected HUMAN handoff passphrase: ")
            confirmed = getpass.getpass("Confirm handoff passphrase: ")
            portfolio.require(outgoing == confirmed)
        result = create(args.encrypted_workspace, args.output_dir,
                        password, args.only, args.ordinal, outgoing)
    except (ValueError, OSError, RecursionError, EOFError, KeyboardInterrupt):
        print("HOLD: No PRIVATE encrypted HUMAN workroom published.",
              file=sys.stderr)
        return 2
    print("PRIVATE offline HUMAN workroom created: %d local anonymous changes; "
          "no original authentication, verified remediation or permission." %
          result["changed_anonymous_routing_appearances_not_original_cases"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
