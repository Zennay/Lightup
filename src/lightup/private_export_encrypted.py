"""Optional encrypted-at-rest PRIVATE source-bound LightUp handoff (offline only).

Authenticated tenant selection uses the unchanged DomainStore and the held
parent's guarded CSV exporter. A cleartext ZIP exists only in process memory;
the code never serializes that ZIP to disk. No active targets, scans or grants.

This is a separate portable v1 AES-GCM envelope, not interoperable with the
original independently owned browser Handoff Vault. Keep vaults distinct.
"""
from __future__ import annotations

import argparse
from datetime import timezone
from getpass import GetPassWarning, getpass
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import warnings

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv
from .private_export_handoff import (
    _atomic_private_publish, _make_archive, _output_path, _read_archive_bytes,
    _report_html, ARCHIVE_LIMIT,
)
from .private_export_continuity import _source_comparison, _html as _continuity_html
from .private_export_workdesk import _load_resume, _render as _workdesk_html

MAGIC = b"LIGHTUP-PRIVATE-AESGCM-V1\x00"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KDF_N = 1 << 15
KDF_R = 8
KDF_P = 1
ENC_EXTENSION = ".lue"
MAX_ENVELOPE_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE + ARCHIVE_LIMIT + TAG_SIZE


def _cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.exceptions import InvalidTag
    except ImportError as exc:
        raise ValueError("optional cryptography dependency not installed") from exc
    return AESGCM, Scrypt, InvalidTag


def _passphrase(label: str, *, confirm: bool = False) -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("secure interactive terminal required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        secret = getpass(label + ": ")
        if type(secret) is not str or not 16 <= len(secret) <= 256:
            raise ValueError("passphrase length outside bounded required range")
        if confirm:
            repeated = getpass("Repeat new private passphrase: ")
            if repeated != secret:
                raise ValueError("passphrases do not match")
            del repeated
    return secret


def _key(secret: str, salt: bytes) -> bytes:
    _, Scrypt, _ = _cryptography()
    if type(salt) is not bytes or len(salt) != SALT_SIZE:
        raise ValueError("invalid envelope KDF salt")
    if type(secret) is not str or not 16 <= len(secret) <= 256:
        raise ValueError("invalid private passphrase")
    return Scrypt(
        salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P
    ).derive(secret.encode("utf-8", "strict"))


def _seal(contents: bytes, secret: str) -> bytes:
    AESGCM, _, _ = _cryptography()
    if type(contents) is not bytes or len(contents) > ARCHIVE_LIMIT:
        raise ValueError("unbounded or invalid original archive bytes")
    # Every encryption uses fresh, independent high-entropy nonce and salt.
    salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
    heading = MAGIC + salt + nonce
    envelope = heading + AESGCM(_key(secret, salt)).encrypt(nonce, contents, heading)
    if len(envelope) > MAX_ENVELOPE_SIZE:
        raise ValueError("encrypted handoff exceeds offline size budget")
    return envelope


def _open_sealed(envelope: bytes, secret: str) -> bytes:
    AESGCM, _, InvalidTag = _cryptography()
    if (
        type(envelope) is not bytes or
        len(envelope) < len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE or
        len(envelope) > MAX_ENVELOPE_SIZE or
        not envelope.startswith(MAGIC)
    ):
        raise ValueError("unrecognized or invalid encrypted handoff")
    offset = len(MAGIC)
    salt = envelope[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = envelope[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    header = envelope[:offset]
    try:
        contents = AESGCM(_key(secret, salt)).decrypt(nonce, envelope[offset:], header)
    except InvalidTag as exc:
        raise ValueError("encrypted handoff authentication failed") from exc
    if len(contents) > ARCHIVE_LIMIT:
        raise ValueError("decrypted archive exceeds admission limit")
    return contents


def _read_encrypted(path: str, secret: str) -> tuple[dict, list[dict[str, str]], bytes]:
    input_path = Path(path).expanduser()
    if not input_path.is_file() or input_path.stat().st_size > MAX_ENVELOPE_SIZE:
        raise ValueError("encrypted archive absent or exceeds size limit")
    content = input_path.read_bytes()
    plaintext = _open_sealed(content, secret)
    manifest, rows = _read_archive_bytes(plaintext)
    return manifest, rows, plaintext


def _authenticated_export(db: str, email: str, client_id: str, engagement_id: str | None) -> bytes:
    if not sys.stdin.isatty() or not Path(db).is_file():
        raise ValueError("secure login terminal and existing original database required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        password = getpass("Existing LightUp account password: ")
    store = DomainStore(db)
    try:
        user = store.authenticate(email, password)
    finally:
        del password
    if user is None:
        raise PermissionError("original sign-in denied")
    context = store.context_for_user(user.user_id)
    csv_text = render_client_findings_csv(
        store, context, client_id, engagement_id=engagement_id
    )
    # Existing original full-batch Unicode/tenant guard executes above.
    return _make_archive(csv_text, client_id, engagement_id)


def _safe_private_output(path: str, payload: bytes) -> None:
    _atomic_private_publish(_output_path(path, Path(path).suffix.lower()), payload)


def _require_acknowledgment(value: bool) -> None:
    if value is not True:
        raise ValueError("explicit private security and transport acknowledgment required")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LightUp authenticated PRIVATE AES-GCM export and offline handling; DRAFT/HOLD"
    )
    subs = parser.add_subparsers(dest="action", required=True)
    create = subs.add_parser("create", help="original sign-in to directly encrypted .lue, never plaintext ZIP")
    create.add_argument("--db", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--client-id", required=True)
    create.add_argument("--engagement-id")
    create.add_argument("--output", required=True)
    inspect = subs.add_parser("inspect", help="authenticate ciphertext and inspect anonymous counts in memory")
    inspect.add_argument("archive")
    report = subs.add_parser("report", help="locally decrypt and produce ID-free private HTML")
    report.add_argument("archive")
    report.add_argument("--output", required=True)
    workdesk = subs.add_parser("workdesk", help="decrypt original ciphertext in memory, render PRIVATE HUMAN workdesk")
    workdesk.add_argument("archive")
    workdesk.add_argument("--output", required=True)
    workdesk.add_argument("--resume", help="previous exact-source PRIVATE human JSON")
    compare = subs.add_parser("compare", help="compare two independently encrypted source ZIPs in memory")
    compare.add_argument("earlier")
    compare.add_argument("later")
    compare.add_argument("--output", required=True)
    rotate = subs.add_parser("rotate", help="decrypt, authenticate and re-encrypt without cleartext disk")
    rotate.add_argument("archive")
    rotate.add_argument("--output", required=True)
    for command in (create, inspect, report, workdesk, compare, rotate):
        command.add_argument("--ack-private-handling", action="store_true")
    workdesk.add_argument("--ack-original-identifiers", action="store_true")
    compare.add_argument("--ack-same-real-client", action="store_true")
    args = parser.parse_args(argv)
    try:
        _require_acknowledgment(args.ack_private_handling)
        if args.action == "create":
            destination = _output_path(args.output, ENC_EXTENSION)
            # Authenticate original source BEFORE publishing anything.
            original_zip = _authenticated_export(
                args.db, args.email, args.client_id, args.engagement_id
            )
            secret = _passphrase("New encryption passphrase", confirm=True)
            encrypted = _seal(original_zip, secret)
            _atomic_private_publish(destination, encrypted)
            print("Encrypted original authorized source saved privately. Recipient identity not verified.")
            print("Local ciphertext SHA-256 (unsigned):", hashlib.sha256(encrypted).hexdigest())
            return 0

        if args.action == "compare":
            if not args.ack_same_real_client:
                raise ValueError("independent same-real-client human approval required")
            destination = _output_path(args.output, ".html")
            old_secret = _passphrase("Earlier source passphrase")
            old_manifest, earlier, _ = _read_encrypted(args.earlier, old_secret)
            del old_secret
            new_secret = _passphrase("Later source passphrase")
            new_manifest, later, _ = _read_encrypted(args.later, new_secret)
            del new_secret
            if any(old_manifest[field] != new_manifest[field] for field in (
                "declared_client_id", "declared_engagement_id"
            )):
                raise ValueError("conflicting declared client engagement provenance")
            delta = _source_comparison(earlier, later)
            _atomic_private_publish(destination, _continuity_html(delta, False).encode("utf-8"))
            print("Created private ID-free comparison. Absent never means repaired.")
            return 0

        if args.action == "rotate":
            destination = _output_path(args.output, ENC_EXTENSION)
            old = _passphrase("Current source passphrase")
            _manifest, _rows, original = _read_encrypted(args.archive, old)
            del old
            fresh = _passphrase("New encryption passphrase", confirm=True)
            encrypted = _seal(original, fresh)
            _atomic_private_publish(destination, encrypted)
            print("Created separately encrypted, unchanged source; manually retire old copy.")
            print("New ciphertext SHA-256 (unsigned):", hashlib.sha256(encrypted).hexdigest())
            return 0

        destination = None
        if args.action in ("report", "workdesk"):
            destination = _output_path(args.output, ".html")
        if args.action == "workdesk" and not args.ack_original_identifiers:
            raise ValueError("explicit private original-source identity acknowledgment required")
        secret = _passphrase("Private source passphrase")
        manifest, rows, _original = _read_encrypted(args.archive, secret)
        del secret
        if args.action == "inspect":
            from collections import Counter
            print("Authenticated local ciphertext, checked internal CSV bytes; sender NOT authenticated.")
            print("Original finding count:", len(rows))
            for field in ("severity", "retest_status"):
                for label, count in sorted(Counter(row[field] for row in rows).items()):
                    print(field + " " + label + ": " + str(count))
        elif args.action == "report":
            _atomic_private_publish(destination, _report_html(rows).encode("utf-8"))
            print("Created unencrypted private ID-free human report; manually protect recipient.")
        else:
            state = _load_resume(args.resume, manifest, rows) if args.resume else {
                row["finding_id"]: {
                    "finding_id": row["finding_id"], "stage": "unassigned",
                    "owner_alias": "", "due_date": "", "human_note": ""
                } for row in rows
            }
            _atomic_private_publish(destination, _workdesk_html(manifest, rows, state))
            print("Created UNENCRYPTED private HUMAN workdesk; no consent or fixes verified.")
        return 0
    except (
        ValueError, OSError, PermissionError, sqlite3.DatabaseError,
        AccountLockedError, GetPassWarning, UnicodeError, EOFError, KeyboardInterrupt
    ):
        print("PRIVATE encryption workflow HOLD: source, login, key, consent acknowledgment or output invalid.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
