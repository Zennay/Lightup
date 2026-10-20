#!/usr/bin/env python3
"""Offline in-memory PRIVATE source-bound recipient reply passphrase rotation.

An existing originally selected encrypted .luhq plus actual encrypted reply
must be re-admitted. Old and new reply passwords stay interactive. No plaintext
reply file, original mutation, network or security/consent claim.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import sys

import reply

WARNING = reply.WARNING

def require(ok: bool, msg: str) -> None:
    reply.require(ok, msg)

def canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True, allow_nan=False).encode("utf-8")

def rotate(original: Path, previous: Path, destination: Path) -> None:
    require(original.is_absolute() and previous.is_absolute()
            and destination.is_absolute() and original != previous
            and destination != original and destination != previous,
            "Original handoff, encrypted reply and destination must be separate")
    require(destination.parent == destination.parent.resolve(strict=True)
            and not destination.exists() and not destination.is_symlink()
            and destination.suffix == ".luhr",
            "Choose a NEW literal absolute .luhr output file")
    reply.schedule.private_parent(destination.parent)
    for source in (original, previous):
        require(source.parent != destination and
                source not in destination.parents and
                destination not in source.parents,
                "PRIVATE response input and output path overlap")

    # Exact original source-bound encrypted handoff and old response bytes.
    packet, source_digest, source_bytes = reply.source(original)
    responses, previous_bytes = reply.admitted_reply(
        previous, packet, source_digest
    )
    if not sys.stdin.isatty():
        raise reply.single_review.review.Hold(
            "New PRIVATE HUMAN password requires interactive private terminal"
        )
    # Original implementation requires 14-256 NFC non-control passphrase,
    # entered twice and never used as an argument, environment or output.
    new_password = reply.encrypted_cockpit.password(confirmation=True)
    body = reply.payload(packet, source_digest, responses)
    body.pop("original_items")  # Existing native minimal reply contract.
    raw = canonical(body)
    require(len(raw) <= reply.MAX_REPLY,
            "PRIVATE HUMAN reply exceeds canonical encrypted input size")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(reply.encrypted_cockpit.aead_key(new_password, salt)).encrypt(
        nonce, raw, reply.AAD
    )
    frame = {
        "kind": reply.ENVELOPE_KIND,
        "version": 1,
        "disposition": reply.DISPOSITION,
        "authority_granted": False,
        "consent_verified": False,
        "source_authenticated": False,
        "remediation_verified": False,
        "warning": WARNING,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 600000,
        "algorithm": "AES-256-GCM",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(cipher).decode("ascii"),
    }
    new_bytes = canonical(frame)
    require(100 <= len(new_bytes) <= reply.MAX_ENCRYPTED,
            "Re-encrypted PRIVATE HUMAN reply exceeds local archive bound")

    # Fail-closed against any source/recipient changes before publication.
    require(reply.encrypted_cockpit.private_envelope(original) == source_bytes
            and reply.schedule_vault.private_vault(previous) == previous_bytes
            and not destination.exists(),
            "PRIVATE HUMAN source or reply changed before password rotation")

    # Create a private 0600 temporary sibling, durable fsync then atomic
    # non-overwriting hardlink. This never writes decrypted plaintext to disk.
    pending = destination.parent / (
        ".lightup-private-human-rekey-" + secrets.token_hex(12)
    )
    fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as writer:
            os.fchmod(writer.fileno(), 0o600)
            writer.write(new_bytes)
            writer.flush()
            os.fsync(writer.fileno())
        # Original files remain unchanged; no replace-capable rename fallback.
        require(reply.encrypted_cockpit.private_envelope(original) == source_bytes
                and reply.schedule_vault.private_vault(previous) == previous_bytes,
                "PRIVATE original selected source or reply changed during rotation")
        # Check the private staging inode before publishing. An already
        # present destination always causes an atomic EEXIST refusal.
        prepared = pending.lstat()
        require(stat.S_ISREG(prepared.st_mode) and prepared.st_nlink == 1
                and prepared.st_mode & 0o077 == 0
                and prepared.st_uid == os.getuid()
                and prepared.st_size == len(new_bytes),
                "Prepared PRIVATE HUMAN ciphertext is not complete and owner-only")
        os.link(pending, destination, follow_symlinks=False)
        try:
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            # Only unlink the destination we atomically created; no rewrite of
            # input or pre-existing destination is ever performed.
            if destination.exists() and destination.stat().st_ino == prepared.st_ino:
                destination.unlink()
            raise
    finally:
        if pending.exists():
            pending.unlink()
    print("REVIEW_ONLY: locally rotated PRIVATE encrypted source-redacted HUMAN reply:", destination)
    print("No readable HUMAN JSON intermediary; original encrypted reply untouched.")
    print("New password is NOT original authenticated sender identity or consent.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", required=True, type=Path,
                        help="Exact original encrypted source-redacted .luhq")
    parser.add_argument("--reply", required=True, type=Path,
                        help="Original existing encrypted selected HUMAN .luhr")
    parser.add_argument("--output-file", required=True, type=Path,
                        help="NEW private absolute .luhr path below 0700 parent")
    args = parser.parse_args()
    try:
        rotate(args.handoff, args.reply, args.output_file)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            KeyError, TypeError, RuntimeError, UnicodeError,
            ImportError, OverflowError) as e:
        print("HOLD: PRIVATE HUMAN encrypted rekey:", str(e), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
