#!/usr/bin/env python3
"""PRIVATE encrypted browser-vault -> original source-bound HUMAN history.

Explicit offline operation. No scan, grant, deletion, subprocess, network,
credential command-line flags, unauthenticated source carry or plaintext output.
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
import re
import stat

from history import AUTHORITY, Hold, MAX_FILES, no_constant, no_duplicates, parse_receipt_bytes, private_html, publish_private

ENVELOPE_KIND = "lightup.private.assessment.retention.encrypted"
ENVELOPE_AAD = b"lightup.private.assessment.retention.encrypted.v1"
ITERATIONS = 310_000
MAX_ENVELOPE_BYTES = 262_144
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
SHA = re.compile(r"^[0-9a-f]{64}$")


def read_bounded_regular(path: str, budget: int, *, owner_private: bool = False) -> bytes:
    """Read one bounded regular file and reject path/descriptor or mid-read drift."""
    p = Path(path)
    try:
        path_meta = p.lstat()
        if not stat.S_ISREG(path_meta.st_mode):
            raise Hold("PRIVATE input must be a regular file (links rejected)")
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            if ((path_meta.st_dev, path_meta.st_ino) != (before.st_dev, before.st_ino)
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_size < 1 or before.st_size > budget):
                raise Hold("PRIVATE file is empty, changed or exceeds bounded original admission")
            if owner_private and (
                before.st_uid != os.getuid()
                or before.st_nlink != 1
                or not before.st_mode & stat.S_IRUSR
                or before.st_mode & 0o077
                or before.st_mode & 0o7000
            ):
                raise Hold("PRIVATE file must be owner-owned, unlinked and owner-only")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(budget + 1)
            after = os.fstat(fd)
            before_identity = (
                before.st_dev, before.st_ino, before.st_size, before.st_mode,
                before.st_uid, before.st_nlink, before.st_mtime_ns, before.st_ctime_ns,
            )
            after_identity = (
                after.st_dev, after.st_ino, after.st_size, after.st_mode,
                after.st_uid, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns,
            )
            if len(raw) != before.st_size or before_identity != after_identity:
                raise Hold("PRIVATE input changed or exceeded its bounded read")
        finally:
            os.close(fd)
    except OSError as exc:
        raise Hold("cannot securely read PRIVATE regular input") from exc
    return raw


def exact_object(value: object, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def canonical_hex(value: object, chars: int) -> bytes:
    if type(value) is not str or len(value) != chars or not re.fullmatch(r"[0-9a-f]+", value):
        raise Hold("invalid encrypted salt/nonce shape")
    return bytes.fromhex(value)


def decode_base64(value: object) -> bytes:
    if (type(value) is not str or not 24 <= len(value) <= 200_000 or
            len(value) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value)):
        raise Hold("invalid or excessive encrypted payload")
    try:
        result = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise Hold("invalid encrypted payload encoding") from exc
    if base64.b64encode(result).decode("ascii") != value:
        raise Hold("noncanonical encrypted payload")
    if not 17 <= len(result) <= 131_072 + 16:
        raise Hold("encrypted payload out of original bound")
    return result


def decrypt_vault(path: str, password: str) -> dict[str, dict]:
    """Read a bounded local envelope, then validate/decrypt its exact bytes."""
    return decrypt_vault_bytes(read_bounded_regular(path, MAX_ENVELOPE_BYTES), password)


def decrypt_vault_bytes(raw: bytes, password: str) -> dict[str, dict]:
    """Return original-validated HUMAN rows only from the exact supplied envelope bytes."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ENVELOPE_BYTES:
        raise Hold("PRIVATE encrypted envelope outside bounded size")
    try:
        envelope = json.loads(raw.decode("utf-8", "strict"),
                              object_pairs_hook=no_duplicates, parse_constant=no_constant)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise Hold("malformed private encrypted envelope") from exc
    required = {"kind", "version", "algorithm", "iterations", "salt", "nonce", "ciphertext", "authority"}
    if (not exact_object(envelope, required)
            or envelope["kind"] != ENVELOPE_KIND
            or type(envelope["version"]) is not int or envelope["version"] != 1
            or envelope["algorithm"] != "PBKDF2-SHA256/AES-256-GCM"
            or type(envelope["iterations"]) is not int or envelope["iterations"] != ITERATIONS
            or not exact_object(envelope["authority"], set(AUTHORITY))
            or any(envelope["authority"][name] is not False for name in AUTHORITY)):
        raise Hold("unknown/authority-claiming encrypted HUMAN contract")
    salt = canonical_hex(envelope["salt"], 32)
    nonce = canonical_hex(envelope["nonce"], 24)
    ciphertext = decode_base64(envelope["ciphertext"])
    # Non-stdlib cryptography is strictly opt-in for this native bridge;
    # no network or shell fallback if it is absent. This is never an auth gate.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise Hold("native bridge requires installed audited 'cryptography' package; no fallback") from exc
    try:
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8", "strict"), salt, ITERATIONS, dklen=32)
        plain = AESGCM(key).decrypt(nonce, ciphertext, ENVELOPE_AAD)
    except (ValueError, UnicodeError) as exc:
        raise Hold("AES-GCM decryption failed: wrong password or modified ciphertext") from exc
    except Exception as exc:
        # InvalidTag may vary between supported versions. No detailed sensitive error.
        raise Hold("AES-GCM decryption refused") from exc
    return parse_receipt_bytes(plain)


def original_sources(paths: list[str], *, owner_private: bool = False) -> set[tuple[str, int]]:
    """Recompute original SHA-256 bytes, no paths/content in output."""
    if not 1 <= len(paths) <= MAX_FILES:
        raise Hold("provide between one and twelve original source files")
    identities: set[tuple[str, int]] = set()
    cumulative = 0
    for path in paths:
        original = read_bounded_regular(path, MAX_SOURCE_BYTES, owner_private=owner_private)
        cumulative += len(original)
        if cumulative > MAX_TOTAL_SOURCE_BYTES:
            raise Hold("aggregate original sources exceed 64 MiB")
        identity = (hashlib.sha256(original).hexdigest(), len(original))
        if identity in identities:
            raise Hold("duplicate original source bytes cannot be admitted")
        identities.add(identity)
    return identities


def main() -> None:
    p = argparse.ArgumentParser(description=(
        "Read 2–12 original encrypted .lurt HUMAN plan revisions, re-hash current "
        "PRIVATE source bytes and publish one 0600 local scriptless HTML history. "
        "Never authorizes scans, deletion or client operations."
    ))
    p.add_argument("--output", required=True, help="New PRIVATE .html file in a pre-existing 0700 directory")
    p.add_argument("--source-file", action="append", required=True, dest="sources",
                   help="Original PRIVATE source to re-hash; repeat for every original file")
    p.add_argument("vaults", nargs="+", help="2–12 operator-ordered original PRIVATE browser .lurt vaults")
    args = p.parse_args()
    if not 2 <= len(args.vaults) <= MAX_FILES:
        p.error("exactly 2–12 original encrypted PRIVATE plans are required")
    try:
        expected = original_sources(args.sources)
        plans = []
        for position, filename in enumerate(args.vaults, 1):
            try:
                password = getpass.getpass(f"PRIVATE encrypted plan {position} password (not echoed): ")
            except (EOFError, KeyboardInterrupt) as exc:
                raise Hold("interactive password entry unavailable or cancelled") from exc
            if (not 12 <= len(password) <= 128 or len(password.encode("utf-8")) > 256
                    or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in password)):
                raise Hold("invalid password shape")
            current = decrypt_vault(filename, password)
            if {(key, row["bytes"]) for key, row in current.items()} != expected:
                raise Hold("encrypted HUMAN plan does not match every current original source byte")
            plans.append(current)
        report = private_html(plans)
        publish_private(args.output, report)
    except Hold as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE source-rehashed AES-256-GCM HUMAN history generated; no plaintext handoff or authorization.")


if __name__ == "__main__":
    main()
