"""Native, offline read-only LightUp PRIVATE HUMAN vault decryption.

Compatible only with review-vault.js LUHUM001. Never stores decrypted CSV
on disk; native human_review.py performs the original receipt/CSV admission.
This encryption authenticates the bytes under a password, NOT the sender,
original source/owner, client consent, revocation or assessment approval.
"""
from __future__ import annotations

import getpass
import hashlib
import os
import stat
import sys

MAGIC = b"LUHUM001"
HEADER_BYTES = 68
MAX_CSV = 256 * 1024
MAX_VAULT = HEADER_BYTES + MAX_CSV + 16
KDF_ROUNDS = 600_000


class VaultHold(ValueError):
    pass


def require(valid: bool) -> None:
    if not valid:
        raise VaultHold("HOLD: PRIVATE HUMAN ciphertext not admitted")


def read_vault(path: str) -> bytes:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and HEADER_BYTES + 16 < info.st_size <= MAX_VAULT)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(MAX_VAULT + 1)
        require(HEADER_BYTES + 16 < len(data) <= MAX_VAULT)
        return data
    except (OSError, ValueError, MemoryError):
        raise VaultHold("HOLD: PRIVATE HUMAN ciphertext file refused") from None
    finally:
        if fd >= 0:
            os.close(fd)


def decrypt_vault(path: str, expected_receipt_sha256: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultHold("HOLD: installed cryptography dependency required") from None
    require(type(expected_receipt_sha256) is str and len(expected_receipt_sha256) == 64)
    try:
        expected = bytes.fromhex(expected_receipt_sha256)
    except ValueError:
        raise VaultHold("HOLD: invalid source-free receipt digest") from None
    require(len(expected) == 32)
    data = read_vault(path)
    header = data[:HEADER_BYTES]
    require(header[:8] == MAGIC)
    # Header is itself authenticated as AES-GCM AAD. Use constant-time comparison
    # to avoid distinct error categories for matching/nonmatching source receipts.
    require(__import__("hmac").compare_digest(header[36:68], expected))
    # Non-echoed interactive TTY required. No password in argv or plaintext files.
    require(sys.stdin.isatty())
    secret = getpass.getpass("PRIVATE HUMAN vault password (not client consent): ")
    try:
        require(14 <= len(secret) <= 256 and all(" " <= c < "\x7f" or ord(c) >= 128 for c in secret))
        key = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), header[8:24], KDF_ROUNDS, 32)
        plain = AESGCM(key).decrypt(header[24:36], data[HEADER_BYTES:], header)
        require(0 < len(plain) <= MAX_CSV)
        return plain
    except (ValueError, UnicodeError, TypeError, OverflowError, MemoryError):
        raise VaultHold("HOLD: PRIVATE HUMAN vault decryption refused") from None
    finally:
        secret = ""  # Best effort: immutable Python strings cannot be securely wiped.
