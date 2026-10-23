"""Native, offline read-only LightUp PRIVATE HUMAN vault decryption.

Compatible only with review-vault.js LUHUM001. Never stores decrypted CSV
on disk; native human_review.py performs the original receipt/CSV admission.
This encryption authenticates the bytes under a password, NOT the sender,
original source/owner, client consent, revocation or assessment approval.
"""
from __future__ import annotations

import getpass
import hmac
import hashlib
import os
import stat
import struct
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


def private_ciphertext_bytes(path: str, minimum: int, maximum: int) -> bytes:
    """Open one owned 0600 ciphertext file, reject aliases and source mutation.

    This is local PRIVATE custody, not client consent or authentic sender proof.
    """
    fd = -1
    try:
        listed = os.stat(path, follow_symlinks=False)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode)
                and minimum < opened.st_size <= maximum
                and opened.st_uid == os.getuid()
                and opened.st_mode & 0o077 == 0
                and opened.st_nlink == 1)
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                    item.st_nlink, item.st_size, item.st_mtime_ns,
                    item.st_ctime_ns)
        require(identity(listed) == identity(opened))
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(maximum + 1)
            after_read = os.fstat(stream.fileno())
        require(minimum < len(data) <= maximum
                and identity(opened) == identity(after_read)
                and identity(opened) == identity(os.stat(path, follow_symlinks=False)))
        return data
    except (OSError, ValueError, MemoryError):
        raise VaultHold("HOLD: PRIVATE HUMAN ciphertext file refused") from None
    finally:
        if fd >= 0:
            os.close(fd)


def read_vault(path: str) -> bytes:
    return private_ciphertext_bytes(path, HEADER_BYTES + 16, MAX_VAULT)


def decrypt_vault(path: str, expected_receipt_sha256: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
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
    require(hmac.compare_digest(header[36:68], expected))
    # Non-echoed interactive TTY required. No password in argv or plaintext files.
    require(sys.stdin.isatty())
    try:
        secret = getpass.getpass("PRIVATE HUMAN vault password (not client consent): ")
    except (EOFError, KeyboardInterrupt):
        raise VaultHold("HOLD: PRIVATE HUMAN password entry cancelled") from None
    try:
        require(14 <= len(secret) <= 256 and all(" " <= c < "\x7f" or ord(c) >= 128 for c in secret))
        key = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), header[8:24], KDF_ROUNDS, 32)
        plain = AESGCM(key).decrypt(header[24:36], data[HEADER_BYTES:], header)
        require(0 < len(plain) <= MAX_CSV)
        return plain
    except (ValueError, UnicodeError, TypeError, OverflowError, MemoryError, InvalidTag):
        raise VaultHold("HOLD: PRIVATE HUMAN vault decryption refused") from None
    finally:
        secret = ""  # Best effort: immutable Python strings cannot be securely wiped.


def encrypt_vault(plain: bytes, receipt_sha256: str) -> bytes:
    """Create interoperable original-receipt-bound encrypted HUMAN CSV in memory."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultHold("HOLD: installed cryptography dependency required") from None
    require(type(plain) is bytes and 0 < len(plain) <= MAX_CSV)
    require(type(receipt_sha256) is str and len(receipt_sha256) == 64)
    try:
        receipt_digest = bytes.fromhex(receipt_sha256)
    except ValueError:
        raise VaultHold("HOLD: invalid PRIVATE receipt digest") from None
    require(len(receipt_digest) == 32)
    require(sys.stdin.isatty())
    try:
        first = getpass.getpass("New PRIVATE HUMAN vault password (not client consent): ")
        second = getpass.getpass("Repeat PRIVATE HUMAN vault password: ")
    except (EOFError, KeyboardInterrupt):
        raise VaultHold("HOLD: PRIVATE password entry cancelled") from None
    try:
        require(14 <= len(first) <= 256 and first == second)
        require(all(" " <= c < "\x7f" or ord(c) >= 128 for c in first))
        salt = os.urandom(16)
        nonce = os.urandom(12)
        header = MAGIC + salt + nonce + receipt_digest
        require(len(header) == HEADER_BYTES)
        key = hashlib.pbkdf2_hmac("sha256", first.encode("utf-8"), salt, KDF_ROUNDS, 32)
        ciphertext = AESGCM(key).encrypt(nonce, plain, header)
        require(len(ciphertext) == len(plain) + 16)
        return header + ciphertext
    except (ValueError, UnicodeError, TypeError, OverflowError, MemoryError):
        raise VaultHold("HOLD: encrypted PRIVATE HUMAN packet not produced") from None
    finally:
        first = ""
        second = ""  # Immutable Python strings cannot be securely erased.


# LUHBP001 encrypts *both* the unsigned source-free receipt and HUMAN CSV.
BUNDLE_MAGIC = b"LUHBP001"
BUNDLE_HEADER = 36  # purpose 8 | salt 16 | nonce 12
BUNDLE_CONTENT_HEADER = 16  # purpose 8 | receipt size u32be | csv size u32be
MAX_RECEIPT = 256 * 1024
MAX_BUNDLE = BUNDLE_HEADER + BUNDLE_CONTENT_HEADER + MAX_RECEIPT + MAX_CSV + 16


def _bundle_password(confirm: bool) -> str:
    require(sys.stdin.isatty())
    try:
        password = getpass.getpass("PRIVATE HUMAN handoff password (no assessment authority): ")
        if confirm:
            duplicate = getpass.getpass("Repeat PRIVATE HUMAN handoff password: ")
            require(password == duplicate)
    except (EOFError, KeyboardInterrupt):
        raise VaultHold("HOLD: HUMAN passphrase was not provided") from None
    require(14 <= len(password) <= 256 and
            all(" " <= char < "\x7f" or ord(char) >= 128 for char in password))
    return password


def encrypt_bundle(receipt: bytes, csv: bytes) -> bytes:
    """Seal original unsigned receipt bytes + exact HUMAN CSV into one private file."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultHold("HOLD: cryptography dependency unavailable") from None
    require(type(receipt) is bytes and 0 < len(receipt) <= MAX_RECEIPT)
    require(type(csv) is bytes and 0 < len(csv) <= MAX_CSV)
    password = _bundle_password(confirm=True)
    try:
        salt, nonce = os.urandom(16), os.urandom(12)
        header = BUNDLE_MAGIC + salt + nonce
        clear = (BUNDLE_MAGIC + struct.pack(">II", len(receipt), len(csv)) +
                 receipt + csv)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  salt, KDF_ROUNDS, 32)
        sealed = AESGCM(key).encrypt(nonce, clear, header)
        require(len(sealed) == len(clear) + 16)
        return header + sealed
    except (ValueError, TypeError, OverflowError, MemoryError):
        raise VaultHold("HOLD: HUMAN bundle could not be encrypted") from None
    finally:
        password = ""  # Python strings cannot be forcibly zeroized.


def decrypt_bundle(path: str) -> tuple[bytes, bytes]:
    """Decrypt bounded authenticated bundle without writing the receipt or CSV."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError:
        raise VaultHold("HOLD: cryptography dependency unavailable") from None
    data = private_ciphertext_bytes(path, BUNDLE_HEADER + BUNDLE_CONTENT_HEADER + 16, MAX_BUNDLE)
    header = data[:BUNDLE_HEADER]
    require(header[:8] == BUNDLE_MAGIC)
    password = _bundle_password(confirm=False)
    try:
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  header[8:24], KDF_ROUNDS, 32)
        clear = AESGCM(key).decrypt(header[24:36], data[BUNDLE_HEADER:], header)
        require(len(clear) >= BUNDLE_CONTENT_HEADER + 2)
        require(clear[:8] == BUNDLE_MAGIC)
        receipt_len, csv_len = struct.unpack(">II", clear[8:16])
        require(0 < receipt_len <= MAX_RECEIPT and 0 < csv_len <= MAX_CSV)
        require(len(clear) == BUNDLE_CONTENT_HEADER + receipt_len + csv_len)
        return (clear[BUNDLE_CONTENT_HEADER:BUNDLE_CONTENT_HEADER + receipt_len],
                clear[BUNDLE_CONTENT_HEADER + receipt_len:])
    except (ValueError, InvalidTag, TypeError, OverflowError, MemoryError):
        raise VaultHold("HOLD: encrypted HUMAN bundle not admitted") from None
    finally:
        password = ""
