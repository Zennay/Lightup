#!/usr/bin/env python3
"""Offline Ed25519 signatures for an already-built LightUp software-only ZIP.

Human custody aid only. NEVER a release gate, client authorization or consent.
Requires separately installed cryptography; no network or targets.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FORMAT = "lightup.offline.software.signature.v1"
PURPOSE = "review-only-software-custody-not-consent-or-release"
DOMAIN = b"LIGHTUP:OFFLINE:SOFTWARE-ONLY:ED25519:V1\x00"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 8192
MAX_KEY_BYTES = 16384
MANIFEST_FIELDS = frozenset({"format", "purpose", "sha256", "size_bytes"})
RECEIPT_FIELDS = MANIFEST_FIELDS | {"signature_b64"}


class Hold(ValueError):
    """Fail closed, with no release or execution status."""


def _regular_file_bytes(path: Path, ceiling: int) -> bytes:
    """Read a bounded regular file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Hold("file cannot be opened as a direct local file") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > ceiling:
            raise Hold("missing, non-regular or over-limit file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(ceiling + 1)
        if len(payload) != info.st_size or len(payload) > ceiling:
            raise Hold("input changed during read or exceeded limit")
        if os.fstat(fd).st_size != info.st_size:
            raise Hold("input changed during read")
        return payload
    finally:
        os.close(fd)


def _write_new_private(path: Path, data: bytes) -> None:
    """Publish a new 0600 file exclusively; never replace or follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise Hold("output already exists, is unsafe or is not writable") from exc
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(data)
            out.flush()
            os.fsync(fd)
        # Durable directory-entry publication matters for local revocation
        # tombstones and trusted key records: fsyncing data alone is insufficient.
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _canonical(data: dict[str, object]) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise Hold("duplicate signature receipt key")
        output[key] = value
    return output


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(key: Ed25519PublicKey) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return _digest(der)


def _archive(path: Path) -> bytes:
    data = _regular_file_bytes(path, MAX_ARCHIVE_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            if not archive.infolist():
                raise Hold("ZIP has no entries")
    except (zipfile.BadZipFile, zipfile.LargeZipFile):
        raise Hold("input is not a valid ZIP container") from None
    return data


def _manifest(data: bytes) -> dict[str, object]:
    return {
        "format": FORMAT,
        "purpose": PURPOSE,
        "sha256": _digest(data),
        "size_bytes": len(data),
    }


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(_regular_file_bytes(path, MAX_KEY_BYTES))
    except (TypeError, ValueError) as exc:
        raise Hold("invalid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise Hold("trusted key is not Ed25519")
    return key


def keygen(folder: Path) -> None:
    if folder.exists() or folder.is_symlink():
        raise Hold("key directory must not already exist")
    password = getpass.getpass("New signing-key passphrase (min 12 characters): ")
    verify_password = getpass.getpass("Confirm signing-key passphrase: ")
    if len(password) < 12 or password != verify_password:
        raise Hold("passphrase too short or confirmation differs")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    public = key.public_key()
    pub = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        folder.mkdir(mode=0o700)
    except OSError as exc:
        raise Hold("cannot create new private key directory") from exc
    try:
        _write_new_private(folder / "signing-private.pem", private)
        _write_new_private(folder / "signing-public.pem", pub)
    except Exception:
        for name in ("signing-private.pem", "signing-public.pem"):
            (folder / name).unlink(missing_ok=True)
        folder.rmdir()
        raise
    print("Key pair generated locally; KEEP private key and passphrase offline.")
    print("Public-key SHA-256 fingerprint (confirm via separate trusted channel):")
    print(_fingerprint(public))
    print("REVIEW_ONLY — key generation does not grant release or client consent.")


def sign(archive_path: Path, private_key_path: Path, receipt_path: Path) -> None:
    archive_data = _archive(archive_path)
    password = getpass.getpass("Offline private-key passphrase: ")
    try:
        key = serialization.load_pem_private_key(
            _regular_file_bytes(private_key_path, MAX_KEY_BYTES),
            password=password.encode("utf-8"),
        )
    except (TypeError, ValueError) as exc:
        raise Hold("private key unlock failed") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise Hold("signing key is not Ed25519")
    manifest = _manifest(archive_data)
    signature = key.sign(DOMAIN + _canonical(manifest))
    receipt = dict(manifest)
    receipt["signature_b64"] = base64.b64encode(signature).decode("ascii")
    _write_new_private(receipt_path, _canonical(receipt) + b"\n")
    print("Unsigned release status: DRAFT/HOLD. Offline signature receipt written.")
    print("Signing public-key fingerprint:", _fingerprint(key.public_key()))
    print("This signature binds ZIP bytes only, not reviews, source ownership or consent.")


def verify(
    archive_path: Path,
    receipt_path: Path,
    trusted_public_key: Path,
    expected_fingerprint: str,
) -> bytes:
    if len(expected_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in expected_fingerprint):
        raise Hold("trusted fingerprint must be 64 lowercase hex characters")
    public = _public_key(trusted_public_key)
    if _fingerprint(public) != expected_fingerprint:
        raise Hold("the local public key does not match the out-of-band trusted fingerprint")
    try:
        receipt = json.loads(
            _regular_file_bytes(receipt_path, MAX_RECEIPT_BYTES).decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("receipt JSON is invalid or ambiguous") from exc
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise Hold("receipt has missing or unknown fields")
    signed = {key: receipt[key] for key in MANIFEST_FIELDS}
    if (
        receipt["format"] != FORMAT
        or receipt["purpose"] != PURPOSE
        or type(receipt["size_bytes"]) is not int
        or type(receipt["sha256"]) is not str
        or type(receipt["signature_b64"]) is not str
    ):
        raise Hold("receipt format/type/purpose differs")
    verified_archive_bytes = _archive(archive_path)
    if signed != _manifest(verified_archive_bytes):
        raise Hold("archive bytes differ from the signed manifest")
    try:
        signature = base64.b64decode(receipt["signature_b64"], validate=True)
        if len(signature) != 64:
            raise Hold("Ed25519 signature must be 64 bytes")
        public.verify(signature, DOMAIN + _canonical(signed))
    except (ValueError, InvalidSignature) as exc:
        raise Hold("invalid signature against trusted public key") from exc
    print("VERIFIED: exact ZIP bytes signed by holder of separately trusted Ed25519 key.")
    print("REVIEW_ONLY — original native receiver must still admit the archive.")
    print("NOT VERIFIED: original source identity, security review, client/operator")
    print("consent, authorization, remediation, deployment or HUMAN GO.")
    return verified_archive_bytes  # immutable captured bytes for native receiver handoff


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("keygen", help="new encrypted Ed25519 keypair in private folder")
    make.add_argument("--directory", type=Path, required=True)
    signer = sub.add_parser("sign", help="sign exact already-built offline software ZIP")
    signer.add_argument("--archive", type=Path, required=True)
    signer.add_argument("--private-key", type=Path, required=True)
    signer.add_argument("--receipt", type=Path, required=True)
    receiver = sub.add_parser("verify", help="verify using public key trusted out of band")
    receiver.add_argument("--archive", type=Path, required=True)
    receiver.add_argument("--receipt", type=Path, required=True)
    receiver.add_argument("--trusted-public-key", type=Path, required=True)
    receiver.add_argument("--trusted-fingerprint", required=True)
    options = parser.parse_args()
    try:
        if options.command == "keygen":
            keygen(options.directory)
        elif options.command == "sign":
            sign(options.archive, options.private_key, options.receipt)
        else:
            verify(
                options.archive,
                options.receipt,
                options.trusted_public_key,
                options.trusted_fingerprint,
            )
    except (Hold, OSError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2  # REVIEW_ONLY, deliberately not a green release exit code.


if __name__ == "__main__":
    raise SystemExit(main())
