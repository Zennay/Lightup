#!/usr/bin/env python3
"""Private, owner-curated offline signer trust registry for original LightUp software.

This is a LOCAL custody registry, not authentication of actual client identity,
human consent, repository source, security review, or authority to deploy.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import sys

from cryptography.hazmat.primitives import serialization

from offline_signatures import (
    Hold, MAX_KEY_BYTES, _canonical, _fingerprint, _pairs_no_duplicates,
    _public_key, _regular_file_bytes, _write_new_private,
)

VERSION = "lightup.software.local_trust.v1"
HEX = re.compile(r"^[a-f0-9]{64}$")
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
REQUIRED = frozenset({"format", "fingerprint", "label", "public_pem_b64"})


def _fingerprint_text(value: str) -> str:
    if type(value) is not str or HEX.fullmatch(value) is None:
        raise Hold("fingerprint must be 64 lowercase hex characters")
    return value


def _owner_private(directory: Path) -> None:
    if not directory.is_absolute() or directory.is_symlink():
        raise Hold("registry directory must be absolute and cannot be a symlink")
    try:
        s = directory.stat(follow_symlinks=False)
    except OSError as exc:
        raise Hold("registry directory missing") from exc
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or (s.st_mode & 0o077):
        raise Hold("registry directory must be owned by the operator and mode 0700")


def init(directory: Path) -> None:
    if directory.exists() or directory.is_symlink() or not directory.is_absolute():
        raise Hold("choose a new, absolute, previously unused registry directory")
    _owner_private(directory.parent)
    directory.mkdir(mode=0o700)
    try:
        (directory / "keys").mkdir(mode=0o700)
        (directory / "revocations").mkdir(mode=0o700)
    except Exception:
        for child in ("keys", "revocations"):
            (directory / child).rmdir() if (directory / child).is_dir() else None
        directory.rmdir()
        raise
    print("REVIEW_ONLY: fresh private registry created. NO KEYS YET TRUSTED.")
    print("Register only keys with fingerprint independently confirmed out of band.")


def _subdirs(directory: Path) -> None:
    _owner_private(directory)
    _owner_private(directory / "keys")
    _owner_private(directory / "revocations")


def _json_file(path: Path) -> dict:
    if path.is_symlink():
        raise Hold("symlink registry record is refused")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or (info.st_mode & 0o077) or info.st_nlink != 1:
        raise Hold("registry record must be owner-private 0600 and single-link")
    raw = _regular_file_bytes(path, 16384)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (ValueError, UnicodeError) as exc:
        raise Hold("registry record has malformed or duplicate JSON fields") from exc
    if type(value) is not dict:
        raise Hold("registry record object required")
    return value


def _record(directory: Path, fingerprint: str) -> dict:
    _subdirs(directory)
    fp = _fingerprint_text(fingerprint)
    obj = _json_file(directory / "keys" / (fp + ".json"))
    if set(obj) != REQUIRED or any(type(obj[key]) is not str for key in REQUIRED):
        raise Hold("registry record fields not canonical")
    if obj["format"] != VERSION or obj["fingerprint"] != fp or LABEL.fullmatch(obj["label"]) is None:
        raise Hold("registry record format, fingerprint or label mismatch")
    try:
        raw_pem = base64.b64decode(obj["public_pem_b64"], validate=True)
    except ValueError as exc:
        raise Hold("invalid registry public key encoding") from exc
    if len(raw_pem) > MAX_KEY_BYTES or not raw_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n"):
        raise Hold("registry public key PEM format mismatch")
    # Only the canonical PEM serialization is stored, not the original input.
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        public = load_pem_public_key(raw_pem)
    except (ValueError, TypeError) as exc:
        raise Hold("registry public key cannot be decoded") from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(public, Ed25519PublicKey) or _fingerprint(public) != fp:
        raise Hold("registry key no longer matches original trusted fingerprint")
    if public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != raw_pem:
        raise Hold("registry PEM is not canonical")
    return obj


def register(directory: Path, pem: Path, expect_fingerprint: str, label: str) -> None:
    _subdirs(directory)
    fp = _fingerprint_text(expect_fingerprint)
    if type(label) is not str or LABEL.fullmatch(label) is None:
        raise Hold("label must be 1-64 visible ASCII letters, numbers, space, dash or dot")
    if (directory / "revocations" / (fp + ".json")).exists():
        raise Hold("revoked fingerprint cannot be registered again")
    public = _public_key(pem)
    if _fingerprint(public) != fp:
        raise Hold("trusted out-of-band fingerprint does not match supplied key")
    normal_pem = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    record = {
        "format": VERSION, "fingerprint": fp, "label": label,
        "public_pem_b64": base64.b64encode(normal_pem).decode("ascii"),
    }
    _write_new_private(directory / "keys" / (fp + ".json"), _canonical(record) + b"\n")
    print("REVIEW_ONLY: separately confirmed Ed25519 custody key registered:", label, fp)
    print("This key is NOT proof of verified source identity, client consent or HUMAN GO.")


def revoke(directory: Path, fingerprint: str) -> None:
    fp = _fingerprint_text(fingerprint)
    _record(directory, fp)
    tombstone = {"format": VERSION, "fingerprint": fp, "status": "PERMANENT_LOCAL_HOLD"}
    _write_new_private(
        directory / "revocations" / (fp + ".json"),
        _canonical(tombstone) + b"\n",
    )
    print("REVIEW_ONLY: local trust permanently revoked for", fp)
    print("Existing packages and previously exported copies cannot be remotely revoked.")


def trusted(directory: Path, fingerprint: str) -> dict:
    obj = _record(directory, fingerprint)
    path = directory / "revocations" / (fingerprint + ".json")
    if path.exists() or path.is_symlink():
        # A tampered tombstone cannot resurrect the key: existence is enough.
        raise Hold("local trust is revoked; this signing key is permanently HOLD")
    return obj


def minimum_signers(directory: Path) -> int:
    """Return persistent local minimum, never trusting caller flags to weaken it."""
    _subdirs(directory)
    marker = directory / "two-signers-required.json"
    if not marker.exists() and not marker.is_symlink():
        return 1
    obj = _json_file(marker)
    if obj != {
        "format": VERSION,
        "policy": "TWO_DISTINCT_LOCALLY_TRUSTED_SIGNERS_REQUIRED",
    }:
        raise Hold("signed-software local minimum signer policy file is malformed")
    return 2


def require_two(directory: Path) -> None:
    """One-way durable local increase, never a grant, approval or release act."""
    _subdirs(directory)
    if minimum_signers(directory) == 2:
        raise Hold("local two-signer policy already exists; it cannot be relaxed")
    candidates = sorted((directory / "keys").glob("*.json"))
    active = 0
    for candidate in candidates:
        if not candidate.is_file() or HEX.fullmatch(candidate.name[:-5]) is None:
            raise Hold("invalid private registry entry before raising local signer floor")
        try:
            trusted(directory, candidate.name[:-5])
        except Hold as exc:
            if "revoked" not in str(exc).lower():
                raise
        else:
            active += 1
    if active < 2:
        raise Hold("register at least TWO currently non-revoked independently trusted keys first")
    marker = {
        "format": VERSION,
        "policy": "TWO_DISTINCT_LOCALLY_TRUSTED_SIGNERS_REQUIRED",
    }
    _write_new_private(directory / "two-signers-required.json", _canonical(marker) + b"\n")
    print("REVIEW_ONLY: local minimum now requires TWO distinct non-revoked keys.")
    print("No automatic downgrade; local policy is not customer consent or release approval.")


def listing(directory: Path) -> None:
    _subdirs(directory)
    found = sorted((directory / "keys").iterdir())
    if len(found) > 256:
        raise Hold("registry entry count exceeds conservative bound")
    for path in found:
        if not path.name.endswith(".json") or HEX.fullmatch(path.name[:-5]) is None:
            raise Hold("unknown file in private trust registry")
        rec = _record(directory, path.name[:-5])
        revoked = (directory / "revocations" / path.name).exists()
        print(("REVOKED" if revoked else "LOCAL_REVIEW_TRUST"), rec["fingerprint"], rec["label"])
    if not found:
        print("EMPTY: no locally registered custody keys")
    print("LOCAL CUSTODY MINIMUM SIGNERS:", minimum_signers(directory))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "register", "revoke", "list", "require-two"):
        sub.add_parser(name).add_argument("--directory", type=Path, required=True)
    reg = sub.choices["register"]
    reg.add_argument("--public-key", type=Path, required=True)
    reg.add_argument("--trusted-fingerprint", required=True)
    reg.add_argument("--label", required=True)
    rev = sub.choices["revoke"]
    rev.add_argument("--trusted-fingerprint", required=True)
    options = parser.parse_args()
    try:
        if options.command == "init":
            init(options.directory)
        elif options.command == "register":
            register(options.directory, options.public_key, options.trusted_fingerprint, options.label)
        elif options.command == "revoke":
            revoke(options.directory, options.trusted_fingerprint)
        elif options.command == "require-two":
            require_two(options.directory)
        else:
            listing(options.directory)
    except (OSError, ValueError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
